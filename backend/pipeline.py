from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Optional

from .config import BackendConfig
from .enrichment import enrich_behavior
from .explainability import extract_explainability, get_explainability_dict
from .features import compute_temporal_features
from .mitre import get_mitre_dict
from .ml_inference import ModelWrapper
from .tailer import ZeekEvent, tail_zeek_jsonlines
from .windowing import ConnObs, DnsObs, HttpObs, SlidingWindow


def _safe_float(v: Any) -> float:
    try:
        return float(v)
    except Exception:
        return 0.0


def _safe_int(v: Any) -> int:
    try:
        return int(v)
    except Exception:
        return 0


def _get(d: Dict[str, Any], key: str, default: Any = None) -> Any:
    if key in d:
        return d.get(key, default)
    return default


def _src_ip_from(rec: Dict[str, Any]) -> str:
    return str(_get(rec, "id.orig_h", ""))


def _dst_ip_from(rec: Dict[str, Any]) -> str:
    return str(_get(rec, "id.resp_h", ""))


def _dst_port_from(rec: Dict[str, Any]) -> int:
    return _safe_int(_get(rec, "id.resp_p", 0))


def conn_to_features(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Map Zeek conn.log record to UNSW-NB15 features for ML model."""
    proto = str(_get(rec, "proto", "")).strip().lower()
    service = str(_get(rec, "service", "-")).strip().lower()
    if not service or service == "-":
        service = "unknown"
    state = str(_get(rec, "conn_state", "")).strip().upper()

    dur = _safe_float(_get(rec, "duration", 0.0))
    spkts = _safe_int(_get(rec, "orig_pkts", 0))
    dpkts = _safe_int(_get(rec, "resp_pkts", 0))
    sbytes = _safe_int(_get(rec, "orig_bytes", 0))
    dbytes = _safe_int(_get(rec, "resp_bytes", 0))
    
    # Derived features
    sload = (sbytes * 8 / dur) if dur > 0 else 0.0  # bits per second
    dload = (dbytes * 8 / dur) if dur > 0 else 0.0
    sinpkt = (dur / spkts) if spkts > 0 else 0.0  # inter-packet time
    dinpkt = (dur / dpkts) if dpkts > 0 else 0.0
    smean = (sbytes / spkts) if spkts > 0 else 0.0  # mean packet size
    dmean = (dbytes / dpkts) if dpkts > 0 else 0.0
    
    # TTL values (Zeek doesn't provide these directly, use defaults)
    sttl = 64
    dttl = 64
    
    return {
        "dur": dur,
        "proto": proto,
        "service": service,
        "state": state,
        "spkts": spkts,
        "dpkts": dpkts,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "sttl": sttl,
        "dttl": dttl,
        "sload": sload,
        "dload": dload,
        "sloss": 0,
        "dloss": 0,
        "sinpkt": sinpkt,
        "dinpkt": dinpkt,
        "sjit": 0.0,
        "djit": 0.0,
        "swin": 0,
        "dwin": 0,
        "tcprtt": 0.0,
        "synack": 0.0,
        "ackdat": 0.0,
        "smean": smean,
        "dmean": dmean,
        "trans_depth": 0,
        "response_body_len": 0,
        "ct_srv_src": 1,
        "ct_state_ttl": 1,
        "ct_dst_ltm": 1,
        "ct_src_dport_ltm": 1,
        "ct_dst_sport_ltm": 1,
        "ct_dst_src_ltm": 1,
        "is_ftp_login": 0,
        "ct_ftp_cmd": 0,
        "ct_flw_http_mthd": 0,
        "ct_src_ltm": 1,
        "ct_srv_dst": 1,
        "is_sm_ips_ports": 0,
    }


class SocPipeline:
    def __init__(
        self,
        *,
        cfg: BackendConfig,
        model: ModelWrapper,
        on_event: Callable[[Dict[str, Any]], Awaitable[None]],
    ):
        self._cfg = cfg
        self._model = model
        self._on_event = on_event
        self._windows: Dict[str, SlidingWindow] = {}
        self._tasks: list[asyncio.Task] = []

    def start(self) -> None:
        self._tasks = [
            asyncio.create_task(self._run_log("conn")),
            asyncio.create_task(self._run_log("dns")),
            asyncio.create_task(self._run_log("http")),
        ]

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    def reset(self) -> None:
        self._windows.clear()

    def _win(self, src: str) -> SlidingWindow:
        w = self._windows.get(src)
        if w is None:
            w = SlidingWindow(window_seconds=self._cfg.window_seconds)
            self._windows[src] = w
        return w

    async def _run_log(self, log: str) -> None:
        path = self._cfg.zeek_log_dir / f"{log}.log"
        async for evt in tail_zeek_jsonlines(path, log_name=log, start_at_end=True):
            await self._handle(evt)
    
    async def process_existing_logs(self, delay: float = 0.5) -> int:
        """Process existing Zeek logs (for PCAP analysis). Returns count of records processed."""
        import json
        count = 0
        
        # Clear old window data for fresh PCAP analysis
        self._windows.clear()
        
        for log in ["conn", "dns", "http"]:
            path = self._cfg.zeek_log_dir / f"{log}.log"
            if not path.exists():
                continue
            try:
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                
                # Check if TSV or JSON format
                fields = []
                for line in lines:
                    line = line.strip()
                    if line.startswith("#fields"):
                        # TSV format - extract field names
                        fields = line.split("\t")[1:]
                        break
                    elif line and not line.startswith("#"):
                        # Try JSON
                        try:
                            json.loads(line)
                            # It's JSON format
                            break
                        except json.JSONDecodeError:
                            pass
                
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    rec = None
                    if fields:
                        # TSV format - parse using field names
                        values = line.split("\t")
                        if len(values) == len(fields):
                            rec = {}
                            for i, field in enumerate(fields):
                                val = values[i]
                                if val == "-" or val == "(empty)":
                                    val = None
                                rec[field] = val
                    else:
                        # JSON format
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                    
                    if rec:
                        evt = ZeekEvent(log=log, record=rec)
                        await self._handle(evt)
                        count += 1
                        # Add delay between flows for visibility
                        if delay > 0:
                            await asyncio.sleep(delay)
            except Exception as e:
                print(f"[Pipeline] Error reading {log}.log: {e}")
        return count

    async def _handle(self, evt: ZeekEvent) -> None:
        rec = evt.record
        ts = _safe_float(_get(rec, "ts", 0.0))
        if ts <= 0:
            return

        if evt.log == "conn":
            src = _src_ip_from(rec)
            dst = _dst_ip_from(rec)
            if not src:
                return
            w = self._win(src)
            w.add_conn(
                ConnObs(
                    ts=ts,
                    src=src,
                    dst=dst,
                    dst_port=_dst_port_from(rec),
                    proto=str(_get(rec, "proto", "")).lower(),
                    duration=_safe_float(_get(rec, "duration", 0.0)),
                    orig_pkts=_safe_int(_get(rec, "orig_pkts", 0)),
                    resp_pkts=_safe_int(_get(rec, "resp_pkts", 0)),
                    orig_bytes=_safe_int(_get(rec, "orig_bytes", 0)),
                    resp_bytes=_safe_int(_get(rec, "resp_bytes", 0)),
                    conn_state=str(_get(rec, "conn_state", "")),
                )
            )

            # Raw Zeek flow record for UI monitor
            await self._on_event(
                {
                    "type": "flow",
                    "timestamp": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                    "log": "conn",
                    "src": src,
                    "dst": dst,
                    "record": rec,
                }
            )
            
            # Send VM stream events for attacker/victim terminals
            dst_port = _dst_port_from(rec)
            proto = str(_get(rec, "proto", "tcp")).lower()
            conn_state = str(_get(rec, "conn_state", ""))
            orig_bytes = _safe_int(_get(rec, "orig_bytes", 0))
            
            # Attacker stream - show connection attempt
            await self._on_event({
                "type": "vm_stream",
                "timestamp": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                "vm": "attacker",
                "stream": "packet",
                "content": f"{proto.upper()} {src}:{_safe_int(_get(rec, 'id.orig_p', 0))} -> {dst}:{dst_port} [{conn_state}] {orig_bytes}B",
            })
            
            # Victim stream - show incoming connection
            await self._on_event({
                "type": "vm_stream",
                "timestamp": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                "vm": "victim",
                "stream": "log",
                "content": f"[conn] {src} -> :{dst_port} ({proto}) state={conn_state}",
            })

            temporal = compute_temporal_features(w.snapshot(ts))

            # ML scoring per-conn (existing model) + behavior enrichment per-window
            ml = self._model.score_conn_features(conn_to_features(rec))
            
            # Use ML prediction directly (like simulator does)
            predicted_attack = ml.predicted_label
            is_normal = predicted_attack.lower() in {'normal', 'benign', '0'}
            
            # Debug output
            print(f"[Pipeline] {src} -> {dst}: {predicted_attack} ({ml.malicious_score:.1%}) normal={is_normal}")
            
            if not is_normal and ml.malicious_score >= self._cfg.alert_threshold:
                # Get MITRE ATT&CK mapping based on ML prediction
                mitre = get_mitre_dict(predicted_attack.lower())
                
                # Get explainability
                xai = extract_explainability(
                    temporal=temporal,
                    window=w,
                    behavior=predicted_attack.lower(),
                    ml_score=ml.malicious_score,
                    conn_record=rec,
                )
                
                # Build evidence like simulator does
                evidence = [
                    f"ML Prediction: {predicted_attack}",
                    f"Confidence: {ml.malicious_score:.1%}",
                ]
                
                await self._on_event(
                    {
                        "type": "attack_alert",
                        "timestamp": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                        "attack": predicted_attack,
                        "confidence": float(ml.malicious_score),
                        "src": src,
                        "dst": dst,
                        "evidence": evidence,
                        "ml": {
                            "malicious_score": float(ml.malicious_score),
                            "model_mode": str(ml.model_mode),
                            "predicted_label": str(ml.predicted_label),
                            "raw_class": ml.raw_class,
                        },
                        "mitre": mitre,
                        "explainability": get_explainability_dict(xai),
                    }
                )

        elif evt.log == "dns":
            src = _src_ip_from(rec)
            if not src:
                return
            q = str(_get(rec, "query", ""))
            rcode = str(_get(rec, "rcode_name", _get(rec, "rcode", "")))
            self._win(src).add_dns(DnsObs(ts=ts, src=src, query=q, rcode=rcode))
        elif evt.log == "http":
            src = _src_ip_from(rec)
            if not src:
                return
            host = str(_get(rec, "host", ""))
            uri = str(_get(rec, "uri", ""))
            method = str(_get(rec, "method", ""))
            code = _safe_int(_get(rec, "status_code", 0))
            self._win(src).add_http(
                HttpObs(ts=ts, src=src, host=host, uri=uri, method=method, status_code=code)
            )
