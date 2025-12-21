from __future__ import annotations

# Suppress sklearn and xgboost version warnings
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", message=".*InconsistentVersionWarning.*")
warnings.filterwarnings("ignore", message=".*unpickle.*")

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Set

from aiohttp import web

from .audit import AuditLogger
from .command_router import CommandRouter
from .config import BackendConfig
from .ml_inference import ModelWrapper
from .pipeline import SocPipeline
from .replay_controller import ReplayController
from .simulator import AttackSimulator
from .state import Alert, SocState
from .zeek_controller import ZeekController


class SocServer:
    def __init__(self, cfg: BackendConfig):
        cfg.backend_log_dir.mkdir(parents=True, exist_ok=True)
        self._cfg = cfg
        self._audit = AuditLogger(cfg.backend_log_dir)
        self._model = ModelWrapper(cfg.model_pipeline_path)
        self._state = SocState(
            cfg=cfg,
            audit=self._audit,
            model=self._model,
            zeek=ZeekController(cfg),
            replay=ReplayController(cfg),
            simulator=AttackSimulator(cfg),
        )
        self._router = CommandRouter(self._state)
        self._clients: Set[web.WebSocketResponse] = set()
        self._pipeline = SocPipeline(cfg=cfg, model=self._model, on_event=self._broadcast)
        self._proc_log_task: Optional[asyncio.Task] = None
        self._stats_task: Optional[asyncio.Task] = None
        self._proc_last_running: Dict[str, bool] = {}

        # Session log: store terminal-relevant events from start to shutdown.
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self._session_log_path: Path = cfg.backend_log_dir / f"session_{ts}.jsonl"
        self._session_log_fp = self._session_log_path.open("a", encoding="utf-8")

    def _system_status_payload(self) -> Dict[str, Any]:
        z = self._state.zeek.status()
        r = self._state.replay.status()
        return {
            "type": "system_status",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "started_at": self._state.started_at,
            "zeek": z.__dict__,
            "replay": r.__dict__,
            "ml": {
                "running": True,
                "model": str(self._cfg.model_pipeline_path.name),
                "threshold": float(self._cfg.alert_threshold),
                "window_seconds": int(self._cfg.window_seconds),
            },
            "telemetry": {
                "last_packet_ts": self._state.last_packet_ts,
                "last_alert_ts": self._state.last_alert_ts,
            },
        }

    async def _send_command_output(self, *, ws: web.WebSocketResponse, lines: list[str], ok: bool) -> None:
        level = "stdout" if ok else "stderr"
        for line in lines:
            await ws.send_str(
                json.dumps(
                    {
                        "type": "command_output",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "stream": "command",
                        "level": level,
                        "line": str(line),
                    },
                    ensure_ascii=False,
                )
            )

    async def _broadcast(self, payload: Dict[str, Any]) -> None:
        ptype = payload.get("type")

        # Persist terminal-ish events for the whole run.
        if ptype in {"command_output", "attack_alert"}:
            try:
                self._session_log_fp.write(json.dumps(payload, ensure_ascii=False) + "\n")
                self._session_log_fp.flush()
            except Exception:
                pass

        if ptype == "flow" and payload.get("log") == "conn":
            rec = payload.get("record")
            if isinstance(rec, dict):
                try:
                    ts = float(rec.get("ts", 0.0))
                except Exception:
                    ts = 0.0
                try:
                    pkts = int(rec.get("orig_pkts", 0)) + int(rec.get("resp_pkts", 0))
                except Exception:
                    pkts = 0
                try:
                    bts = int(rec.get("orig_bytes", 0)) + int(rec.get("resp_bytes", 0))
                except Exception:
                    bts = 0
                self._state.record_flow(ts=ts, bytes_total=bts, pkts_total=pkts)

        if ptype == "attack_alert":
            # Extract MITRE and explainability from payload
            mitre = payload.get("mitre", {})
            xai = payload.get("explainability", {})
            
            # Persist for /export
            self._state.alerts.append(
                Alert(
                    timestamp=str(payload.get("timestamp")),
                    attack=str(payload.get("attack")),
                    confidence=float(payload.get("confidence", 0.0)),
                    src=str(payload.get("src")),
                    dst=payload.get("dst"),
                    evidence=list(payload.get("evidence", [])),
                    mitre_technique_id=mitre.get("technique_id"),
                    mitre_technique_name=mitre.get("technique_name"),
                    mitre_tactic_id=mitre.get("tactic_id"),
                    mitre_tactic_name=mitre.get("tactic_name"),
                    explainability_features=xai.get("top_features", []),
                    explainability_evidence=xai.get("zeek_evidence", []),
                )
            )
            # Prefer Zeek ts from payload timestamp if possible.
            ts_val: float
            try:
                ts_val = datetime.fromisoformat(str(payload.get("timestamp"))).timestamp()
            except Exception:
                ts_val = datetime.now(timezone.utc).timestamp()
            self._state.record_alert(ts=ts_val)

        msg = json.dumps(payload, ensure_ascii=False)
        dead: Set[web.WebSocketResponse] = set()
        for ws in self._clients:
            try:
                await ws.send_str(msg)
            except Exception:
                dead.add(ws)
        self._clients.difference_update(dead)

    async def ws_handler(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)
        self._clients.add(ws)

        await ws.send_str(json.dumps(self._system_status_payload(), ensure_ascii=False))
        await ws.send_str(
            json.dumps(
                {
                    "type": "stats_update",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "stats": self._state.stats_snapshot(window_s=60.0),
                },
                ensure_ascii=False,
            )
        )

        try:
            async for msg in ws:
                if msg.type == web.WSMsgType.TEXT:
                    await self._handle_ws_text(ws, msg.data)
                elif msg.type == web.WSMsgType.ERROR:
                    break
        except asyncio.CancelledError:
            # During Ctrl+C / graceful shutdown aiohttp cancels in-flight handlers.
            # Treat as a normal disconnect to avoid noisy shutdown tracebacks.
            pass
        finally:
            self._clients.discard(ws)
        return ws

    async def _handle_ws_text(self, ws: web.WebSocketResponse, data: str) -> None:
        client = ws._req.remote if getattr(ws, "_req", None) else None
        cmd = None
        try:
            payload = json.loads(data)
            if isinstance(payload, dict) and payload.get("type") == "command":
                cmd = str(payload.get("command", ""))
        except Exception:
            cmd = data

        if not cmd:
            await ws.send_str(json.dumps({"type": "error", "message": "No command provided"}))
            return

        res = self._router.dispatch(cmd, client=client)
        await self._send_command_output(ws=ws, lines=res.messages, ok=res.ok)
        
        # Handle simulation action
        if res.data and res.data.get("action") == "simulate":
            attack_type = res.data.get("attack_type")
            count = res.data.get("count", 5)
            # Run simulation in background
            asyncio.create_task(self._run_simulation(attack_type, count))
        
        # Handle zeek-pcap action - wait for Zeek to finish then process logs
        if res.data and res.data.get("action") == "zeek_pcap":
            asyncio.create_task(self._process_zeek_pcap(res.data.get("pcap", "")))
        
        # Push status after any command (cheap and keeps UI truthful).
        await self._broadcast(self._system_status_payload())

    async def health(self, _request: web.Request) -> web.Response:
        return web.json_response({"ok": True, "time": datetime.now(timezone.utc).isoformat()})

    async def index(self, _request: web.Request) -> web.StreamResponse:
        ui = self._cfg.project_root / "attack-detection-viz.html"
        if ui.exists():
            return web.FileResponse(path=ui)
        return web.Response(status=404, text="UI file not found: attack-detection-viz.html")

    async def on_startup(self, _app: web.Application) -> None:
        self._pipeline.start()
        self._proc_log_task = asyncio.create_task(self._drain_process_logs())
        self._stats_task = asyncio.create_task(self._emit_stats())

    async def on_cleanup(self, _app: web.Application) -> None:
        await self._pipeline.stop()
        if self._proc_log_task:
            self._proc_log_task.cancel()
            await asyncio.gather(self._proc_log_task, return_exceptions=True)
        if self._stats_task:
            self._stats_task.cancel()
            await asyncio.gather(self._stats_task, return_exceptions=True)
        self._state.replay.stop()
        self._state.zeek.stop()

        try:
            self._session_log_fp.close()
        except Exception:
            pass

    async def _drain_process_logs(self) -> None:
        """Continuously forward Zeek/tcpreplay stdout as command_output events."""
        while True:
            try:
                for name, proc in (
                    ("zeek", self._state.zeek.process()),
                    ("replay", self._state.replay.process()),
                ):
                    if not proc:
                        continue

                    # Drain output even if the process already exited, otherwise
                    # fast failures (e.g., permissions, interface open) can be missed.
                    lines = proc.drain_output(max_lines=50)
                    for line in lines:
                        await self._broadcast(
                            {
                                "type": "command_output",
                                "stream": name,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "level": "stdout",
                                "line": line,
                            }
                        )

                    is_running = proc.is_running()
                    was_running = bool(self._proc_last_running.get(name, False))
                    if was_running and not is_running:
                        rc = None
                        try:
                            if getattr(proc, "proc", None) is not None:
                                rc = proc.proc.poll()  # type: ignore[union-attr]
                        except Exception:
                            rc = None
                        await self._broadcast(
                            {
                                "type": "command_output",
                                "stream": name,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "level": "stderr",
                                "line": f"[{name}] process exited (code={rc})",
                            }
                        )
                    self._proc_last_running[name] = is_running
            except Exception:
                # keep the pump alive
                pass
            await asyncio.sleep(0.2)

    async def _emit_stats(self) -> None:
        while True:
            try:
                await self._broadcast(
                    {
                        "type": "stats_update",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "stats": self._state.stats_snapshot(window_s=60.0),
                    }
                )
            except Exception:
                pass
            await asyncio.sleep(1.0)

    async def _run_simulation(self, attack_type: Optional[str], count: int) -> None:
        """Run attack simulation in background."""
        try:
            result = await self._state.simulator.simulate_attack(
                attack_type=attack_type,
                on_event=self._broadcast,
                model_wrapper=self._model,
                count=count,
                delay=0.5,
            )
            # Send completion message
            await self._broadcast({
                "type": "command_output",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stream": "simulator",
                "level": "stdout" if result.success else "stderr",
                "line": result.message,
            })
        except Exception as e:
            await self._broadcast({
                "type": "command_output",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stream": "simulator",
                "level": "stderr",
                "line": f"Simulation error: {e}",
            })

    async def _process_zeek_pcap(self, pcap_path: str) -> None:
        """Wait for Zeek to finish processing PCAP, then read and broadcast the logs with VM windows."""
        import json
        
        try:
            pcap_name = Path(pcap_path).name if pcap_path else "PCAP"
            
            # Wait for Zeek process to finish (with timeout)
            for _ in range(60):  # Max 60 seconds
                if not self._state.zeek.status().running:
                    break
                await asyncio.sleep(0.5)
            
            # Wait for logs to be fully written
            await asyncio.sleep(1.0)
            
            # Check if conn.log exists
            conn_log = self._cfg.zeek_log_dir / "conn.log"
            if not conn_log.exists():
                await self._broadcast({
                    "type": "command_output",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "stream": "zeek",
                    "level": "stderr",
                    "line": "No conn.log found - Zeek may have failed",
                })
                return
            
            # Extract first src/dst IPs from conn.log for VM setup
            attacker_ip = "Unknown"
            victim_ip = "Unknown"
            try:
                with conn_log.open("r", encoding="utf-8", errors="replace") as f:
                    fields = []
                    for line in f:
                        line = line.strip()
                        if line.startswith("#fields"):
                            fields = line.split("\t")[1:]
                        elif line and not line.startswith("#"):
                            # Try to parse first data line
                            if fields:
                                # TSV format
                                values = line.split("\t")
                                if len(values) == len(fields):
                                    rec = dict(zip(fields, values))
                                    attacker_ip = rec.get("id.orig_h", "Unknown")
                                    victim_ip = rec.get("id.resp_h", "Unknown")
                                    break
                            else:
                                # Try JSON
                                try:
                                    rec = json.loads(line)
                                    attacker_ip = rec.get("id.orig_h", "Unknown")
                                    victim_ip = rec.get("id.resp_h", "Unknown")
                                    break
                                except json.JSONDecodeError:
                                    pass
            except Exception:
                pass
            
            # Send VM setup event (like /attack command does)
            await self._broadcast({
                "type": "vm_setup",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "attack_type": "pcap_analysis",
                "description": f"Zeek PCAP Analysis - {pcap_name}",
                "attacker": {"ip": attacker_ip, "hostname": "source-host"},
                "victim": {"ip": victim_ip, "hostname": "target-host"},
            })
            
            # Notify start of ML analysis
            await self._broadcast({
                "type": "command_output",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stream": "zeek",
                "level": "stdout",
                "line": f"Running ML detection on {pcap_name}...",
            })
            
            # Process existing Zeek logs with delay between flows
            count = await self._pipeline.process_existing_logs(delay=0.3)
            
            # Send completion message
            await self._broadcast({
                "type": "command_output",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stream": "zeek",
                "level": "stdout",
                "line": f"Completed: {count} flows analyzed with ML model",
            })
        except Exception as e:
            await self._broadcast({
                "type": "command_output",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stream": "zeek",
                "level": "stderr",
                "line": f"Error processing PCAP logs: {e}",
            })

    def make_app(self) -> web.Application:
        app = web.Application(client_max_size=1_000_000)
        app.add_routes(
            [
                web.get("/", self.index),
                web.get("/ui", self.index),
                web.get(self._cfg.websocket_path, self.ws_handler),
                web.get("/api/health", self.health),
            ]
        )
        app.on_startup.append(self.on_startup)
        app.on_cleanup.append(self.on_cleanup)
        return app


def main() -> int:
    cfg = BackendConfig.from_env()
    server = SocServer(cfg)
    app = server.make_app()
    web.run_app(app, host=cfg.listen_host, port=cfg.listen_port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
