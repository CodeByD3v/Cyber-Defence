from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .security import ValidationError, resolve_pcap_path
from .state import SocState


@dataclass(frozen=True)
class CommandResult:
    ok: bool
    messages: List[str]
    data: Dict[str, Any] | None = None


class CommandRouter:
    def __init__(self, state: SocState):
        self._state = state

    def _help(self) -> CommandResult:
        return CommandResult(
            ok=True,
            messages=[
                "═══════════════════════════════════════════════════════════",
                "  SOC PLATFORM - COMMANDS",
                "═══════════════════════════════════════════════════════════",
                "",
                "SYSTEM:",
                "  /help              Show this help",
                "  /status            System status",
                "  /stats             Statistics",
                "  /clear             Reset state",
                "",
                "PCAP ANALYSIS (Real Traffic):",
                "  /zeek-pcap         List PCAP files",
                "  /zeek-pcap <file>  Process PCAP with Zeek + ML detection",
                "",
                "DATASET SIMULATION (UNSW-NB15):",
                "  /attack            10 random attacks from dataset",
                "  /attack <type>     1 specific attack type",
                "  /simulate <n>      N random attacks (1-100)",
                "  /attacks           List attack types",
                "",
                "EXPORT:",
                "  /export [json|csv] Export alerts",
                "═══════════════════════════════════════════════════════════",
            ],
        )

    def _stats(self) -> CommandResult:
        stats = self._state.stats_snapshot(window_s=60.0)
        uptime_s = (datetime.now(timezone.utc) - datetime.fromisoformat(self._state.started_at)).total_seconds()
        now_ts = datetime.now(timezone.utc).timestamp()
        alerts_1m = sum(1 for ts in self._state._alert_ts if ts >= now_ts - 60)
        alerts_5m = sum(1 for ts in self._state._alert_ts if ts >= now_ts - 300)
        
        return CommandResult(
            ok=True,
            messages=[
                "═══════════════════════════════════════════════════════════",
                "  STATISTICS",
                "═══════════════════════════════════════════════════════════",
                f"  Uptime:           {int(uptime_s // 3600)}h {int((uptime_s % 3600) // 60)}m {int(uptime_s % 60)}s",
                f"  Total Flows:      {stats['total_flows']:,}",
                f"  Total Alerts:     {stats['total_alerts']:,}",
                f"  Alerts (1m/5m):   {alerts_1m} / {alerts_5m}",
                "═══════════════════════════════════════════════════════════",
            ],
            data=stats,
        )

    def _status(self) -> CommandResult:
        z = self._state.zeek.status()
        payload = {
            "started_at": self._state.started_at,
            "zeek": z.__dict__,
            "alerts_total": len(self._state.alerts),
        }
        self._state.last_status = payload
        return CommandResult(ok=True, messages=[json.dumps(payload, indent=2)], data=payload)

    def dispatch(self, command: str, *, client: str | None = None) -> CommandResult:
        cmdline = command.strip()
        if not cmdline.startswith("/"):
            return CommandResult(ok=False, messages=["Commands must start with '/'"])

        parts = cmdline.split()
        head = parts[0].lower()
        args = parts[1:]

        try:
            if head == "/help":
                res = self._help()
            elif head == "/status":
                res = self._status()
            elif head == "/stats":
                res = self._stats()
            elif head == "/clear":
                self._state.clear()
                res = CommandResult(ok=True, messages=["State cleared."])
            elif head == "/zeek-pcap":
                if not args:
                    pcap_dir = self._state.cfg.pcap_dir
                    pcaps = list(pcap_dir.glob("*.pcap")) + list(pcap_dir.glob("*.cap"))
                    if not pcaps:
                        res = CommandResult(ok=False, messages=["No PCAP files in PCAP/ directory."])
                    else:
                        msgs = ["Available PCAP files:", ""]
                        for p in sorted(pcaps):
                            size_kb = p.stat().st_size / 1024
                            msgs.append(f"  {p.name} ({size_kb:.1f} KB)")
                        msgs.append("")
                        msgs.append("Usage: /zeek-pcap <filename>")
                        res = CommandResult(ok=True, messages=msgs)
                else:
                    pcap = resolve_pcap_path(self._state.cfg.pcap_dir, args[0])
                    self._state.zeek.stop()
                    self._state.zeek.start_pcap(pcap)
                    res = CommandResult(
                        ok=True,
                        messages=[
                            f"Processing {pcap.name} with Zeek...",
                            "Results will appear in Network Monitor",
                        ],
                        data={"action": "zeek_pcap", "pcap": str(pcap)}
                    )
            elif head == "/zeek":
                # Live Zeek capture (requires WSL with Zeek installed)
                sub = args[0].lower() if args else "status"
                if sub == "start":
                    self._state.zeek.start_live()
                    res = CommandResult(ok=True, messages=["Starting Zeek live capture..."])
                elif sub == "stop":
                    self._state.zeek.stop()
                    res = CommandResult(ok=True, messages=["Zeek stopped."])
                elif sub == "status":
                    z = self._state.zeek.status()
                    res = CommandResult(ok=True, messages=[
                        f"Zeek Status: {'Running' if z.running else 'Stopped'}",
                        f"Mode: {z.mode or 'N/A'}",
                    ])
                else:
                    res = CommandResult(ok=False, messages=[
                        "Usage: /zeek start|stop|status",
                        "Note: Requires Zeek installed in WSL"
                    ])
            elif head == "/attack":
                attack_type = args[0].lower() if args else None
                if attack_type:
                    available = self._state.simulator.get_available_attacks()
                    if attack_type not in available:
                        available_str = ", ".join(sorted(available))
                        raise ValidationError(f"Unknown: '{attack_type}'\nAvailable: {available_str}")
                    count = 1
                    msg = f"Simulating {attack_type.title()} attack..."
                else:
                    count = 10
                    msg = "Simulating 10 random attacks..."
                res = CommandResult(
                    ok=True,
                    messages=[msg],
                    data={"action": "simulate", "attack_type": attack_type, "count": count}
                )
            elif head == "/attacks":
                available = self._state.simulator.get_available_attacks()
                if not available:
                    res = CommandResult(ok=False, messages=["No attack samples loaded."])
                else:
                    from .mitre import get_mitre_dict
                    msgs = ["Attack types (UNSW-NB15 Dataset):", ""]
                    for at in sorted(available):
                        mitre = get_mitre_dict(at)
                        msgs.append(f"  {at.title():12} {mitre['technique_id']}")
                    msgs.append("")
                    msgs.append("Usage: /attack <type> or /simulate <count>")
                    res = CommandResult(ok=True, messages=msgs)
            elif head == "/simulate":
                # Simulate N random attacks from dataset
                count = 10
                if args:
                    try:
                        count = int(args[0])
                        count = max(1, min(count, 100))
                    except ValueError:
                        raise ValidationError("Usage: /simulate <count> (1-100)")
                res = CommandResult(
                    ok=True,
                    messages=[f"Simulating {count} random attacks from dataset..."],
                    data={"action": "simulate", "attack_type": None, "count": count}
                )
            elif head == "/export":
                fmt = (args[0].lower() if args else "json")
                if fmt not in {"json", "csv"}:
                    raise ValidationError("Usage: /export [json|csv]")
                self._state.cfg.detections_dir.mkdir(parents=True, exist_ok=True)
                ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                if fmt == "json":
                    out = self._state.cfg.detections_dir / f"export_{ts}.json"
                    with out.open("w", encoding="utf-8") as f:
                        json.dump([a.__dict__ for a in self._state.alerts], f, indent=2)
                else:
                    out = self._state.cfg.detections_dir / f"export_{ts}.csv"
                    with out.open("w", encoding="utf-8") as f:
                        f.write("timestamp,attack,confidence,src,dst,mitre\n")
                        for a in self._state.alerts:
                            mitre = a.mitre_technique_id or ""
                            f.write(f"{a.timestamp},{a.attack},{a.confidence:.4f},{a.src},{a.dst or ''},{mitre}\n")
                res = CommandResult(ok=True, messages=[f"Exported: {out.name}"])
            else:
                res = CommandResult(ok=False, messages=[f"Unknown command: {head}"])

            self._state.audit.log_command(command=cmdline, ok=res.ok, detail={"head": head}, client=client)
            return res
        except ValidationError as ve:
            self._state.audit.log_command(command=cmdline, ok=False, detail={"error": str(ve)}, client=client)
            return CommandResult(ok=False, messages=[str(ve)])
        except Exception as e:
            self._state.audit.log_command(command=cmdline, ok=False, detail={"error": repr(e)}, client=client)
            return CommandResult(ok=False, messages=["Internal error."])
