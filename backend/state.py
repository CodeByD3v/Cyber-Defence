from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

from .audit import AuditLogger
from .config import BackendConfig
from .enrichment import BehaviorVerdict
from .ml_inference import ModelWrapper
from .replay_controller import ReplayController
from .simulator import AttackSimulator
from .zeek_controller import ZeekController


@dataclass
class Alert:
    timestamp: str
    attack: str
    confidence: float
    src: str
    dst: Optional[str]
    evidence: List[str]
    # Lifecycle fields
    state: str = "new"  # new, investigating, confirmed, false_positive, closed
    analyst_notes: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    # MITRE ATT&CK mapping
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic_id: Optional[str] = None
    mitre_tactic_name: Optional[str] = None
    # Explainability
    explainability_features: List[str] = field(default_factory=list)
    explainability_evidence: List[str] = field(default_factory=list)


@dataclass
class SocState:
    cfg: BackendConfig
    audit: AuditLogger
    model: ModelWrapper
    zeek: ZeekController
    replay: ReplayController
    simulator: AttackSimulator
    alerts: List[Alert] = field(default_factory=list)
    last_status: Dict[str, Any] = field(default_factory=dict)
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    shutdown_event: asyncio.Event = field(default_factory=asyncio.Event)

    # Live telemetry (derived from real Zeek events)
    last_packet_ts: Optional[str] = None
    last_alert_ts: Optional[str] = None

    _flow_ts: Deque[float] = field(default_factory=lambda: deque(maxlen=200_000), repr=False)
    _alert_ts: Deque[float] = field(default_factory=lambda: deque(maxlen=50_000), repr=False)
    _byte_events: Deque[Tuple[float, int]] = field(default_factory=lambda: deque(maxlen=200_000), repr=False)
    _pkt_events: Deque[Tuple[float, int]] = field(default_factory=lambda: deque(maxlen=200_000), repr=False)

    _total_flows: int = 0
    _total_alerts: int = 0

    def clear(self) -> None:
        self.alerts.clear()
        self.last_status.clear()
        self.last_packet_ts = None
        self.last_alert_ts = None
        self._flow_ts.clear()
        self._alert_ts.clear()
        self._byte_events.clear()
        self._pkt_events.clear()
        self._total_flows = 0
        self._total_alerts = 0

    def record_flow(self, *, ts: float, bytes_total: int, pkts_total: int) -> None:
        """Record a single Zeek conn event (for rolling stats)."""

        if ts <= 0:
            return
        self._total_flows += 1
        self._flow_ts.append(ts)
        self._byte_events.append((ts, max(0, int(bytes_total))))
        self._pkt_events.append((ts, max(0, int(pkts_total))))
        self.last_packet_ts = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    def record_alert(self, *, ts: float) -> None:
        if ts <= 0:
            return
        self._total_alerts += 1
        self._alert_ts.append(ts)
        self.last_alert_ts = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    def stats_snapshot(self, *, now_ts: float | None = None, window_s: float = 60.0) -> Dict[str, Any]:
        """Compute rolling rates over a fixed trailing window.

        Uses Zeek timestamps (not wall clock) when available.
        """

        if now_ts is None:
            # Fall back to wall clock for idle status / startup.
            now_ts = datetime.now(timezone.utc).timestamp()

        cutoff = float(now_ts) - float(window_s)

        while self._flow_ts and self._flow_ts[0] < cutoff:
            self._flow_ts.popleft()
        while self._alert_ts and self._alert_ts[0] < cutoff:
            self._alert_ts.popleft()
        while self._byte_events and self._byte_events[0][0] < cutoff:
            self._byte_events.popleft()
        while self._pkt_events and self._pkt_events[0][0] < cutoff:
            self._pkt_events.popleft()

        flows_last_window = len(self._flow_ts)
        alerts_last_window = len(self._alert_ts)
        bytes_last_window = sum(b for _t, b in self._byte_events)
        pkts_last_window = sum(p for _t, p in self._pkt_events)

        denom = max(1.0, float(window_s))
        return {
            "window_s": float(window_s),
            "total_flows": int(self._total_flows),
            "total_alerts": int(self._total_alerts),
            "flows_last_window": int(flows_last_window),
            "alerts_last_window": int(alerts_last_window),
            "flows_per_second": float(flows_last_window) / denom,
            "packets_per_second": float(pkts_last_window) / denom,
            "bytes_per_second": float(bytes_last_window) / denom,
            "last_packet_ts": self.last_packet_ts,
            "last_alert_ts": self.last_alert_ts,
        }
