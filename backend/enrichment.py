from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from .features import TemporalFeatures
from .windowing import SlidingWindow


BEHAVIORS = [
    "benign",
    "reconnaissance",
    "fuzzing",
    "dos_ddos",
    "exploitation",
    "backdoor_like_c2",
    "worm_like",
    "malicious_unclassified",
]


@dataclass(frozen=True)
class BehaviorVerdict:
    behavior: str
    confidence: float
    evidence: List[str]
    dst_hint: Optional[str] = None


def enrich_behavior(
    *,
    malicious_score: float,
    temporal: TemporalFeatures,
    window: SlidingWindow,
    alert_threshold: float,
) -> BehaviorVerdict:
    """Convert a binary malicious score + Zeek temporal indicators into behavior taxonomy.

    This is intentionally honest: if your shipped model is binary, the *behavior* label is
    derived from Zeek evidence (rules), while the confidence reflects ML malicious score.
    """

    if malicious_score < alert_threshold:
        return BehaviorVerdict(behavior="benign", confidence=1.0 - malicious_score, evidence=["Below ML alert threshold"])

    evidence: List[str] = []

    # DNS periodicity -> C2-like
    if temporal.periodicity_score >= 0.70 and len(window.dns) >= 8:
        evidence.append("Periodic DNS")
        return BehaviorVerdict(
            behavior="backdoor_like_c2",
            confidence=malicious_score,
            evidence=evidence,
        )

    # DoS/DDoS-like: very high packet rate and many flows
    if temporal.packets_per_second >= 200 or (temporal.flow_count >= 400 and temporal.packets_per_second >= 50):
        evidence.append("High PPS")
        return BehaviorVerdict(behavior="dos_ddos", confidence=malicious_score, evidence=evidence)

    # Worm-like: high fan-out to many destinations
    if temporal.unique_dst_ips >= 25 and temporal.unique_dst_ports >= 10:
        evidence.append("High fan-out")
        return BehaviorVerdict(behavior="worm_like", confidence=malicious_score, evidence=evidence)

    # Recon: many dst ports with short/low-byte connections
    short = [c for c in window.conns if c.duration <= 0.5]
    low_payload = [c for c in window.conns if (c.orig_bytes + c.resp_bytes) <= 200]
    if temporal.unique_dst_ports >= 30 and len(short) >= 25 and len(low_payload) >= 25:
        evidence.append("Port scanning")
        return BehaviorVerdict(behavior="reconnaissance", confidence=malicious_score, evidence=evidence)

    # Fuzzing: repeated requests to same service/port with many short conns (heuristic)
    if temporal.flow_count >= 200 and temporal.unique_dst_ips <= 3 and len(short) >= 100:
        evidence.append("High-volume short sessions")
        return BehaviorVerdict(behavior="fuzzing", confidence=malicious_score, evidence=evidence)

    # Exploitation: fewer flows but higher bytes and non-trivial durations
    if temporal.flow_count <= 50 and temporal.bytes_per_second >= 5000:
        evidence.append("High transfer rate")
        return BehaviorVerdict(behavior="exploitation", confidence=malicious_score, evidence=evidence)

    evidence.append("Behavior unclear")
    return BehaviorVerdict(behavior="malicious_unclassified", confidence=malicious_score, evidence=evidence)
