"""Explainability (XAI-lite) for attack alerts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from .features import TemporalFeatures
from .windowing import SlidingWindow


@dataclass(frozen=True)
class ExplainabilityResult:
    top_features: List[str]
    zeek_evidence: List[str]
    confidence_factors: List[str]


def extract_explainability(
    *,
    temporal: TemporalFeatures,
    window: SlidingWindow,
    behavior: str,
    ml_score: float,
    conn_record: Dict[str, Any] | None = None,
) -> ExplainabilityResult:
    """Extract human-readable explanations for why an alert was triggered."""
    
    top_features: List[str] = []
    zeek_evidence: List[str] = []
    confidence_factors: List[str] = []
    
    # Temporal feature explanations
    if temporal.packets_per_second >= 200:
        top_features.append(f"Very high packet rate ({temporal.packets_per_second:.0f} pps)")
    elif temporal.packets_per_second >= 50:
        top_features.append(f"High packet rate ({temporal.packets_per_second:.0f} pps)")
    
    if temporal.unique_dst_ips >= 25:
        top_features.append(f"High destination fan-out ({temporal.unique_dst_ips} unique IPs)")
    
    if temporal.unique_dst_ports >= 30:
        top_features.append(f"Many destination ports ({temporal.unique_dst_ports} ports)")
    
    if temporal.periodicity_score >= 0.70:
        top_features.append(f"Periodic DNS pattern (score: {temporal.periodicity_score:.2f})")
    
    if temporal.flow_count >= 200:
        top_features.append(f"High flow count ({temporal.flow_count} flows)")
    
    if temporal.duration_mean < 0.5 and temporal.flow_count > 10:
        top_features.append(f"Short-lived connections (avg: {temporal.duration_mean:.2f}s)")
    
    if temporal.bytes_per_second >= 5000:
        top_features.append(f"High data transfer ({temporal.bytes_per_second:.0f} B/s)")
    
    # Zeek evidence from connection record
    if conn_record:
        proto = str(conn_record.get("proto", "")).upper()
        if proto:
            zeek_evidence.append(f"proto={proto}")
        
        service = str(conn_record.get("service", ""))
        if service:
            zeek_evidence.append(f"service={service}")
        
        conn_state = str(conn_record.get("conn_state", ""))
        if conn_state:
            zeek_evidence.append(f"conn_state={conn_state}")
            # Explain connection states
            if conn_state in ("S0", "S1", "S2", "S3"):
                confidence_factors.append("Incomplete TCP handshake")
            elif conn_state in ("REJ", "RSTO", "RSTR"):
                confidence_factors.append("Connection rejected/reset")
        
        duration = conn_record.get("duration")
        if duration is not None:
            zeek_evidence.append(f"duration={float(duration):.3f}s")
        
        orig_bytes = conn_record.get("orig_bytes", 0)
        resp_bytes = conn_record.get("resp_bytes", 0)
        if orig_bytes or resp_bytes:
            zeek_evidence.append(f"bytes={orig_bytes}→{resp_bytes}")
    
    # Confidence factors based on ML score
    if ml_score >= 0.95:
        confidence_factors.append("Very high ML confidence")
    elif ml_score >= 0.85:
        confidence_factors.append("High ML confidence")
    elif ml_score >= 0.70:
        confidence_factors.append("Moderate ML confidence")
    else:
        confidence_factors.append("Low ML confidence - analyst review recommended")
    
    # Behavior-specific explanations
    if behavior == "backdoor_like_c2":
        confidence_factors.append("Periodic beaconing pattern detected")
    elif behavior == "dos_ddos":
        confidence_factors.append("Flood-like traffic pattern")
    elif behavior == "reconnaissance":
        confidence_factors.append("Scanning/probing behavior")
    elif behavior == "worm_like":
        confidence_factors.append("Lateral movement pattern")
    elif behavior == "exploitation":
        confidence_factors.append("Potential exploit delivery")
    elif behavior == "fuzzing":
        confidence_factors.append("Repeated malformed requests")
    
    return ExplainabilityResult(
        top_features=top_features or ["No specific features flagged"],
        zeek_evidence=zeek_evidence or ["No Zeek evidence available"],
        confidence_factors=confidence_factors or ["Standard detection"],
    )


def get_explainability_dict(result: ExplainabilityResult) -> Dict[str, List[str]]:
    """Convert ExplainabilityResult to dict for JSON serialization."""
    return {
        "top_features": result.top_features,
        "zeek_evidence": result.zeek_evidence,
        "confidence_factors": result.confidence_factors,
    }
