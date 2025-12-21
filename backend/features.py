from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Set

from .windowing import SlidingWindow


@dataclass(frozen=True)
class TemporalFeatures:
    flow_count: int
    unique_dst_ips: int
    unique_dst_ports: int
    packets_per_second: float
    bytes_per_second: float
    duration_mean: float
    duration_p95: float
    periodicity_score: float


def _percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    v = sorted(values)
    k = int(math.ceil((p / 100.0) * len(v))) - 1
    k = max(0, min(k, len(v) - 1))
    return float(v[k])


def compute_temporal_features(window: SlidingWindow) -> TemporalFeatures:
    conns = list(window.conns)
    if not conns:
        return TemporalFeatures(
            flow_count=0,
            unique_dst_ips=0,
            unique_dst_ports=0,
            packets_per_second=0.0,
            bytes_per_second=0.0,
            duration_mean=0.0,
            duration_p95=0.0,
            periodicity_score=0.0,
        )

    dst_ips: Set[str] = set()
    dst_ports: Set[int] = set()

    total_pkts = 0
    total_bytes = 0
    durations: List[float] = []

    for c in conns:
        dst_ips.add(c.dst)
        dst_ports.add(int(c.dst_port))
        total_pkts += int(c.orig_pkts) + int(c.resp_pkts)
        total_bytes += int(c.orig_bytes) + int(c.resp_bytes)
        durations.append(float(c.duration))

    ws = max(1.0, float(window.window_seconds))
    packets_per_second = float(total_pkts) / ws
    bytes_per_second = float(total_bytes) / ws
    duration_mean = float(sum(durations) / len(durations)) if durations else 0.0
    duration_p95 = _percentile(durations, 95.0)

    # Periodicity score from DNS inter-arrival times (per src-window)
    dns_ts = [d.ts for d in window.dns]
    dns_ts.sort()
    periodicity_score = 0.0
    if len(dns_ts) >= 6:
        intervals = [dns_ts[i] - dns_ts[i - 1] for i in range(1, len(dns_ts))]
        intervals = [x for x in intervals if x > 0]
        if len(intervals) >= 5:
            mean_i = sum(intervals) / len(intervals)
            if mean_i > 0:
                var = sum((x - mean_i) ** 2 for x in intervals) / len(intervals)
                std = math.sqrt(var)
                cv = std / mean_i
                # Map low CV (regular) -> high score
                periodicity_score = max(0.0, min(1.0, 1.0 - min(cv, 1.0)))

    return TemporalFeatures(
        flow_count=len(conns),
        unique_dst_ips=len(dst_ips),
        unique_dst_ports=len(dst_ports),
        packets_per_second=packets_per_second,
        bytes_per_second=bytes_per_second,
        duration_mean=duration_mean,
        duration_p95=duration_p95,
        periodicity_score=periodicity_score,
    )
