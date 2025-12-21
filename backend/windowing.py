from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Iterable, List, Optional, Tuple


@dataclass
class ConnObs:
    ts: float
    src: str
    dst: str
    dst_port: int
    proto: str
    duration: float
    orig_pkts: int
    resp_pkts: int
    orig_bytes: int
    resp_bytes: int
    conn_state: str


@dataclass
class DnsObs:
    ts: float
    src: str
    query: str
    rcode: str


@dataclass
class HttpObs:
    ts: float
    src: str
    host: str
    uri: str
    method: str
    status_code: int


@dataclass
class SlidingWindow:
    window_seconds: int
    conns: Deque[ConnObs] = field(default_factory=lambda: deque(maxlen=10000))
    dns: Deque[DnsObs] = field(default_factory=lambda: deque(maxlen=10000))
    http: Deque[HttpObs] = field(default_factory=lambda: deque(maxlen=10000))

    def _evict(self, now_ts: float) -> None:
        cutoff = now_ts - float(self.window_seconds)
        while self.conns and self.conns[0].ts < cutoff:
            self.conns.popleft()
        while self.dns and self.dns[0].ts < cutoff:
            self.dns.popleft()
        while self.http and self.http[0].ts < cutoff:
            self.http.popleft()

    def add_conn(self, obs: ConnObs) -> None:
        self._evict(obs.ts)
        self.conns.append(obs)

    def add_dns(self, obs: DnsObs) -> None:
        self._evict(obs.ts)
        self.dns.append(obs)

    def add_http(self, obs: HttpObs) -> None:
        self._evict(obs.ts)
        self.http.append(obs)

    def snapshot(self, now_ts: float) -> "SlidingWindow":
        self._evict(now_ts)
        return self
