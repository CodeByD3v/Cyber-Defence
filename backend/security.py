from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


PCAP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,200}\.pcap$", re.ASCII)


@dataclass(frozen=True)
class ValidationError(Exception):
    message: str

    def __str__(self) -> str:  # pragma: no cover
        return self.message


def validate_pcap_name(name: str) -> str:
    n = name.strip()
    if not PCAP_NAME_RE.fullmatch(n):
        raise ValidationError(
            "Invalid PCAP name. Use a filename like 'slammer.pcap' (no paths)."
        )
    return n


def resolve_pcap_path(pcap_dir: Path, pcap_name: str) -> Path:
    safe_name = validate_pcap_name(pcap_name)
    p = (pcap_dir / safe_name).resolve()
    if pcap_dir.resolve() not in p.parents and p != pcap_dir.resolve():
        raise ValidationError("PCAP must be inside the PCAP/ directory")
    if not p.exists():
        raise ValidationError(f"PCAP not found: {safe_name}")
    return p
