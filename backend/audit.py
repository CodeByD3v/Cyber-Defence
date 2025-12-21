from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class AuditEvent:
    ts: str
    kind: str
    command: str
    ok: bool
    detail: Dict[str, Any]
    client: Optional[str] = None


class AuditLogger:
    def __init__(self, log_dir: Path):
        self._log_dir = log_dir
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._path = self._log_dir / "commands.jsonl"

    def log_command(
        self,
        *,
        command: str,
        ok: bool,
        detail: Dict[str, Any] | None = None,
        client: str | None = None,
    ) -> None:
        evt = AuditEvent(
            ts=datetime.now(timezone.utc).isoformat(),
            kind="command",
            command=command,
            ok=ok,
            detail=detail or {},
            client=client,
        )
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(evt.__dict__, ensure_ascii=False) + "\n")
