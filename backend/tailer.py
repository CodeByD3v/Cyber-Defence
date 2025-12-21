from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Optional


@dataclass(frozen=True)
class ZeekEvent:
    log: str
    record: Dict[str, Any]


async def tail_zeek_jsonlines(
    path: Path,
    *,
    log_name: str,
    start_at_end: bool = True,
    poll_interval_s: float = 0.25,
) -> AsyncIterator[ZeekEvent]:
    """Tail a Zeek JSON-lines log file.

    Handles "file not yet created" and basic truncation/rotation.
    """

    fp: Optional[object] = None
    pos = 0

    while True:
        if not path.exists():
            await asyncio.sleep(poll_interval_s)
            continue

        try:
            if fp is None:
                f = path.open("r", encoding="utf-8", errors="replace")
                fp = f
                if start_at_end:
                    f.seek(0, 2)
                pos = f.tell()

            f2 = fp  # type: ignore[assignment]
            # Detect truncation
            try:
                size = path.stat().st_size
                if size < pos:
                    f2.close()
                    fp = None
                    pos = 0
                    continue
            except Exception:
                pass

            line = f2.readline()
            if not line:
                await asyncio.sleep(poll_interval_s)
                continue
            pos = f2.tell()

            line = line.strip()
            if not line or line.startswith("#"):
                continue

            try:
                rec = json.loads(line)
            except Exception:
                continue

            if isinstance(rec, dict):
                yield ZeekEvent(log=log_name, record=rec)
        except Exception:
            try:
                if fp is not None:
                    fp.close()  # type: ignore[attr-defined]
            except Exception:
                pass
            fp = None
            await asyncio.sleep(0.5)
