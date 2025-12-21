from __future__ import annotations

import queue
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import os
import signal


@dataclass
class ManagedProcess:
    name: str
    args: List[str]
    cwd: Optional[Path] = None
    proc: Optional[subprocess.Popen] = None
    _out_q: "queue.Queue[str]" = queue.Queue()
    _reader_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self.proc and self.proc.poll() is None:
            return
        popen_kwargs = {}
        # In WSL/Linux, Zeek may spawn child processes; isolate into a new session
        # so we can terminate the full process group safely.
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True

        self.proc = subprocess.Popen(
            self.args,
            cwd=str(self.cwd) if self.cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            **popen_kwargs,
        )

        # Background stdout reader for streaming to WebSocket clients.
        if self.proc.stdout is not None:
            def _reader() -> None:
                try:
                    for line in self.proc.stdout:
                        if not line:
                            continue
                        self._out_q.put(line.rstrip("\n"))
                except Exception:
                    return

            self._reader_thread = threading.Thread(target=_reader, name=f"{self.name}-stdout", daemon=True)
            self._reader_thread.start()

    def drain_output(self, *, max_lines: int = 200) -> List[str]:
        lines: List[str] = []
        for _ in range(max_lines):
            try:
                lines.append(self._out_q.get_nowait())
            except queue.Empty:
                break
        return lines

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self, *, timeout_s: float = 3.0) -> None:
        if not self.proc:
            return
        if self.proc.poll() is not None:
            return

        try:
            if os.name == "posix" and self.proc.pid:
                os.killpg(self.proc.pid, signal.SIGTERM)
            else:
                self.proc.terminate()
        except Exception:
            return

        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return
            time.sleep(0.1)

        try:
            if os.name == "posix" and self.proc.pid:
                os.killpg(self.proc.pid, signal.SIGKILL)
            else:
                self.proc.kill()
        except Exception:
            pass
