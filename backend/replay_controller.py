
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import List, Optional

from .config import BackendConfig
from .processes import ManagedProcess


@dataclass
class ReplayStatus:
    running: bool
    interface: Optional[str] = None
    pcap: Optional[str] = None


class ReplayController:
    def __init__(self, cfg: BackendConfig):
        self._cfg = cfg
        self._proc: ManagedProcess | None = None
        self._status = ReplayStatus(running=False)

    def process(self) -> ManagedProcess | None:
        return self._proc

    def status(self) -> ReplayStatus:
        if self._proc and self._proc.is_running():
            return ReplayStatus(running=True, interface=self._cfg.interface, pcap=self._status.pcap)
        return ReplayStatus(running=False)

    def start(self, pcap_path: Path, *, mbps: int = 10) -> None:
        args: List[str] = []
        if self._cfg.use_sudo:
            args.append("sudo")
            if self._cfg.sudo_preserve_env:
                args.append("-E")
            if self._cfg.sudo_non_interactive:
                args.append("-n")
            args += ["env", f"PATH={os.environ.get('PATH', '')}"]
        args += [
            self._cfg.tcpreplay_bin,
            "-i",
            self._cfg.interface,
            f"--mbps={int(mbps)}",
            str(pcap_path),
        ]
        self._proc = ManagedProcess(name="tcpreplay", args=args, cwd=self._cfg.project_root)
        self._proc.start()
        self._status = ReplayStatus(running=True, interface=self._cfg.interface, pcap=str(pcap_path))

    def stop(self) -> None:
        if self._proc:
            self._proc.stop(timeout_s=3.0)
        self._proc = None
        self._status = ReplayStatus(running=False)
