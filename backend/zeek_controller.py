from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import List, Optional

from .config import BackendConfig
from .processes import ManagedProcess


@dataclass
class ZeekStatus:
    running: bool
    mode: str
    interface: Optional[str] = None
    pcap: Optional[str] = None


class ZeekController:
    def __init__(self, cfg: BackendConfig):
        self._cfg = cfg
        self._proc: ManagedProcess | None = None
        self._status = ZeekStatus(running=False, mode="stopped")

    def process(self) -> ManagedProcess | None:
        return self._proc

    def status(self) -> ZeekStatus:
        if self._proc and self._proc.is_running():
            return ZeekStatus(running=True, mode=self._status.mode, interface=self._status.interface, pcap=self._status.pcap)
        return ZeekStatus(running=False, mode="stopped")

    def start_live(self) -> None:
        """Start live Zeek capture. On Windows, uses WSL."""
        is_windows = os.name == "nt"
        args: List[str] = []
        
        if is_windows:
            # On Windows, run Zeek through WSL
            def to_wsl_path(win_p: str) -> str:
                if len(win_p) > 2 and win_p[1] == ':':
                    return f"/mnt/{win_p[0].lower()}{win_p[2:].replace(chr(92), '/')}"
                return win_p.replace("\\", "/")
            
            wsl_log_dir = to_wsl_path(str(self._cfg.zeek_log_dir.absolute()))
            wsl_script = to_wsl_path(str(self._cfg.zeek_script.absolute()))
            interface = self._cfg.interface
            
            # Live capture command - needs sudo in WSL
            zeek_cmd = f"cd {wsl_log_dir} && sudo /opt/zeek/bin/zeek -i {interface} -C {wsl_script}"
            args = ["wsl", "bash", "-c", zeek_cmd]
        else:
            if self._cfg.use_sudo:
                args.append("sudo")
                if self._cfg.sudo_preserve_env:
                    args.append("-E")
                if self._cfg.sudo_non_interactive:
                    args.append("-n")
                args += ["env", f"PATH={os.environ.get('PATH', '')}"]
            args += [
                self._cfg.zeek_bin,
                "-i",
                self._cfg.interface,
                "-C",
                str(self._cfg.zeek_script),
            ]

        self._proc = ManagedProcess(name="zeek", args=args, cwd=self._cfg.zeek_log_dir)
        self._proc.start()
        self._status = ZeekStatus(running=True, mode="live", interface=self._cfg.interface)

    def start_pcap(self, pcap_path: Path) -> None:
        args: List[str] = []
        is_windows = os.name == "nt"
        cwd = self._cfg.zeek_log_dir  # Run in log dir so logs are written there
        
        # Clear old Zeek logs before processing new PCAP
        for log_name in ["conn.log", "dns.log", "http.log", "weird.log", "notice.log", "packet_filter.log"]:
            log_path = self._cfg.zeek_log_dir / log_name
            if log_path.exists():
                try:
                    log_path.unlink()
                except Exception:
                    # If can't delete, try to truncate
                    try:
                        with log_path.open("w") as f:
                            f.truncate(0)
                    except Exception:
                        pass
        
        if is_windows and self._cfg.zeek_bin == "wsl":
            # Run Zeek through WSL on Windows
            # Convert Windows paths to WSL paths
            def to_wsl_path(win_p: str) -> str:
                if len(win_p) > 2 and win_p[1] == ':':
                    return f"/mnt/{win_p[0].lower()}{win_p[2:].replace(chr(92), '/')}"
                return win_p.replace("\\", "/")
            
            wsl_pcap = to_wsl_path(str(pcap_path.absolute()))
            wsl_log_dir = to_wsl_path(str(self._cfg.zeek_log_dir.absolute()))
            wsl_script = to_wsl_path(str(self._cfg.zeek_script.absolute()))
            
            # Run Zeek in the log directory with local.zeek script for JSON output
            zeek_cmd = f"cd {wsl_log_dir} && /opt/zeek/bin/zeek -r {wsl_pcap} -C {wsl_script}"
            args = ["wsl", "bash", "-c", zeek_cmd]
        else:
            if self._cfg.use_sudo:
                args.append("sudo")
                if self._cfg.sudo_preserve_env:
                    args.append("-E")
                if self._cfg.sudo_non_interactive:
                    args.append("-n")
                args += ["env", f"PATH={os.environ.get('PATH', '')}"]
            args += [
                self._cfg.zeek_bin,
                "-r",
                str(pcap_path),
                "-C",
                str(self._cfg.zeek_script),
            ]

        self._proc = ManagedProcess(name="zeek", args=args, cwd=cwd)
        self._proc.start()
        self._status = ZeekStatus(running=True, mode="pcap", pcap=str(pcap_path))

    def stop(self) -> None:
        if self._proc:
            self._proc.stop(timeout_s=5.0)
        self._proc = None
        self._status = ZeekStatus(running=False, mode="stopped")
