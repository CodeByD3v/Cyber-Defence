from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


@dataclass(frozen=True)
class BackendConfig:
    project_root: Path
    pcap_dir: Path
    zeek_script: Path
    zeek_log_dir: Path
    detections_dir: Path
    backend_log_dir: Path

    listen_host: str
    listen_port: int
    websocket_path: str

    interface: str
    window_seconds: int
    alert_threshold: float

    use_sudo: bool
    sudo_non_interactive: bool
    sudo_preserve_env: bool

    zeek_bin: str
    tcpreplay_bin: str

    model_pipeline_path: Path

    @staticmethod
    def from_env(project_root: Path | None = None) -> "BackendConfig":
        root = project_root or Path(__file__).resolve().parents[1]
        pcap_dir = root / "PCAP"
        zeek_script = root / "zeek-live" / "local.zeek"
        zeek_log_dir = root / "zeek-live"
        detections_dir = root / "detection_results"
        backend_log_dir = root / "backend_logs"

        listen_host = os.getenv("SOC_LISTEN_HOST", "127.0.0.1")
        listen_port = int(os.getenv("SOC_LISTEN_PORT", "8765"))
        websocket_path = os.getenv("SOC_WS_PATH", "/ws")

        interface = os.getenv("SOC_INTERFACE", "eth0")
        window_seconds = int(os.getenv("SOC_WINDOW_SECONDS", "60"))
        alert_threshold = float(os.getenv("SOC_ALERT_THRESHOLD", "0.30"))

        # Disable sudo on Windows by default
        is_windows = os.name == "nt"
        use_sudo = _env_bool("SOC_USE_SUDO", not is_windows)
        sudo_non_interactive = _env_bool("SOC_SUDO_NON_INTERACTIVE", True)
        sudo_preserve_env = _env_bool("SOC_SUDO_PRESERVE_ENV", True)

        zeek_bin_env = os.getenv("SOC_ZEEK_BIN")
        if zeek_bin_env:
            zeek_bin = zeek_bin_env
        elif is_windows:
            # On Windows, try to use Zeek through WSL
            zeek_bin = "wsl"  # Will be called as: wsl -d Ubuntu-22.04 -- zeek ...
        else:
            # Common Zeek install locations (especially in WSL/manual installs).
            candidates = [
                "/opt/zeek/bin/zeek",
                "/usr/local/zeek/bin/zeek",
                "/usr/bin/zeek",
            ]
            zeek_bin = "zeek"
            for c in candidates:
                if Path(c).exists():
                    zeek_bin = c
                    break

        tcpreplay_bin_env = os.getenv("SOC_TCPREPLAY_BIN")
        if tcpreplay_bin_env:
            tcpreplay_bin = tcpreplay_bin_env
        else:
            candidates = [
                "/usr/bin/tcpreplay",
                "/usr/local/bin/tcpreplay",
            ]
            tcpreplay_bin = "tcpreplay"
            for c in candidates:
                if Path(c).exists():
                    tcpreplay_bin = c
                    break

        # Use the trained attack classifier model
        # Try RF binary first, then fall back to XGBoost multiclass
        rf_model = root / "model" / "rf_binary_classifier.joblib"
        xgb_model = root / "model" / "attack_classifier.joblib"
        
        if rf_model.exists():
            default_model = rf_model
        else:
            default_model = xgb_model
        
        model_pipeline_path = Path(
            os.getenv(
                "SOC_MODEL_PIPELINE",
                str(default_model),
            )
        )

        return BackendConfig(
            project_root=root,
            pcap_dir=pcap_dir,
            zeek_script=zeek_script,
            zeek_log_dir=zeek_log_dir,
            detections_dir=detections_dir,
            backend_log_dir=backend_log_dir,
            listen_host=listen_host,
            listen_port=listen_port,
            websocket_path=websocket_path,
            interface=interface,
            window_seconds=window_seconds,
            alert_threshold=alert_threshold,
            use_sudo=use_sudo,
            sudo_non_interactive=sudo_non_interactive,
            sudo_preserve_env=sudo_preserve_env,
            zeek_bin=zeek_bin,
            tcpreplay_bin=tcpreplay_bin,
            model_pipeline_path=model_pipeline_path,
        )
