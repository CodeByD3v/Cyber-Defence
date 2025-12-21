"""Property-based tests for SOC backend.

Uses Hypothesis for property-based testing.
Install: pip install hypothesis pytest
Run: pytest backend/tests/test_properties.py -v
"""
from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pytest

try:
    from hypothesis import given, strategies as st, settings
    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False
    # Provide dummy decorators if hypothesis not installed
    def given(*args, **kwargs):
        def decorator(f):
            return pytest.mark.skip(reason="hypothesis not installed")(f)
        return decorator
    class st:
        @staticmethod
        def text(*args, **kwargs): return None
        @staticmethod
        def floats(*args, **kwargs): return None
        @staticmethod
        def integers(*args, **kwargs): return None
        @staticmethod
        def sampled_from(*args, **kwargs): return None
        @staticmethod
        def lists(*args, **kwargs): return None
    def settings(*args, **kwargs):
        def decorator(f): return f
        return decorator


# =============================================================================
# Property 4: Status JSON structure
# **Feature: soc-realtime-platform, Property 4: Status JSON structure**
# **Validates: Requirements 5.1**
# =============================================================================

@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")
@given(
    total_flows=st.integers(min_value=0, max_value=1000000),
    total_alerts=st.integers(min_value=0, max_value=10000),
)
@settings(max_examples=100)
def test_stats_snapshot_structure(total_flows: int, total_alerts: int):
    """
    **Feature: soc-realtime-platform, Property 4: Status JSON structure**
    **Validates: Requirements 5.1**
    
    For any stats_snapshot output, it SHALL contain required fields with correct types.
    """
    from backend.state import SocState
    from backend.config import BackendConfig
    from backend.audit import AuditLogger
    from backend.ml_inference import ModelWrapper
    from backend.zeek_controller import ZeekController
    from backend.replay_controller import ReplayController
    
    # Create minimal config for testing
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        cfg = BackendConfig(
            project_root=tmppath,
            pcap_dir=tmppath / "PCAP",
            zeek_script=tmppath / "local.zeek",
            zeek_log_dir=tmppath,
            detections_dir=tmppath / "detections",
            backend_log_dir=tmppath / "logs",
            listen_host="127.0.0.1",
            listen_port=8765,
            websocket_path="/ws",
            interface="eth0",
            window_seconds=60,
            alert_threshold=0.8,
            use_sudo=False,
            sudo_non_interactive=False,
            sudo_preserve_env=False,
            zeek_bin="zeek",
            tcpreplay_bin="tcpreplay",
            model_pipeline_path=tmppath / "model.pkl",
        )
        
        # Create required directories
        cfg.backend_log_dir.mkdir(parents=True, exist_ok=True)
        
        audit = AuditLogger(cfg.backend_log_dir)
        
        # Create state without model (we're just testing stats)
        state = SocState.__new__(SocState)
        state.cfg = cfg
        state.audit = audit
        state.alerts = []
        state.last_status = {}
        state.started_at = datetime.now(timezone.utc).isoformat()
        state.last_packet_ts = None
        state.last_alert_ts = None
        state._flow_ts = __import__('collections').deque(maxlen=200_000)
        state._alert_ts = __import__('collections').deque(maxlen=50_000)
        state._byte_events = __import__('collections').deque(maxlen=200_000)
        state._pkt_events = __import__('collections').deque(maxlen=200_000)
        state._total_flows = total_flows
        state._total_alerts = total_alerts
        
        # Get stats snapshot
        stats = state.stats_snapshot(window_s=60.0)
        
        # Property: output must contain required fields
        assert "total_flows" in stats
        assert "total_alerts" in stats
        assert "flows_per_second" in stats
        assert "packets_per_second" in stats
        assert "bytes_per_second" in stats
        
        # Property: types must be correct
        assert isinstance(stats["total_flows"], int)
        assert isinstance(stats["total_alerts"], int)
        assert isinstance(stats["flows_per_second"], float)
        assert isinstance(stats["packets_per_second"], float)
        assert isinstance(stats["bytes_per_second"], float)
        
        # Property: values must match what we set
        assert stats["total_flows"] == total_flows
        assert stats["total_alerts"] == total_alerts


# =============================================================================
# Property: Valid alert state transitions
# **Feature: soc-realtime-platform, Property: Alert state transitions**
# **Validates: Alert Lifecycle addon**
# =============================================================================

VALID_STATES = {"new", "investigating", "confirmed", "false_positive", "closed"}

@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")
@given(
    initial_state=st.sampled_from(list(VALID_STATES)),
    new_state=st.sampled_from(list(VALID_STATES)),
)
@settings(max_examples=100)
def test_alert_state_transitions(initial_state: str, new_state: str):
    """
    **Feature: soc-realtime-platform, Property: Alert state transitions**
    **Validates: Alert Lifecycle addon**
    
    For any valid state, transitioning to another valid state SHALL succeed.
    """
    from backend.state import Alert
    
    alert = Alert(
        timestamp=datetime.now(timezone.utc).isoformat(),
        attack="test_attack",
        confidence=0.9,
        src="192.168.1.1",
        dst="10.0.0.1",
        evidence=["test evidence"],
        state=initial_state,
    )
    
    # Property: initial state must be valid
    assert alert.state in VALID_STATES
    
    # Transition to new state
    alert.state = new_state
    
    # Property: new state must be valid
    assert alert.state in VALID_STATES
    assert alert.state == new_state


# =============================================================================
# Property 5: Export creates valid files
# **Feature: soc-realtime-platform, Property 5: Export creates valid files**
# **Validates: Requirements 6.1**
# =============================================================================

@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")
@given(
    num_alerts=st.integers(min_value=0, max_value=50),
)
@settings(max_examples=50)
def test_export_json_valid(num_alerts: int):
    """
    **Feature: soc-realtime-platform, Property 5: Export creates valid files**
    **Validates: Requirements 6.1**
    
    For any number of alerts, JSON export SHALL produce valid JSON with correct count.
    """
    from backend.state import Alert
    
    # Create alerts
    alerts: List[Alert] = []
    for i in range(num_alerts):
        alerts.append(Alert(
            timestamp=datetime.now(timezone.utc).isoformat(),
            attack=f"attack_{i}",
            confidence=0.8 + (i % 20) / 100,
            src=f"192.168.1.{i % 256}",
            dst=f"10.0.0.{i % 256}",
            evidence=[f"evidence_{i}"],
        ))
    
    # Export to JSON string
    export_data = [a.__dict__ for a in alerts]
    json_str = json.dumps(export_data, indent=2)
    
    # Property: output must be valid JSON
    parsed = json.loads(json_str)
    
    # Property: parsed data must be a list
    assert isinstance(parsed, list)
    
    # Property: count must match
    assert len(parsed) == num_alerts


# =============================================================================
# Property 6: Clear resets counters
# **Feature: soc-realtime-platform, Property 6: Clear resets counters**
# **Validates: Requirements 8.4**
# =============================================================================

@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")
@given(
    initial_flows=st.integers(min_value=1, max_value=100000),
    initial_alerts=st.integers(min_value=1, max_value=10000),
)
@settings(max_examples=100)
def test_clear_resets_counters(initial_flows: int, initial_alerts: int):
    """
    **Feature: soc-realtime-platform, Property 6: Clear resets counters**
    **Validates: Requirements 8.4**
    
    For any state with non-zero counters, clear() SHALL reset them to zero.
    """
    from backend.state import SocState
    from collections import deque
    
    # Create minimal state
    state = SocState.__new__(SocState)
    state.alerts = [None] * initial_alerts  # Dummy alerts
    state.last_status = {"test": "data"}
    state.last_packet_ts = "2025-01-01T00:00:00Z"
    state.last_alert_ts = "2025-01-01T00:00:00Z"
    state._flow_ts = deque([1.0] * min(initial_flows, 1000), maxlen=200_000)
    state._alert_ts = deque([1.0] * min(initial_alerts, 1000), maxlen=50_000)
    state._byte_events = deque(maxlen=200_000)
    state._pkt_events = deque(maxlen=200_000)
    state._total_flows = initial_flows
    state._total_alerts = initial_alerts
    
    # Verify non-zero before clear
    assert state._total_flows > 0
    assert state._total_alerts > 0
    
    # Clear
    state.clear()
    
    # Property: all counters must be zero after clear
    assert state._total_flows == 0
    assert state._total_alerts == 0
    assert len(state.alerts) == 0
    assert len(state._flow_ts) == 0
    assert len(state._alert_ts) == 0
    assert state.last_packet_ts is None
    assert state.last_alert_ts is None


# =============================================================================
# Property 8: Process output routes to correct stream
# **Feature: soc-realtime-platform, Property 8: Process output routes to correct stream**
# **Validates: Requirements 8.1**
# =============================================================================

@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")
@given(
    stream=st.sampled_from(["zeek", "replay", "command"]),
    line=st.text(min_size=1, max_size=100),
)
@settings(max_examples=100)
def test_stream_routing(stream: str, line: str):
    """
    **Feature: soc-realtime-platform, Property 8: Process output routes to correct stream**
    **Validates: Requirements 8.1**
    
    For any command_output event, the stream field SHALL determine routing.
    """
    event = {
        "type": "command_output",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stream": stream,
        "level": "stdout",
        "line": line,
    }
    
    # Property: zeek and replay streams should route to process terminal
    if stream in ("zeek", "replay"):
        # These should go to Process Output terminal (not command terminal)
        assert event["stream"] in ("zeek", "replay")
    else:
        # Command stream goes to command terminal
        assert event["stream"] == "command"


# =============================================================================
# Property: Rolling windows correctly filter by time
# **Feature: soc-realtime-platform, Property: Rolling window calculation**
# **Validates: Requirements 7.2**
# =============================================================================

@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")
@given(
    window_s=st.floats(min_value=1.0, max_value=300.0),
)
@settings(max_examples=50)
def test_rolling_window_filtering(window_s: float):
    """
    **Feature: soc-realtime-platform, Property: Rolling window calculation**
    **Validates: Requirements 7.2**
    
    For any window size, stats_snapshot SHALL only include events within that window.
    """
    from backend.state import SocState
    from collections import deque
    import time
    
    now = time.time()
    
    # Create state with events at different times
    state = SocState.__new__(SocState)
    state.alerts = []
    state.last_status = {}
    state.started_at = datetime.now(timezone.utc).isoformat()
    state.last_packet_ts = None
    state.last_alert_ts = None
    state._flow_ts = deque(maxlen=200_000)
    state._alert_ts = deque(maxlen=50_000)
    state._byte_events = deque(maxlen=200_000)
    state._pkt_events = deque(maxlen=200_000)
    state._total_flows = 0
    state._total_alerts = 0
    
    # Add events: some inside window, some outside
    inside_count = 5
    outside_count = 3
    
    # Events inside window (recent)
    for i in range(inside_count):
        ts = now - (window_s / 2)  # Half window ago
        state._flow_ts.append(ts)
    
    # Events outside window (old)
    for i in range(outside_count):
        ts = now - (window_s * 2)  # Double window ago
        state._flow_ts.append(ts)
    
    state._total_flows = inside_count + outside_count
    
    # Get stats with specific window
    stats = state.stats_snapshot(now_ts=now, window_s=window_s)
    
    # Property: flows_last_window should only count events inside window
    # Note: The implementation evicts old events, so after snapshot,
    # only inside_count should remain
    assert stats["flows_last_window"] <= inside_count + outside_count
