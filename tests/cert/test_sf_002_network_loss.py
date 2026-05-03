"""SF-002 — Network-loss safe-stop (simulator)."""

import time

from robot_md_gateway.cert.safety import GatewayState, SafetyMonitor


def test_sf_002_safe_stop_after_staleness():
    sm = SafetyMonitor(heartbeat_staleness_s=0.05)
    sm.last_heartbeat_at = time.monotonic() - 1.0
    sm.tick()
    assert sm.state == GatewayState.SAFE_STOP
    assert not sm.can_actuate()


def test_sf_002_no_safe_stop_when_recent_heartbeat():
    sm = SafetyMonitor(heartbeat_staleness_s=10.0)
    sm.tick()
    assert sm.state == GatewayState.READY


def test_sf_002_heartbeat_does_not_auto_resume():
    sm = SafetyMonitor()
    sm.state = GatewayState.SAFE_STOP
    sm.on_heartbeat()
    assert sm.state == GatewayState.SAFE_STOP
