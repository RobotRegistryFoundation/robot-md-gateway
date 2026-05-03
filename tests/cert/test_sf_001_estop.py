"""SF-001 — ESTOP preemption (simulator)."""

from robot_md_gateway.cert.safety import GatewayState, SafetyMonitor


def test_sf_001_estop_transitions_from_ready():
    sm = SafetyMonitor()
    assert sm.state == GatewayState.READY
    sm.on_estop_wire(tripped=True, msg_id="estop-1")
    assert sm.state == GatewayState.ESTOP_ACTIVE
    assert not sm.can_actuate()


def test_sf_001_estop_preempts_safe_stop():
    sm = SafetyMonitor()
    sm.state = GatewayState.SAFE_STOP
    sm.on_estop_wire(tripped=True)
    assert sm.state == GatewayState.ESTOP_ACTIVE
