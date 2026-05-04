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


def test_sf_001_re_trip_while_active_is_idempotent():
    """Re-tripping ESTOP while already ESTOP_ACTIVE must not record a phantom transition."""
    from robot_md_gateway.cert import report as cert_report

    cert_report.reset()
    sm = SafetyMonitor()
    sm.on_estop_wire(tripped=True)
    assert sm.state == GatewayState.ESTOP_ACTIVE
    first_count = sum(
        1 for p in cert_report._GLOBAL_REPORT.properties if p.property_id == "SF-001"
    )
    sm.on_estop_wire(tripped=True)  # re-trip while already active
    sm.on_estop_wire(tripped=True)  # again
    second_count = sum(
        1 for p in cert_report._GLOBAL_REPORT.properties if p.property_id == "SF-001"
    )
    assert sm.state == GatewayState.ESTOP_ACTIVE
    assert first_count == 1
    assert second_count == 1, "Re-trips while already ESTOP_ACTIVE should not record"
