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


def test_safety_monitor_clear_returns_ready():
    """The exit from ESTOP_ACTIVE that is not a process restart.

    Before this, the only way out of ESTOP_ACTIVE was to restart the gateway -
    and the restart also wiped the in-memory audit chain, so recovering from a
    stop cost the record of why the robot stopped. The clear is gated at the
    `commission` tier (making a robot movable again is an actuation-class
    decision, not an observation) and both the allow and the refusal are written
    into the chain, because a refused clear is exactly the event an operator
    later needs to find.
    """
    from robot_md_gateway.cert.audit import AuditChain

    chain = AuditChain()
    sm = SafetyMonitor()
    sm.on_estop_wire(tripped=True, msg_id="estop-1")
    assert sm.state == GatewayState.ESTOP_ACTIVE

    # Refused below commission, and the refusal does not move the state.
    for tier in ("anon", "read", "actuate"):
        cleared, reason = sm.clear(tier=tier, audit_chain=chain, msg_id=f"clear-{tier}")
        assert cleared is False, tier
        assert "commission" in reason
        assert sm.state == GatewayState.ESTOP_ACTIVE
        assert not sm.can_actuate()

    cleared, reason = sm.clear(tier="commission", audit_chain=chain, msg_id="clear-ok")
    assert cleared is True
    assert sm.state == GatewayState.READY
    assert sm.can_actuate()

    # Every decision landed in the hash-linked chain, in order, and the chain
    # still links: the refusals are entries, not silence.
    decisions = [(e.msg_id, e.decision) for e in chain.entries]
    assert decisions == [
        ("clear-anon", "deny"),
        ("clear-read", "deny"),
        ("clear-actuate", "deny"),
        ("clear-ok", "allow"),
    ]
    assert chain.entries[0].chain_prev == "0" * 64
    for prev, entry in zip(chain.entries, chain.entries[1:]):
        assert entry.chain_prev == prev.chain_hash
    assert "safety.clear" in chain.entries[-1].decision_reason


def test_safety_monitor_clear_without_an_audit_chain_still_works():
    """An operator with no chain configured must still be able to get out of a
    stop. The chain is evidence, not a precondition."""
    sm = SafetyMonitor()
    sm.on_estop_wire(tripped=True)
    cleared, _ = sm.clear(tier="commission")
    assert cleared is True
    assert sm.state == GatewayState.READY


def test_safety_monitor_clear_records_no_cert_property():
    """A clear is not evidence for SF-001.

    SF-001 is the claim that an ESTOP wire trip preempts everything else. The
    clear is the opposite transition, so filing it as an SF-001 pass would let a
    gateway that never once tripped accumulate SF-001 evidence it has not
    earned. The audit chain is the record of a clear; the cert report is not.
    """
    from robot_md_gateway.cert import report as cert_report

    cert_report.reset()
    sm = SafetyMonitor()
    sm.on_estop_wire(tripped=True, msg_id="trip")
    before = [p.property_id for p in cert_report._GLOBAL_REPORT.properties]
    assert before == ["SF-001"]

    sm.clear(tier="read")          # refused
    sm.clear(tier="commission")    # allowed
    after = [p.property_id for p in cert_report._GLOBAL_REPORT.properties]
    assert after == before, "clear() must not add cert-property records"
