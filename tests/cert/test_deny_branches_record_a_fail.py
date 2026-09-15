"""OC-09 - every deny branch in the cert modules records a FAIL.

Until this landed, five modules called ``record_property_pass`` on the branch
where they REFUSED something. The report could therefore not tell a refusal
from a success: a gateway that denied every request it ever saw produced the
same evidence as one that allowed everything correctly, and a tripped ESTOP
filed SF-001 evidence in the gateway's favour - the more often the stop was
pulled, the better the report looked.

These tests drive each deny branch through the real code path and assert the
recorded outcome is not "pass". They are deliberately written against the
OUTCOME rather than against the function name, so renaming the recorder cannot
make them pass while the report stays wrong.

Exempt on purpose: cert/report.py (it defines the recorders) and
cert/revocation.py + receiver.py, which already recorded fails correctly.
"""

from __future__ import annotations

import pytest

from robot_md_gateway.cert import report as cert_report
from robot_md_gateway.cert.envelope import (
    FreshnessPolicy,
    ReplayCache,
    check_freshness,
    check_replay,
)
from robot_md_gateway.cert.gates import (
    ConfidencePolicy,
    HiTLPolicy,
    check_confidence,
    check_hitl,
)
from robot_md_gateway.cert.policy import ToolAllowlist, check_tier, check_tool
from robot_md_gateway.cert.rrn_binding import verify_rrn_binding
from robot_md_gateway.cert.safety import GatewayState, SafetyMonitor


@pytest.fixture(autouse=True)
def _clean_report():
    cert_report.reset()
    yield
    cert_report.reset()


def _outcomes(property_id: str) -> list[str]:
    return [
        p.outcome
        for p in cert_report._GLOBAL_REPORT.properties
        if p.property_id == property_id
    ]


# --------------------------------------------------------------------------- #
# The named test from the item's done_when: a denied tool records a fail.
# --------------------------------------------------------------------------- #


def test_denied_tool_records_a_fail():
    allowed, _ = check_tool(
        "mcp__robot__execute_capability",
        ToolAllowlist(allowed_tools=("mcp__robot__render",)),
        msg_id="deny-tool",
    )
    assert allowed is False
    assert _outcomes("GW-002") == ["fail"]


def test_estop_wire_records_a_fail():
    sm = SafetyMonitor()
    sm.on_estop_wire(tripped=True, msg_id="deny-estop")
    assert sm.state == GatewayState.ESTOP_ACTIVE
    assert _outcomes("SF-001") == ["fail"]


# --------------------------------------------------------------------------- #
# Every remaining deny branch, module by module.
# --------------------------------------------------------------------------- #


class TestPolicyDenies:
    def test_read_tier_denied_actuation_records_a_fail(self):
        ok, _ = check_tier("read", "MANIPULATE", msg_id="d1")
        assert ok is False
        assert _outcomes("GW-003") == ["fail"]

    def test_commission_scope_without_commission_tier_records_a_fail(self):
        ok, _ = check_tier("actuate", "COMMISSION", msg_id="d2")
        assert ok is False
        assert _outcomes("GW-003") == ["fail"]

    def test_the_allow_branches_still_record_a_pass(self):
        """The sweep must not have turned the whole report into fails."""
        assert check_tier("actuate", "MANIPULATE", msg_id="a1")[0] is True
        assert check_tool(
            "mcp__robot__render",
            ToolAllowlist(allowed_tools=("mcp__robot__render",)),
            msg_id="a2",
        )[0] is True
        assert _outcomes("GW-003") == ["pass"]
        assert _outcomes("GW-002") == ["pass"]


class TestConfidenceAndHitlDenies:
    def test_missing_inference_confidence_records_a_fail(self):
        ok, _ = check_confidence({"msg_id": "d3", "scope": "MANIPULATE"}, ConfidencePolicy())
        assert ok is False
        assert _outcomes("RC-003") == ["fail"]

    def test_confidence_below_threshold_records_a_fail(self):
        ok, _ = check_confidence(
            {"msg_id": "d4", "scope": "MANIPULATE",
             "payload": {"inference_confidence": 0.10}},
            ConfidencePolicy(),
        )
        assert ok is False
        assert _outcomes("RC-003") == ["fail"]

    def test_confidence_above_threshold_records_a_pass(self):
        ok, _ = check_confidence(
            {"msg_id": "a3", "scope": "MANIPULATE",
             "payload": {"inference_confidence": 0.99}},
            ConfidencePolicy(),
        )
        assert ok is True
        assert _outcomes("RC-003") == ["pass"]

    def test_no_hitl_chain_records_a_fail(self):
        ok, _ = check_hitl(
            {"msg_id": "d5", "scope": "MANIPULATE", "delegation_chain": []},
            HiTLPolicy(),
        )
        assert ok is False
        assert _outcomes("RC-004") == ["fail"]

    def test_hitl_chain_final_scope_mismatch_records_a_fail(self):
        ok, _ = check_hitl(
            {"msg_id": "d6", "scope": "MANIPULATE",
             "delegation_chain": [{"scope": "READ", "human_subject": "operator-badge"}]},
            HiTLPolicy(),
        )
        assert ok is False
        assert _outcomes("RC-004") == ["fail"]

    def test_hitl_chain_missing_human_subject_records_a_fail(self):
        ok, _ = check_hitl(
            {"msg_id": "d7", "scope": "MANIPULATE",
             "delegation_chain": [{"scope": "MANIPULATE"}]},
            HiTLPolicy(),
        )
        assert ok is False
        assert _outcomes("RC-004") == ["fail"]

    def test_satisfied_hitl_chain_records_a_pass(self):
        ok, _ = check_hitl(
            {"msg_id": "a4", "scope": "MANIPULATE",
             "delegation_chain": [{"scope": "MANIPULATE", "human_subject": "operator-badge"}]},
            HiTLPolicy(),
        )
        assert ok is True
        assert _outcomes("RC-004") == ["pass"]


class TestRrnBindingDenies:
    def test_no_rrn_host_records_a_fail(self):
        rb = verify_rrn_binding("rcan://lab.local/bot", "RRN-AAAA1111", msg_id="d8")
        assert rb.accepted is False
        assert _outcomes("MF-003") == ["fail"]

    def test_rrn_mismatch_records_a_fail(self):
        rb = verify_rrn_binding("rcan://RRN-BBBB2222/arm", "RRN-AAAA1111", msg_id="d9")
        assert rb.accepted is False
        assert _outcomes("MF-003") == ["fail"]

    def test_manifest_without_rrn_records_a_fail(self):
        rb = verify_rrn_binding("rcan://RRN-AAAA1111/arm", "", msg_id="d10")
        assert rb.accepted is False
        assert _outcomes("MF-003") == ["fail"]

    def test_matching_rrn_records_a_pass(self):
        rb = verify_rrn_binding("rcan://RRN-AAAA1111/arm", "RRN-AAAA1111", msg_id="a5")
        assert rb.accepted is True
        assert _outcomes("MF-003") == ["pass"]


class TestEnvelopeDenies:
    def test_replay_records_a_fail(self):
        cache = ReplayCache()
        assert check_replay({"msg_id": "d11"}, cache)[0] is True
        assert check_replay({"msg_id": "d11"}, cache)[0] is False
        # First (fresh) is a genuine pass; the replay refusal is a fail.
        assert _outcomes("RC-002") == ["pass", "fail"]

    def test_stale_timestamp_records_a_fail(self):
        ok, _ = check_freshness(
            {"msg_id": "d12", "timestamp_ms": 0}, FreshnessPolicy(max_skew_s=300.0),
        )
        assert ok is False
        assert _outcomes("RC-002") == ["fail"]


class TestSafetyDenies:
    def test_heartbeat_staleness_safe_stop_records_a_fail(self):
        sm = SafetyMonitor(heartbeat_staleness_s=0.01)
        sm.last_heartbeat_at -= 5.0
        sm.tick()
        assert sm.state == GatewayState.SAFE_STOP
        assert _outcomes("SF-002") == ["fail"]

    def test_a_clear_still_records_no_cert_property(self):
        """Unchanged by the sweep, and it should stay that way: there is no
        cert property for leaving ESTOP, and inventing one would let a gateway
        that never tripped accumulate SF-001 evidence."""
        sm = SafetyMonitor(state=GatewayState.ESTOP_ACTIVE)
        cleared, _ = sm.clear(tier="commission")
        assert cleared is True
        assert _outcomes("SF-001") == []
