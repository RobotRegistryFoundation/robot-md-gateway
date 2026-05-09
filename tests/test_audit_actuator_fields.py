"""Tests for AuditEntry's actuator_* fields (added in v0.5.0a1)."""
from __future__ import annotations

import json

from rcan.audit_bundle import canonical_json

from robot_md_gateway.cert.audit import AuditChain, AuditEntry


class TestAuditEntryActuatorFields:
    def test_default_fields_are_none(self):
        e = AuditEntry(
            msg_id="m1",
            timestamp_ms=1000,
            decision="allow",
            decision_reason="ok",
            envelope_kid=None,
        )
        assert e.actuator_name is None
        assert e.actuator_outcome_kind is None
        assert e.actuator_telemetry_sha256 is None
        assert e.actuator_telemetry_path is None
        assert e.actuator_error_kind is None

    def test_chain_hash_includes_actuator_fields(self):
        # Two entries identical except for actuator_outcome_kind must produce
        # different chain_hash values.
        chain_a = AuditChain()
        chain_a.append(AuditEntry(
            msg_id="m1", timestamp_ms=1000,
            decision="allow", decision_reason="ok", envelope_kid=None,
            actuator_name="foo", actuator_outcome_kind="executed",
        ))
        chain_b = AuditChain()
        chain_b.append(AuditEntry(
            msg_id="m1", timestamp_ms=1000,
            decision="allow", decision_reason="ok", envelope_kid=None,
            actuator_name="foo", actuator_outcome_kind="no_op",
        ))
        assert chain_a.entries[0].chain_hash != chain_b.entries[0].chain_hash

    def test_populated_fields_round_trip(self):
        e = AuditEntry(
            msg_id="m1",
            timestamp_ms=1000,
            decision="allow",
            decision_reason="ok",
            envelope_kid=None,
            actuator_name="my-actuator",
            actuator_outcome_kind="executed",
            actuator_telemetry_sha256="a" * 64,
            actuator_telemetry_path="/tmp/telem.json",
            actuator_error_kind=None,
        )
        d = e.__dict__
        # canonical_json must accept the dict (no unhashable types)
        canonical_json(d)
