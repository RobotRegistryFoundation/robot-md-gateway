"""Tests for the /v1/audit/last read-only endpoint."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from robot_md_gateway.cert.audit import AuditChain, AuditEntry
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.receiver import make_app


class _FakeResolver:
    def resolve_kid_for_robot(self, ruri: str) -> str | None:
        return "fake-kid"


def _make_app(audit_chain=None):
    return make_app(
        resolver=_FakeResolver(),
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
        bearer_tiers={"actuate-token": "actuate"},
        audit_chain=audit_chain,
    )


class TestAuditLastEndpoint:
    def test_returns_last_entry(self):
        chain = AuditChain()
        chain.append(AuditEntry(
            msg_id="m1", timestamp_ms=1000,
            decision="allow", decision_reason="ok", envelope_kid=None,
            actuator_name="noop", actuator_outcome_kind="no_op",
        ))
        chain.append(AuditEntry(
            msg_id="m2", timestamp_ms=2000,
            decision="allow", decision_reason="ok", envelope_kid=None,
            actuator_name="noop", actuator_outcome_kind="executed",
        ))
        app = _make_app(audit_chain=chain)

        with TestClient(app) as client:
            r = client.get("/v1/audit/last", headers={"Authorization": "Bearer actuate-token"})

        assert r.status_code == 200
        body = r.json()
        assert body["msg_id"] == "m2"
        assert body["actuator_outcome_kind"] == "executed"
        assert "chain_hash" in body  # full entry returned

    def test_empty_chain_returns_404(self):
        chain = AuditChain()
        app = _make_app(audit_chain=chain)

        with TestClient(app) as client:
            r = client.get("/v1/audit/last", headers={"Authorization": "Bearer actuate-token"})

        assert r.status_code == 404

    def test_no_audit_chain_configured_returns_404(self):
        app = _make_app(audit_chain=None)
        with TestClient(app) as client:
            r = client.get("/v1/audit/last", headers={"Authorization": "Bearer actuate-token"})
        assert r.status_code == 404

    def test_missing_bearer_returns_401(self):
        chain = AuditChain()
        chain.append(AuditEntry(
            msg_id="m1", timestamp_ms=1000,
            decision="allow", decision_reason="ok", envelope_kid=None,
        ))
        app = _make_app(audit_chain=chain)
        with TestClient(app) as client:
            r = client.get("/v1/audit/last")
        assert r.status_code == 401

    def test_unknown_bearer_returns_403(self):
        chain = AuditChain()
        chain.append(AuditEntry(
            msg_id="m1", timestamp_ms=1000,
            decision="allow", decision_reason="ok", envelope_kid=None,
        ))
        app = _make_app(audit_chain=chain)
        with TestClient(app) as client:
            r = client.get("/v1/audit/last", headers={"Authorization": "Bearer unknown"})
        assert r.status_code == 403
