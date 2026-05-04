"""Plan 6 Phase 4 — AuditChain wiring through /v1/invoke.

Unit tests for AuditChain + verify_audit_bundle live in
test_ev_001_audit_export.py. These tests verify the receiver records
allow/deny decisions to the chain at every policy gate, but does NOT
record on 422 schema-parse failures.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from robot_md_gateway.cert import report as cert_report
from robot_md_gateway.cert.audit import AuditChain, verify_audit_bundle
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.cert.safety import SafetyMonitor
from robot_md_gateway.receiver import make_app

FIXTURES = Path(__file__).parent.parent / "fixtures" / "manifests"


@pytest.fixture(autouse=True)
def _reset():
    cert_report.reset()
    yield


def _ed25519_pair() -> tuple[bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def _client(*, audit_chain: AuditChain | None = None, safety_monitor: SafetyMonitor | None = None,
            tool_allowlist: ToolAllowlist | None = None):
    kid = (FIXTURES / "signing-key.kid").read_text().strip()
    pub = (FIXTURES / "signing-key.pub").read_bytes()

    class R:
        def resolve_public_key_pem(self, k):
            return pub if k == kid else None

    app = make_app(
        resolver=R(),
        tool_allowlist=tool_allowlist or ToolAllowlist(
            allowed_tools=("mcp__robot__execute_capability", "mcp__robot__render"),
        ),
        bearer_tiers={"actuate-token": "actuate"},
        audit_chain=audit_chain,
        safety_monitor=safety_monitor,
    )
    return TestClient(app), app


def _envelope(**overrides):
    base = {
        "msg_id": "msg-audit-1",
        "type": "INVOKE",
        "ruri": "rcan://x/y/z/0",
        "scope": "MANIPULATE",
        "tool_name": "mcp__robot__execute_capability",
        "tool_args": {},
        "manifest_path": str(FIXTURES / "signed-good.md"),
    }
    base.update(overrides)
    return base


def test_no_audit_chain_default_unchanged():
    """Opt-in: when audit_chain=None, the receiver behaves as before."""
    client, _ = _client()
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_envelope(),
    )
    assert r.status_code == 200


def test_allow_records_one_entry():
    chain = AuditChain()
    client, _ = _client(audit_chain=chain)
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_envelope(),
    )
    assert r.status_code == 200
    assert len(chain.entries) == 1
    entry = chain.entries[0]
    assert entry.decision == "allow"
    assert entry.msg_id == "msg-audit-1"
    assert entry.envelope_kid is not None  # manifest kid recorded


def test_tool_allowlist_deny_records_one_entry():
    chain = AuditChain()
    client, _ = _client(
        audit_chain=chain,
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
    )
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_envelope(tool_name="mcp__robot__execute_capability"),
    )
    assert r.status_code == 403
    assert len(chain.entries) == 1
    entry = chain.entries[0]
    assert entry.decision == "deny"
    assert "tool_allowlist" in entry.decision_reason


def test_schema_422_does_not_record():
    """Parser errors are not policy decisions — chain stays empty."""
    chain = AuditChain()
    client, _ = _client(audit_chain=chain)
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json={"msg_id": "incomplete"},
    )
    assert r.status_code == 422
    assert chain.entries == []


def test_safety_deny_records_with_unknown_kid():
    """Pre-schema deny path uses None for envelope_kid."""
    chain = AuditChain()
    sm = SafetyMonitor()
    sm.on_estop_wire(tripped=True)
    client, _ = _client(audit_chain=chain, safety_monitor=sm)
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_envelope(),
    )
    assert r.status_code == 403
    assert len(chain.entries) == 1
    entry = chain.entries[0]
    assert entry.decision == "deny"
    assert "safety_state" in entry.decision_reason
    assert entry.envelope_kid is None


def test_chain_export_signed_round_trip_through_receiver():
    """Multi-decision chain accumulated via receiver verifies offline."""
    chain = AuditChain()
    client, _ = _client(audit_chain=chain)

    client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_envelope(msg_id="m-allow-1"),
    )
    client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_envelope(msg_id="m-deny-1", tool_name="mcp__robot__not_allowed"),
    )
    assert len(chain.entries) == 2

    priv_pem, pub_pem = _ed25519_pair()
    bundle = chain.export_signed(signing_key_pem=priv_pem, kid="gateway-phase4-test")
    assert verify_audit_bundle(bundle, kid_to_pem={"gateway-phase4-test": pub_pem})
