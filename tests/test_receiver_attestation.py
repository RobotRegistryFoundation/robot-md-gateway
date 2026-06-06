"""Emitter wiring: allow + every deny path write one signed NDJSON trace line."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from robot_md_gateway.attestation import SigningIdentity
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.envelope import canonical_json
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.receiver import make_app


@pytest.fixture
def gateway_keypair():
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem


@pytest.fixture
def identity(gateway_keypair):
    priv, _ = gateway_keypair
    return SigningIdentity(priv=priv, kid="gw-kid", ran="RAN-000000000020")


class _Resolver:
    def __init__(self, mapping):
        self._m = mapping

    def resolve_public_key_pem(self, kid):
        return self._m.get(kid)


def _read_lines(export: Path):
    return [json.loads(x) for x in export.read_text().splitlines() if x.strip()]


def _verify_outcome(outcome: dict, pub_pem: bytes) -> bool:
    pub = serialization.load_pem_public_key(pub_pem)
    sig = base64.b64decode(outcome["envelope_signature"]["sig"])
    try:
        pub.verify(sig, canonical_json(outcome, exclude="envelope_signature"))
        return True
    except Exception:
        return False


# --- fixtures: a signed-good manifest the receiver accepts ---
FIX = Path(__file__).parent / "fixtures" / "manifests"
MANIFEST_KID = (FIX / "signing-key.kid").read_text().strip()
MANIFEST_PUB = (FIX / "signing-key.pub").read_bytes()
GOOD_MANIFEST = str(FIX / "signed-good.md")


def _base_envelope(msg_id, **over):
    body = {
        "msg_id": msg_id, "type": "INVOKE", "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "READ", "tool_name": "mcp__robot__render", "tool_args": {},
        "manifest_path": GOOD_MANIFEST,
    }
    body.update(over)
    return body


def test_allow_path_writes_one_signed_ok_trace(tmp_path, identity, gateway_keypair):
    _, gw_pub = gateway_keypair
    export = tmp_path / "traces.ndjson"
    app = make_app(
        resolver=_Resolver({MANIFEST_KID: MANIFEST_PUB}),
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
        audit_chain=AuditChain(),
        signing_identity=identity,
        attestation_export_file=export,
    )
    r = TestClient(app).post("/v1/invoke", json=_base_envelope("allow-1"))
    assert r.status_code == 200

    lines = _read_lines(export)
    assert len(lines) == 1
    rec = lines[0]
    assert rec["v"] == "rcan-action-trace/1"
    assert rec["corr_id"] == "allow-1"
    out = rec["outcome"]
    assert out["corr_id"] == "allow-1"
    assert out["status"] == "ok"
    assert out["rrn"] == "RRN-000000000999"   # signed-good.md top-level rrn (verified)
    assert "started_at" in out and "ended_at" in out
    assert out["envelope_signature"]["kid"] == "gw-kid"
    assert _verify_outcome(out, gw_pub)
    # invoke passed verbatim
    assert rec["invoke"]["msg_id"] == "allow-1"


def test_tool_allowlist_deny_writes_one_signed_denied_trace(tmp_path, identity, gateway_keypair):
    _, gw_pub = gateway_keypair
    export = tmp_path / "traces.ndjson"
    app = make_app(
        resolver=_Resolver({MANIFEST_KID: MANIFEST_PUB}),
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
        audit_chain=AuditChain(),
        signing_identity=identity,
        attestation_export_file=export,
    )
    # A post-manifest deny: tool not in the allowlist (rrn is available).
    r = TestClient(app).post(
        "/v1/invoke",
        json=_base_envelope("deny-1", tool_name="mcp__robot__execute_capability"),
    )
    assert r.status_code == 403

    lines = _read_lines(export)
    assert len(lines) == 1
    out = lines[0]["outcome"]
    assert out["status"] == "denied"
    assert out["corr_id"] == "deny-1"
    assert out["rrn"] == "RRN-000000000999"   # post-manifest deny -> hoisted manifest rrn
    assert out["error"]["kind"] == "tool_allowlist"
    assert _verify_outcome(out, gw_pub)


def test_actuator_exception_writes_error_status(tmp_path, identity):
    export = tmp_path / "traces.ndjson"

    class _Boom:
        name = "boom"

        def execute(self, **kw):
            raise RuntimeError("kaboom")

    app = make_app(
        resolver=_Resolver({MANIFEST_KID: MANIFEST_PUB}),
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
        audit_chain=AuditChain(),
        actuator=_Boom(),
        signing_identity=identity,
        attestation_export_file=export,
    )
    r = TestClient(app).post("/v1/invoke", json=_base_envelope("err-1"))
    assert r.status_code == 500
    out = _read_lines(export)[0]["outcome"]
    assert out["status"] == "error"
    assert out["error"]["kind"] == "RuntimeError"


def test_disabled_identity_writes_nothing(tmp_path):
    export = tmp_path / "traces.ndjson"
    app = make_app(
        resolver=_Resolver({MANIFEST_KID: MANIFEST_PUB}),
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
        audit_chain=AuditChain(),
        signing_identity=None,           # attestation disabled
        attestation_export_file=export,
    )
    r = TestClient(app).post("/v1/invoke", json=_base_envelope("noattest-1"))
    assert r.status_code == 200
    assert not export.exists()           # no line written


def test_signature_gate_deny_emits_pre_manifest_with_best_effort_rrn(tmp_path, identity):
    """A pre-manifest deny (bad envelope signature) still emits; rrn is None/best-effort."""
    export = tmp_path / "traces.ndjson"
    app = make_app(
        resolver=_Resolver({MANIFEST_KID: MANIFEST_PUB}),
        require_envelope_signature=True,
        audit_chain=AuditChain(),
        signing_identity=identity,
        attestation_export_file=export,
    )
    # Unsigned envelope -> envelope_signature deny BEFORE manifest verify.
    r = TestClient(app).post("/v1/invoke", json=_base_envelope("presig-1"))
    assert r.status_code == 403
    out = _read_lines(export)[0]["outcome"]
    assert out["status"] == "denied"
    assert out["corr_id"] == "presig-1"
    assert out["error"]["kind"] == "envelope_signature"
    assert out["rrn"] == ""              # best-effort empty on pre-manifest denies
