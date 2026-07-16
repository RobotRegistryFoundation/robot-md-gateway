"""Signed-receipt WIRE surface (T-001).

The gateway's file-only attestation trace is now ALSO embedded in the HTTP
response of /v1/invoke, so a paired client can verify the receipt on the wire:

  * ALLOW (200): body carries `envelope_signature: {kid, alg, sig}`, the full
    signed `outcome`, and `attestation: "attested"`.
  * DENY (403): the HTTPException detail carries the same signed record.
  * When no attestation identity is configured the gateway runs verifier-only and
    the wire carries `envelope_signature: null` + `attestation: "unattested"`,
    still returning 200/403 (never a crash).

These assert the wire shape end-to-end through FastAPI's TestClient and verify
the embedded signature independently with the gateway's public key.
"""

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

FIX = Path(__file__).parent / "fixtures" / "manifests"
MANIFEST_KID = (FIX / "signing-key.kid").read_text().strip()
MANIFEST_PUB = (FIX / "signing-key.pub").read_bytes()
GOOD_MANIFEST = str(FIX / "signed-good.md")


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


def _base_envelope(msg_id, **over):
    body = {
        "msg_id": msg_id, "type": "INVOKE", "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "READ", "tool_name": "mcp__robot__render", "tool_args": {},
        "manifest_path": GOOD_MANIFEST,
    }
    body.update(over)
    return body


def _verify_outcome(outcome: dict, pub_pem: bytes) -> bool:
    """Independent Ed25519 check over the wire receipt — the exact recipe the app
    (and cert.envelope.verify_envelope) uses: verify the detached signature over
    canonical_json(outcome, exclude='envelope_signature')."""
    pub = serialization.load_pem_public_key(pub_pem)
    sig = base64.b64decode(outcome["envelope_signature"]["sig"])
    try:
        pub.verify(sig, canonical_json(outcome, exclude="envelope_signature"))
        return True
    except Exception:
        return False


def _make(identity=None, export=None):
    return make_app(
        resolver=_Resolver({MANIFEST_KID: MANIFEST_PUB}),
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
        audit_chain=AuditChain(),
        signing_identity=identity,
        attestation_export_file=export,
    )


# --------------------------------------------------------------------------- #
# 1. signed-allow shape                                                        #
# --------------------------------------------------------------------------- #
def test_allow_response_carries_verifiable_signature(identity, gateway_keypair):
    _, gw_pub = gateway_keypair
    r = TestClient(_make(identity)).post("/v1/invoke", json=_base_envelope("wire-allow-1"))
    assert r.status_code == 200
    body = r.json()
    # Existing fields preserved.
    assert body["ok"] is True
    assert body["actuator_name"] == "noop"
    # New wire signature.
    assert body["attestation"] == "attested"
    sig = body["envelope_signature"]
    assert set(("kid", "sig")).issubset(sig.keys())
    assert sig["kid"] == "gw-kid"
    # The signed outcome receipt is embedded and verifies with the gateway key.
    out = body["outcome"]
    assert out["corr_id"] == "wire-allow-1"
    assert out["status"] == "ok"
    assert out["rrn"] == "RRN-000000000999"
    # Top-level envelope_signature mirrors the receipt's own signature block.
    assert out["envelope_signature"] == sig
    assert _verify_outcome(out, gw_pub) is True


# --------------------------------------------------------------------------- #
# 2. signed-deny shape                                                         #
# --------------------------------------------------------------------------- #
def test_deny_response_carries_verifiable_signature(identity, gateway_keypair):
    _, gw_pub = gateway_keypair
    r = TestClient(_make(identity)).post(
        "/v1/invoke",
        json=_base_envelope("wire-deny-1", tool_name="mcp__robot__execute_capability"),
    )
    assert r.status_code == 403
    detail = r.json()["detail"]
    # Existing deny fields preserved.
    assert detail["deny"] == "tool_allowlist"
    assert "reason" in detail
    # New signed record on the deny path.
    assert detail["attestation"] == "attested"
    sig = detail["envelope_signature"]
    assert set(("kid", "sig")).issubset(sig.keys())
    out = detail["outcome"]
    assert out["status"] == "denied"
    assert out["corr_id"] == "wire-deny-1"
    assert out["error"]["kind"] == "tool_allowlist"
    assert out["envelope_signature"] == sig
    assert _verify_outcome(out, gw_pub) is True


# --------------------------------------------------------------------------- #
# 3. unattested fallback (no signing identity)                                 #
# --------------------------------------------------------------------------- #
def test_unattested_allow_is_non_crashing_with_explicit_marker():
    r = TestClient(_make(identity=None)).post("/v1/invoke", json=_base_envelope("wire-noattest-1"))
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["attestation"] == "unattested"
    assert body["envelope_signature"] is None
    assert "outcome" not in body


def test_unattested_deny_is_non_crashing_with_explicit_marker():
    r = TestClient(_make(identity=None)).post(
        "/v1/invoke",
        json=_base_envelope("wire-noattest-deny", tool_name="mcp__robot__execute_capability"),
    )
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert detail["deny"] == "tool_allowlist"
    assert detail["attestation"] == "unattested"
    assert detail["envelope_signature"] is None
    assert "outcome" not in detail


# --------------------------------------------------------------------------- #
# 4. tamper + wrong-key rejection (both directions)                           #
# --------------------------------------------------------------------------- #
def test_tampering_the_wire_receipt_breaks_verification(identity, gateway_keypair):
    _, gw_pub = gateway_keypair
    r = TestClient(_make(identity)).post("/v1/invoke", json=_base_envelope("wire-tamper-1"))
    out = r.json()["outcome"]
    assert _verify_outcome(out, gw_pub) is True          # authentic
    tampered = json.loads(json.dumps(out))
    tampered["status"] = "denied"                         # flip one signed field
    assert _verify_outcome(tampered, gw_pub) is False     # rejected


def test_wrong_key_does_not_verify(identity, gateway_keypair):
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    r = TestClient(_make(identity)).post("/v1/invoke", json=_base_envelope("wire-wrongkey-1"))
    out = r.json()["outcome"]
    assert _verify_outcome(out, other) is False
