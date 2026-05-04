"""Plan 6 Phase 2 — RevocationResolver wiring through /v1/invoke.

Unit tests for RevocationCache + round_trip_register live in
test_rr_001_rr_002.py. These tests verify the receiver path: opt-in
via make_app(revocation_resolver=...), revocation fires only when
require_envelope_signature=True (we need env_result.kid first), and
denials surface detail.deny == "revoked_key".
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from robot_md_gateway.cert import report as cert_report
from robot_md_gateway.cert.envelope import canonical_json
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.receiver import make_app

FIXTURES = Path(__file__).parent.parent / "fixtures" / "manifests"
ENV_KID = "envelope-signing-kid"


@pytest.fixture(autouse=True)
def _reset():
    cert_report.reset()
    yield


@pytest.fixture
def env_keypair():
    """Ephemeral envelope-signing keypair (separate from manifest signing key)."""
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem


def _client(
    *,
    env_pub_pem: bytes,
    revocation_resolver=None,
    require_envelope_signature: bool = True,
):
    """Build a TestClient. The resolver answers BOTH manifest kid and envelope kid."""
    manifest_kid = (FIXTURES / "signing-key.kid").read_text().strip()
    manifest_pub = (FIXTURES / "signing-key.pub").read_bytes()

    class R:
        def resolve_public_key_pem(self, k):
            if k == manifest_kid:
                return manifest_pub
            if k == ENV_KID:
                return env_pub_pem
            return None

    app = make_app(
        resolver=R(),
        tool_allowlist=ToolAllowlist(
            allowed_tools=("mcp__robot__execute_capability", "mcp__robot__render"),
        ),
        bearer_tiers={"actuate-token": "actuate"},
        require_envelope_signature=require_envelope_signature,
        revocation_resolver=revocation_resolver,
    )
    return TestClient(app), app


def _signed_envelope(priv, **overrides):
    body = {
        "msg_id": overrides.pop("msg_id", "msg-rr-1"),
        "type": "INVOKE",
        "ruri": "rcan://x/y/z/0",
        "scope": "MANIPULATE",
        "tool_name": "mcp__robot__execute_capability",
        "tool_args": {},
        "manifest_path": str(FIXTURES / "signed-good.md"),
        "payload": {"inference_confidence": 0.95},
        "delegation_chain": [
            {"scope": "MANIPULATE", "human_subject": "operator@x.com"},
        ],
    }
    body.update(overrides)
    sig = priv.sign(canonical_json(body))
    body["envelope_signature"] = {
        "kid": ENV_KID,
        "alg": "Ed25519",
        "sig": base64.b64encode(sig).decode(),
    }
    return body


def test_no_revocation_resolver_default_unchanged(env_keypair):
    """Opt-in: when revocation_resolver=None, behavior matches prior phases."""
    priv, pub_pem = env_keypair
    client, _ = _client(env_pub_pem=pub_pem, revocation_resolver=None)
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_signed_envelope(priv),
    )
    assert r.status_code == 200
    rr_001 = [
        p for p in cert_report._GLOBAL_REPORT.properties if p.property_id == "RR-001"
    ]
    assert rr_001 == []


def test_revoked_kid_returns_403(env_keypair):
    priv, pub_pem = env_keypair

    class Revoker:
        def is_revoked(self, kid):
            return kid == ENV_KID

    client, _ = _client(env_pub_pem=pub_pem, revocation_resolver=Revoker())
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_signed_envelope(priv),
    )
    assert r.status_code == 403
    assert r.json()["detail"]["deny"] == "revoked_key"
    assert ENV_KID in r.json()["detail"]["reason"]


def test_unrevoked_kid_passes(env_keypair):
    priv, pub_pem = env_keypair

    class NotRevoker:
        def is_revoked(self, kid):
            return False

    client, _ = _client(env_pub_pem=pub_pem, revocation_resolver=NotRevoker())
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_signed_envelope(priv),
    )
    assert r.status_code == 200
    rr_001 = [
        p for p in cert_report._GLOBAL_REPORT.properties if p.property_id == "RR-001"
    ]
    assert len(rr_001) == 1
    assert rr_001[0].evidence["outcome"] == "allowed (not revoked)"


def test_revocation_cache_shared_across_requests(env_keypair):
    """Cache must persist across requests when revocation_resolver is provided.

    Regression for the receiver-level bug where revocation_cache=None caused
    a fresh RevocationCache() to be built per request, defeating the TTL.
    """
    priv, pub_pem = env_keypair
    calls = []

    class CountingResolver:
        def is_revoked(self, kid):
            calls.append(kid)
            return False

    client, _ = _client(
        env_pub_pem=pub_pem, revocation_resolver=CountingResolver(),
    )
    r1 = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_signed_envelope(priv, msg_id="msg-cache-1"),
    )
    assert r1.status_code == 200
    r2 = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_signed_envelope(priv, msg_id="msg-cache-2"),
    )
    assert r2.status_code == 200
    # Resolver should be called exactly once — second request hits cache.
    assert calls == [ENV_KID]
    rr_001 = [
        p for p in cert_report._GLOBAL_REPORT.properties if p.property_id == "RR-001"
    ]
    # Two RR-001 records: one from resolver, one from cache.
    assert len(rr_001) == 2
    sources = [p.evidence.get("source") for p in rr_001]
    assert sources == ["resolver", "cache"]


def test_revocation_not_checked_without_envelope_signature_required(env_keypair):
    """When require_envelope_signature=False, env_result.kid is unknown — no RR-001."""
    priv, pub_pem = env_keypair

    class Revoker:
        def is_revoked(self, kid):
            return True

    client, _ = _client(
        env_pub_pem=pub_pem,
        revocation_resolver=Revoker(),
        require_envelope_signature=False,
    )
    # Use unsigned envelope shape — no envelope_signature needed since we
    # disabled the check. But _signed_envelope still works (signature ignored).
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_signed_envelope(priv),
    )
    assert r.status_code == 200
    rr_001 = [
        p for p in cert_report._GLOBAL_REPORT.properties if p.property_id == "RR-001"
    ]
    assert rr_001 == []
