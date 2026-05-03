"""RC-001 — Signed INVOKE envelope accepted."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from robot_md_gateway.cert.envelope import canonical_json, verify_envelope


@pytest.fixture
def keypair():
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem


def _build_envelope(priv, kid, **overrides):
    body = {
        "msg_id": overrides.get("msg_id", "rc-001-test"),
        "type": "INVOKE",
        "ruri": "rcan://lab/test/bot/0",
        "scope": "READ",
        "tool_name": "mcp__robot__render",
        "tool_args": {},
        "manifest_path": "/tmp/x",
    }
    body.update(overrides)
    canon = canonical_json(body)
    sig = priv.sign(canon)
    body["envelope_signature"] = {
        "kid": kid,
        "alg": "Ed25519",
        "sig": base64.b64encode(sig).decode(),
    }
    return body


def test_rc_001_signed_envelope_accepted(keypair):
    priv, pub_pem = keypair
    env = _build_envelope(priv, "principal-kid")

    class R:
        def resolve_public_key_pem(self, k):
            return pub_pem if k == "principal-kid" else None

    result = verify_envelope(env, resolver=R())
    assert result.accepted is True


def test_rc_001_unsigned_envelope_rejected(keypair):
    env = {
        "msg_id": "x", "type": "INVOKE", "ruri": "rcan://x/y/z/0", "scope": "READ",
        "tool_name": "t", "tool_args": {}, "manifest_path": "/x",
    }

    class R:
        def resolve_public_key_pem(self, k):
            return None

    assert verify_envelope(env, resolver=R()).accepted is False


def test_rc_001_tampered_envelope_rejected(keypair):
    priv, pub_pem = keypair
    env = _build_envelope(priv, "principal-kid")
    env["scope"] = "MANIPULATE"

    class R:
        def resolve_public_key_pem(self, k):
            return pub_pem

    assert verify_envelope(env, resolver=R()).accepted is False
