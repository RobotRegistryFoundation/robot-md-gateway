"""RC-002 — Replay rejected."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from robot_md_gateway.cert.envelope import canonical_json
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.receiver import make_app

FIXTURES = Path(__file__).parent.parent / "fixtures" / "manifests"


@pytest.fixture
def signed_envelope_factory():
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    def make(msg_id):
        body = {
            "msg_id": msg_id, "type": "INVOKE", "ruri": "rcan://lab/test/bot/0",
            "scope": "READ", "tool_name": "mcp__robot__render", "tool_args": {},
            "manifest_path": str(FIXTURES / "signed-good.md"),
        }
        sig = priv.sign(canonical_json(body))
        body["envelope_signature"] = {
            "kid": "principal-kid",
            "alg": "Ed25519",
            "sig": base64.b64encode(sig).decode(),
        }
        return body

    return make, pub_pem


def test_rc_002_first_envelope_accepted_replay_rejected(signed_envelope_factory):
    make, pub_pem = signed_envelope_factory
    manifest_kid = (FIXTURES / "signing-key.kid").read_text().strip()
    manifest_pub = (FIXTURES / "signing-key.pub").read_bytes()

    class R:
        def resolve_public_key_pem(self, k):
            return {manifest_kid: manifest_pub, "principal-kid": pub_pem}.get(k)

    client = TestClient(make_app(
        resolver=R(),
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
        require_envelope_signature=True,
    ))
    env = make("rc-002-replay-1")
    r1 = client.post("/v1/invoke", json=env)
    assert r1.status_code == 200, r1.text
    r2 = client.post("/v1/invoke", json=env)
    assert r2.status_code == 403
    assert r2.json()["detail"]["deny"] == "replay"
