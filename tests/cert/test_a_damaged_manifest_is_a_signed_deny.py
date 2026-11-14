"""A ROBOT.md that is damaged in a way its parser did not expect is refused
with a signed deny, never answered with a 500 (review of #35, finding 1).

A 500 carries no receipt and leaves no audit entry, and on the trip path the
same exceptions used to cancel the gateway's own stop. These are the shapes
the review and its probes found: frontmatter of the wrong type, a signature
footer that is not base64, and a non-UTF-8 byte.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from robot_md_gateway.actuator import NoOpActuator
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.manifest_provenance import verify_manifest
from robot_md_gateway.receiver import make_app

KID = "test-damaged-manifest"
PRIV = Ed25519PrivateKey.generate()
PUB_PEM = PRIV.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


class _Resolver:
    def resolve_public_key_pem(self, kid: str) -> bytes | None:
        return PUB_PEM if kid == KID else None


def _signed(tmp_path: Path, frontmatter: str) -> Path:
    body = f"---\n{frontmatter}\n---\n\n# testbot\n"
    sig = base64.b64encode(PRIV.sign(body.encode())).decode()
    path = tmp_path / "ROBOT.md"
    path.write_text(body + f"\n<!-- ROBOT-MD-SIG kid={KID} sig={sig} -->\n")
    return path


def _invoke(app, manifest: Path, tool="status.report", scope="OBSERVE"):
    client = TestClient(app, raise_server_exceptions=False)
    return client.post("/v1/invoke", json={
        "msg_id": "m-1", "type": "rcan/v1/invoke", "ruri": "rcan://RRN-test/x",
        "scope": scope, "tool_name": tool, "tool_args": {},
        "manifest_path": str(manifest),
    })


def _app(**kw):
    chain = AuditChain()
    app = make_app(resolver=_Resolver(), actuator=NoOpActuator(), actuator_config={},
                   tool_allowlist=ToolAllowlist(allowed_tools=("status.report",)),
                   audit_chain=chain, **kw)
    return app, chain


@pytest.mark.parametrize("safety", ["safety: oops", "safety:\n  hitl_gates: [oops]",
                                    "safety:\n  hitl_gates: 7"])
def test_hitl_gates_of_the_wrong_shape_are_a_signed_deny(tmp_path, safety):
    app, chain = _app(hitl_from_manifest=True)
    response = _invoke(app, _signed(tmp_path, f"rrn: RRN-000000000011\n{safety}"))
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["deny"] == "hitl_required"
    assert chain.entries[-1].decision == "deny"


@pytest.mark.parametrize("frontmatter", ["metadata: oops", "- a list\n- not a mapping",
                                         "just a string"])
def test_frontmatter_of_the_wrong_shape_is_not_a_500(tmp_path, frontmatter):
    app, chain = _app()
    response = _invoke(app, _signed(tmp_path, frontmatter))
    assert response.status_code == 200, response.text
    assert chain.entries[-1].decision == "allow"


def test_a_signature_that_is_not_base64_is_a_signed_deny(tmp_path):
    path = tmp_path / "ROBOT.md"
    path.write_text("---\nrrn: RRN-1\n---\n\n# x\n"
                    f"\n<!-- ROBOT-MD-SIG kid={KID} sig=abc -->\n")
    assert verify_manifest(path, resolver=_Resolver()).reason == "signature is not valid base64"
    app, chain = _app()
    response = _invoke(app, path)
    assert response.status_code == 403
    assert response.json()["detail"]["deny"] == "manifest_provenance"
    assert chain.entries[-1].decision == "deny"


def test_a_byte_that_is_not_utf8_is_a_signed_deny(tmp_path):
    path = _signed(tmp_path, "rrn: RRN-1")
    path.write_bytes(path.read_bytes().replace(b"testbot", b"test\xffbot"))
    app, chain = _app()
    response = _invoke(app, path)
    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "manifest unreadable: UnicodeDecodeError"
    assert chain.entries[-1].decision == "deny"
