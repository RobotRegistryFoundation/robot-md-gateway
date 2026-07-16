"""End-to-end coverage for scripts/verify_receipt.py (the independent verifier).

Captures a REAL signed receipt from the gateway via TestClient, writes it and the
gateway public key to disk, then runs the standalone script as a subprocess:

  * correct pubkey  -> exit 0 (authentic verifies AND a flipped byte is rejected)
  * wrong pubkey    -> exit 1

The script imports only stdlib + cryptography, so this proves a third party can
verify a receipt without the gateway package.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from robot_md_gateway.attestation import SigningIdentity
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.receiver import make_app

FIX = Path(__file__).parent / "fixtures" / "manifests"
MANIFEST_KID = (FIX / "signing-key.kid").read_text().strip()
MANIFEST_PUB = (FIX / "signing-key.pub").read_bytes()
GOOD_MANIFEST = str(FIX / "signed-good.md")
SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify_receipt.py"


class _Resolver:
    def __init__(self, mapping):
        self._m = mapping

    def resolve_public_key_pem(self, kid):
        return self._m.get(kid)


def _envelope(msg_id, **over):
    body = {
        "msg_id": msg_id, "type": "INVOKE", "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "READ", "tool_name": "mcp__robot__render", "tool_args": {},
        "manifest_path": GOOD_MANIFEST,
    }
    body.update(over)
    return body


def _pub_pem(priv):
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _capture(tmp_path, envelope) -> tuple[Path, Path, Path]:
    priv = Ed25519PrivateKey.generate()
    app = make_app(
        resolver=_Resolver({MANIFEST_KID: MANIFEST_PUB}),
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
        audit_chain=AuditChain(),
        signing_identity=SigningIdentity(priv=priv, kid="gw-kid", ran=None),
        attestation_export_file=None,
    )
    r = TestClient(app).post("/v1/invoke", json=envelope)
    receipt = tmp_path / "receipt.json"
    receipt.write_bytes(r.content)
    good = tmp_path / "gw.pub"
    good.write_bytes(_pub_pem(priv))
    wrong = tmp_path / "wrong.pub"
    wrong.write_bytes(_pub_pem(Ed25519PrivateKey.generate()))
    return receipt, good, wrong


def _run(receipt: Path, pubkey: Path) -> int:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--receipt", str(receipt), "--pubkey", str(pubkey)],
        capture_output=True, text=True,
    ).returncode


@pytest.mark.parametrize(
    "envelope",
    [
        _envelope("script-allow"),
        _envelope("script-deny", tool_name="mcp__robot__execute_capability"),
    ],
    ids=["allow", "deny"],
)
def test_script_verifies_real_receipt_and_detects_tamper(tmp_path, envelope):
    receipt, good, wrong = _capture(tmp_path, envelope)
    assert _run(receipt, good) == 0     # authentic + tamper-evident (both directions)
    assert _run(receipt, wrong) == 1    # wrong key must not verify
