"""Manifest pin (#29).

The envelope names the manifest it wants enforced. Provenance only proves that
file was signed by a trusted key, so a second signed copy anywhere on disk (an
old one, or one with a looser tier/allowlist posture) used to pass. With a pin,
the receiver enforces the operator's ROBOT_MD_PATH and denies any other path,
403 and audited, before reading the caller-named file.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from robot_md_gateway.__main__ import _pinned_manifest_from_env
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.receiver import make_app

FIX = Path(__file__).parent / "fixtures" / "manifests"
MANIFEST_KID = (FIX / "signing-key.kid").read_text().strip()
MANIFEST_PUB = (FIX / "signing-key.pub").read_bytes()
PINNED = FIX / "signed-good.md"


class _Resolver:
    def resolve_public_key_pem(self, kid):
        return MANIFEST_PUB if kid == MANIFEST_KID else None


def _make(pinned, chain):
    return make_app(
        resolver=_Resolver(),
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
        audit_chain=chain,
        pinned_manifest_path=pinned,
    )


def _envelope(msg_id, manifest_path):
    return {
        "msg_id": msg_id, "type": "INVOKE", "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "READ", "tool_name": "mcp__robot__render", "tool_args": {},
        "manifest_path": str(manifest_path),
    }


@pytest.fixture
def second_signed_copy(tmp_path):
    # Byte-identical, so provenance-valid: exactly the "old signed copy" case.
    copy = tmp_path / "ROBOT.md"
    shutil.copy(PINNED, copy)
    return copy


def test_unpinned_gateway_accepts_any_signed_manifest(second_signed_copy):
    # The hole, kept as the documented no-pin behavior so the pin test means something.
    r = TestClient(_make(None, AuditChain())).post(
        "/v1/invoke", json=_envelope("pin-0", second_signed_copy),
    )
    assert r.status_code == 200


def test_pinned_gateway_denies_a_second_signed_manifest(second_signed_copy):
    chain = AuditChain()
    r = TestClient(_make(PINNED, chain)).post(
        "/v1/invoke", json=_envelope("pin-1", second_signed_copy),
    )
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert detail["deny"] == "manifest_pin"
    assert str(PINNED) in detail["reason"]
    last = chain.entries[-1]
    assert last.msg_id == "pin-1"
    assert last.decision == "deny"
    assert last.decision_reason.startswith("manifest_pin:")


def test_pinned_gateway_allows_the_pinned_manifest():
    r = TestClient(_make(PINNED, AuditChain())).post(
        "/v1/invoke", json=_envelope("pin-2", PINNED),
    )
    assert r.status_code == 200


def test_pin_compares_resolved_paths(tmp_path):
    # A symlink to the pinned file, or a ../ spelling of it, IS the pinned file.
    link = tmp_path / "ROBOT.md"
    link.symlink_to(PINNED)
    dotted = PINNED.parent / ".." / PINNED.parent.name / PINNED.name
    client = TestClient(_make(PINNED, AuditChain()))
    assert client.post("/v1/invoke", json=_envelope("pin-3", link)).status_code == 200
    assert client.post("/v1/invoke", json=_envelope("pin-4", dotted)).status_code == 200


def test_pin_denies_a_missing_file_without_reading_it(tmp_path):
    r = TestClient(_make(PINNED, AuditChain())).post(
        "/v1/invoke", json=_envelope("pin-5", tmp_path / "nope.md"),
    )
    assert r.status_code == 403
    assert r.json()["detail"]["deny"] == "manifest_pin"


@pytest.mark.parametrize("value", ["", "   "])
def test_env_unset_or_blank_means_no_pin(value, monkeypatch):
    monkeypatch.setenv("ROBOT_MD_PATH", value)
    assert _pinned_manifest_from_env() is None


def test_env_unset_means_no_pin(monkeypatch):
    monkeypatch.delenv("ROBOT_MD_PATH", raising=False)
    assert _pinned_manifest_from_env() is None


def test_env_set_pins(monkeypatch):
    monkeypatch.setenv("ROBOT_MD_PATH", "/etc/robot-md-gateway/ROBOT.md")
    assert _pinned_manifest_from_env() == Path("/etc/robot-md-gateway/ROBOT.md")
