"""MF-003 wiring — RRN binding + manifest-driven HiTL flags through POST /v1/invoke.

Uses the same signed fixture as MF-001 (signed-good.md, rrn=RRN-000000000999).
The flags default OFF, so existing behavior is unchanged; these assert the ON paths.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from robot_md_gateway.cert import report as cert_report
from robot_md_gateway.receiver import make_app

FIXTURES = Path(__file__).parent.parent / "fixtures" / "manifests"
MANIFEST_RRN = "RRN-000000000999"  # declared in signed-good.md


class _FakeResolver:
    def __init__(self, mapping):
        self._mapping = mapping

    def resolve_public_key_pem(self, kid):
        return self._mapping.get(kid)


@pytest.fixture(autouse=True)
def _reset():
    cert_report.reset()
    yield
    cert_report.reset()


def _app(**flags):
    kid = (FIXTURES / "signing-key.kid").read_text().strip()
    pub = (FIXTURES / "signing-key.pub").read_bytes()
    return TestClient(make_app(resolver=_FakeResolver({kid: pub}), **flags))


def _req(ruri):
    return {
        "msg_id": "m-rrn",
        "type": "INVOKE",
        "ruri": ruri,
        "scope": "READ",
        "tool_name": "mcp__robot__render",  # in the default allowlist
        "tool_args": {},
        "manifest_path": str(FIXTURES / "signed-good.md"),
    }


def test_rrn_binding_on_accepts_matching_ruri():
    client = _app(require_rrn_binding=True)
    resp = client.post("/v1/invoke", json=_req(f"rcan://{MANIFEST_RRN}/skill"))
    assert resp.status_code == 200, resp.json()


def test_rrn_binding_on_rejects_mismatched_ruri():
    client = _app(require_rrn_binding=True)
    resp = client.post("/v1/invoke", json=_req("rcan://RRN-000000000001/skill"))
    assert resp.status_code == 403
    assert resp.json()["detail"]["deny"] == "rrn_binding"


def test_rrn_binding_off_allows_mismatch():
    # default (flag off) — identity is not bound, mismatched ruri still passes
    client = _app()
    resp = client.post("/v1/invoke", json=_req("rcan://RRN-000000000001/skill"))
    assert resp.status_code == 200, resp.json()


def test_hitl_from_manifest_off_by_default_for_read():
    # READ scope is never HiTL-gated; flag on must not break the read path
    client = _app(hitl_from_manifest=True)
    resp = client.post("/v1/invoke", json=_req(f"rcan://{MANIFEST_RRN}/skill"))
    assert resp.status_code == 200, resp.json()
