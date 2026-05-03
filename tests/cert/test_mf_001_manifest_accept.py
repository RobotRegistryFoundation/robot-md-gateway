"""MF-001 — Manifest signature accept (Track 2 Gateway Authority).

A properly signed ROBOT.md, with the signing key registered to the
robot's RRN at RRF, must be accepted by POST /v1/invoke. Result:
HTTP 200, manifest_kid is the expected fixture kid.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from robot_md_gateway.cert import report as cert_report
from robot_md_gateway.receiver import make_app

FIXTURES = Path(__file__).parent.parent / "fixtures" / "manifests"


class _FakeResolver:
    def __init__(self, mapping: dict[str, bytes]) -> None:
        self._mapping = mapping

    def resolve_public_key_pem(self, kid: str) -> bytes | None:
        return self._mapping.get(kid)


@pytest.fixture(autouse=True)
def _reset_cert_report():
    cert_report.reset()
    yield
    cert_report.reset()


@pytest.fixture
def client():
    kid = (FIXTURES / "signing-key.kid").read_text().strip()
    pub = (FIXTURES / "signing-key.pub").read_bytes()
    app = make_app(resolver=_FakeResolver({kid: pub}))
    return TestClient(app)


def test_mf_001_signed_good_manifest_accepted(client):
    """MF-001 cert property: a properly signed manifest is accepted."""
    response = client.post("/v1/invoke", json={
        "msg_id": "msg-mf-001",
        "type": "INVOKE",
        "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "READ",
        "tool_name": "mcp__robot__render",
        "tool_args": {},
        "manifest_path": str(FIXTURES / "signed-good.md"),
    })
    assert response.status_code == 200, response.json()
    body = response.json()
    assert body["ok"] is True
    expected_kid = (FIXTURES / "signing-key.kid").read_text().strip()
    assert body["manifest_kid"] == expected_kid


def test_mf_001_pass_records_cert_evidence(client):
    """A passing MF-001 must produce a cert evidence entry."""
    client.post("/v1/invoke", json={
        "msg_id": "msg-mf-001b",
        "type": "INVOKE",
        "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "READ",
        "tool_name": "mcp__robot__render",
        "tool_args": {},
        "manifest_path": str(FIXTURES / "signed-good.md"),
    })
    serialized = cert_report.serialize(repo="robot-md-gateway", sha="HEAD")
    mf_001 = [p for p in serialized["properties"] if p["property_id"] == "MF-001"]
    assert len(mf_001) >= 1
    assert mf_001[0]["outcome"] == "pass"
    assert mf_001[0]["evidence"]["manifest_kid"]
