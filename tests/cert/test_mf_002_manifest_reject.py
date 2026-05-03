"""MF-002 — Manifest signature reject (Track 2 Gateway Authority)."""

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
def client_with_resolver():
    kid = (FIXTURES / "signing-key.kid").read_text().strip()
    pub = (FIXTURES / "signing-key.pub").read_bytes()
    app = make_app(resolver=_FakeResolver({kid: pub}))
    return TestClient(app)


def test_mf_002_tampered_manifest_rejected(client_with_resolver):
    response = client_with_resolver.post("/v1/invoke", json={
        "msg_id": "msg-mf-002",
        "type": "INVOKE",
        "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "READ",
        "tool_name": "mcp__robot__render",
        "tool_args": {},
        "manifest_path": str(FIXTURES / "signed-tampered.md"),
    })
    assert response.status_code == 403, response.text
    body = response.json()
    assert body["detail"]["deny"] == "manifest_provenance"


def test_mf_002_unknown_kid_rejected():
    """If the kid is not registered, the manifest is rejected — even if the file looks signed."""
    empty_resolver = _FakeResolver({})
    app = make_app(resolver=empty_resolver)
    client = TestClient(app)
    response = client.post("/v1/invoke", json={
        "msg_id": "msg-mf-002b",
        "type": "INVOKE",
        "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "READ",
        "tool_name": "mcp__robot__render",
        "tool_args": {},
        "manifest_path": str(FIXTURES / "signed-good.md"),
    })
    assert response.status_code == 403


def test_mf_002_reject_emits_cert_evidence(client_with_resolver):
    client_with_resolver.post("/v1/invoke", json={
        "msg_id": "msg-mf-002c",
        "type": "INVOKE",
        "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "READ",
        "tool_name": "mcp__robot__render",
        "tool_args": {},
        "manifest_path": str(FIXTURES / "signed-tampered.md"),
    })
    serialized = cert_report.serialize(repo="robot-md-gateway", sha="HEAD")
    mf_002_records = [p for p in serialized["properties"] if p["property_id"] == "MF-002"]
    assert len(mf_002_records) >= 1
    assert mf_002_records[0]["outcome"] == "fail"
    assert "reason" in mf_002_records[0]["evidence"]
