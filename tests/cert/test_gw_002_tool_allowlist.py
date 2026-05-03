"""GW-002 — Unallowlisted motion tool denied before driver (Track 2)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from robot_md_gateway.cert import report as cert_report
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.receiver import make_app

FIXTURES = Path(__file__).parent.parent / "fixtures" / "manifests"


class _FakeResolver:
    def __init__(self, mapping):
        self._mapping = mapping

    def resolve_public_key_pem(self, kid):
        return self._mapping.get(kid)


@pytest.fixture(autouse=True)
def _reset_cert_report():
    cert_report.reset()
    yield


def _client_with_allowlist(allowed: tuple[str, ...]):
    kid = (FIXTURES / "signing-key.kid").read_text().strip()
    pub = (FIXTURES / "signing-key.pub").read_bytes()
    app = make_app(
        resolver=_FakeResolver({kid: pub}),
        tool_allowlist=ToolAllowlist(allowed_tools=allowed),
    )
    return TestClient(app)


def test_gw_002_unallowlisted_tool_denied():
    client = _client_with_allowlist(allowed=("mcp__robot__render", "mcp__robot__validate"))
    response = client.post("/v1/invoke", json={
        "msg_id": "msg-gw-002-1",
        "type": "INVOKE",
        "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "MANIPULATE",
        "tool_name": "mcp__robot__execute_capability",
        "tool_args": {},
        "manifest_path": str(FIXTURES / "signed-good.md"),
    })
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["deny"] == "tool_allowlist"


def test_gw_002_allowlisted_tool_accepted():
    client = _client_with_allowlist(
        allowed=("mcp__robot__render", "mcp__robot__execute_capability"),
    )
    response = client.post("/v1/invoke", json={
        "msg_id": "msg-gw-002-2",
        "type": "INVOKE",
        "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "MANIPULATE",
        "tool_name": "mcp__robot__execute_capability",
        "tool_args": {},
        "manifest_path": str(FIXTURES / "signed-good.md"),
    })
    assert response.status_code == 200


def test_gw_002_pass_recorded():
    client = _client_with_allowlist(allowed=("mcp__robot__render",))
    client.post("/v1/invoke", json={
        "msg_id": "msg-gw-002-3", "type": "INVOKE",
        "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "MANIPULATE",
        "tool_name": "mcp__robot__execute_capability",
        "tool_args": {},
        "manifest_path": str(FIXTURES / "signed-good.md"),
    })
    serialized = cert_report.serialize(repo="robot-md-gateway", sha="HEAD")
    gw_002 = [p for p in serialized["properties"] if p["property_id"] == "GW-002"]
    assert len(gw_002) == 1 and gw_002[0]["outcome"] == "pass"
