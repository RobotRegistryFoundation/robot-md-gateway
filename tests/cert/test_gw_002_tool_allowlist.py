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


# Behavior change (T-003 anon fail-open fix): the tier gate now runs BEFORE the
# tool-allowlist gate, and anon (no/unknown bearer) is denied actuation. These
# tests exercise the GW-002 tool allowlist on the MANIPULATE scope, so they must
# present an actuate-tier bearer to reach the tool gate at all — otherwise they'd
# stop at tier_policy. The bearer is incidental to what they assert (the tool
# allowlist), so it is baked into the client helper.
ACTUATE_HEADERS = {"Authorization": "Bearer gw-002-actuate"}


def _client_with_allowlist(allowed: tuple[str, ...]):
    kid = (FIXTURES / "signing-key.kid").read_text().strip()
    pub = (FIXTURES / "signing-key.pub").read_bytes()
    app = make_app(
        resolver=_FakeResolver({kid: pub}),
        tool_allowlist=ToolAllowlist(allowed_tools=allowed),
        bearer_tiers={"gw-002-actuate": "actuate"},
    )
    return TestClient(app)


def test_gw_002_unallowlisted_tool_denied():
    client = _client_with_allowlist(allowed=("mcp__robot__render", "mcp__robot__validate"))
    response = client.post("/v1/invoke", headers=ACTUATE_HEADERS, json={
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
    response = client.post("/v1/invoke", headers=ACTUATE_HEADERS, json={
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
    client.post("/v1/invoke", headers=ACTUATE_HEADERS, json={
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
