"""GW-003 — Read-tier principal denied actuation."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from robot_md_gateway.cert import report as cert_report
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.receiver import make_app

FIXTURES = Path(__file__).parent.parent / "fixtures" / "manifests"


@pytest.fixture(autouse=True)
def _reset():
    cert_report.reset()
    yield


def _client(read_tokens=("read-token",), actuate_tokens=("actuate-token",)):
    kid = (FIXTURES / "signing-key.kid").read_text().strip()
    pub = (FIXTURES / "signing-key.pub").read_bytes()

    class R:
        def resolve_public_key_pem(self, k):
            return pub if k == kid else None

    bearer_tiers = (
        {token: "read" for token in read_tokens}
        | {token: "actuate" for token in actuate_tokens}
    )
    app = make_app(
        resolver=R(),
        tool_allowlist=ToolAllowlist(
            allowed_tools=("mcp__robot__execute_capability", "mcp__robot__render"),
        ),
        bearer_tiers=bearer_tiers,
    )
    return TestClient(app)


def test_gw_003_read_token_denies_manipulate():
    client = _client()
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer read-token"},
        json={
            "msg_id": "1", "type": "INVOKE", "ruri": "rcan://x/y/z/0", "scope": "MANIPULATE",
            "tool_name": "mcp__robot__execute_capability", "tool_args": {},
            "manifest_path": str(FIXTURES / "signed-good.md"),
        },
    )
    assert r.status_code == 403
    assert r.json()["detail"]["deny"] == "tier_policy"


def test_gw_003_actuate_token_allows_manipulate():
    client = _client()
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json={
            "msg_id": "2", "type": "INVOKE", "ruri": "rcan://x/y/z/0", "scope": "MANIPULATE",
            "tool_name": "mcp__robot__execute_capability", "tool_args": {},
            "manifest_path": str(FIXTURES / "signed-good.md"),
        },
    )
    assert r.status_code == 200


def test_gw_003_read_token_allows_read_scope():
    client = _client()
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer read-token"},
        json={
            "msg_id": "3", "type": "INVOKE", "ruri": "rcan://x/y/z/0", "scope": "READ",
            "tool_name": "mcp__robot__render", "tool_args": {},
            "manifest_path": str(FIXTURES / "signed-good.md"),
        },
    )
    assert r.status_code == 200


# T-003 — anon fail-open regression. Before the fix, an unauthenticated (anon)
# actuation invoke slipped past check_tier (which only denied tier=='read'),
# under-gating COMMAND-class calls. These assert the gate is now closed while the
# legitimate anon read/discover path stays open.
def test_gw_003_anon_denied_manipulate():
    client = _client()
    r = client.post(  # NO Authorization header -> tier 'anon'
        "/v1/invoke",
        json={
            "msg_id": "anon-1", "type": "INVOKE", "ruri": "rcan://x/y/z/0",
            "scope": "MANIPULATE",
            "tool_name": "mcp__robot__execute_capability", "tool_args": {},
            "manifest_path": str(FIXTURES / "signed-good.md"),
        },
    )
    assert r.status_code == 403
    assert r.json()["detail"]["deny"] == "tier_policy"


def test_gw_003_anon_denied_commission():
    client = _client()
    r = client.post(  # no credential + COMMISSION scope
        "/v1/invoke",
        json={
            "msg_id": "anon-2", "type": "INVOKE", "ruri": "rcan://x/y/z/0",
            "scope": "COMMISSION",
            "tool_name": "mcp__robot__execute_capability", "tool_args": {},
            "manifest_path": str(FIXTURES / "signed-good.md"),
        },
    )
    assert r.status_code == 403
    assert r.json()["detail"]["deny"] == "tier_policy"


def test_gw_003_unknown_bearer_denied_manipulate():
    client = _client()
    r = client.post(  # unknown/insufficient bearer maps to 'anon'
        "/v1/invoke",
        headers={"Authorization": "Bearer not-a-real-token"},
        json={
            "msg_id": "anon-3", "type": "INVOKE", "ruri": "rcan://x/y/z/0",
            "scope": "MANIPULATE",
            "tool_name": "mcp__robot__execute_capability", "tool_args": {},
            "manifest_path": str(FIXTURES / "signed-good.md"),
        },
    )
    assert r.status_code == 403
    assert r.json()["detail"]["deny"] == "tier_policy"


def test_gw_003_anon_allows_read_scope():
    # The legitimate anon read/discover path must stay open (not broken by the fix).
    client = _client()
    r = client.post(  # no Authorization header, READ scope
        "/v1/invoke",
        json={
            "msg_id": "anon-4", "type": "INVOKE", "ruri": "rcan://x/y/z/0", "scope": "READ",
            "tool_name": "mcp__robot__render", "tool_args": {},
            "manifest_path": str(FIXTURES / "signed-good.md"),
        },
    )
    assert r.status_code == 200
