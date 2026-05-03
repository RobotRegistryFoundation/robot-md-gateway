"""Integration tests for RC-003 + RC-004 wiring through /v1/invoke.

Unit tests for `check_confidence` and `check_hitl` live in
`test_rc_003_confidence.py` and `test_rc_004_hitl.py`. These tests
verify the wiring inside `make_app` — that policies are actually
honored on the request path and that denials surface the documented
detail.deny strings.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from robot_md_gateway.cert import report as cert_report
from robot_md_gateway.cert.gates import ConfidencePolicy, HiTLPolicy
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.receiver import make_app

FIXTURES = Path(__file__).parent.parent / "fixtures" / "manifests"


@pytest.fixture(autouse=True)
def _reset():
    cert_report.reset()
    yield


def _client(*, confidence_policy=None, hitl_policy=None):
    kid = (FIXTURES / "signing-key.kid").read_text().strip()
    pub = (FIXTURES / "signing-key.pub").read_bytes()

    class R:
        def resolve_public_key_pem(self, k):
            return pub if k == kid else None

    bearer_tiers = {"actuate-token": "actuate"}
    app = make_app(
        resolver=R(),
        tool_allowlist=ToolAllowlist(
            allowed_tools=("mcp__robot__execute_capability", "mcp__robot__render"),
        ),
        bearer_tiers=bearer_tiers,
        confidence_policy=confidence_policy,
        hitl_policy=hitl_policy,
    )
    return TestClient(app)


def _envelope(**overrides):
    base = {
        "msg_id": "1",
        "type": "INVOKE",
        "ruri": "rcan://x/y/z/0",
        "scope": "MANIPULATE",
        "tool_name": "mcp__robot__execute_capability",
        "tool_args": {},
        "manifest_path": str(FIXTURES / "signed-good.md"),
        "payload": {"inference_confidence": 0.95},
        "delegation_chain": [{"scope": "MANIPULATE", "human_subject": "operator@x.com"}],
    }
    base.update(overrides)
    return base


def test_rc_003_wiring_low_confidence_returns_403():
    client = _client(confidence_policy=ConfidencePolicy())
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_envelope(payload={"inference_confidence": 0.5}),
    )
    assert r.status_code == 403
    assert r.json()["detail"]["deny"] == "confidence_threshold"


def test_rc_003_wiring_above_threshold_passes():
    client = _client(confidence_policy=ConfidencePolicy())
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_envelope(payload={"inference_confidence": 0.95}),
    )
    assert r.status_code == 200


def test_rc_004_wiring_missing_chain_returns_403():
    client = _client(hitl_policy=HiTLPolicy())
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_envelope(delegation_chain=[]),
    )
    assert r.status_code == 403
    assert r.json()["detail"]["deny"] == "hitl_required"


def test_rc_004_wiring_with_chain_passes():
    client = _client(hitl_policy=HiTLPolicy())
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_envelope(),
    )
    assert r.status_code == 200
