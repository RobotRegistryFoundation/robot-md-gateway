"""Plan 6 Phase 4 — SafetyMonitor wiring through /v1/invoke.

Unit tests for SafetyMonitor live in test_sf_001_estop.py and
test_sf_002_network_loss.py. These tests verify the receiver path:
opt-in via make_app(safety_monitor=...), per-request tick, and
can_actuate gating before any other policy check.

ESTOP and heartbeat are exposed via app.state.safety_monitor — there
are no HTTP routes for these signals because SF-001 is conceptually
a hardware wire, not an HTTP layer.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from robot_md_gateway.cert import report as cert_report
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.cert.safety import GatewayState, SafetyMonitor
from robot_md_gateway.receiver import make_app

FIXTURES = Path(__file__).parent.parent / "fixtures" / "manifests"


@pytest.fixture(autouse=True)
def _reset():
    cert_report.reset()
    yield


def _client(*, safety_monitor: SafetyMonitor | None = None):
    kid = (FIXTURES / "signing-key.kid").read_text().strip()
    pub = (FIXTURES / "signing-key.pub").read_bytes()

    class R:
        def resolve_public_key_pem(self, k):
            return pub if k == kid else None

    app = make_app(
        resolver=R(),
        tool_allowlist=ToolAllowlist(
            allowed_tools=("mcp__robot__execute_capability", "mcp__robot__render"),
        ),
        bearer_tiers={"actuate-token": "actuate"},
        safety_monitor=safety_monitor,
    )
    return TestClient(app), app


def _envelope(**overrides):
    base = {
        "msg_id": "msg-phase4-1",
        "type": "INVOKE",
        "ruri": "rcan://x/y/z/0",
        "scope": "MANIPULATE",
        "tool_name": "mcp__robot__execute_capability",
        "tool_args": {},
        "manifest_path": str(FIXTURES / "signed-good.md"),
    }
    base.update(overrides)
    return base


def test_no_safety_monitor_default_unchanged():
    """Opt-in: when safety_monitor=None, the receiver behaves as before."""
    client, _ = _client()
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_envelope(),
    )
    assert r.status_code == 200


def test_estop_trip_denies_invoke():
    sm = SafetyMonitor()
    client, app = _client(safety_monitor=sm)
    # Operator/external integration path: trip ESTOP wire through app.state.
    app.state.safety_monitor.on_estop_wire(tripped=True, msg_id="hw-trip-1")
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_envelope(),
    )
    assert r.status_code == 403
    assert r.json()["detail"]["deny"] == "safety_state"
    assert "estop_active" in r.json()["detail"]["reason"]


def test_heartbeat_staleness_transitions_safe_stop_on_next_tick():
    """SF-002: per-request tick catches network-loss after heartbeat staleness threshold."""
    sm = SafetyMonitor(heartbeat_staleness_s=0.05)
    # Force last_heartbeat into the past so the tick at request time triggers.
    sm.last_heartbeat_at = time.monotonic() - 1.0
    client, _ = _client(safety_monitor=sm)
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_envelope(),
    )
    assert r.status_code == 403
    assert r.json()["detail"]["deny"] == "safety_state"
    assert sm.state == GatewayState.SAFE_STOP


def test_fresh_heartbeat_allows_actuation():
    sm = SafetyMonitor(heartbeat_staleness_s=10.0)
    sm.on_heartbeat()
    client, _ = _client(safety_monitor=sm)
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json=_envelope(),
    )
    assert r.status_code == 200
    assert sm.state == GatewayState.READY


def test_safety_check_runs_before_other_gates():
    """SF-001 precedence: ESTOP must preempt even malformed envelope shape."""
    sm = SafetyMonitor()
    client, app = _client(safety_monitor=sm)
    app.state.safety_monitor.on_estop_wire(tripped=True)
    # Missing required fields would normally yield 422; safety must fire first.
    r = client.post(
        "/v1/invoke",
        headers={"Authorization": "Bearer actuate-token"},
        json={"msg_id": "m"},
    )
    assert r.status_code == 403
    assert r.json()["detail"]["deny"] == "safety_state"
