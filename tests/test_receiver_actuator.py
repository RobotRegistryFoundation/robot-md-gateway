"""Integration tests: gates pass → actuator runs → audit captures outcome."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from robot_md_gateway.actuator import Actuator, ActuatorOutcome, NoOpActuator
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.manifest_provenance import RRFResolver
from robot_md_gateway.receiver import make_app


class _FakeResolver:
    """Resolver that validates manifest signatures using the fixture signing key."""
    def __init__(self):
        fixture_dir = Path(__file__).parent / "fixtures" / "manifests"
        self.kid = (fixture_dir / "signing-key.kid").read_text().strip()
        self.pub_pem = (fixture_dir / "signing-key.pub").read_bytes()

    def resolve_kid_for_robot(self, ruri: str) -> str | None:
        return self.kid

    def resolve_public_key_pem(self, kid: str) -> bytes | None:
        if kid == self.kid:
            return self.pub_pem
        return None


def _make_test_app(actuator=None, actuator_config=None, audit_chain=None):
    return make_app(
        resolver=_FakeResolver(),
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
        bearer_tiers={"actuate-token": "actuate"},
        actuator=actuator,
        actuator_config=actuator_config or {},
        audit_chain=audit_chain,
    )


class TestMakeAppAcceptsActuator:
    def test_actuator_param_optional_defaults_to_noop(self):
        # Should NOT raise; actuator defaults to NoOpActuator instance.
        app = _make_test_app()
        assert app is not None
        # The instantiated NoOpActuator is on app.state for inspection.
        assert isinstance(app.state.actuator, NoOpActuator)

    def test_explicit_actuator_passed_through(self):
        custom = NoOpActuator()
        app = _make_test_app(actuator=custom)
        assert app.state.actuator is custom

    def test_actuator_config_param_defaults_to_empty_dict(self):
        app = _make_test_app()
        assert app.state.actuator_config == {}


class _SpyActuator:
    """Test-only actuator that records calls and returns a configurable outcome."""
    name = "spy"
    description = "test spy"
    config_schema: dict = {}

    def __init__(self, outcome=None):
        self.calls: list[dict] = []
        self._outcome = outcome or ActuatorOutcome(
            success=True, outcome_kind="executed",
            telemetry={"spy_marker": "ok"},
        )

    def execute(self, *, envelope, manifest_path, tier, config):
        self.calls.append({
            "envelope_msg_id": envelope.get("msg_id"),
            "manifest_path": str(manifest_path),
            "tier": tier,
            "config": dict(config),
        })
        return self._outcome


def _valid_envelope(tmp_path):
    # Use the fixture signed manifest so no monkeypatch is needed.
    fixture_manifest = Path(__file__).parent / "fixtures" / "manifests" / "signed-good.md"
    return {
        "msg_id": "test-msg-1",
        "type": "rcan/v1/invoke",
        "ruri": "rcan://RRN-test/skill",
        "scope": "actuate",
        "tool_name": "mcp__robot__render",
        "tool_args": {},
        "manifest_path": str(fixture_manifest),
    }


class TestActuatorCalledAfterGates:
    def test_actuator_executed_when_all_gates_pass(self, tmp_path):
        spy = _SpyActuator()
        chain = AuditChain()
        app = _make_test_app(actuator=spy, audit_chain=chain)

        with TestClient(app) as client:
            response = client.post(
                "/v1/invoke",
                json=_valid_envelope(tmp_path),
                headers={"Authorization": "Bearer actuate-token"},
            )

        assert response.status_code == 200
        body = response.json()
        assert body["ok"] is True
        assert body["actuator_name"] == "spy"
        assert body["outcome_kind"] == "executed"

        # Spy was called with the envelope.
        assert len(spy.calls) == 1
        assert spy.calls[0]["envelope_msg_id"] == "test-msg-1"
        assert spy.calls[0]["tier"] == "actuate"

        # Audit chain has one entry with actuator outcome captured.
        assert len(chain.entries) == 1
        entry = chain.entries[0]
        assert entry.decision == "allow"
        assert entry.actuator_name == "spy"
        assert entry.actuator_outcome_kind == "executed"

    def test_actuator_not_called_when_gate_denies(self, tmp_path, monkeypatch):
        # Manifest provenance fails → gate denies → actuator must NOT be called.
        # Use a resolver that doesn't have the signing key so verification fails.
        class FailResolver:
            def resolve_public_key_pem(self, kid: str) -> bytes | None:
                return None

        spy = _SpyActuator()
        chain = AuditChain()
        app = make_app(
            resolver=FailResolver(),
            tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
            bearer_tiers={"actuate-token": "actuate"},
            actuator=spy,
            actuator_config={},
            audit_chain=chain,
        )

        with TestClient(app) as client:
            response = client.post(
                "/v1/invoke",
                json=_valid_envelope(tmp_path),
                headers={"Authorization": "Bearer actuate-token"},
            )

        assert response.status_code == 403
        assert spy.calls == []
        # Audit entry recorded a deny, no actuator fields populated.
        assert len(chain.entries) == 1
        assert chain.entries[0].decision == "deny"
        assert chain.entries[0].actuator_name is None
