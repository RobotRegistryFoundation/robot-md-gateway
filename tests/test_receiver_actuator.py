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
    """Resolver that approves any manifest_path against a single fake kid."""
    def resolve_kid_for_robot(self, ruri: str) -> str | None:
        return "fake-kid"


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
