"""Tests for the Actuator extension surface."""
from __future__ import annotations

from pathlib import Path

import pytest

from robot_md_gateway.actuator import ActuatorOutcome


from robot_md_gateway.actuator import Actuator, NoOpActuator


class TestActuatorOutcome:
    def test_minimal_construction(self):
        outcome = ActuatorOutcome(success=True, outcome_kind="executed")
        assert outcome.success is True
        assert outcome.outcome_kind == "executed"
        assert outcome.telemetry == {}
        assert outcome.error_message is None
        assert outcome.telemetry_path is None

    def test_full_construction(self):
        outcome = ActuatorOutcome(
            success=False,
            outcome_kind="error",
            telemetry={"k": "v"},
            error_message="boom",
            telemetry_path=Path("/tmp/x.json"),
        )
        assert outcome.success is False
        assert outcome.outcome_kind == "error"
        assert outcome.telemetry == {"k": "v"}
        assert outcome.error_message == "boom"
        assert outcome.telemetry_path == Path("/tmp/x.json")


class TestNoOpActuator:
    def test_protocol_conformance(self):
        actuator = NoOpActuator()
        assert isinstance(actuator, Actuator)

    def test_metadata(self):
        actuator = NoOpActuator()
        assert actuator.name == "noop"
        assert "log" in actuator.description.lower() or "default" in actuator.description.lower()
        assert actuator.config_schema == {}

    def test_execute_returns_no_op_outcome(self):
        actuator = NoOpActuator()
        envelope = {"msg_id": "test-msg-001", "tool_name": "render"}
        outcome = actuator.execute(
            envelope=envelope,
            manifest_path=Path("/tmp/ROBOT.md"),
            tier="actuate",
            config={},
        )
        assert outcome.success is True
        assert outcome.outcome_kind == "no_op"
        assert outcome.telemetry == {"msg_id": "test-msg-001", "tier": "actuate"}
        assert outcome.error_message is None
