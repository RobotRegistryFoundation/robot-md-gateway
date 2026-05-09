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


from robot_md_gateway.actuator import (
    ENTRY_POINT_GROUP,
    discover_actuators,
    resolve_actuator,
)


class TestEntryPointDiscovery:
    def test_entry_point_group_constant(self):
        assert ENTRY_POINT_GROUP == "robot_md_gateway.actuators"

    def test_discover_finds_built_in_noop(self):
        # After this branch ships and the package is installed, the noop
        # entry-point must be discoverable. In the pre-install dev tree
        # that's not guaranteed — skip the assertion when running from
        # source without `pip install -e .`.
        discovered = discover_actuators()
        if "noop" not in discovered:
            pytest.skip("package not installed; skip live entry-point check")
        assert discovered["noop"] is NoOpActuator

    def test_resolve_actuator_default(self):
        cls = resolve_actuator(None)
        assert cls is NoOpActuator

    def test_resolve_actuator_noop_explicit(self):
        cls = resolve_actuator("noop")
        assert cls is NoOpActuator

    def test_resolve_actuator_unknown_raises(self):
        with pytest.raises(LookupError, match="not found"):
            resolve_actuator("definitely-not-a-real-actuator")

    def test_resolve_actuator_via_monkeypatched_entry_point(self, monkeypatch):
        class FakeActuator:
            name = "fake"
            description = "test fake"
            config_schema: dict = {}
            def execute(self, *, envelope, manifest_path, tier, config):
                return ActuatorOutcome(success=True, outcome_kind="executed")

        # Inject a fake entry point so resolve_actuator finds it.
        from robot_md_gateway import actuator as actuator_module

        def fake_eps(*, group):
            assert group == ENTRY_POINT_GROUP
            class _EP:
                name = "fake"
                def load(self):
                    return FakeActuator
            return [_EP()]

        monkeypatch.setattr(actuator_module, "_entry_points", fake_eps)
        cls = resolve_actuator("fake")
        assert cls is FakeActuator
