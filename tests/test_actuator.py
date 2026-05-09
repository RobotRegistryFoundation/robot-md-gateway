"""Tests for the Actuator extension surface."""
from __future__ import annotations

from pathlib import Path

import pytest

from robot_md_gateway.actuator import ActuatorOutcome


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
