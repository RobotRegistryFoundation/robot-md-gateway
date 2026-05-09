"""Actuator extension surface for robot-md-gateway.

The gateway is Layer 3 (enforcement). After all policy gates pass on a
signed RCAN INVOKE envelope, the gateway delegates the actuation step to
an Actuator implementation discovered via Python entry-points
(``robot_md_gateway.actuators`` group). The actuator returns an
ActuatorOutcome that the gateway records in the audit chain — making the
chain a record of "what actually happened" rather than only "the gate
let it through".

The built-in default is NoOpActuator (returns outcome_kind="no_op").
Operators ship their own actuator package with a pyproject.toml that
declares the same entry-point group; gateway picks it up at serve time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

ENTRY_POINT_GROUP = "robot_md_gateway.actuators"


@dataclass
class ActuatorOutcome:
    success: bool
    outcome_kind: str  # "executed" | "no_op" | "deferred" | "error"
    telemetry: dict = field(default_factory=dict)
    error_message: str | None = None
    telemetry_path: Path | None = None
