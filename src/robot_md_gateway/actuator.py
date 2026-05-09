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
from importlib.metadata import entry_points as _entry_points
from pathlib import Path
from typing import Protocol, runtime_checkable

ENTRY_POINT_GROUP = "robot_md_gateway.actuators"


@dataclass
class ActuatorOutcome:
    success: bool
    outcome_kind: str  # "executed" | "no_op" | "deferred" | "error"
    telemetry: dict = field(default_factory=dict)
    error_message: str | None = None
    telemetry_path: Path | None = None


@runtime_checkable
class Actuator(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def description(self) -> str: ...

    @property
    def config_schema(self) -> dict: ...

    def execute(
        self,
        *,
        envelope: dict,
        manifest_path: Path,
        tier: str,
        config: dict,
    ) -> ActuatorOutcome: ...


class NoOpActuator:
    name = "noop"
    description = (
        "Built-in default. Logs envelope, returns no_op. Use until a driver is wired."
    )
    config_schema: dict = {}

    def execute(
        self,
        *,
        envelope: dict,
        manifest_path: Path,
        tier: str,
        config: dict,
    ) -> ActuatorOutcome:
        return ActuatorOutcome(
            success=True,
            outcome_kind="no_op",
            telemetry={"msg_id": envelope.get("msg_id"), "tier": tier},
        )


def discover_actuators() -> dict[str, type]:
    """Resolve all entry-points in the ``robot_md_gateway.actuators`` group.

    Returns: mapping of entry-point name to the loaded class.
    """
    return {ep.name: ep.load() for ep in _entry_points(group=ENTRY_POINT_GROUP)}


def resolve_actuator(name: str | None, *, fallback: type = NoOpActuator) -> type:
    """Resolve an actuator class by entry-point name.

    Args:
        name: entry-point name (e.g. ``"noop"``, ``"my-camera-stack"``);
            ``None`` or ``"noop"`` returns the built-in NoOpActuator.
        fallback: returned when ``name`` is ``None``. Defaults to NoOpActuator.

    Raises:
        LookupError: ``name`` is given but not found in the entry-point group.
    """
    if name is None or name == "noop":
        return fallback
    discovered = discover_actuators()
    if name not in discovered:
        raise LookupError(
            f"actuator {name!r} not found in entry-point group {ENTRY_POINT_GROUP!r}"
        )
    return discovered[name]
