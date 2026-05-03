"""Safety state machine: ESTOP precedence (SF-001) + network-loss safe-stop (SF-002)."""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field

from . import report as cert_report


class GatewayState(enum.Enum):
    READY = "ready"
    SAFE_STOP = "safe_stop"
    ESTOP_ACTIVE = "estop_active"


@dataclass
class SafetyMonitor:
    state: GatewayState = GatewayState.READY
    last_heartbeat_at: float = field(default_factory=time.monotonic)
    heartbeat_staleness_s: float = 3.0   # spec §3 robot-md-pendant: 3-second staleness rule

    def on_estop_wire(self, *, tripped: bool, msg_id: str | None = None) -> None:
        """SF-001 — ESTOP wire transitions preempt other state."""
        if tripped and self.state != GatewayState.ESTOP_ACTIVE:
            prev = self.state
            self.state = GatewayState.ESTOP_ACTIVE
            cert_report.record_property_pass(
                property_id="SF-001",
                evidence={"prev_state": prev.value, "new_state": self.state.value, "msg_id": msg_id,
                          "outcome": "estop preempted"},
            )

    def on_heartbeat(self) -> None:
        self.last_heartbeat_at = time.monotonic()
        if self.state == GatewayState.SAFE_STOP:
            # Resume requires explicit operator signal, NOT a heartbeat alone.
            pass

    def tick(self, *, now: float | None = None) -> None:
        """SF-002 — call regularly. Transition to SAFE_STOP on heartbeat staleness."""
        now = now if now is not None else time.monotonic()
        if self.state == GatewayState.READY and (now - self.last_heartbeat_at) > self.heartbeat_staleness_s:
            self.state = GatewayState.SAFE_STOP
            cert_report.record_property_pass(
                property_id="SF-002",
                evidence={"prev_state": "ready", "new_state": "safe_stop",
                          "staleness_s": now - self.last_heartbeat_at, "outcome": "network_loss safe-stop"},
            )

    def can_actuate(self) -> bool:
        return self.state == GatewayState.READY
