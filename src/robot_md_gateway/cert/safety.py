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
        staleness = now - self.last_heartbeat_at
        if self.state == GatewayState.READY and staleness > self.heartbeat_staleness_s:
            self.state = GatewayState.SAFE_STOP
            cert_report.record_property_pass(
                property_id="SF-002",
                evidence={
                    "prev_state": "ready",
                    "new_state": "safe_stop",
                    "staleness_s": staleness,
                    "outcome": "network_loss safe-stop",
                },
            )

    def clear(
        self,
        *,
        tier: str,
        audit_chain=None,  # noqa: ANN001 - duck-typed AuditChain
        msg_id: str | None = None,
    ) -> tuple[bool, str]:
        """Leave ESTOP_ACTIVE without restarting the process.

        Until this existed the only exit from ESTOP_ACTIVE was a restart, and a
        restart also throws away the in-memory audit chain - so the record of
        why the robot stopped died with the stop. Recovering from a stop must
        not cost the evidence of it.

        Gated at the `commission` tier, which is the same bearer that authorises
        bring-up motion: clearing a stop is the act of making a robot movable
        again, so it is an actuation-class decision, not an observation.

        The decision is written into `audit_chain` when one is supplied, allow
        or deny alike - a refused clear is exactly the event an operator later
        needs to find.

        Returns ``(cleared, reason)``. Honest about what it does NOT do: it
        restores this state machine only. It does not touch an actuator's own
        latch (each driver clears its own), it does not refresh the heartbeat,
        and a gateway whose heartbeat is still stale drops back to SAFE_STOP on
        the next `tick`.
        """
        prev = self.state
        if tier != "commission":
            reason = (
                f"safety.clear: {tier!r}-tier principal cannot clear "
                f"{prev.value}; requires the 'commission' tier"
            )
            self._audit_clear(audit_chain, decision="deny", reason=reason, msg_id=msg_id)
            return False, reason
        self.state = GatewayState.READY
        reason = f"safety.clear: {prev.value} -> {self.state.value}"
        self._audit_clear(audit_chain, decision="allow", reason=reason, msg_id=msg_id)
        # Deliberately records NO cert property. SF-001 is the claim that an
        # ESTOP wire trip preempts everything else (docs/hil/track-3-test-plan.md:
        # "100% of 10 trip events stop actuation within 100ms"), and a clear is
        # the opposite transition. Filing a clear as an SF-001 pass would let a
        # gateway that never once tripped accumulate SF-001 evidence, which is a
        # conformance claim it has not earned. The audit chain above is the
        # record of a clear; there is no cert property for one, and inventing a
        # pass for it would be the software asserting more than it knows.
        return True, reason

    @staticmethod
    def _audit_clear(audit_chain, decision: str, reason: str, msg_id: str | None) -> None:
        if audit_chain is None:
            return
        from .audit import AuditEntry

        audit_chain.append(AuditEntry(
            msg_id=msg_id or "safety.clear",
            timestamp_ms=int(time.time() * 1000),
            decision=decision,
            decision_reason=reason,
            envelope_kid=None,
        ))

    def can_actuate(self) -> bool:
        return self.state == GatewayState.READY
