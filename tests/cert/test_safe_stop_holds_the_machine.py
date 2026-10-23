"""SF-002 in a served gateway: a stale heartbeat stops the machine, and it holds.

Before this, `make_app` took a SafetyMonitor but nothing in production passed
one, and the monitor that tests passed in was only ever ticked by an incoming
request. Neither half stopped anything: SAFE_STOP refused NEW requests, while a
motion already dispatched to the actuator ran to its end, and with no requests
arriving the state never changed at all.

What a served gateway does now, and what these tests pin:

- a watchdog ticks the monitor on its own, so staleness is enforced while no
  request arrives;
- the moment the monitor leaves READY (stale heartbeat, ESTOP wire), the gateway
  sends every actuator that declares a stop its own stop tool, once per trip;
- a heartbeat alone never resumes; resume is an explicit operator signal at the
  commission tier, and only with a fresh heartbeat.

The actuator here is a simulation that behaves like so-arm101-actuator's
paced move: it latches on `arm.estop`, ends a move at its next setpoint once
latched, holds, and refuses motion until `arm.estop.clear` at commission tier.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import ClassVar

import pytest
from fastapi.testclient import TestClient

from robot_md_gateway.actuator import ActuatorOutcome, NoOpActuator
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.cert.safety import GatewayState, SafetyMonitor
from robot_md_gateway.receiver import make_app

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "manifests"
STALE_S = 0.3
BEARERS = {"read-token": "read", "actuate-token": "actuate", "commission-token": "commission"}
ALLOWED = ("arm.move_to", "arm.estop", "arm.estop.clear")


class _Resolver:
    def __init__(self):
        self.kid = (FIXTURES / "signing-key.kid").read_text().strip()
        self.pub_pem = (FIXTURES / "signing-key.pub").read_bytes()

    def resolve_public_key_pem(self, kid: str) -> bytes | None:
        return self.pub_pem if kid == self.kid else None


class _SimArm:
    """A simulated arm: position advances one step per setpoint of a paced move."""

    name = "arm"
    description = "simulated arm"
    config_schema: ClassVar[dict] = {}
    motion_capabilities = frozenset({"arm.move_to"})
    stop_capabilities = frozenset({"arm.estop"})
    STEP_S = 0.01

    def __init__(self, steps: int = 300):
        self.steps = steps
        self.position = 0
        self.latched = False
        self.stops: list[dict] = []          # every arm.estop this arm received
        self.moving = threading.Event()
        self._lock = threading.Lock()

    def execute(self, *, envelope, manifest_path, tier, config):
        tool = envelope["tool_name"]
        if tool == "arm.estop":
            with self._lock:
                self.latched = True          # latch first, like the real driver
                self.stops.append({"msg_id": envelope["msg_id"], "tier": tier,
                                   "while_moving": self.moving.is_set(),
                                   "held_at": self.position})
            return ActuatorOutcome(success=True, outcome_kind="executed",
                                   telemetry={"estopped": True, "held_at": self.position})
        if tool == "arm.estop.clear":
            if tier != "commission":
                return ActuatorOutcome(success=False, outcome_kind="denied",
                                       error_message="estop.clear needs the commission tier")
            self.latched = False
            return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})
        if self.latched:
            return ActuatorOutcome(success=False, outcome_kind="denied",
                                   error_message="estop_latched: arm is e-stopped",
                                   telemetry={"deny": "estop_latched"})
        self.moving.set()
        try:
            done = 0
            while done < self.steps and not self.latched:   # checked per setpoint
                self.position += 1
                done += 1
                time.sleep(self.STEP_S)
        finally:
            self.moving.clear()
        return ActuatorOutcome(success=True, outcome_kind="executed",
                               telemetry={"steps": done, "stopped_by_estop": done < self.steps})


def _app(arm, chain=None, *, staleness=STALE_S, monitor=None):
    monitor = monitor or SafetyMonitor(heartbeat_staleness_s=staleness)
    return make_app(
        resolver=_Resolver(),
        tool_allowlist=ToolAllowlist(allowed_tools=ALLOWED),
        bearer_tiers=BEARERS,
        safety_monitor=monitor,
        audit_chain=chain,
        actuator=arm,
        actuator_config={},
    )


def _invoke(client, tool, scope="MANIPULATE", token="actuate-token", msg_id=None):
    return client.post(
        "/v1/invoke",
        json={
            "msg_id": msg_id or f"m-{tool}-{time.monotonic_ns()}",
            "type": "rcan/v1/invoke",
            "ruri": "rcan://RRN-test/arm",
            "scope": scope,
            "tool_name": tool,
            "tool_args": {},
            "manifest_path": str(FIXTURES / "signed-good.md"),
        },
        headers={"Authorization": f"Bearer {token}"},
    )


def _heartbeat(client, token="read-token"):
    return client.post("/v1/safety/heartbeat", headers={"Authorization": f"Bearer {token}"})


def _clear(client, token="commission-token"):
    return client.post("/v1/safety/clear", headers={"Authorization": f"Bearer {token}"})


def _wait_for(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def _gateway_stops(chain: AuditChain):
    return [e for e in chain.entries if e.decision_reason.startswith("safety_stop:")]


def _trip(client, monitor):
    """Let the heartbeat go stale and wait for the watchdog to act."""
    assert _wait_for(lambda: monitor.state is GatewayState.SAFE_STOP), monitor.state


# --------------------------------------------------------------------------- #
# A stale heartbeat stops the machine, with no request arriving
# --------------------------------------------------------------------------- #


def test_a_stale_heartbeat_enters_safe_stop_and_stops_the_actuator_unprompted():
    arm, chain = _SimArm(), AuditChain()
    app = _app(arm, chain)
    with TestClient(app):                     # no request is ever sent
        assert _wait_for(lambda: arm.stops), "the watchdog never stopped the arm"
        assert app.state.safety_monitor.state is GatewayState.SAFE_STOP

    [stop] = arm.stops
    assert stop["msg_id"].startswith("safety-stop-")
    [entry] = _gateway_stops(chain)
    assert entry.decision == "allow"
    assert entry.decision_reason.startswith("safety_stop: gateway safe_stop (no heartbeat for")
    assert "sent arm.estop to arm" in entry.decision_reason
    assert entry.actuator_name == "arm"
    assert entry.actuator_outcome_kind == "executed"
    # Sent by the gateway itself: no credential was presented for it.
    assert (entry.caller, entry.tier) == (None, None)


def test_a_motion_in_flight_is_stopped_and_the_machine_holds():
    arm, chain = _SimArm(steps=300), AuditChain()         # ~3 s of motion
    app = _app(arm, chain)
    monitor = app.state.safety_monitor
    with TestClient(app) as client:
        result: dict = {}
        mover = threading.Thread(
            target=lambda: result.update(r=_invoke(client, "arm.move_to")))
        mover.start()
        assert arm.moving.wait(2), "the move never started"
        started = time.monotonic()
        mover.join(timeout=5)                 # no heartbeat arrives: it goes stale
        took = time.monotonic() - started

        assert monitor.state is GatewayState.SAFE_STOP
        [stop] = arm.stops
        assert stop["while_moving"], "the stop must reach the arm while it moves"
        assert took < 2.0, f"the move ran {took:.1f} s; the stop did not end it"
        moved = result["r"].json()["telemetry"]
        assert moved["stopped_by_estop"] is True

        # ... and it HOLDS: nothing moves it afterwards, and a new motion is
        # refused by the gateway and recorded as a refusal.
        held = arm.position
        time.sleep(STALE_S)
        refused = _invoke(client, "arm.move_to")
        assert arm.position == held
        assert refused.status_code == 403
        assert refused.json()["detail"]["deny"] == "safety_state"
        assert chain.entries[-1].decision == "deny"


def test_one_trip_sends_one_stop():
    arm = _SimArm()
    app = _app(arm)
    with TestClient(app) as client:
        _trip(client, app.state.safety_monitor)
        time.sleep(0.5)                       # several watchdog ticks
        _invoke(client, "arm.move_to")        # and a request tick
        assert len(arm.stops) == 1


def test_an_estop_wire_trip_stops_the_actuator_too():
    arm = _SimArm()
    app = _app(arm, staleness=60.0)           # the heartbeat is not the cause here
    with TestClient(app):
        app.state.safety_monitor.on_estop_wire(tripped=True, msg_id="wire")
        assert _wait_for(lambda: arm.stops, timeout=1.0)
        assert app.state.safety_monitor.state is GatewayState.ESTOP_ACTIVE


def test_a_stop_still_gets_through_after_the_gateway_stopped_the_machine():
    arm = _SimArm()
    app = _app(arm)
    with TestClient(app) as client:
        _trip(client, app.state.safety_monitor)
        response = _invoke(client, "arm.estop", scope="HALT", token="read-token")
    assert response.status_code == 200, response.text
    assert len(arm.stops) == 2                # the gateway's, then the operator's


# --------------------------------------------------------------------------- #
# A heartbeat never resumes; the operator does, at the commission tier
# --------------------------------------------------------------------------- #


def test_a_fresh_heartbeat_after_staleness_does_not_resume():
    arm, chain = _SimArm(), AuditChain()
    app = _app(arm, chain)
    monitor = app.state.safety_monitor
    with TestClient(app) as client:
        _trip(client, monitor)
        for _ in range(5):
            assert _heartbeat(client).status_code == 200
            time.sleep(0.02)
        response = _invoke(client, "arm.move_to")

    assert monitor.state is GatewayState.SAFE_STOP
    assert response.status_code == 403
    assert response.json()["detail"]["deny"] == "safety_state"
    assert chain.entries[-1].decision == "deny"
    assert arm.position == 0


def test_resume_needs_the_commission_tier():
    chain = AuditChain()
    app = _app(_SimArm(), chain)
    monitor = app.state.safety_monitor
    with TestClient(app) as client:
        _trip(client, monitor)
        _heartbeat(client)
        refused = _clear(client, token="actuate-token")
        assert refused.status_code == 403
        assert refused.json()["detail"]["deny"] == "safety_clear"
        assert monitor.state is GatewayState.SAFE_STOP

        _heartbeat(client)
        cleared = _clear(client, token="commission-token")
        assert cleared.status_code == 200, cleared.text
        assert cleared.json()["state"] == "ready"

    clears = [e for e in chain.entries if e.decision_reason.startswith("safety.clear")]
    assert [(e.decision, e.tier) for e in clears] == [("deny", "actuate"), ("allow", "commission")]


def test_resume_is_refused_while_the_heartbeat_is_stale():
    """Recovery needs fresh heartbeats AND the explicit signal: a clear sent
    into a silence would only drop straight back into SAFE_STOP."""
    chain = AuditChain()
    app = _app(_SimArm(), chain)
    monitor = app.state.safety_monitor
    with TestClient(app) as client:
        _trip(client, monitor)
        response = _clear(client)

    assert response.status_code == 403
    assert response.json()["detail"]["deny"] == "safety_clear"
    assert "heartbeat" in response.json()["detail"]["reason"]
    assert monitor.state is GatewayState.SAFE_STOP
    assert chain.entries[-1].decision == "deny"
    assert chain.entries[-1].tier == "commission"


def test_the_whole_resume_is_explicit_at_both_layers_and_then_motion_runs():
    """The gateway's clear does not touch the actuator's own latch: the arm
    refuses until arm.estop.clear at commission tier. Two explicit steps."""
    arm = _SimArm(steps=3)
    app = _app(arm, staleness=1.0)
    monitor = app.state.safety_monitor
    with TestClient(app) as client:
        _trip(client, monitor)
        _heartbeat(client)
        assert _clear(client).status_code == 200

        still_latched = _invoke(client, "arm.move_to")
        assert still_latched.status_code == 403
        assert still_latched.json()["detail"]["deny"] == "actuator_policy"

        unlatched = _invoke(client, "arm.estop.clear", scope="COMMISSION",
                            token="commission-token")
        assert unlatched.status_code == 200, unlatched.text
        moved = _invoke(client, "arm.move_to")
        assert moved.status_code == 200, moved.text
    assert arm.position == 3


def test_after_a_resume_the_next_stale_heartbeat_stops_the_machine_again():
    arm = _SimArm()
    app = _app(arm)
    monitor = app.state.safety_monitor
    with TestClient(app) as client:
        _trip(client, monitor)
        _heartbeat(client)
        assert _clear(client).status_code == 200
        _trip(client, monitor)                # silence again
        assert _wait_for(lambda: len(arm.stops) == 2)


# --------------------------------------------------------------------------- #
# The heartbeat route, and the honest edges
# --------------------------------------------------------------------------- #


def test_the_heartbeat_takes_any_known_bearer_and_nothing_else():
    app = _app(_SimArm(), staleness=60.0)
    monitor = app.state.safety_monitor
    with TestClient(app) as client:
        assert client.post("/v1/safety/heartbeat").status_code == 401
        assert _heartbeat(client, token="nobody").status_code == 403
        before = monitor.last_heartbeat_at
        time.sleep(0.01)
        response = _heartbeat(client, token="read-token")
    assert response.status_code == 200
    assert response.json() == {"state": "ready", "heartbeat_staleness_s": 60.0}
    assert monitor.last_heartbeat_at > before


def test_heartbeats_keep_the_gateway_ready():
    arm = _SimArm(steps=3)
    app = _app(arm)
    monitor = app.state.safety_monitor
    with TestClient(app) as client:
        deadline = time.monotonic() + 3 * STALE_S
        while time.monotonic() < deadline:
            _heartbeat(client)
            time.sleep(STALE_S / 4)
        assert monitor.state is GatewayState.READY
        assert _invoke(client, "arm.move_to").status_code == 200
    assert arm.stops == []


def test_a_trip_with_no_actuator_that_declares_a_stop_says_so(caplog):
    """The no-op actuator declares no stop, so there is nothing to send. The
    gateway still refuses new requests, and it says loudly that it stopped
    nothing, rather than implying it did."""
    app = make_app(resolver=_Resolver(), safety_monitor=SafetyMonitor(heartbeat_staleness_s=0.1),
                   actuator=NoOpActuator())
    with caplog.at_level(logging.ERROR, logger="robot_md_gateway.receiver"), TestClient(app):
        assert _wait_for(lambda: "nothing was told to stop" in caplog.text)


def test_a_stop_that_raises_is_logged_and_recorded_and_the_watchdog_lives_on():
    class _Broken(_SimArm):
        def execute(self, *, envelope, manifest_path, tier, config):
            if envelope["tool_name"] == "arm.estop":
                self.stops.append({"msg_id": envelope["msg_id"]})
                raise OSError("bus down")
            return super().execute(envelope=envelope, manifest_path=manifest_path,
                                   tier=tier, config=config)

    arm, chain = _Broken(), AuditChain()
    app = _app(arm, chain)
    monitor = app.state.safety_monitor
    with TestClient(app) as client:
        _trip(client, monitor)
        assert _wait_for(lambda: _gateway_stops(chain))
        _heartbeat(client)
        assert _clear(client).status_code == 200
        _trip(client, monitor)                # the watchdog is still running
        assert _wait_for(lambda: len(arm.stops) == 2)
    entry = _gateway_stops(chain)[0]
    assert entry.actuator_outcome_kind == "error"
    assert entry.actuator_error_kind == "OSError"


def test_the_watchdog_stops_with_the_app():
    app = _app(_SimArm(), staleness=60.0)
    with TestClient(app):
        assert any(t.name == "robot-md-gateway-safety-watchdog" for t in threading.enumerate())
    assert not any(t.name == "robot-md-gateway-safety-watchdog" and t.is_alive()
                   for t in threading.enumerate())


def test_make_app_without_a_safety_monitor_says_so(caplog):
    """The opt-out exists for tests and embedders, and it is loud."""
    with caplog.at_level(logging.WARNING, logger="robot_md_gateway.receiver"):
        make_app(resolver=_Resolver())
    assert "no_safety_monitor" in caplog.text


@pytest.mark.parametrize("route", ["/v1/safety/heartbeat", "/v1/safety/clear"])
def test_the_safety_routes_404_on_a_gateway_with_no_monitor(route):
    app = make_app(resolver=_Resolver(), bearer_tiers=BEARERS)
    response = TestClient(app).post(route, headers={"Authorization": "Bearer commission-token"})
    assert response.status_code == 404
