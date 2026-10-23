"""SF-002 in a served gateway: a stale heartbeat stops the machine, and it holds.

What a served gateway does, and what these tests pin:

- a watchdog ticks the monitor on its own, so staleness is enforced while no
  request arrives;
- the moment the monitor leaves READY (stale heartbeat, ESTOP wire, a stuck
  watchdog) the gateway sends every actuator that declares a stop its stop,
  each on a thread of its own, with a timeout;
- a trip is handled only when every stop has answered or timed out: a stop
  that could not be started is retried, and a clear cannot overtake a trip
  that has not been acted on;
- a heartbeat alone never resumes; resume is an explicit operator signal at the
  commission tier, with a fresh heartbeat from the supervisor credential;
- trips, stops, timeouts and clears are all recorded.

TIME. Heartbeat staleness is judged on a fake clock passed to make_app
(`clock=`), and a tick is driven with `app.state.safety_tick()`, so no test
depends on how fast this machine is. Real time appears only in "eventually"
waits for work that takes milliseconds, with generous timeouts.

The actuator is a simulation that behaves like so-arm101-actuator's paced
move: it latches on `arm.estop`, ends a move at its next setpoint once latched,
holds, and refuses motion until `arm.estop.clear` at commission tier.
"""

from __future__ import annotations

import json
import logging
import shutil
import threading
import time
from pathlib import Path
from typing import ClassVar

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import robot_md_gateway.receiver as receiver_mod
from robot_md_gateway.actuator import ActuatorOutcome, NoOpActuator
from robot_md_gateway.attestation import SigningIdentity
from robot_md_gateway.auth import _BearerEntry
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.cert.safety import GatewayState, SafetyMonitor
from robot_md_gateway.receiver import make_app

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "manifests"
STALE_S = 3.0
BEARERS = {"read-token": "read", "actuate-token": "actuate", "commission-token": "commission"}
#: The heartbeat credential: role supervisor, read tier, held by the person's device.
SUPERVISOR = {"supervisor-token": _BearerEntry(token="supervisor-token", tier="read",
                                              caller_id="pendant", role="supervisor")}
ALLOWED = ("arm.move_to", "arm.estop", "arm.estop.clear")


class FakeClock:
    """The monotonic clock the staleness rule reads; moves only when told to."""

    def __init__(self, start: float = 1000.0):
        self.t = start
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self.t

    def advance(self, seconds: float) -> None:
        with self._lock:
            self.t += seconds


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

    def __init__(self, steps: int = 1000):
        self.steps = steps
        self.position = 0
        self.latched = False
        self.stops: list[dict] = []          # every arm.estop this arm received
        self.moving = threading.Event()
        self.stop_gate: threading.Event | None = None   # set => the stop blocks on it
        self._lock = threading.Lock()

    def execute(self, *, envelope, manifest_path, tier, config):
        tool = envelope["tool_name"]
        if tool == "arm.estop":
            with self._lock:
                self.latched = True          # latch first, like the real driver
                self.stops.append({"msg_id": envelope["msg_id"], "tier": tier,
                                   "while_moving": self.moving.is_set(),
                                   "held_at": self.position})
            if self.stop_gate is not None:
                self.stop_gate.wait(30)
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


def _app(arm=None, chain=None, *, clock=None, monitor=None, actuators=None, **extra):
    chain = chain if chain is not None else AuditChain()
    clock = clock or FakeClock()
    monitor = monitor or SafetyMonitor(heartbeat_staleness_s=STALE_S, last_heartbeat_at=clock())
    actuation = (dict(actuators=actuators) if actuators is not None
                 else dict(actuator=arm, actuator_config={}))
    app = make_app(
        resolver=_Resolver(),
        tool_allowlist=extra.pop("tool_allowlist", ToolAllowlist(allowed_tools=ALLOWED)),
        bearer_tiers=BEARERS,
        bearers=SUPERVISOR,
        safety_monitor=monitor,
        audit_chain=chain,
        clock=clock,
        **actuation,
        **extra,
    )
    return app, monitor, clock


def _invoke(client, tool, scope="MANIPULATE", token="actuate-token", manifest=None, **extra):
    return client.post(
        "/v1/invoke",
        json={
            "msg_id": f"m-{tool}-{time.monotonic_ns()}",
            "type": "rcan/v1/invoke",
            "ruri": "rcan://RRN-test/arm",
            "scope": scope,
            "tool_name": tool,
            "tool_args": {},
            "manifest_path": str(manifest or FIXTURES / "signed-good.md"),
            **extra,
        },
        headers={"Authorization": f"Bearer {token}"},
    )


def _heartbeat(client, token="supervisor-token"):
    return client.post("/v1/safety/heartbeat", headers={"Authorization": f"Bearer {token}"})


def _clear(client, token="commission-token"):
    return client.post("/v1/safety/clear", headers={"Authorization": f"Bearer {token}"})


def _wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


def _trip(app, clock):
    """Let the heartbeat go stale on the fake clock, and tick once."""
    clock.advance(STALE_S + 1.0)
    return app.state.safety_tick()


def _reasons(chain: AuditChain, prefix: str) -> list[str]:
    return [e.decision_reason for e in chain.entries if e.decision_reason.startswith(prefix)]


def _stopped(app, n: int = 1) -> bool:
    """Wait until n of the gateway's own stops have answered and been recorded."""
    return _wait_for(lambda: len(_reasons(app.state.audit_chain, "safety_stop:")) >= n)


def _refusals_at_the_safety_state(chain: AuditChain) -> list:
    return [e for e in chain.entries if e.decision_reason.startswith("safety_state:")]


def _start_move(client, **kw):
    box: dict = {}
    mover = threading.Thread(target=lambda: box.update(r=_invoke(client, "arm.move_to", **kw)))
    mover.start()
    return mover, box


# --------------------------------------------------------------------------- #
# A stale heartbeat stops the machine, with no request arriving
# --------------------------------------------------------------------------- #


def test_the_watchdog_trips_and_stops_the_actuator_with_no_request():
    arm, chain = _SimArm(), AuditChain()
    app, monitor, clock = _app(arm, chain)
    with TestClient(app):
        clock.advance(STALE_S + 1.0)          # no request is ever sent: only the watchdog ticks
        assert _wait_for(lambda: arm.stops), "the watchdog never stopped the arm"
        assert _wait_for(lambda: _reasons(chain, "safety_stop:"))
    assert monitor.state is GatewayState.SAFE_STOP
    [stop] = arm.stops
    assert stop["msg_id"].startswith("safety-stop-")
    assert stop["tier"] == "read"             # SAFETY_STOP_TIER
    [entry] = [e for e in chain.entries if e.decision_reason.startswith("safety_stop:")]
    assert entry.decision == "allow"
    assert "sent arm.estop to arm" in entry.decision_reason
    assert entry.actuator_outcome_kind == "executed"
    assert (entry.caller, entry.tier) == (None, None)     # the gateway itself


def test_a_motion_in_flight_is_stopped_and_the_machine_holds():
    arm, chain = _SimArm(steps=1000), AuditChain()        # ~10 s of motion
    app, monitor, clock = _app(arm, chain)
    with TestClient(app) as client:
        mover, box = _start_move(client)
        assert arm.moving.wait(5), "the move never started"
        _trip(app, clock)
        mover.join(15)
        assert monitor.state is GatewayState.SAFE_STOP
        [stop] = arm.stops
        assert stop["while_moving"], "the stop must reach the arm while it moves"
        assert box["r"].json()["telemetry"]["stopped_by_estop"] is True

        # ... and it HOLDS: nothing moves it afterwards, and a new motion is
        # refused by the gateway and recorded as a refusal.
        held = arm.position
        app.state.safety_tick()
        refused = _invoke(client, "arm.move_to")
        assert arm.position == held
        assert refused.status_code == 403
        assert refused.json()["detail"]["deny"] == "safety_state"
        [entry] = _refusals_at_the_safety_state(chain)
        assert entry.decision == "deny"


def test_one_trip_sends_one_stop():
    arm = _SimArm()
    app, _monitor, clock = _app(arm)
    with TestClient(app) as client:
        _trip(app, clock)
        assert _stopped(app)
        for _ in range(5):
            app.state.safety_tick()
        _invoke(client, "arm.move_to")        # a request tick too
        assert len(arm.stops) == 1


def test_an_estop_wire_trip_stops_the_actuator_too():
    arm = _SimArm()
    app, monitor, _clock = _app(arm)
    with TestClient(app):
        monitor.on_estop_wire(tripped=True, msg_id="wire")
        app.state.safety_tick()
        assert _wait_for(lambda: arm.stops)
    assert monitor.state is GatewayState.ESTOP_ACTIVE


def test_an_estop_during_a_safe_stop_sends_the_stops_again():
    """A trip whose stop may have failed must not absorb a later ESTOP."""
    arm = _SimArm()
    app, monitor, clock = _app(arm)
    with TestClient(app):
        _trip(app, clock)
        assert _stopped(app)
        monitor.on_estop_wire(tripped=True, msg_id="wire")
        app.state.safety_tick()
        assert _stopped(app, 2)
    assert monitor.state is GatewayState.ESTOP_ACTIVE
    assert len(arm.stops) == 2
    trips = _reasons(app.state.audit_chain, "safety_trip:")
    assert trips[1].startswith("safety_trip: safe_stop -> estop_active (ESTOP wire tripped)")


def test_a_return_to_ready_made_outside_the_routes_is_recorded_too():
    app, monitor, clock = _app(_SimArm())
    with TestClient(app) as client:
        _trip(app, clock)
        assert _stopped(app)
        _heartbeat(client)
        monitor.clear(tier="commission")      # an embedder, not /v1/safety/clear
        app.state.safety_tick()
    [entry] = [e for e in app.state.audit_chain.entries
               if e.decision_reason.startswith("safety_transition:")]
    assert entry.decision_reason == ("safety_transition: safe_stop -> ready "
                                     "(not through /v1/safety/clear)")
    assert entry.decision == "allow"


def test_a_stop_still_gets_through_after_the_gateway_stopped_the_machine():
    arm = _SimArm()
    app, _monitor, clock = _app(arm)
    with TestClient(app) as client:
        _trip(app, clock)
        assert _stopped(app)
        response = _invoke(client, "arm.estop", scope="SAFETY", token="read-token")
    assert response.status_code == 200, response.text
    assert len(arm.stops) == 2                # the gateway's, then the operator's


# --------------------------------------------------------------------------- #
# Finding 1: nothing on the trip path can cancel the stop
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("corrupt", [
    lambda raw: raw.replace(b"Test Robot", b"Test \xffRobot"),          # not UTF-8
    lambda raw: raw.replace(b"metadata:", b"metadata: oops\nwas:", 1),  # not a mapping
])
def test_a_manifest_that_does_not_parse_cannot_cancel_the_trip_stop(tmp_path, corrupt):
    """The review's reproduction: the pinned ROBOT.md is damaged mid-move. The
    stop used to be cancelled before it was sent, and nothing retried it."""
    pinned = tmp_path / "ROBOT.md"
    shutil.copy(FIXTURES / "signed-good.md", pinned)
    arm, chain = _SimArm(steps=1000), AuditChain()
    app, monitor, clock = _app(arm, chain, pinned_manifest_path=pinned)
    with TestClient(app) as client:
        mover, box = _start_move(client, manifest=pinned)
        assert arm.moving.wait(5)
        pinned.write_bytes(corrupt(pinned.read_bytes()))
        _trip(app, clock)
        mover.join(15)
    assert monitor.state is GatewayState.SAFE_STOP
    assert len(arm.stops) == 1, "the gateway's stop was not sent"
    assert box["r"].json()["telemetry"]["stopped_by_estop"] is True
    assert _reasons(chain, "safety_stop:")


def test_a_damaged_manifest_is_a_signed_refusal_for_a_motion_not_a_500(tmp_path):
    bad = tmp_path / "ROBOT.md"
    bad.write_bytes((FIXTURES / "signed-good.md").read_bytes().replace(b"Test Robot",
                                                                         b"Test \xffRobot"))
    arm = _SimArm()
    app, _monitor, _clock = _app(arm)
    with TestClient(app, raise_server_exceptions=False) as client:
        response = _invoke(client, "arm.move_to", manifest=bad)
    assert response.status_code == 403
    assert response.json()["detail"]["deny"] == "manifest_provenance"
    assert arm.position == 0


def test_a_stop_whose_thread_could_not_start_is_retried(monkeypatch):
    """Never mark a trip handled until each stop was sent or definitively failed."""
    real = threading.Thread

    class _NoThreadOnce(real):
        failed: ClassVar[list] = []

        def start(self):
            if self.name.startswith("robot-md-gateway-stop-") and not _NoThreadOnce.failed:
                _NoThreadOnce.failed.append(self.name)
                raise RuntimeError("can't start new thread")
            return super().start()

    arm = _SimArm()
    app, _monitor, clock = _app(arm)
    with TestClient(app) as client:
        monkeypatch.setattr(receiver_mod.threading, "Thread", _NoThreadOnce)
        _trip(app, clock)
        assert _NoThreadOnce.failed and arm.stops == []
        _heartbeat(client)
        early = _clear(client)                # the trip still owes its stop
        app.state.safety_tick()               # the next tick retries it
        assert _wait_for(lambda: arm.stops)
    assert early.status_code == 409
    assert len(arm.stops) == 1


# --------------------------------------------------------------------------- #
# Finding 5: a clear cannot discard a trip the gateway has not acted on
# --------------------------------------------------------------------------- #


def test_a_clear_racing_an_unacted_trip_sends_the_stop_first_and_waits_for_it():
    """The review's P4: an ESTOP-wire trip, then a commission clear before any
    tick. The clear now acts on the trip under the same lock (the stop goes
    out) and refuses until that stop has answered.

    No lifespan, so no watchdog: nothing but the clear itself can notice the
    trip, which is the case under test. The stop cannot answer before the
    clear decides, because marking it answered needs the lock the clear holds.
    """
    arm, chain = _SimArm(steps=1000), AuditChain()
    app, monitor, _clock = _app(arm, chain)
    client = TestClient(app)
    mover, box = _start_move(client)
    assert arm.moving.wait(5)
    _heartbeat(client)
    monitor.on_estop_wire(tripped=True, msg_id="wire")
    first = _clear(client)                    # no tick has run since the trip
    mover.join(15)
    assert _stopped(app)
    second = _clear(client)
    assert monitor.state is GatewayState.READY
    assert first.status_code == 409
    assert "still being sent" in first.json()["detail"]["reason"]
    assert len(arm.stops) == 1 and arm.stops[0]["while_moving"]
    assert box["r"].json()["telemetry"]["stopped_by_estop"] is True
    assert second.status_code == 200, second.text


# --------------------------------------------------------------------------- #
# Finding 6: stops run concurrently, with a timeout, off the watchdog
# --------------------------------------------------------------------------- #


def test_a_slow_stop_does_not_delay_another_actuators_stop():
    slow, fast = _SimArm(), _SimArm()
    slow.name, fast.name = "arm", "base"
    fast.stop_capabilities = frozenset({"arm.estop"})
    slow.stop_gate = threading.Event()        # the arm's stop waits for its bus
    app, _monitor, clock = _app(actuators={"arm": slow, "base": fast})
    with TestClient(app):
        _trip(app, clock)
        try:
            assert _wait_for(lambda: fast.stops, timeout=2.0), "base waited behind arm"
            assert slow.stops                  # the arm's stop was sent too, and is blocked
        finally:
            slow.stop_gate.set()


def test_a_hung_stop_neither_wedges_the_watchdog_nor_is_waited_for_forever():
    arm, chain = _SimArm(), AuditChain()
    arm.stop_gate = threading.Event()         # the stop never answers, until the end
    app, monitor, clock = _app(arm, chain)
    try:
        with TestClient(app) as client:
            _trip(app, clock)
            assert _wait_for(lambda: arm.stops)
            _heartbeat(client)
            assert _clear(client).status_code == 409          # still being sent
            clock.advance(receiver_mod.STOP_TIMEOUT_S + 0.5)
            app.state.safety_tick()
            [timeout] = [e for e in chain.entries
                         if e.decision_reason.startswith("safety_stop_timeout: trip 1:")]
            assert "arm.estop to arm did not answer within 10 s" in timeout.decision_reason
            _heartbeat(client)
            assert _clear(client).status_code == 200          # timed out: the operator decides
            clock.advance(STALE_S + 1.0)                      # silence again: only the watchdog
            assert _wait_for(lambda: monitor.state is GatewayState.SAFE_STOP)
            assert _wait_for(lambda: len(arm.stops) == 2)     # it is still ticking
    finally:
        arm.stop_gate.set()


def test_a_stuck_watchdog_fails_closed(monkeypatch):
    """If the watchdog stops ticking, a heartbeat is no longer answered 200
    and the gateway goes to SAFE_STOP, sending its stops."""
    monkeypatch.setattr(receiver_mod, "WATCHDOG_STALE_S", 0.2)
    monkeypatch.setattr(receiver_mod, "SAFETY_TICK_S", 60.0)   # it ticks once a minute: stuck
    arm, chain = _SimArm(), AuditChain()
    app, monitor, _clock = _app(arm, chain)
    with TestClient(app) as client:
        time.sleep(0.3)
        response = _heartbeat(client)
        refused = _invoke(client, "arm.move_to")
        assert _stopped(app)
        not_cleared = _clear(client)
    assert response.status_code == 503
    assert response.json()["detail"]["deny"] == "safety_watchdog"
    assert monitor.state is GatewayState.SAFE_STOP
    assert refused.status_code == 403
    assert not_cleared.status_code == 503
    assert "watchdog has not ticked" in not_cleared.json()["detail"]["reason"]
    assert any("safety watchdog has not ticked" in r for r in _reasons(chain, "safety_trip:"))


# --------------------------------------------------------------------------- #
# Finding 9: trips, stops and clears are recorded
# --------------------------------------------------------------------------- #


def test_the_trip_itself_is_recorded_with_the_last_supervisor():
    arm, chain = _SimArm(), AuditChain()
    app, _monitor, clock = _app(arm, chain)
    with TestClient(app) as client:
        assert _heartbeat(client).status_code == 200
        _trip(app, clock)
    [trip] = [e for e in chain.entries if e.decision_reason.startswith("safety_trip:")]
    assert trip.decision == "deny"
    assert trip.decision_reason.startswith(
        "safety_trip: ready -> safe_stop (no heartbeat for 4.0 s")
    assert "the last one came from supervisor 'pendant'" in trip.decision_reason
    assert trip.decision_reason.endswith("sending arm.estop to arm")


def test_a_trip_with_no_actuator_that_declares_a_stop_is_recorded_and_says_so(caplog):
    chain = AuditChain()
    app, _monitor, clock = _app(NoOpActuator(), chain)
    with caplog.at_level(logging.ERROR, logger="robot_md_gateway.receiver"), TestClient(app):
        _trip(app, clock)
    [trip] = _reasons(chain, "safety_trip:")
    assert trip.endswith("no actuator declares a stop, so nothing was told to stop")
    assert "nothing was told to stop" in caplog.text


def test_a_clear_gets_a_signed_receipt_and_a_line_in_the_export(tmp_path):
    export = tmp_path / "trace.ndjsonl"
    identity = SigningIdentity(priv=Ed25519PrivateKey.generate(), kid="gw", ran=None)
    chain = AuditChain()
    app, _monitor, clock = _app(_SimArm(), chain, signing_identity=identity,
                               attestation_export_file=export)
    with TestClient(app) as client:
        _trip(app, clock)
        assert _stopped(app)
        _heartbeat(client)
        refused = _clear(client, token="actuate-token")
        cleared = _clear(client)
    assert refused.status_code == 403
    assert refused.json()["detail"]["outcome"]["status"] == "denied"
    assert cleared.status_code == 200
    assert cleared.json()["outcome"]["status"] == "ok"
    assert cleared.json()["envelope_signature"]["kid"] == "gw"
    lines = [json.loads(x) for x in export.read_text().splitlines() if x.strip()]
    clears = [r for r in lines if r["invoke"].get("type") == "ESTOP_CLEAR"]
    assert [r["outcome"]["status"] for r in clears] == ["denied", "ok"]
    clears_in_chain = [e for e in chain.entries if e.decision_reason.startswith("safety.clear")]
    assert [(e.decision, e.tier, e.caller) for e in clears_in_chain] == [
        ("deny", "actuate", None), ("allow", "commission", None)]


# --------------------------------------------------------------------------- #
# A heartbeat never resumes; the operator does, at the commission tier
# --------------------------------------------------------------------------- #


def test_a_fresh_heartbeat_after_staleness_does_not_resume():
    arm, chain = _SimArm(), AuditChain()
    app, monitor, clock = _app(arm, chain)
    with TestClient(app) as client:
        _trip(app, clock)
        for _ in range(5):
            assert _heartbeat(client).status_code == 200
        app.state.safety_tick()
        response = _invoke(client, "arm.move_to")
    assert monitor.state is GatewayState.SAFE_STOP
    assert response.status_code == 403
    assert response.json()["detail"]["deny"] == "safety_state"
    [entry] = _refusals_at_the_safety_state(chain)
    assert entry.decision == "deny"
    assert arm.position == 0


def test_resume_needs_the_commission_tier():
    arm = _SimArm()
    app, monitor, clock = _app(arm)
    with TestClient(app) as client:
        _trip(app, clock)
        assert _stopped(app)
        _heartbeat(client)
        refused = _clear(client, token="actuate-token")
        assert refused.status_code == 403
        assert refused.json()["detail"]["deny"] == "safety_clear"
        assert monitor.state is GatewayState.SAFE_STOP
        cleared = _clear(client, token="commission-token")
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["state"] == "ready"


def test_resume_is_refused_while_the_heartbeat_is_stale():
    chain = AuditChain()
    arm = _SimArm()
    app, monitor, clock = _app(arm, chain)
    with TestClient(app) as client:
        _trip(app, clock)
        assert _stopped(app)
        response = _clear(client)
    assert response.status_code == 403
    assert "heartbeat" in response.json()["detail"]["reason"]
    assert monitor.state is GatewayState.SAFE_STOP
    [entry] = [e for e in chain.entries if e.decision_reason.startswith("safety.clear")]
    assert (entry.decision, entry.tier) == ("deny", "commission")


def test_the_whole_resume_is_explicit_at_both_layers_and_then_motion_runs():
    """The gateway's clear does not touch the actuator's own latch: the arm
    refuses until arm.estop.clear at commission tier. Two explicit steps."""
    arm = _SimArm(steps=3)
    app, _monitor, clock = _app(arm)
    with TestClient(app) as client:
        _trip(app, clock)
        assert _stopped(app)
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
    app, _monitor, clock = _app(arm)
    with TestClient(app) as client:
        _trip(app, clock)
        assert _stopped(app)
        _heartbeat(client)
        assert _clear(client).status_code == 200
        _trip(app, clock)                      # silence again
        assert _stopped(app, 2)
    assert len(arm.stops) == 2


# --------------------------------------------------------------------------- #
# The heartbeat route, and the honest edges
# --------------------------------------------------------------------------- #


def test_the_heartbeat_takes_only_the_supervisor_credential():
    """Not a read token, not the agent's actuate token, not the commission
    token: a credential that can move the robot, or that the agent may hold,
    must never be what keeps the robot movable."""
    app, monitor, clock = _app(_SimArm())
    with TestClient(app) as client:
        assert client.post("/v1/safety/heartbeat").status_code == 401
        assert _heartbeat(client, token="nobody").status_code == 403
        for token in ("read-token", "actuate-token", "commission-token"):
            refused = _heartbeat(client, token=token)
            assert refused.status_code == 403, token
            assert refused.json()["detail"]["deny"] == "not_a_supervisor"
        clock.advance(1.0)
        response = _heartbeat(client)
    assert response.status_code == 200
    assert response.json() == {"state": "ready", "heartbeat_staleness_s": STALE_S}
    assert monitor.last_heartbeat_at == clock()


def test_heartbeats_keep_the_gateway_ready():
    arm = _SimArm(steps=3)
    app, monitor, clock = _app(arm)
    with TestClient(app) as client:
        for _ in range(10):                    # 10 x 2 s = 20 s of fake time, 2 s apart
            clock.advance(2.0)
            assert _heartbeat(client).status_code == 200
            app.state.safety_tick()
        assert monitor.state is GatewayState.READY
        assert _invoke(client, "arm.move_to").status_code == 200
    assert arm.stops == []


def test_a_stop_that_raises_is_recorded_and_the_watchdog_lives_on():
    class _Broken(_SimArm):
        def execute(self, *, envelope, manifest_path, tier, config):
            if envelope["tool_name"] == "arm.estop":
                self.stops.append({"msg_id": envelope["msg_id"]})
                raise OSError("bus down")
            return super().execute(envelope=envelope, manifest_path=manifest_path,
                                   tier=tier, config=config)

    arm, chain = _Broken(), AuditChain()
    app, _monitor, clock = _app(arm, chain)
    with TestClient(app) as client:
        _trip(app, clock)
        assert _wait_for(lambda: _reasons(chain, "safety_stop:"))
        _heartbeat(client)
        assert _clear(client).status_code == 200      # an answer, even a failure, settles it
        clock.advance(STALE_S + 1.0)                   # only the watchdog ticks now
        assert _wait_for(lambda: len(arm.stops) == 2)
    entry = next(e for e in chain.entries if e.decision_reason.startswith("safety_stop:"))
    assert entry.actuator_outcome_kind == "error"
    assert entry.actuator_error_kind == "OSError"
    assert "it did not succeed: OSError: bus down" in entry.decision_reason


def test_the_watchdog_stops_with_the_app():
    app, _monitor, _clock = _app(_SimArm())
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
    app = make_app(resolver=_Resolver(), bearer_tiers=BEARERS, bearers=SUPERVISOR)
    response = TestClient(app).post(route, headers={"Authorization": "Bearer supervisor-token"})
    assert response.status_code == 404
