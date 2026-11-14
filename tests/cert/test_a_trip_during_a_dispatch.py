"""A trip while a request is being dispatched (blocking 1 of the second review).

The review's reproduction: a motion admitted in READY wrote its intent record
(slow with the attestation export on: a lock and an fsync), a trip happened in
that time, the trip's stop reached the actuator, and then the motion did. An
actuator whose stop does not latch (castor-hal's `Transport.estop` is a
best-effort stop or hold) kept the motion's goal, and nothing stopped it again.

Now:
- the gateway checks its state once more after the intent record, as the last
  statement before the actuator is called; a trip by then is a signed refusal
  whose record carries the intent's chain hash;
- a trip that begins after that check, while the actuator runs, is answered
  with that actuator's stop again once it returns, so the last word the
  actuator hears is a stop. A clear waits for that stop as for the trip's own.
The trip's own stop never waits for the motion: it runs on its own thread.
"""

from __future__ import annotations

import threading
import time

import pytest
from fastapi.testclient import TestClient

from robot_md_gateway.actuator import ActuatorOutcome
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.cert.safety import GatewayState

from .test_safe_stop_holds_the_machine import (
    STALE_S,
    _app,
    _clear,
    _heartbeat,
    _invoke,
    _reasons,
    _SimArm,
    _stopped,
    _wait_for,
)

DRIVE_TOOLS = ToolAllowlist(allowed_tools=("drive.go", "drive.stop"))


class Drive:
    """Holds the last goal it was given; its stop does not latch. A goal is set
    when `execute` returns, as a goal-setting transport sets it, and `hold`
    keeps `execute` from returning until the test says so."""

    name, description, config_schema = "drive", "drive", {}
    motion_capabilities = frozenset({"drive.go"})
    stop_capabilities = frozenset({"drive.stop"})

    def __init__(self):
        self.log: list[str] = []
        self.goal = "stopped"
        self.inside = threading.Event()
        self.hold: threading.Event | None = None
        self.stop_hold: threading.Event | None = None
        self.stop_held = threading.Event()

    def execute(self, *, envelope, manifest_path, tier, config):
        tool = envelope["tool_name"]
        if tool == "drive.go":
            self.inside.set()
            if self.hold is not None:
                self.hold.wait(10)
            self.goal = "going"
        else:
            if self.stop_hold is not None and self.log[-1:] == ["drive.go"]:
                self.stop_held.set()             # only the stop that follows the goal
                self.stop_hold.wait(10)
            self.goal = "stopped"
        self.log.append(tool)
        return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})


class SlowIntent(AuditChain):
    """The intent record takes a while, as with the attestation export on."""

    def __init__(self):
        super().__init__()
        self.inside, self.go = threading.Event(), threading.Event()

    def append(self, entry):
        if entry.entry_kind == "intent" and entry.tool_name == "drive.go":
            self.inside.set()
            self.go.wait(5)
        return super().append(entry)


def test_a_trip_during_the_intent_record_refuses_the_motion_with_the_intents_hash():
    """The review's reproduction, which now fails: the motion never reaches the
    actuator."""
    drive, chain = Drive(), SlowIntent()
    app, monitor, clock = _app(drive, chain, tool_allowlist=DRIVE_TOOLS)
    box: dict = {}
    with TestClient(app) as client:
        _heartbeat(client)
        _clear(client)
        mover = threading.Thread(target=lambda: box.update(r=_invoke(client, "drive.go")))
        mover.start()
        assert chain.inside.wait(5)                  # past every earlier state check
        clock.advance(STALE_S + 1)
        app.state.safety_tick()                      # the trip: drive.stop is sent
        assert _wait_for(lambda: "drive.stop" in drive.log)
        chain.go.set()
        mover.join(5)
    assert monitor.state is GatewayState.SAFE_STOP
    assert drive.log == ["drive.stop"]               # the motion never arrived
    assert drive.goal == "stopped"
    assert box["r"].status_code == 403
    detail = box["r"].json()["detail"]
    assert detail["deny"] == "safety_state"
    assert detail["reason"] == ("gateway state=safe_stop (it changed while this request was "
                                "being dispatched)")
    [intent] = [e for e in chain.entries if e.entry_kind == "intent"]
    [refusal] = [e for e in chain.entries if e.entry_kind == "outcome"
                 and e.decision_reason.startswith("safety_state:")]
    assert refusal.decision == "deny"
    assert refusal.intent_chain_hash == intent.chain_hash


def test_a_trip_while_the_actuator_runs_is_followed_by_its_stop_again():
    """The trip's stop reaches the drive while the motion is still being
    dispatched, and the goal is set after it. The gateway sends the stop again
    when the motion returns."""
    drive = Drive()
    drive.hold = threading.Event()
    app, monitor, clock = _app(drive, AuditChain(), tool_allowlist=DRIVE_TOOLS)
    box: dict = {}
    with TestClient(app) as client:
        _heartbeat(client)
        _clear(client)
        mover = threading.Thread(target=lambda: box.update(r=_invoke(client, "drive.go")))
        mover.start()
        assert drive.inside.wait(5)                  # inside execute, past the last check
        clock.advance(STALE_S + 1)
        app.state.safety_tick()
        # The trip's stop does not wait for the motion, and it has answered
        # (and been recorded) before the motion returns.
        assert _stopped(app)
        assert drive.log == ["drive.stop"]
        drive.hold.set()
        mover.join(5)
    assert monitor.state is GatewayState.SAFE_STOP
    assert drive.log == ["drive.stop", "drive.go", "drive.stop"]
    assert drive.goal == "stopped"
    assert box["r"].status_code == 200               # the drive did set the goal
    assert box["r"].json()["stopped_again"] == (
        "the gateway tripped (trip 1) while drive.go was being dispatched, and its stop to "
        "drive answered first, so drive.stop was sent to drive again after it returned")
    chain = app.state.audit_chain
    again = [e for e in chain.entries if e.decision_reason.startswith("safety_stop:")
             and " again, because drive.go (" in e.decision_reason]
    assert len(again) == 1 and again[0].decision == "allow"
    [outcome] = [e for e in chain.entries if e.entry_kind == "outcome"
                 and e.decision_reason.startswith("ok; the gateway tripped")]
    assert outcome.decision == "allow"


def test_a_clear_waits_for_the_stop_sent_again():
    drive = Drive()
    drive.hold, drive.stop_hold = threading.Event(), threading.Event()
    app, monitor, clock = _app(drive, AuditChain(), tool_allowlist=DRIVE_TOOLS)
    box: dict = {}
    with TestClient(app) as client:
        _heartbeat(client)
        _clear(client)
        mover = threading.Thread(target=lambda: box.update(r=_invoke(client, "drive.go")))
        mover.start()
        assert drive.inside.wait(5)
        clock.advance(STALE_S + 1)
        app.state.safety_tick()
        assert _stopped(app)                         # the trip's own stop has answered
        drive.hold.set()                             # the goal is set; its stop then hangs
        assert drive.stop_held.wait(5)
        _heartbeat(client)
        waiting = _clear(client)
        drive.stop_hold.set()
        mover.join(5)
        _heartbeat(client)
        cleared = _clear(client)
    assert waiting.status_code == 409
    assert "drive.stop to drive" in waiting.json()["detail"]["reason"]
    assert cleared.status_code == 200, cleared.text
    assert monitor.state is GatewayState.READY
    assert drive.log == ["drive.stop", "drive.go", "drive.stop"]


def test_the_stop_is_sent_again_even_after_the_trip_was_cleared():
    """The clear was for the trip, not for a motion admitted before it."""
    drive = Drive()
    drive.hold = threading.Event()
    app, monitor, clock = _app(drive, AuditChain(), tool_allowlist=DRIVE_TOOLS)
    box: dict = {}
    with TestClient(app) as client:
        _heartbeat(client)
        _clear(client)
        mover = threading.Thread(target=lambda: box.update(r=_invoke(client, "drive.go")))
        mover.start()
        assert drive.inside.wait(5)
        clock.advance(STALE_S + 1)
        app.state.safety_tick()
        assert _stopped(app)                         # the trip's own stop has answered
        _heartbeat(client)
        assert _clear(client).status_code == 200
        drive.hold.set()
        mover.join(5)
    assert monitor.state is GatewayState.READY
    assert drive.log == ["drive.stop", "drive.go", "drive.stop"]
    assert drive.goal == "stopped"
    assert "drive.stop was sent to drive again" in box["r"].json()["stopped_again"]


def test_an_arm_clear_admitted_before_a_trip_gets_no_second_stop():
    """The second review's R2-12: an `arm.estop.clear` admitted before the
    trip reaches the arm after the trip's stop latched it, and unlatches it.
    Round 2 sent the stop again after any dispatch; from round 3 only a motion
    gets a second stop (note N1), so the arm is left unlatched. Nothing moves:
    the gateway itself is held and refuses every motion until a commission
    clear, after which the arm's own clear is not needed again."""

    class _ClearArm(_SimArm):
        def __init__(self):
            super().__init__()
            self.clearing, self.hold = threading.Event(), threading.Event()

        def execute(self, *, envelope, manifest_path, tier, config):
            if envelope["tool_name"] == "arm.estop.clear":
                self.clearing.set()
                self.hold.wait(10)
            return super().execute(envelope=envelope, manifest_path=manifest_path,
                                   tier=tier, config=config)

    arm = _ClearArm()
    app, monitor, clock = _app(arm, AuditChain())
    box: dict = {}
    with TestClient(app) as client:
        _heartbeat(client)
        _clear(client)
        clearer = threading.Thread(target=lambda: box.update(
            r=_invoke(client, "arm.estop.clear", scope="COMMISSION", token="commission-token")))
        clearer.start()
        assert arm.clearing.wait(5)
        clock.advance(STALE_S + 1)
        app.state.safety_tick()
        assert _stopped(app)
        arm.hold.set()
        clearer.join(5)
        moved = _invoke(client, "arm.move_to")
    assert monitor.state is GatewayState.SAFE_STOP
    assert box["r"].status_code == 200 and "stopped_again" not in box["r"].json()
    assert len(arm.stops) == 1
    assert not arm.latched                       # the race R2-12 found, left as decided
    assert moved.status_code == 403 and moved.json()["detail"]["deny"] == "safety_state"
    assert arm.position == 0


def test_a_dispatch_with_no_trip_sends_no_extra_stop():
    drive = Drive()
    app, _monitor, _clock = _app(drive, AuditChain(), tool_allowlist=DRIVE_TOOLS)
    with TestClient(app) as client:
        _heartbeat(client)
        _clear(client)
        response = _invoke(client, "drive.go")
    assert response.status_code == 200
    assert "stopped_again" not in response.json()
    assert drive.log == ["drive.go"]


# --------------------------------------------------------------------------- #
# Note N1 of the third review: a stop sent again must not queue behind the
# trip's own stop, and a read gets none
# --------------------------------------------------------------------------- #


class BusArm:
    """Behaves as so-arm101-actuator does on its servo bus. One bus lock: a
    paced move holds it for its whole stream and checks the latch before every
    setpoint, and a read holds it while it reads. A stop latches at once, then
    waits for the bus to write its hold. While that stop waits, any other
    request that has not got the bus is refused as busy, a stop repeated while
    latched included, since only the stop that latched goes first."""

    name, description, config_schema = "arm", "an arm on a servo bus", {}
    motion_capabilities = frozenset({"arm.move_to"})
    stop_capabilities = frozenset({"arm.estop"})
    STEP_S, READ_S, HOLD_S = 0.01, 0.03, 0.02

    def __init__(self, steps=500):
        self.steps = steps
        self.bus = threading.Lock()
        self.latched = False
        self.stops_waiting = 0
        self.holds = 0
        self.position = 0
        self.busy: list[str] = []
        self.moving, self.reading = threading.Event(), threading.Event()
        self._count = threading.Lock()

    def _busy(self, tool):
        self.busy.append(tool)
        return ActuatorOutcome(success=False, outcome_kind="error",
                               error_message="busy: a stop is waiting for the bus")

    def execute(self, *, envelope, manifest_path, tier, config):
        tool = envelope["tool_name"]
        if tool == "arm.estop":
            with self._count:
                first = not self.latched
                self.latched = True                  # latch first, outside the bus
                if not first and self.stops_waiting:
                    return self._busy(tool)
                if first:
                    self.stops_waiting += 1
            try:
                self.bus.acquire()
            finally:
                if first:
                    with self._count:
                        self.stops_waiting -= 1
            try:
                time.sleep(self.HOLD_S)              # the hold, one write per joint
                self.holds += 1
            finally:
                self.bus.release()
            return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})
        if self.stops_waiting:
            return self._busy(tool)
        if tool == "arm.estop.clear":
            if tier != "commission":
                return ActuatorOutcome(success=False, outcome_kind="denied",
                                       error_message="needs the commission tier")
            with self.bus:
                self.latched = False
            return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})
        if tool == "arm.state":
            with self.bus:
                self.reading.set()
                time.sleep(self.READ_S)
            return ActuatorOutcome(success=True, outcome_kind="executed",
                                   telemetry={"position": self.position})
        if self.latched:
            return ActuatorOutcome(success=False, outcome_kind="denied",
                                   error_message="estop_latched")
        with self.bus:
            self.moving.set()
            done = 0
            while done < self.steps and not self.latched:
                self.position += 1
                done += 1
                time.sleep(self.STEP_S)
        self.moving.clear()
        return ActuatorOutcome(success=True, outcome_kind="executed",
                               telemetry={"stopped_by_estop": done < self.steps})


BUS_TOOLS = ToolAllowlist(allowed_tools=("arm.move_to", "arm.state", "arm.estop",
                                         "arm.estop.clear"))


def _resume_and_move(client, arm):
    """The documented resume after a trip: heartbeats, the gateway's clear,
    the arm's own clear, then a short move."""
    _heartbeat(client)
    cleared = _clear(client)
    unlatched = _invoke(client, "arm.estop.clear", scope="COMMISSION", token="commission-token")
    arm.steps = 3
    return cleared, unlatched, _invoke(client, "arm.move_to")


@pytest.mark.parametrize("in_flight, scope, started", [
    ("arm.move_to", "MANIPULATE", "moving"),
    ("arm.state", "OBSERVE", "reading"),
])
def test_a_trip_during_a_move_or_a_read_on_a_bus_arm_sends_one_stop(in_flight, scope, started):
    """The third review's R3-10 (a paced move) and R3-12 (a read) on
    so-arm101-actuator. The trip's stop latched and waited for the bus; the
    request returned while it waited; the gateway sent the stop again at once,
    the driver refused it as busy, departure (e) counted that as a failed stop,
    and every move after the documented resume was 403 `stop_unreachable`.

    Now the move returns before the trip's own stop has answered, so that stop
    lands after it and nothing is sent again; and a read never gets a second
    stop. One stop, and the resume works."""
    arm, chain = BusArm(), AuditChain()
    app, _monitor, clock = _app(arm, chain, tool_allowlist=BUS_TOOLS)
    box: dict = {}
    with TestClient(app) as client:
        _heartbeat(client)
        _clear(client)
        request = threading.Thread(target=lambda: box.update(
            r=_invoke(client, in_flight, scope=scope)))
        request.start()
        assert getattr(arm, started).wait(5)
        clock.advance(STALE_S + 1)
        app.state.safety_tick()
        request.join(10)
        assert _stopped(app)
        cleared, unlatched, moved = _resume_and_move(client, arm)
    assert box["r"].status_code == 200 and "stopped_again" not in box["r"].json()
    stops = _reasons(chain, "safety_stop:")
    assert len(stops) == 1 and "did not succeed" not in stops[0]
    assert arm.holds == 1 and arm.busy == []
    assert (cleared.status_code, unlatched.status_code) == (200, 200)
    assert moved.status_code == 200, moved.text


def test_a_stop_sent_again_that_fails_is_not_held_against_the_actuator():
    """The trip's own stop answered first, so the drive gets its stop again
    after the motion; that second stop fails. The failure is recorded, and
    motion through the drive is not refused for it: the trip's own stop
    worked."""

    class _SecondStopFails(Drive):
        def execute(self, *, envelope, manifest_path, tier, config):
            if envelope["tool_name"] == "drive.stop" and "drive.go" in self.log:
                self.log.append("drive.stop")
                return ActuatorOutcome(success=False, outcome_kind="error",
                                       error_message="IO_ERROR")
            return super().execute(envelope=envelope, manifest_path=manifest_path,
                                   tier=tier, config=config)

    drive, chain = _SecondStopFails(), AuditChain()
    drive.hold = threading.Event()
    app, _monitor, clock = _app(drive, chain, tool_allowlist=DRIVE_TOOLS)
    box: dict = {}
    with TestClient(app) as client:
        _heartbeat(client)
        _clear(client)
        mover = threading.Thread(target=lambda: box.update(r=_invoke(client, "drive.go")))
        mover.start()
        assert drive.inside.wait(5)
        clock.advance(STALE_S + 1)
        app.state.safety_tick()
        assert _stopped(app)
        drive.hold.set()
        mover.join(5)
        _heartbeat(client)
        assert _clear(client).status_code == 200
        drive.hold = None
        moved = _invoke(client, "drive.go")
    assert box["r"].json()["stopped_again"].endswith("sent to drive again after it returned")
    [again] = [r for r in _reasons(chain, "safety_stop:") if " again, because " in r]
    assert again.endswith("it did not succeed: IO_ERROR; a stop sent again is not held "
                          "against the actuator, whose own trip stop answered")
    assert moved.status_code == 200, moved.text
