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
        # The trip's stop does not wait for the motion.
        assert _wait_for(lambda: drive.log == ["drive.stop"])
        drive.hold.set()
        mover.join(5)
    assert monitor.state is GatewayState.SAFE_STOP
    assert drive.log == ["drive.stop", "drive.go", "drive.stop"]
    assert drive.goal == "stopped"
    assert box["r"].status_code == 200               # the drive did set the goal
    assert box["r"].json()["stopped_again"] == (
        "the gateway tripped (trip 1) while drive.go was being dispatched, so drive.stop "
        "was sent to drive again after it returned")
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


def test_an_arm_clear_admitted_before_a_trip_is_followed_by_the_arm_stop_again():
    """The review's R2-12: an `arm.estop.clear` admitted before the trip reached
    the arm after the trip's stop had latched it, and unlatched it while the
    gateway stayed tripped. The stop sent again latches it once more."""

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
        assert _wait_for(lambda: arm.latched and arm.stops)
        arm.hold.set()
        clearer.join(5)
    assert monitor.state is GatewayState.SAFE_STOP
    assert box["r"].status_code == 200
    assert len(arm.stops) == 2
    assert arm.latched, "the arm was left unlatched while the gateway is tripped"


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
