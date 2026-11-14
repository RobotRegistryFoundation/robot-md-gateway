"""Stops at start, and the clean shutdown that skips them (#37, the fifth
review's blocking item, R5-37-01).

Booting held is not a trip: it sends no stop. After a watchdog kill, a crash
or any end but the normal exit path, hardware that keeps its last goal can
still be moving. So `serve` sends every declared stop as the app is built
(`make_app(stops_at_start=...)`) unless the previous process left a
clean-shutdown marker, which it leaves only when its shutdown found nothing
that could still be moving (`app.state.clean_shutdown is None`).

Decided for Craig, failing toward stops:
- a stop at start that fails or does not answer leaves its actuator refused
  (`stop_unconfirmed`) until a stop to it succeeds;
- the first commission clear sends it again and is refused with 409; a clear
  once it has answered arms the gateway. An actuator whose stop still did not
  succeed stays refused, so a stop that keeps failing cannot hold the gateway
  held forever.

The serve path, the marker and a real restart are in
tests/test_a_restart_sends_the_stops.py.
"""

from __future__ import annotations

import threading
import time
from typing import ClassVar

from fastapi.testclient import TestClient

import robot_md_gateway.receiver as receiver_mod
from robot_md_gateway.actuator import ActuatorOutcome
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.cert.safety import GatewayState, SafetyMonitor

from .test_safe_stop_holds_the_machine import (
    STALE_S,
    FakeClock,
    _app,
    _clear,
    _heartbeat,
    _invoke,
    _reasons,
    _trip,
    _wait_for,
)

BASE_TOOLS = ToolAllowlist(allowed_tools=("base.go", "base.stop"))
WHY = "the previous process left no clean-shutdown marker in /var/lib/test"


class _Base:
    """Keeps its last velocity. Each stop answers as `stops` says, in order,
    then "ok": "ok", "fail" (an error outcome), or "hang" (until `release`)."""

    name, description, config_schema = "base", "a base", {}
    motion_capabilities = frozenset({"base.go"})
    stop_capabilities = frozenset({"base.stop"})

    def __init__(self, *stops: str):
        self.stops = list(stops)
        self.heard: list[str] = []
        self.goal = "going"                     # left moving by the process before
        self.release = threading.Event()

    def execute(self, *, envelope, manifest_path, tier, config):
        tool = envelope["tool_name"]
        self.heard.append(tool)
        if tool == "base.go":
            self.goal = "going"
            return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})
        how = self.stops.pop(0) if self.stops else "ok"
        if how == "hang":
            self.release.wait(30)
        if how == "fail":
            return ActuatorOutcome(success=False, outcome_kind="error",
                                   error_message="IO_ERROR: the bus is not up yet")
        self.goal = "stopped"
        return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})


def _held_app(base, **extra):
    """As `serve` builds it: held, with no heartbeat yet."""
    clock = FakeClock()
    monitor = SafetyMonitor(state=GatewayState.SAFE_STOP, last_heartbeat_at=float("-inf"),
                            heartbeat_staleness_s=STALE_S)
    chain = AuditChain()
    app, _monitor, _clock = _app(base, chain, clock=clock, monitor=monitor,
                                 tool_allowlist=BASE_TOOLS, **extra)
    return app, monitor, clock, chain


def _stop_records(chain):
    return _reasons(chain, "safety_stop:")


# --------------------------------------------------------------------------- #
# The stops go out at start
# --------------------------------------------------------------------------- #


def test_every_declared_stop_goes_out_at_start_with_no_request():
    """R5-37-01 in the app's own terms: built, not yet served, nobody asking."""
    base = _Base()
    _built, _monitor, _clock, chain = _held_app(base, stops_at_start=WHY)
    assert _wait_for(lambda: len(_stop_records(chain)) == 1)
    assert base.heard == ["base.stop"] and base.goal == "stopped"
    [start] = _reasons(chain, "safety_start:")
    assert start == f"safety_start: {WHY}; sending base.stop to base"
    [stop] = _stop_records(chain)
    assert stop == f"safety_stop: the stops sent at start ({WHY}); sent base.stop to base"


def test_without_a_reason_nothing_is_sent_at_start():
    """A clean shutdown before (or a test, or an embedder): no stop."""
    base = _Base()
    app, _monitor, _clock, chain = _held_app(base)
    with TestClient(app) as client:
        _heartbeat(client)
        cleared = _clear(client)
    assert cleared.status_code == 200, cleared.text
    assert base.heard == [] and base.goal == "going"
    assert _reasons(chain, "safety_start:") == []


def test_the_clear_waits_for_the_stops_sent_at_start():
    base = _Base("hang")
    app, monitor, _clock, chain = _held_app(base, stops_at_start=WHY)
    try:
        with TestClient(app) as client:
            _heartbeat(client)
            waiting = _clear(client)
            base.release.set()
            assert _wait_for(lambda: len(_stop_records(chain)) == 1)
            _heartbeat(client)
            cleared = _clear(client)
    finally:
        base.release.set()
    assert waiting.status_code == 409
    assert waiting.json()["detail"]["reason"] == (
        "safety.clear: refused, the stops sent at start are still being sent (base.stop to "
        "base); retry once they have answered")
    assert cleared.status_code == 200, cleared.text
    assert monitor.state is GatewayState.READY


def test_motion_waits_for_the_stop_at_start_even_on_an_app_built_ready():
    """An embedder's app, built READY: no motion through the base until its
    stop at start has succeeded."""
    base = _Base("hang")
    chain = AuditChain()
    app, _monitor, _clock = _app(base, chain, tool_allowlist=BASE_TOOLS, stops_at_start=WHY)
    try:
        with TestClient(app) as client:
            _heartbeat(client)
            early = _invoke(client, "base.go")
            base.release.set()
            assert _wait_for(lambda: len(_stop_records(chain)) == 1)
            later = _invoke(client, "base.go")
    finally:
        base.release.set()
    assert early.status_code == 403
    assert early.json()["detail"]["deny"] == "stop_unconfirmed"
    assert early.json()["detail"]["reason"].startswith(
        "actuator 'base' has not confirmed a stop since the gateway started: its stop at "
        "start (base.stop) has not answered yet")
    assert later.status_code == 200, later.text


# --------------------------------------------------------------------------- #
# A stop at start that fails or does not answer fails closed
# --------------------------------------------------------------------------- #


def test_a_stop_at_start_that_fails_is_sent_again_by_the_clear_before_it_arms():
    base = _Base("fail")                         # the clear's resend succeeds
    app, monitor, _clock, chain = _held_app(base, stops_at_start=WHY)
    with TestClient(app) as client:
        assert _wait_for(lambda: len(_stop_records(chain)) == 1)
        _heartbeat(client)
        first = _clear(client)
        assert _wait_for(lambda: len(_stop_records(chain)) == 2)
        _heartbeat(client)
        second = _clear(client)
        moved = _invoke(client, "base.go")
    assert first.status_code == 409
    assert first.json()["detail"]["reason"] == (
        "safety.clear: refused for now, a stop sent at start has not succeeded: base.stop to "
        "base sent again; clear again once they have answered. An actuator whose stop still "
        "does not succeed stays refused until one does")
    failed, again = _stop_records(chain)
    assert failed.endswith("it did not succeed: IO_ERROR: the bus is not up yet; motion "
                           "through it is refused until a stop to it succeeds")
    assert again.startswith("safety_stop: the stops the last clear sent again (a clear by ")
    assert "found actuator 'base' has not confirmed a stop since the gateway started" in again
    [resend] = _reasons(chain, "safety_clear_resend:")
    assert resend.endswith("sending base.stop to base again; the gateway arms on a clear "
                           "once each has answered")
    assert second.status_code == 200, second.text
    assert monitor.state is GatewayState.READY
    assert moved.status_code == 200, moved.text
    assert base.heard == ["base.stop", "base.stop", "base.go"]


def test_a_stop_that_keeps_failing_does_not_hold_the_gateway_but_refuses_its_actuator():
    """The resend fails too. The next clear arms the gateway, and motion
    through the base is refused until a stop to it succeeds: here, an
    operator's own declared stop."""
    base = _Base("fail", "fail")
    app, monitor, _clock, chain = _held_app(base, stops_at_start=WHY)
    with TestClient(app) as client:
        assert _wait_for(lambda: len(_stop_records(chain)) == 1)
        _heartbeat(client)
        assert _clear(client).status_code == 409
        assert _wait_for(lambda: len(_stop_records(chain)) == 2)
        _heartbeat(client)
        armed = _clear(client)
        refused = _invoke(client, "base.go")
        stopped = _invoke(client, "base.stop", scope="SAFETY", token="read-token")
        moved = _invoke(client, "base.go")
    assert armed.status_code == 200, armed.text
    assert monitor.state is GatewayState.READY
    assert refused.status_code == 403
    detail = refused.json()["detail"]
    assert detail["deny"] == "stop_unconfirmed"
    assert detail["reason"] == (
        "actuator 'base' has not confirmed a stop since the gateway started: the stop a clear "
        "sent it again (base.stop) did not succeed (IO_ERROR: the bus is not up yet); motion "
        "through it is refused until a stop to it succeeds")
    assert stopped.status_code == 200, stopped.text
    assert moved.status_code == 200, moved.text
    assert base.heard == ["base.stop", "base.stop", "base.stop", "base.go"]


def test_a_stop_at_start_that_does_not_answer_is_sent_again_by_the_clear():
    base = _Base("hang")
    app, monitor, clock, chain = _held_app(base, stops_at_start=WHY)
    try:
        with TestClient(app) as client:
            clock.advance(receiver_mod.STOP_TIMEOUT_S + 0.5)
            app.state.safety_tick()              # the gateway stops waiting for it
            _heartbeat(client)
            first = _clear(client)               # sends it again; that one answers
            assert _wait_for(lambda: len(_stop_records(chain)) == 1)
            _heartbeat(client)
            second = _clear(client)
            moved = _invoke(client, "base.go")
    finally:
        base.release.set()
    [timeout] = _reasons(chain, "safety_stop_timeout:")
    assert timeout == ("safety_stop_timeout: the stops sent at start: base.stop to base did "
                       "not answer within 10 s; the gateway stopped waiting for it; motion "
                       "through it is refused until a stop to it succeeds")
    assert first.status_code == 409
    assert second.status_code == 200, second.text
    assert monitor.state is GatewayState.READY
    assert moved.status_code == 200, moved.text


def test_a_late_answer_to_the_stop_at_start_confirms_it():
    """The gateway stopped waiting for it, and then it succeeded: a stop to
    the base has succeeded, so nothing is sent again and the clear arms."""
    base = _Base("hang")
    app, monitor, clock, chain = _held_app(base, stops_at_start=WHY)
    try:
        with TestClient(app) as client:
            clock.advance(receiver_mod.STOP_TIMEOUT_S + 0.5)
            app.state.safety_tick()
            base.release.set()
            assert _wait_for(lambda: len(_stop_records(chain)) == 1)
            _heartbeat(client)
            cleared = _clear(client)
            moved = _invoke(client, "base.go")
    finally:
        base.release.set()
    [late] = _stop_records(chain)
    assert late.endswith("sent base.stop to base; it answered after the gateway stopped "
                         "waiting (10 s)")
    assert cleared.status_code == 200, cleared.text
    assert monitor.state is GatewayState.READY
    assert moved.status_code == 200, moved.text
    assert _reasons(chain, "safety_clear_resend:") == []


def test_the_resend_happens_once_per_held_spell():
    """After the gateway arms and trips again, a stop that is still
    unconfirmed is sent by the trip; if that one succeeds, nothing is left
    to resend."""
    base = _Base("fail", "fail")
    app, _monitor, clock, chain = _held_app(base, stops_at_start=WHY)
    with TestClient(app) as client:
        assert _wait_for(lambda: len(_stop_records(chain)) == 1)
        _heartbeat(client)
        _clear(client)
        assert _wait_for(lambda: len(_stop_records(chain)) == 2)
        _heartbeat(client)
        assert _clear(client).status_code == 200
        _trip(app, clock)                         # the trip's own stop succeeds
        assert _wait_for(lambda: len(_stop_records(chain)) == 3)
        _heartbeat(client)
        cleared = _clear(client)
        moved = _invoke(client, "base.go")
    assert cleared.status_code == 200, cleared.text
    assert moved.status_code == 200, moved.text
    assert len(_reasons(chain, "safety_clear_resend:")) == 1


# --------------------------------------------------------------------------- #
# What the shutdown says about the marker
# --------------------------------------------------------------------------- #


def test_a_shutdown_while_held_with_every_stop_answered_may_leave_the_marker():
    base = _Base()
    app, _monitor, _clock, chain = _held_app(base, stops_at_start=WHY)
    assert app.state.clean_shutdown == ("the gateway did not shut down through its normal "
                                        "exit path")
    with TestClient(app):
        assert _wait_for(lambda: len(_stop_records(chain)) == 1)
    assert app.state.clean_shutdown is None


def test_a_shutdown_while_armed_leaves_no_marker():
    """Something the gateway moved may still be moving, so the next start
    sends the stops."""
    base = _Base()
    app, _monitor, _clock, _chain = _held_app(base)
    with TestClient(app) as client:
        _heartbeat(client)
        assert _clear(client).status_code == 200
        _invoke(client, "base.go")
    assert app.state.clean_shutdown == ("the gateway was armed (ready) when it stopped, so "
                                        "something it moved may still be moving")


def test_a_shutdown_with_a_stop_unconfirmed_leaves_no_marker():
    base = _Base("fail")
    app, _monitor, _clock, chain = _held_app(base, stops_at_start=WHY)
    with TestClient(app):
        assert _wait_for(lambda: len(_stop_records(chain)) == 1)
    assert app.state.clean_shutdown.startswith(
        "actuator 'base' has not confirmed a stop since the gateway started")


def test_a_shutdown_with_a_trip_stop_that_failed_leaves_no_marker():
    base = _Base("ok", "fail")
    app, _monitor, clock, chain = _held_app(base, stops_at_start=WHY)
    with TestClient(app) as client:
        assert _wait_for(lambda: len(_stop_records(chain)) == 1)
        _heartbeat(client)
        assert _clear(client).status_code == 200
        _trip(app, clock)
        assert _wait_for(lambda: len(_stop_records(chain)) == 2)
    assert app.state.clean_shutdown.startswith("actuator 'base' failed the gateway's own stop")


def test_a_shutdown_waits_for_a_stop_in_flight_and_then_judges(monkeypatch):
    """`serve`'s shutdown (an `on_shutdown` hook) waits up to STOP_TIMEOUT_S
    for a stop still on its way, then judges."""
    monkeypatch.setattr(receiver_mod, "STOP_TIMEOUT_S", 0.3)
    base, told = _Base("hang"), []
    app, _monitor, _clock, _chain = _held_app(base, stops_at_start=WHY, on_shutdown=told.append)
    try:
        with TestClient(app):
            pass
    finally:
        base.release.set()
    assert told == ["the stops sent at start had not all answered"]
    assert app.state.clean_shutdown == told[0]


def test_a_stop_that_answers_while_the_shutdown_waits_lets_it_be_clean(monkeypatch):
    monkeypatch.setattr(receiver_mod, "STOP_TIMEOUT_S", 5.0)
    base, told = _Base("hang"), []
    app, _monitor, _clock, chain = _held_app(base, stops_at_start=WHY, on_shutdown=told.append)
    try:
        with TestClient(app):
            threading.Timer(0.3, base.release.set).start()
    finally:
        base.release.set()
    assert told == [None]
    assert len(_stop_records(chain)) == 1


def test_without_a_hook_the_shutdown_does_not_wait():
    """Tests and embedders pass no `on_shutdown`: nothing acts on the answer,
    so a hung stop does not hold their shutdown."""
    base = _Base("hang")
    app, _monitor, _clock, _chain = _held_app(base, stops_at_start=WHY)
    started = time.monotonic()
    try:
        with TestClient(app):
            pass
    finally:
        base.release.set()
    assert time.monotonic() - started < receiver_mod.STOP_TIMEOUT_S
    assert app.state.clean_shutdown == "the stops sent at start had not all answered"


def test_an_actuator_refused_from_startup_for_its_declared_tiers_does_not_spoil_the_marker():
    """`stop_unreachable` found at startup from a declaration is a fixed
    fact about the actuator, not a stop that failed."""

    class _ReadRefused(_Base):
        required_tiers: ClassVar[dict] = {"base.stop": ("commission",)}

    base = _ReadRefused()
    app, _monitor, _clock, _chain = _held_app(base)
    with TestClient(app):
        pass
    assert app.state.clean_shutdown is None
