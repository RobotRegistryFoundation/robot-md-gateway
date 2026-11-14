"""The safety watchdog tells systemd it is ticking (the second review of #35, R2-18).

A gateway whose watchdog thread has died enforces nothing until a request or a
heartbeat arrives and finds it stuck. With the supervisor gone and no traffic,
nothing ever does. Under the unit (`Type=notify`, `WatchdogSec=`), the watchdog
now sends READY=1 after its first tick and WATCHDOG=1 while it keeps ticking;
when the pings stop, systemd stops the gateway and starts it again, held.

These tests run the real app, served by TestClient with its lifespan, against
a real datagram socket standing in for systemd's.
"""

from __future__ import annotations

import contextlib
import os
import socket
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from robot_md_gateway import sd_notify
from robot_md_gateway.cert.safety import SafetyMonitor

from .cert.test_safe_stop_holds_the_machine import STALE_S, FakeClock, _app, _SimArm, _wait_for
from .test_systemd_bearers import _directive

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def systemd_socket(tmp_path, monkeypatch):
    """A datagram socket where systemd's would be; NOTIFY_SOCKET names it."""
    path = tmp_path / "notify"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(str(path))
    sock.settimeout(0.05)
    monkeypatch.setenv("NOTIFY_SOCKET", str(path))
    monkeypatch.delenv("WATCHDOG_PID", raising=False)
    try:
        yield sock
    finally:
        sock.close()


def _received(sock, seconds: float) -> list[str]:
    messages, deadline = [], time.monotonic() + seconds
    while time.monotonic() < deadline:
        with contextlib.suppress(TimeoutError):       # socket.timeout, from 3.10
            messages.append(sock.recv(256).decode())
    return messages


def _fill():
    """Fill the socket's queue, as a PID 1 that has stopped reading it would
    leave it (net.unix.max_dgram_qlen, 10 by default)."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
        sender.setblocking(False)
        sender.connect(os.environ["NOTIFY_SOCKET"])
        with contextlib.suppress(BlockingIOError):
            for _ in range(100_000):
                sender.send(b"X=1")


# --- the protocol ------------------------------------------------------------


def test_notify_sends_one_datagram_to_the_named_socket(systemd_socket):
    assert sd_notify.notify("READY=1") is True
    assert systemd_socket.recv(256) == b"READY=1"


def test_notify_reaches_an_abstract_socket(monkeypatch):
    name = f"robot-md-gateway-test-{os.getpid()}-{time.monotonic_ns()}"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind("\0" + name)
    try:
        monkeypatch.setenv("NOTIFY_SOCKET", "@" + name)
        assert sd_notify.notify("WATCHDOG=1") is True
        assert sock.recv(256) == b"WATCHDOG=1"
    finally:
        sock.close()


def test_outside_systemd_notify_does_nothing(monkeypatch):
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    assert sd_notify.notify("READY=1") is False
    assert sd_notify.watchdog_interval_s() is None


def test_a_socket_that_refuses_is_reported_not_raised(tmp_path, monkeypatch):
    monkeypatch.setenv("NOTIFY_SOCKET", str(tmp_path / "nobody-listens"))
    assert sd_notify.notify("WATCHDOG=1") is False


def test_notify_never_waits_for_a_systemd_that_has_stopped_reading(systemd_socket):
    """The fifth review's N1 (R5-37-03): the send blocked on a full queue, and
    the safety watchdog's thread, which sends, waited with it."""
    _fill()
    sent: list[bool] = []
    sender = threading.Thread(target=lambda: sent.append(sd_notify.notify("WATCHDOG=1")),
                              daemon=True)
    sender.start()
    sender.join(2)
    assert sent == [False]


@pytest.mark.parametrize("env, expected", [
    ({"NOTIFY_SOCKET": "/run/x", "WATCHDOG_USEC": "5000000"}, 5.0),
    ({"NOTIFY_SOCKET": "/run/x", "WATCHDOG_USEC": "5000000", "WATCHDOG_PID": "{pid}"}, 5.0),
    ({"NOTIFY_SOCKET": "/run/x", "WATCHDOG_USEC": "5000000", "WATCHDOG_PID": "1"}, None),
    ({"NOTIFY_SOCKET": "/run/x", "WATCHDOG_USEC": "five"}, None),
    ({"NOTIFY_SOCKET": "/run/x", "WATCHDOG_USEC": "0"}, None),
    ({"WATCHDOG_USEC": "5000000"}, None),
])
def test_the_watchdog_interval_is_systemds_and_this_process_s(env, expected):
    env = {k: v.format(pid=os.getpid()) for k, v in env.items()}
    assert sd_notify.watchdog_interval_s(env) == expected


# --- the gateway's watchdog --------------------------------------------------


def test_a_served_gateway_is_ready_after_its_first_tick_then_pings(systemd_socket, monkeypatch):
    monkeypatch.setenv("WATCHDOG_USEC", "400000")        # a ping every 0.1 s at most
    app, _monitor, _clock = _app(_SimArm())
    with TestClient(app):
        messages = _received(systemd_socket, 1.0)
    assert messages[0] == "READY=1"
    assert messages.count("READY=1") == 1
    assert messages.count("WATCHDOG=1") >= 4


def test_without_watchdog_sec_it_only_says_ready(systemd_socket, monkeypatch):
    monkeypatch.delenv("WATCHDOG_USEC", raising=False)
    app, _monitor, _clock = _app(_SimArm())
    with TestClient(app):
        messages = _received(systemd_socket, 0.5)
    assert messages == ["READY=1"]


def test_ready_goes_once_there_is_room_and_only_once(systemd_socket, monkeypatch):
    """A READY=1 that could not go is sent again on the next tick: lost, the
    unit's start would time out."""
    monkeypatch.delenv("WATCHDOG_USEC", raising=False)
    _fill()
    app, _monitor, _clock = _app(_SimArm())
    with TestClient(app):
        time.sleep(0.5)                                   # ticks whose READY=1 cannot go
        everything = _received(systemd_socket, 1.0)       # the filler, then room
    assert everything.count("READY=1") == 1
    assert everything[-1] == "READY=1" and set(everything[:-1]) == {"X=1"}


def test_a_systemd_that_stops_reading_does_not_stall_the_safety_tick(systemd_socket,
                                                                       monkeypatch):
    """R5-37-03: PID 1 stops reading, its queue fills, then the supervisor
    goes and no request arrives. The watchdog still trips and stops the arm.
    With a blocking send it was stuck inside a ping, and nothing tripped."""
    monkeypatch.setenv("WATCHDOG_USEC", "400000")         # a ping every 0.1 s
    arm = _SimArm()
    app, _monitor, clock = _app(arm)
    with TestClient(app):
        assert "READY=1" in _received(systemd_socket, 0.3)
        _fill()                                           # it stops reading
        time.sleep(0.3)                                   # pings that cannot go
        clock.advance(STALE_S + 1)                        # the supervisor has gone
        stopped = _wait_for(lambda: arm.stops, 3)
    assert stopped


def test_a_watchdog_whose_ticks_fail_stops_pinging(systemd_socket, monkeypatch):
    """A tick that raises is not a tick that ran: no ping for it. If every tick
    fails, systemd hears nothing and restarts the gateway."""

    class _Breaks(SafetyMonitor):
        broken = False

        def tick(self, *, now=None):
            if self.broken:
                raise RuntimeError("the monitor cannot be read")
            return super().tick(now=now)

    monkeypatch.setenv("WATCHDOG_USEC", "400000")
    clock = FakeClock()
    monitor = _Breaks(heartbeat_staleness_s=STALE_S, last_heartbeat_at=clock())
    app, _monitor, _clock = _app(_SimArm(), clock=clock, monitor=monitor)
    with TestClient(app):
        before = _received(systemd_socket, 0.5)
        monitor.broken = True
        _received(systemd_socket, 0.2)                    # a ping already on its way
        after = _received(systemd_socket, 0.6)
    assert "WATCHDOG=1" in before
    assert after == []


def test_a_gateway_with_no_watchdog_running_sends_nothing(systemd_socket, monkeypatch):
    """Built but not served (no lifespan), the app runs no watchdog and must
    not tell systemd it is ready."""
    monkeypatch.setenv("WATCHDOG_USEC", "400000")
    _app(_SimArm())
    assert _received(systemd_socket, 0.3) == []


# --- the unit ----------------------------------------------------------------


def test_the_unit_waits_for_the_watchdog_and_restarts_without_it():
    assert _directive("Type") == ["notify"]
    assert _directive("NotifyAccess") == ["main"]
    [watchdog_sec] = _directive("WatchdogSec")
    assert watchdog_sec.endswith("s") and 1 < float(watchdog_sec[:-1]) <= 10
    assert _directive("Restart") == ["on-failure"]        # a watchdog kill is a failure
