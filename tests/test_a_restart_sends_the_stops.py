"""R5-37-01, the fifth review's blocking item on #37, end to end.

The real `serve`, in a process of its own (tests/_served_with_a_goal_holding_base.py),
drives a base that keeps its last velocity after its host process ends. The
test plays systemd: a datagram socket where its notify socket would be, a
SIGABRT after WatchdogSec without a WATCHDOG=1, a restart, and a
StateDirectory.

1. The gateway starts after a clean shutdown, so it sends no stop. Armed,
   the base is sent `base.go`. Then the supervisor's device goes and the
   safety watchdog thread dies, so nothing trips and no ping is sent.
   systemd kills the gateway. The base is still going.
2. The restart sends `base.stop` before anything asks it to: the killed
   process left no clean-shutdown marker. Without this change it sent
   nothing, and booting held is not a trip: the base kept going until
   someone sent `base.stop`.
3. A clean SIGTERM while held leaves the marker, and the start after it
   sends no stop: a person posing an arm by hand is not surprised by it
   stiffening.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).resolve().parent
SERVED = HERE / "_served_with_a_goal_holding_base.py"
MANIFEST = HERE / "fixtures" / "manifests" / "signed-good.md"
WATCHDOG_S = 2.0

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="SO_PASSCRED is Linux's")


class _Systemd:
    """Where systemd's notify socket would be: each message, when, and from
    which pid (SO_PASSCRED, as systemd reads it for NotifyAccess=main)."""

    def __init__(self, path: Path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(str(path))
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.sock.settimeout(0.05)
        self.address = str(path)
        self.messages: list[tuple[float, str, int | None]] = []
        self._done = threading.Event()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        while not self._done.is_set():
            try:
                data, ancillary, _flags, _addr = self.sock.recvmsg(256, socket.CMSG_SPACE(12))
            except (TimeoutError, OSError):
                continue
            pid = None
            for level, kind, cred in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                    pid = struct.unpack("iII", cred[:12])[0]
            self.messages.append((time.monotonic(), data.decode(), pid))

    def last(self, message: str, pid: int) -> float | None:
        times = [t for t, m, p in self.messages if m == message and p == pid]
        return max(times) if times else None

    def close(self):
        self._done.set()
        self.sock.close()


def _wait_for(predicate, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def _post(url: str, token: str, body: dict | None = None) -> int:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method="POST", headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_a_restart_after_a_watchdog_kill_sends_the_stops_and_a_clean_one_does_not(tmp_path):
    systemd = _Systemd(tmp_path / "notify")
    state = tmp_path / "state"                    # StateDirectory=
    state.mkdir()
    # What a clean shutdown before this test would have left (clean_shutdown.write).
    (state / "clean-shutdown").write_text(json.dumps({"clean_shutdown": True}))
    device, device_log = tmp_path / "device", tmp_path / "device.log"
    device.write_text("stopped")
    device_log.write_text("")
    sup, com, act = (secrets.token_urlsafe(32) for _ in range(3))
    bearers = tmp_path / "bearers.yaml"
    bearers.write_text(yaml.safe_dump({
        "bearers": [{"token": sup, "role": "supervisor", "caller": "pendant"},
                    {"token": com, "tier": "commission", "caller": "operator"},
                    {"token": act, "tier": "actuate", "caller": "agent"}],
        "actuator": {"name": "test-base"},
    }))
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    env = {k: v for k, v in os.environ.items() if not k.startswith("ROBOT_MD_")}
    env.update(DEVICE_FILE=str(device), DEVICE_LOG=str(device_log), PORT=str(port),
               BEARERS=str(bearers), NOTIFY_SOCKET=systemd.address,
               WATCHDOG_USEC=str(int(WATCHDOG_S * 1_000_000)), STATE_DIRECTORY=str(state),
               ROBOT_MD_TOOL_ALLOWLIST="base.go,base.stop", PYTHONUNBUFFERED="1")
    env.pop("WATCHDOG_PID", None)
    processes: list[subprocess.Popen] = []

    def start(n: int) -> subprocess.Popen:
        out = (tmp_path / f"gateway-{n}.log").open("w")
        process = subprocess.Popen([sys.executable, str(SERVED)], env=env, cwd=tmp_path,
                                   stdout=out, stderr=subprocess.STDOUT)
        processes.append(process)
        assert _wait_for(lambda: systemd.last("READY=1", process.pid) is not None, 60), (
            (tmp_path / f"gateway-{n}.log").read_text())
        return process

    def heard(process: subprocess.Popen) -> list[str]:
        return [line.split(" ", 1)[1] for line in device_log.read_text().splitlines()
                if line.split(" ", 1)[0] == str(process.pid)]

    def go():
        return _post(url + "/v1/invoke", act, {
            "msg_id": f"m-{secrets.token_hex(6)}", "type": "rcan/v1/invoke",
            "ruri": "rcan://RRN-000000000011/base", "scope": "MANIPULATE",
            "tool_name": "base.go", "tool_args": {}, "manifest_path": str(MANIFEST)})

    try:
        # 1. A start after a clean shutdown: no stop. Armed, the agent then
        #    sets the base going.
        first = start(1)
        time.sleep(0.5)
        assert heard(first) == []
        assert _post(url + "/v1/safety/heartbeat", sup) == 200
        assert _post(url + "/v1/safety/clear", com) == 200
        assert go() == 200
        assert device.read_text() == "going"
        # The supervisor's device goes, and the watchdog thread dies with it.
        assert _post(url + "/v1/safety/heartbeat", sup) == 200
        first.send_signal(signal.SIGUSR1)
        silent = lambda: (time.monotonic() - (systemd.last("WATCHDOG=1", first.pid) or 0)  # noqa: E731
                          >= WATCHDOG_S)
        assert _wait_for(silent, 15), "the watchdog kept pinging"
        first.send_signal(signal.SIGABRT)          # systemd's watchdog kill
        assert first.wait(10) == -signal.SIGABRT
        assert device.read_text() == "going"       # the hazard: nothing stopped it

        # 2. Restart=on-failure. The new process stops the base, unasked: the
        #    killed one had removed the marker at its start and left none.
        second = start(2)
        assert _wait_for(lambda: device.read_text() == "stopped", 10), (
            "the restart left the base going: it sent no stop")
        assert heard(second) == ["base.stop"]
        assert "the previous process left no clean-shutdown marker" in (
            (tmp_path / "gateway-2.log").read_text())

        # 3. A clean stop while held leaves the marker; the next start reads
        #    it, removes it, and sends nothing.
        second.send_signal(signal.SIGTERM)
        # uvicorn (0.29 and later) shuts down, then raises the SIGTERM again,
        # so the process ends by it; systemd counts that as a clean stop.
        assert second.wait(30) in (0, -signal.SIGTERM)
        assert (state / "clean-shutdown").exists()
        third = start(3)
        time.sleep(1.0)
        assert heard(third) == []
        assert not (state / "clean-shutdown").exists()
        assert ("the previous process shut down cleanly" in
                (tmp_path / "gateway-3.log").read_text())
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(10)
        systemd.close()
