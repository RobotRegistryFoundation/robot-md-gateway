"""A stop does not queue behind other requests for a worker thread.

The handler is synchronous and FastAPI runs it on a shared pool of 40 threads,
first come, first served. EV-03's review held a paced move on the arm, pointed
120 looping clients at arm.state and then sent arm.estop: the stop reached the
actuator 5.9 s after it was sent, because every thread was busy with a poll
waiting for the bus. Stop tools now run on threads of their own.
"""
from __future__ import annotations

import threading
import time

from robot_md_gateway.actuator import ActuatorOutcome

from .test_tool_scope import _Arm, _client, _post

SHARED_POOL = 40


class _Busy(_Arm):
    """Every tool but the stop blocks until released, holding its thread."""

    def __init__(self):
        super().__init__()
        self.release = threading.Event()
        self.blocked = 0
        self._count = threading.Lock()

    def execute(self, *, envelope, manifest_path, tier, config):
        if envelope["tool_name"] in self.stop_capabilities:
            return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})
        with self._count:
            self.blocked += 1
        self.release.wait(20)
        return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})


def test_a_stop_runs_while_every_shared_thread_is_busy():
    arm = _Busy()
    with _client(arm) as client:
        flood = [threading.Thread(target=_post, args=(client, "arm.home", "MANIPULATE"),
                                  kwargs={"msg_id": f"flood-{i}"})
                 for i in range(SHARED_POOL + 5)]
        for thread in flood:
            thread.start()
        deadline = time.monotonic() + 10
        while arm.blocked < SHARED_POOL and time.monotonic() < deadline:
            time.sleep(0.01)
        try:
            assert arm.blocked == SHARED_POOL          # the shared pool is full
            started = time.monotonic()
            response = _post(client, "arm.estop", "HALT", msg_id="the-stop")
            took = time.monotonic() - started
        finally:
            arm.release.set()
            for thread in flood:
                thread.join(timeout=20)
    assert response.status_code == 200, response.text
    assert took < 2.0, f"the stop waited {took:.1f} s for a thread"


def test_other_tools_still_share_the_default_pool():
    """Only the stop is moved: a flood of polls is still limited to 40 threads."""
    arm = _Busy()
    with _client(arm) as client:
        flood = [threading.Thread(target=_post, args=(client, "arm.home", "MANIPULATE"),
                                  kwargs={"msg_id": f"flood-{i}"})
                 for i in range(SHARED_POOL + 5)]
        for thread in flood:
            thread.start()
        deadline = time.monotonic() + 10
        while arm.blocked < SHARED_POOL and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(0.2)
        try:
            assert arm.blocked == SHARED_POOL
        finally:
            arm.release.set()
            for thread in flood:
                thread.join(timeout=20)
    assert arm.blocked == SHARED_POOL + 5
