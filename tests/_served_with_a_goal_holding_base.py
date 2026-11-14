"""`robot-md-gateway serve`, the real command, in a process of its own, with one
actuator whose hardware keeps its last goal after the process ends: a file,
DEVICE_FILE. Every command it receives is appended to DEVICE_LOG with this
process's pid. Run by tests/test_a_restart_sends_the_stops.py.

Two things a test cannot have here are stood in for: the installed actuator
(an entry point) and RRF (the key that signed the fixture manifest). SIGUSR1
kills the safety watchdog thread: its next tick raises SystemExit, which its
loop does not catch, as a fault in the monitor would.
"""

from __future__ import annotations

import os
import resource
import signal
import sys
import threading
from pathlib import Path

from robot_md_gateway import actuator as actuator_module
from robot_md_gateway import auth
from robot_md_gateway.actuator import ActuatorOutcome
from robot_md_gateway.cert import safety

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "manifests"
DEVICE = Path(os.environ["DEVICE_FILE"])
LOG = Path(os.environ["DEVICE_LOG"])

# systemd's watchdog kill is SIGABRT; leave no core file behind.
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class _Resolver:
    def __init__(self):
        self.kid = (FIXTURES / "signing-key.kid").read_text().strip()
        self.pub = (FIXTURES / "signing-key.pub").read_bytes()

    def resolve_public_key_pem(self, kid):
        return self.pub if kid == self.kid else None


class Base:
    name = "base"
    description = "keeps its last velocity after its host process ends"
    config_schema: dict = {}  # noqa: RUF012
    motion_capabilities = frozenset({"base.go"})
    stop_capabilities = frozenset({"base.stop"})

    def execute(self, *, envelope, manifest_path, tier, config):
        tool = envelope["tool_name"]
        with LOG.open("a") as log:
            log.write(f"{os.getpid()} {tool}\n")
        DEVICE.write_text("stopped" if tool == "base.stop" else "going")
        return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})


actuator_module.resolve_actuator = lambda name: Base
auth.RRFResolverFromEnv.from_env = classmethod(lambda cls: _Resolver())

_killed = threading.Event()
_tick = safety.SafetyMonitor.tick


def _tick_unless_killed(self, *args, **kwargs):
    if _killed.is_set() and threading.current_thread().name == "robot-md-gateway-safety-watchdog":
        raise SystemExit("the test killed the safety watchdog thread")
    return _tick(self, *args, **kwargs)


safety.SafetyMonitor.tick = _tick_unless_killed
signal.signal(signal.SIGUSR1, lambda *_: _killed.set())

sys.argv = ["robot-md-gateway", "serve", "--host", "127.0.0.1", "--port", os.environ["PORT"],
            "--bearers", os.environ["BEARERS"]]
from robot_md_gateway.__main__ import main  # noqa: E402

main()
