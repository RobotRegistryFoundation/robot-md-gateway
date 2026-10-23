"""A stop does not queue behind other requests for a worker thread.

The handler is synchronous and FastAPI runs it on a shared pool of 40 threads,
first come, first served. EV-03's review held a paced move on the arm, pointed
120 looping clients at arm.state and then sent arm.estop: the stop reached the
actuator 5.9 s after it was sent, because every thread was busy with a poll
waiting for the bus. Stop tools now run on threads of their own.
"""
from __future__ import annotations

import json
import threading
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import robot_md_gateway.receiver as receiver_mod
from robot_md_gateway.actuator import ActuatorOutcome
from robot_md_gateway.attestation import SigningIdentity
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.cert.safety import SafetyMonitor
from robot_md_gateway.receiver import STOP_LANES, make_app

from .test_safe_stop_holds_the_machine import (
    BEARERS,
    FIXTURES,
    STALE_S,
    SUPERVISOR,
    FakeClock,
    _clear,
    _heartbeat,
    _Resolver,
    _wait_for,
)
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


# --------------------------------------------------------------------------- #
# Who gets a stop lane (blocking 2 of the second review), and a stop that
# reaches the actuator before its records (note H1)
# --------------------------------------------------------------------------- #

class _Stops:
    """Takes its declared stop at once, and notes when."""

    description, config_schema = "test actuator", {}

    def __init__(self, name, *, stops=frozenset({"drive.stop"})):
        self.name = name
        self.motion_capabilities = frozenset({"drive.go"}) if stops else frozenset()
        self.stop_capabilities = stops
        self.log: list[str] = []

    def execute(self, *, envelope, manifest_path, tier, config):
        self.log.append(envelope["tool_name"])
        return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})


def _stop_envelope(actuator_name=None, tool="drive.stop", **extra):
    body = {"msg_id": uuid.uuid4().hex, "type": "rcan/v1/invoke", "ruri": "rcan://RRN-test/x",
            "scope": "SAFETY", "tool_name": tool, "tool_args": {},
            "manifest_path": str(FIXTURES / "signed-good.md"), **extra}
    if actuator_name is not None:
        body["actuator_name"] = actuator_name
    return body


def test_requests_that_are_not_declared_stops_never_hold_the_stop_lanes():
    """The review's reproduction, which now fails: anonymous requests naming a
    stop tool for an actuator that does not declare it, each with a made-up key
    id the registry takes 2 s to refuse, no longer queue in front of a known
    bearer's declared stop."""
    class SlowResolver(_Resolver):
        def resolve_public_key_pem(self, kid):
            if kid != self.kid:
                time.sleep(2.0)                      # RRFResolverFromEnv: 5 s, no negative cache
            return super().resolve_public_key_pem(kid)

    arm, clock = _Stops("arm"), FakeClock()
    app = make_app(
        resolver=SlowResolver(), tool_allowlist=ToolAllowlist(allowed_tools=("drive.stop",)),
        bearer_tiers=BEARERS, bearers=SUPERVISOR, clock=clock, require_envelope_signature=True,
        safety_monitor=SafetyMonitor(heartbeat_staleness_s=STALE_S, last_heartbeat_at=clock()),
        actuators={"arm": arm, "host": _Stops("host", stops=frozenset())}, actuator_configs={},
    )
    bogus = {"envelope_signature": {"kid": "nobody", "alg": "Ed25519", "sig": "AA=="}}
    with TestClient(app) as client:
        _heartbeat(client)
        _clear(client)
        flood = [threading.Thread(target=lambda: client.post(
            "/v1/invoke", json=_stop_envelope("host", **bogus)))
            for _ in range(3 * STOP_LANES)]
        for thread in flood:
            thread.start()
        time.sleep(0.3)
        started = time.monotonic()
        response = client.post("/v1/invoke", json=_stop_envelope("arm"),
                               headers={"Authorization": "Bearer read-token"})
        took = time.monotonic() - started
        for thread in flood:
            thread.join(10)
    assert response.status_code == 200, response.text
    assert arm.log == ["drive.stop"]
    assert took < 1.0, f"the stop waited {took:.1f} s behind requests that are not stops"


def test_a_stop_reaches_the_actuator_while_the_export_is_stuck(monkeypatch, tmp_path):
    """Note H1 and blocking 2 together. With storage that has stopped
    answering, every record waits on the export. Anonymous stops are refused,
    and each refusal waits there; they used to hold every stop lane, and the
    known bearer's stop itself waited on its intent record before the actuator.
    Now anonymous requests share the default pool, and a stop is sent before it
    is recorded."""
    release, stuck = threading.Event(), []
    real_append = receiver_mod.append_trace_line

    def stuck_append(path, record):
        stuck.append(record.get("record_kind") or "outcome")
        release.wait(20)
        return real_append(path, record)

    monkeypatch.setattr(receiver_mod, "append_trace_line", stuck_append)
    arm, chain, export = _Stops("arm"), AuditChain(), tmp_path / "trace.ndjsonl"
    app = make_app(
        resolver=_Resolver(), tool_allowlist=ToolAllowlist(allowed_tools=("drive.stop",)),
        bearer_tiers=BEARERS, actuator=arm, actuator_config={}, audit_chain=chain,
        signing_identity=SigningIdentity(priv=Ed25519PrivateKey.generate(), kid="gw", ran=None),
        attestation_export_file=export,
    )
    with TestClient(app) as client:
        flood = [threading.Thread(target=lambda: client.post("/v1/invoke",
                                                             json=_stop_envelope()))
                 for _ in range(STOP_LANES)]
        for thread in flood:
            thread.start()
        try:
            assert _wait_for(lambda: len(stuck) >= STOP_LANES), "no refusal reached the export"
            stop = _stop_envelope()
            box: dict = {"msg_id": stop["msg_id"]}
            stopper = threading.Thread(target=lambda: box.update(r=client.post(
                "/v1/invoke", json=stop, headers={"Authorization": "Bearer read-token"})))
            started = time.monotonic()
            stopper.start()
            reached = _wait_for(lambda: arm.log == ["drive.stop"], timeout=5)
            took = time.monotonic() - started
        finally:
            release.set()
            for thread in [*flood, stopper]:
                thread.join(20)
    assert reached, "the stop never reached the actuator while the export was stuck"
    assert took < 1.0, f"the stop reached the actuator after {took:.1f} s"
    assert box["r"].status_code == 200
    # The record is complete: an intent and an outcome, linked, both after the stop.
    [intent] = [e for e in chain.entries if e.entry_kind == "intent"]
    [outcome] = [e for e in chain.entries if e.entry_kind == "outcome"
                 and e.decision == "allow"]
    assert outcome.intent_chain_hash == intent.chain_hash
    assert intent.decision_reason.endswith(
        "so this entry was written after the actuator was called")
    lines = [json.loads(line) for line in export.read_text().splitlines()]
    mine = [line for line in lines if line.get("corr_id") == box["msg_id"]]
    assert [line.get("record_kind", "outcome") for line in mine] == ["intent", "outcome"]
