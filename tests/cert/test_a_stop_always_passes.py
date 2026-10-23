"""An allowlisted, declared stop from a known credential always passes.

Review of #35, finding 4: a stop was still refused for the scope label the
caller wrote, for a replayed msg_id, for a revoked or unresolvable key, and so
on. A declared stop now takes its own path (receiver._invoke_stop):

- judged as SAFETY, whatever scope the envelope carries;
- passes whatever state the gateway is in;
- never refused for its signature, freshness, revocation or replay (a replay is
  processed and logged as REPLAY_DETECTED), and the key registry is never
  consulted for it;
- never refused for the manifest it names: the actuator gets the pinned one;
- not gated on confidence or HiTL;
- still needs a bearer this gateway knows (any tier), and still meets the
  operator's allowlist and per-tool tiers.

Also here: finding 7 (a request admitted in READY is not dispatched after a
trip that happened while its gates ran) and finding 8 (what an actuator
declares is checked at startup).
"""

from __future__ import annotations

import base64
import logging
import sys
import threading
import time
import types
from pathlib import Path
from typing import ClassVar

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from robot_md_gateway.actuator import ActuatorOutcome
from robot_md_gateway.auth import _BearerEntry
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.envelope import canonical_json
from robot_md_gateway.cert.gates import ConfidencePolicy, HiTLPolicy
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.cert.safety import GatewayState, SafetyMonitor
from robot_md_gateway.receiver import make_app

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "manifests"
MANIFEST_KID = (FIXTURES / "signing-key.kid").read_text().strip()
MANIFEST_PUB = (FIXTURES / "signing-key.pub").read_bytes()
ENV_KID = "envelope-kid"
ENV_PRIV = Ed25519PrivateKey.generate()
ENV_PUB = ENV_PRIV.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
BEARERS = {"read-token": "read", "actuate-token": "actuate",
           "commission-token": "commission"}
SUPERVISOR = {"supervisor-token": _BearerEntry(token="supervisor-token", tier="read",
                                              caller_id="pendant", role="supervisor")}
ALLOWED = ("arm.move_to", "arm.estop", "arm.state")
TRIPPED_AND_NOT = [GatewayState.READY, GatewayState.SAFE_STOP, GatewayState.ESTOP_ACTIVE]


class _Resolver:
    """Knows the manifest key and the envelope key; counts every lookup."""

    def __init__(self, *, offline: bool = False):
        self.offline = offline
        self.lookups: list[str] = []

    def resolve_public_key_pem(self, kid: str) -> bytes | None:
        self.lookups.append(kid)
        if self.offline:
            raise OSError("robotregistryfoundation.org unreachable")
        return {MANIFEST_KID: MANIFEST_PUB, ENV_KID: ENV_PUB}.get(kid)


class _Arm:
    name = "arm"
    description = "test arm"
    config_schema: ClassVar[dict] = {}
    motion_capabilities = frozenset({"arm.move_to"})
    stop_capabilities = frozenset({"arm.estop"})

    def __init__(self):
        self.calls: list[tuple[str, str, object]] = []      # (tool, tier, manifest_path)

    def execute(self, *, envelope, manifest_path, tier, config):
        self.calls.append((envelope["tool_name"], tier, manifest_path))
        return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})


def _app(state=GatewayState.SAFE_STOP, *, arm=None, chain=None, resolver=None, **kw):
    arm = arm or _Arm()
    chain = chain if chain is not None else AuditChain()
    kw.setdefault("tool_allowlist", ToolAllowlist(allowed_tools=ALLOWED))
    app = make_app(resolver=resolver or _Resolver(), bearer_tiers=BEARERS,
                   safety_monitor=SafetyMonitor(state=state), audit_chain=chain,
                   actuator=arm, actuator_config={}, **kw)
    return TestClient(app), arm, chain


def _envelope(tool="arm.estop", scope="SAFETY", msg_id=None, sign=False, kid=ENV_KID,
              **extra):
    body = {"msg_id": msg_id or f"m-{time.monotonic_ns()}", "type": "rcan/v1/invoke",
            "ruri": "rcan://RRN-000000000011/arm", "scope": scope, "tool_name": tool,
            "tool_args": {}, "manifest_path": str(FIXTURES / "signed-good.md"), **extra}
    if sign:
        body["envelope_signature"] = {"kid": kid, "alg": "Ed25519", "sig": base64.b64encode(
            ENV_PRIV.sign(canonical_json(body))).decode()}
    return body


def _post(client, body, token="read-token"):
    return client.post("/v1/invoke", json=body, headers={"Authorization": f"Bearer {token}"})


def _intent(chain: AuditChain) -> str:
    [intent] = [e for e in chain.entries if e.entry_kind == "intent"]
    return intent.decision_reason


# --------------------------------------------------------------------------- #
# The scope label, the state, confidence and HiTL
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("state", TRIPPED_AND_NOT)
@pytest.mark.parametrize("scope", ["actuate", "MANIPULATE", "COMMISSION", "OBSERVE", "HALT"])
def test_a_read_bearer_stops_whatever_scope_it_writes(state, scope):
    """The review's P11: `arm.estop`, read bearer, scope "actuate" (robot-md's
    default) was a 403 tier_policy on a tripped gateway."""
    client, arm, chain = _app(state)
    response = _post(client, _envelope(scope=scope))
    assert response.status_code == 200, response.text
    assert response.json()["scope"] == "SAFETY"
    assert arm.calls == [("arm.estop", "read", None)]
    assert _intent(chain).startswith(
        "dispatching: a declared stop of actuator 'arm', judged as SAFETY")
    assert [(e.entry_kind, e.decision) for e in chain.entries] == [
        ("intent", "allow"), ("outcome", "allow")]


def test_confidence_and_hitl_do_not_gate_a_stop():
    """ConfidencePolicy has no SAFETY entry, so a stop judged under the default
    strict threshold, or under a HiTL rule for its written scope, would be
    refused. Neither applies to a stop."""
    client, arm, _ = _app(confidence_policy=ConfidencePolicy(),
                          hitl_policy=HiTLPolicy(required_for_scopes=frozenset(
                              {"MANIPULATE", "SAFETY"})))
    response = _post(client, _envelope(scope="MANIPULATE"))
    assert response.status_code == 200, response.text
    assert [c[0] for c in arm.calls] == ["arm.estop"]


# --------------------------------------------------------------------------- #
# Signatures, keys, freshness, revocation and replay
# --------------------------------------------------------------------------- #


def test_an_unsigned_stop_passes_where_signatures_are_required_and_says_so():
    client, _arm, chain = _app(require_envelope_signature=True)
    response = _post(client, _envelope())
    assert response.status_code == 200, response.text
    assert "signature, freshness and revocation are not checked on a stop" in _intent(chain)
    assert chain.entries[0].envelope_kid is None


def test_the_key_registry_is_never_consulted_for_a_stop():
    """offline.astro: registry connectivity is never required to halt a robot.
    After a restart with no internet, every signed stop used to be refused
    (a 5 s lookup that failed); now the resolver is not called at all."""
    resolver = _Resolver(offline=True)
    client, arm, _ = _app(require_envelope_signature=True, resolver=resolver)
    for sign, kid in ((True, ENV_KID), (True, "kid-nobody-registered"), (False, ENV_KID)):
        response = _post(client, _envelope(sign=sign, kid=kid))
        assert response.status_code == 200, response.text
    assert resolver.lookups == []
    assert len(arm.calls) == 3


def test_a_stale_stop_passes():
    stale = int(time.time() * 1000) - 3_600_000          # an hour old
    client, _arm, _ = _app(require_envelope_signature=True)
    response = _post(client, _envelope(sign=True, timestamp_ms=stale))
    assert response.status_code == 200, response.text


def test_a_stop_signed_by_a_revoked_key_passes():
    """revocation.astro: an ESTOP from a revoked source MUST be accepted."""
    class _AllRevoked:
        def is_revoked(self, kid):
            return True

    client, _arm, _ = _app(require_envelope_signature=True, revocation_resolver=_AllRevoked())
    response = _post(client, _envelope(sign=True))
    assert response.status_code == 200, response.text


def test_a_replayed_stop_is_processed_and_logged_as_replay_detected():
    """The review's P12: a stop retried with the same msg_id was a 403 replay.
    replay-prevention.astro: a fresh duplicate ESTOP MUST be processed."""
    chain = AuditChain()
    client, arm, _ = _app(require_envelope_signature=True, chain=chain)
    body = _envelope(sign=True, msg_id="stop-once")
    first, second = _post(client, body), _post(client, body)
    assert (first.status_code, second.status_code) == (200, 200)
    intents = [e.decision_reason for e in chain.entries if e.entry_kind == "intent"]
    assert "REPLAY_DETECTED" not in intents[0]
    assert "REPLAY_DETECTED: msg_id stop-once was seen before" in intents[1]
    assert len(arm.calls) == 2


def test_a_stop_still_records_its_msg_id_so_a_motion_cannot_reuse_it():
    client, _arm, _ = _app(GatewayState.READY, require_envelope_signature=True)
    assert _post(client, _envelope(sign=True, msg_id="shared")).status_code == 200
    motion = _envelope(tool="arm.move_to", scope="MANIPULATE", sign=True, msg_id="shared")
    response = _post(client, motion, token="actuate-token")
    assert response.status_code == 403
    assert response.json()["detail"]["deny"] == "replay"


def test_everything_that_is_not_a_stop_still_needs_its_signature():
    client, arm, _chain = _app(GatewayState.READY, require_envelope_signature=True)
    response = _post(client, _envelope(tool="arm.move_to", scope="MANIPULATE"),
                     token="actuate-token")
    assert response.status_code == 403
    assert response.json()["detail"]["deny"] == "envelope_signature"
    assert arm.calls == []


# --------------------------------------------------------------------------- #
# The manifest it names, and the RRN
# --------------------------------------------------------------------------- #


def test_a_stop_naming_another_manifest_gets_the_pinned_one(tmp_path):
    pinned = tmp_path / "ROBOT.md"
    pinned.write_bytes((FIXTURES / "signed-good.md").read_bytes())
    client, arm, _ = _app(pinned_manifest_path=pinned, require_rrn_binding=True)
    response = _post(client, _envelope(manifest_path="/nonexistent/ROBOT.md",
                                       ruri="rcan://RRN-999999999999/someone-else"))
    assert response.status_code == 200, response.text
    assert arm.calls == [("arm.estop", "read", pinned)]


def test_a_stop_with_a_manifest_that_does_not_verify_passes():
    client, _arm, _ = _app(GatewayState.READY)
    response = _post(client, _envelope(manifest_path=str(FIXTURES / "signed-tampered.md")))
    assert response.status_code == 200, response.text


# --------------------------------------------------------------------------- #
# What still applies to a stop
# --------------------------------------------------------------------------- #


def test_the_operators_per_tool_tiers_still_apply_to_a_stop():
    client, arm, _chain = _app(tool_tier_requirements={"arm.estop": frozenset({"actuate"})})
    refused = _post(client, _envelope())
    allowed = _post(client, _envelope(), token="actuate-token")
    assert refused.status_code == 403
    assert refused.json()["detail"]["deny"] == "tool_tier"
    assert allowed.status_code == 200, allowed.text
    assert arm.calls == [("arm.estop", "actuate", None)]


def test_a_malformed_stop_is_a_parser_error():
    client, arm, _ = _app()
    body = _envelope()
    del body["ruri"]
    assert _post(client, body).status_code == 422
    assert arm.calls == []


def test_a_stop_that_two_actuators_declare_needs_a_name():
    """Ambiguous without actuator_name: it is not treated as a stop, so the
    gated path answers it (refused while tripped)."""
    one, two = _Arm(), _Arm()
    two.name = "arm2"
    app = make_app(resolver=_Resolver(), bearer_tiers=BEARERS,
                   tool_allowlist=ToolAllowlist(allowed_tools=ALLOWED),
                   safety_monitor=SafetyMonitor(state=GatewayState.SAFE_STOP),
                   actuators={"arm": one, "arm2": two})
    client = TestClient(app)
    ambiguous = _post(client, _envelope())
    named = _post(client, _envelope(actuator_name="arm2"))
    assert ambiguous.status_code == 403
    assert ambiguous.json()["detail"]["deny"] == "safety_state"
    assert named.status_code == 200, named.text
    assert one.calls == [] and [c[0] for c in two.calls] == ["arm.estop"]


# --------------------------------------------------------------------------- #
# Finding 7: the state is checked again just before dispatch
# --------------------------------------------------------------------------- #


class _FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_a_trip_while_the_gates_run_stops_the_dispatch():
    """The review's P13: a key lookup takes long enough for the heartbeat to go
    stale. The request was admitted in READY; it must not be dispatched."""
    clock = _FakeClock()

    class _SlowResolver(_Resolver):
        def resolve_public_key_pem(self, kid):
            clock.t += 10.0                      # the lookup outlasts the heartbeat
            return super().resolve_public_key_pem(kid)

    arm, chain = _Arm(), AuditChain()
    app = make_app(resolver=_SlowResolver(), bearer_tiers=BEARERS,
                   tool_allowlist=ToolAllowlist(allowed_tools=ALLOWED),
                   safety_monitor=SafetyMonitor(last_heartbeat_at=clock()),
                   audit_chain=chain, actuator=arm, actuator_config={}, clock=clock)
    response = _post(TestClient(app), _envelope(tool="arm.move_to", scope="MANIPULATE"),
                     token="actuate-token")
    assert response.status_code == 403, response.text
    assert response.json()["detail"] == {
        **response.json()["detail"], "deny": "safety_state",
        "reason": "gateway state=safe_stop (it changed while this request was being checked)"}
    deadline = time.monotonic() + 5
    while not any(c[0] == "arm.estop" for c in arm.calls) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert [c[0] for c in arm.calls] == ["arm.estop"]        # the trip's stop, no motion
    assert not any(e.entry_kind == "intent" and e.tool_name == "arm.move_to"
                   for e in chain.entries)


# --------------------------------------------------------------------------- #
# Finding 8: what an actuator declares is checked at startup
# --------------------------------------------------------------------------- #


def test_a_tool_declared_both_as_a_stop_and_as_a_motion_refuses_to_start():
    class _Confused(_Arm):
        motion_capabilities = frozenset({"arm.move_to", "arm.estop"})

    with pytest.raises(ValueError, match=r"arm\.estop as both a stop and a motion"):
        make_app(resolver=_Resolver(), actuator=_Confused(), actuator_config={})


def _arm_needing(tiers: frozenset[str], *, on_module: bool = False):
    """An arm whose stop needs `tiers`, declared as an attribute or, like
    so-arm101-actuator, as REQUIRED_TIERS in the actuator's module."""
    if not on_module:
        class _Strict(_Arm):
            required_tiers: ClassVar[dict] = {"arm.estop": tiers}
        return _Strict()
    module = types.ModuleType("fake_strict_actuator")
    module.REQUIRED_TIERS = {"arm.estop": tiers}
    sys.modules[module.__name__] = module
    cls = type("_ModuleStrict", (_Arm,), {"__module__": module.__name__})
    return cls()


@pytest.mark.parametrize("on_module", [False, True])
def test_motion_through_an_actuator_that_would_refuse_the_gateways_stop_is_refused(
        caplog, on_module):
    """The review's P6: an actuator whose stop needs the actuate tier refused
    the gateway's stop (sent at read), and its move ran to the end."""
    arm, chain = _arm_needing(frozenset({"actuate", "commission"}), on_module=on_module), \
        AuditChain()
    with caplog.at_level(logging.ERROR, logger="robot_md_gateway.receiver"):
        client, _, _ = _app(GatewayState.READY, arm=arm, chain=chain)
    assert "stop_unreachable: actuator 'arm' requires one of ['actuate', 'commission']" \
        in caplog.text
    motion = _post(client, _envelope(tool="arm.move_to", scope="MANIPULATE"),
                   token="actuate-token")
    stop = _post(client, _envelope(), token="actuate-token")
    assert motion.status_code == 403
    assert motion.json()["detail"]["deny"] == "stop_unreachable"
    assert chain.entries[0].decision == "deny"
    assert stop.status_code == 200, stop.text                 # a caller's stop still runs
    assert [c[0] for c in arm.calls] == ["arm.estop"]


def test_an_actuator_that_accepts_its_stop_at_read_is_not_refused():
    """so-arm101-actuator gives arm.estop to read, actuate and commission."""
    arm = _arm_needing(frozenset({"read", "actuate", "commission"}), on_module=True)
    client, _, _ = _app(GatewayState.READY, arm=arm)
    response = _post(client, _envelope(tool="arm.move_to", scope="MANIPULATE"),
                     token="actuate-token")
    assert response.status_code == 200, response.text


def test_an_actuator_that_declares_no_stop_is_named_at_startup(caplog):
    class _NoStop(_Arm):
        stop_capabilities = frozenset()

    with caplog.at_level(logging.ERROR, logger="robot_md_gateway.receiver"):
        make_app(resolver=_Resolver(), actuator=_NoStop(), actuator_config={},
                 safety_monitor=SafetyMonitor())
    assert "no_declared_stop: actuator 'arm' declares no stop_capabilities" in caplog.text


def test_the_trip_sends_the_stop_at_the_tier_the_startup_check_used():
    """The startup check and the trip agree on SAFETY_STOP_TIER."""
    clock = _FakeClock()
    arm = _arm_needing(frozenset({"read"}))
    done = threading.Event()
    original = arm.execute

    def execute(**kw):
        outcome = original(**kw)
        done.set()
        return outcome

    arm.execute = execute
    app = make_app(resolver=_Resolver(), actuator=arm, actuator_config={},
                   safety_monitor=SafetyMonitor(last_heartbeat_at=clock()), clock=clock)
    clock.t += 10
    app.state.safety_tick()
    assert done.wait(5)
    assert arm.calls == [("arm.estop", "read", None)]


# castor-hal's TransportActuator (RobotRegistryFoundation/castor-hal#1) declares
# these: its four stop spellings, and as motion every goal tool parse_goal maps,
# which is its fail-safe default when the transport's type is not given.
CASTOR_HAL_STOPS = frozenset({"estop", "stop", "emergency_stop", "halt"})
CASTOR_HAL_GOALS = frozenset({
    "move", "set_joint_positions", "joint_positions", "home", "go_home", "set_velocity",
    "cmd_vel", "drive", "body_twist", "set_gripper", "gripper", "set_rate", "rate_setpoint",
    "set_sections", "section_state", "flight_setpoint", "goto", "set_trajectory",
    "joint_trajectory"})


def test_castor_hals_fail_safe_declarations_start_and_get_its_first_stop_on_a_trip():
    class _Transport(_Arm):
        name = "castor-transport"
        stop_capabilities = CASTOR_HAL_STOPS
        motion_capabilities = CASTOR_HAL_GOALS

    clock = _FakeClock()
    transport = _Transport()
    done = threading.Event()
    original = transport.execute

    def execute(**kw):
        outcome = original(**kw)
        done.set()
        return outcome

    transport.execute = execute
    app = make_app(resolver=_Resolver(), actuator=transport, actuator_config={},
                   safety_monitor=SafetyMonitor(last_heartbeat_at=clock()), clock=clock)
    clock.t += 10
    app.state.safety_tick()
    assert done.wait(5)
    assert transport.calls == [("emergency_stop", "read", None)]


def test_a_telemetry_only_actuator_starts_and_is_named_as_unstoppable(caplog):
    """castor-hal's J1939 tap: no goals and no stop. The gateway starts, says it
    cannot stop it, and has nothing of it to refuse as motion."""
    class _Tap(_Arm):
        name = "j1939"
        stop_capabilities = frozenset()
        motion_capabilities = frozenset()

    with caplog.at_level(logging.ERROR, logger="robot_md_gateway.receiver"):
        make_app(resolver=_Resolver(), actuator=_Tap(), actuator_config={},
                 safety_monitor=SafetyMonitor())
    assert "no_declared_stop: actuator 'j1939'" in caplog.text
    assert "stop_unreachable" not in caplog.text


def test_an_actuator_that_refuses_the_gateways_stop_gets_no_more_motion():
    """The review's P6, for an actuator that declares no tiers, so the startup
    check cannot see it: it refuses the gateway's stop at tier read. The move
    in flight cannot be stopped; every motion after it is refused."""
    class _ReadCannotStop(_Arm):
        def execute(self, *, envelope, manifest_path, tier, config):
            if envelope["tool_name"] == "arm.estop" and tier == "read":
                self.calls.append((envelope["tool_name"], tier, manifest_path))
                return ActuatorOutcome(success=False, outcome_kind="denied",
                                       error_message="tier read may not stop")
            return super().execute(envelope=envelope, manifest_path=manifest_path,
                                   tier=tier, config=config)

    clock, arm, chain = _FakeClock(), _ReadCannotStop(), AuditChain()
    app = make_app(resolver=_Resolver(), bearer_tiers=BEARERS, bearers=SUPERVISOR,
                   tool_allowlist=ToolAllowlist(allowed_tools=ALLOWED),
                   safety_monitor=SafetyMonitor(last_heartbeat_at=clock()), audit_chain=chain,
                   actuator=arm, actuator_config={}, clock=clock)
    client = TestClient(app)
    clock.t += 10
    app.state.safety_tick()
    deadline = time.monotonic() + 5
    while not [e for e in chain.entries if e.decision_reason.startswith("safety_stop:")]:
        assert time.monotonic() < deadline, "the gateway's stop was never recorded"
        time.sleep(0.01)
    [stop] = [e for e in chain.entries if e.decision_reason.startswith("safety_stop:")]
    assert stop.decision == "deny"
    assert stop.decision_reason.endswith("motion through it is refused from now on")
    assert client.post("/v1/safety/heartbeat",
                       headers={"Authorization": "Bearer supervisor-token"}).status_code == 200
    assert client.post("/v1/safety/clear",
                       headers={"Authorization": "Bearer commission-token"}).status_code == 200
    motion = _post(client, _envelope(tool="arm.move_to", scope="MANIPULATE"),
                   token="actuate-token")
    assert motion.status_code == 403
    assert motion.json()["detail"]["deny"] == "stop_unreachable"
    assert "refused the gateway's own stop" in motion.json()["detail"]["reason"]
    assert [c[0] for c in arm.calls] == ["arm.estop"]
