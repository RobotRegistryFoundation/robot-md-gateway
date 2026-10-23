"""A stop gets through a tripped safety monitor. Nothing else does.

The safety-state check runs first, before any other gate and before tool
routing, and it used to refuse EVERY request while the gateway was out of
READY: the stop tools too. A gateway in SAFE_STOP or ESTOP_ACTIVE therefore
refused the one command an operator sends when something is wrong.

The exemption is exactly: a tool that the receiving actuator declares in
`stop_capabilities`. It is an exemption from the safety-state check only; the
stop still passes every other gate (bearer tier, allowlist, manifest), and it
is still recorded like any other dispatch.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest
from fastapi.testclient import TestClient

from robot_md_gateway.actuator import ActuatorOutcome
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.cert.safety import GatewayState, SafetyMonitor
from robot_md_gateway.receiver import make_app

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "manifests"
TRIPPED = [GatewayState.SAFE_STOP, GatewayState.ESTOP_ACTIVE]


class _Resolver:
    def __init__(self):
        self.kid = (FIXTURES / "signing-key.kid").read_text().strip()
        self.pub_pem = (FIXTURES / "signing-key.pub").read_bytes()

    def resolve_public_key_pem(self, kid: str) -> bytes | None:
        return self.pub_pem if kid == self.kid else None


class _Arm:
    name = "arm"
    description = "test arm"
    config_schema: ClassVar[dict] = {}
    motion_capabilities = frozenset({"arm.move_to", "arm.home"})
    stop_capabilities = frozenset({"arm.estop"})

    def __init__(self):
        self.calls: list[str] = []

    def execute(self, *, envelope, manifest_path, tier, config):
        self.calls.append(envelope["tool_name"])
        return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})


class _Camera:
    """Declares no stop: a stop-named tool is not a stop for this actuator."""

    name = "cam"
    description = "test camera"
    config_schema: ClassVar[dict] = {}

    def __init__(self):
        self.calls: list[str] = []

    def execute(self, *, envelope, manifest_path, tier, config):
        self.calls.append(envelope["tool_name"])
        return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})


ALLOWED = ("arm.move_to", "arm.home", "arm.estop", "arm.estop.clear", "arm.state")


def _client(state, *, allowed=ALLOWED, chain=None, **actuation):
    if not actuation:
        actuation = {"actuator": _Arm(), "actuator_config": {}}
    app = make_app(
        resolver=_Resolver(),
        tool_allowlist=ToolAllowlist(allowed_tools=allowed),
        bearer_tiers={"actuate-token": "actuate"},
        safety_monitor=SafetyMonitor(state=state),
        audit_chain=chain,
        **actuation,
    )
    return TestClient(app)


def _post(client, tool, scope, **extra):
    return client.post(
        "/v1/invoke",
        json={
            "msg_id": f"m-{tool}",
            "type": "rcan/v1/invoke",
            "ruri": "rcan://RRN-test/arm",
            "scope": scope,
            "tool_name": tool,
            "tool_args": {},
            "manifest_path": str(FIXTURES / "signed-good.md"),
            **extra,
        },
        headers={"Authorization": "Bearer actuate-token"},
    )


@pytest.mark.parametrize("state", TRIPPED)
def test_a_stop_executes_while_the_monitor_is_tripped(state):
    arm, chain = _Arm(), AuditChain()
    with _client(state, chain=chain, actuator=arm, actuator_config={}) as client:
        response = _post(client, "arm.estop", "HALT")

    assert response.status_code == 200, response.text
    assert arm.calls == ["arm.estop"]
    # Recorded like any dispatch: the intent before, the outcome after.
    assert [(e.entry_kind, e.decision) for e in chain.entries] == [
        ("intent", "allow"), ("outcome", "allow"),
    ]


@pytest.mark.parametrize("state", TRIPPED)
def test_a_motion_is_denied_and_recorded_as_a_deny_while_tripped(state):
    arm, chain = _Arm(), AuditChain()
    with _client(state, chain=chain, actuator=arm, actuator_config={}) as client:
        response = _post(client, "arm.move_to", "MANIPULATE")

    assert response.status_code == 403, response.text
    assert response.json()["detail"]["deny"] == "safety_state"
    assert arm.calls == []
    assert [e.decision for e in chain.entries] == ["deny"]
    assert chain.entries[0].decision_reason == f"safety_state: gateway state={state.value}"


@pytest.mark.parametrize("tool", ["arm.estop.clear", "arm.state", "arm.home", "estop"])
def test_nothing_but_a_declared_stop_is_exempt(tool):
    """Not the clear (it makes the arm movable again), not a read, not a
    motion, and not a tool that is merely named like a stop."""
    arm = _Arm()
    with _client(GatewayState.SAFE_STOP, allowed=(*ALLOWED, "estop"),
                 actuator=arm, actuator_config={}) as client:
        response = _post(client, tool, "HALT")

    assert response.status_code == 403, response.text
    assert response.json()["detail"]["deny"] == "safety_state"
    assert arm.calls == []


def test_a_stop_name_routed_to_an_actuator_that_does_not_declare_it_is_denied():
    """The exemption follows the actuator that receives the request: arm.estop
    is a stop for the arm, and nothing at all for the camera."""
    arm, cam, chain = _Arm(), _Camera(), AuditChain()
    with _client(GatewayState.ESTOP_ACTIVE, chain=chain,
                 actuators={"arm": arm, "cam": cam}) as client:
        response = _post(client, "arm.estop", "HALT", actuator_name="cam")

    assert response.status_code == 403, response.text
    assert response.json()["detail"]["deny"] == "safety_state"
    assert cam.calls == [] and arm.calls == []
    assert [e.decision for e in chain.entries] == ["deny"]


def test_a_stop_routed_by_name_to_its_actuator_runs_in_multi_actuator_mode():
    arm, cam = _Arm(), _Camera()
    with _client(GatewayState.ESTOP_ACTIVE, actuators={"arm": arm, "cam": cam}) as client:
        response = _post(client, "arm.estop", "HALT", actuator_name="arm")

    assert response.status_code == 200, response.text
    assert arm.calls == ["arm.estop"] and cam.calls == []


def test_the_exempt_stop_still_passes_every_other_gate():
    """Only the safety-state check is skipped. A stop the operator has not
    allowlisted is still refused by the allowlist, signed and audited."""
    arm, chain = _Arm(), AuditChain()
    with _client(GatewayState.SAFE_STOP, allowed=("arm.move_to",), chain=chain,
                 actuator=arm, actuator_config={}) as client:
        response = _post(client, "arm.estop", "HALT")

    assert response.status_code == 403, response.text
    assert response.json()["detail"]["deny"] == "tool_allowlist"
    assert arm.calls == []
    assert [e.decision for e in chain.entries] == ["deny"]


def test_a_stop_from_an_unknown_bearer_is_not_given_a_higher_tier():
    """The exemption does not touch the principal: a request with no bearer is
    still anon all the way to the actuator."""
    seen: list[str] = []

    class _TierSpy(_Arm):
        def execute(self, *, envelope, manifest_path, tier, config):
            seen.append(tier)
            return super().execute(envelope=envelope, manifest_path=manifest_path,
                                   tier=tier, config=config)

    with _client(GatewayState.SAFE_STOP, actuator=_TierSpy(), actuator_config={}) as client:
        response = client.post("/v1/invoke", json={
            "msg_id": "anon-stop", "type": "rcan/v1/invoke", "ruri": "rcan://RRN-test/arm",
            "scope": "HALT", "tool_name": "arm.estop", "tool_args": {},
            "manifest_path": str(FIXTURES / "signed-good.md"),
        })
    assert response.status_code == 200, response.text
    assert seen == ["anon"]
