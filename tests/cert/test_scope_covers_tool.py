"""The envelope's declared scope must cover the tool it names.

EV-03 (8 Oct 2026): an actuate-tier envelope whose scope said OBSERVE executed
`arm.move_to`. check_tier reads the scope, check_tool_tier the credential, and
neither asked whether the scope the signer declared can carry the tool. The
actuator already declares which of its tools move the robot; the gateway now
refuses a motion tool under a non-actuation scope, signed and audited, before
dispatch. A stop is never refused for its scope.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest
from fastapi.testclient import TestClient

from robot_md_gateway.actuator import ActuatorOutcome
from robot_md_gateway.cert import report as cert_report
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.receiver import make_app

FIXTURES = Path(__file__).parent.parent / "fixtures" / "manifests"


@pytest.fixture(autouse=True)
def _reset():
    cert_report.reset()
    yield


class _Arm:
    """Declares what moves and what stops, as the real drivers do, and records
    every call that reaches it."""

    name = "arm"
    description = "test double"
    config_schema: ClassVar[dict] = {}
    motion_capabilities = frozenset({"arm.move_to", "arm.home"})
    stop_capabilities = frozenset({"arm.estop"})

    def __init__(self) -> None:
        self.calls: list[str] = []

    def execute(self, *, envelope, manifest_path, tier, config):
        self.calls.append(envelope["tool_name"])
        return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})


def _client(arm: _Arm) -> TestClient:
    kid = (FIXTURES / "signing-key.kid").read_text().strip()
    pub = (FIXTURES / "signing-key.pub").read_bytes()

    class Resolver:
        def resolve_public_key_pem(self, k):
            return pub if k == kid else None

    app = make_app(
        resolver=Resolver(),
        tool_allowlist=ToolAllowlist(allowed_tools=("arm.move_to", "arm.home", "arm.estop",
                                                    "arm.state")),
        bearer_tiers={"actuate-token": "actuate", "read-token": "read"},
        actuator=arm,
    )
    return TestClient(app)


def _invoke(client, tool, scope, token="actuate-token"):
    return client.post(
        "/v1/invoke",
        headers={"Authorization": f"Bearer {token}"},
        json={"msg_id": f"{tool}-{scope}", "type": "INVOKE", "ruri": "rcan://x/y/z/0",
              "scope": scope, "tool_name": tool, "tool_args": {},
              "manifest_path": str(FIXTURES / "signed-good.md")},
    )


@pytest.mark.parametrize("scope", ["OBSERVE", "STATUS", "DISCOVER", "observe", ""])
def test_a_motion_tool_under_a_non_actuation_scope_is_refused(scope):
    arm = _Arm()
    response = _invoke(_client(arm), "arm.move_to", scope)

    assert response.status_code == 403
    assert response.json()["detail"]["deny"] == "scope_mismatch"
    assert arm.calls == [], "the refusal must come before dispatch"


@pytest.mark.parametrize("scope", ["MANIPULATE", "ACTUATE", "EXECUTE"])
def test_a_motion_tool_under_an_actuation_scope_is_dispatched(scope):
    arm = _Arm()
    response = _invoke(_client(arm), "arm.move_to", scope)
    assert response.status_code == 200, response.text
    assert arm.calls == ["arm.move_to"]


def test_no_scope_refuses_a_stop():
    arm = _Arm()
    response = _invoke(_client(arm), "arm.estop", "OBSERVE", token="read-token")
    assert response.status_code == 200, response.text
    assert arm.calls == ["arm.estop"]


def test_a_tool_that_moves_nothing_keeps_its_observe_scope():
    arm = _Arm()
    response = _invoke(_client(arm), "arm.state", "OBSERVE", token="read-token")
    assert response.status_code == 200, response.text
    assert arm.calls == ["arm.state"]


def test_an_actuator_that_declares_no_motion_tools_is_unaffected():
    """Additive: a driver written before motion_capabilities existed keeps
    working exactly as it did."""

    class Legacy(_Arm):
        motion_capabilities = None

    arm = Legacy()
    response = _invoke(_client(arm), "arm.move_to", "OBSERVE")
    assert response.status_code == 200, response.text
