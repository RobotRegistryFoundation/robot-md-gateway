"""SF-002's heartbeat comes from a supervisor credential, and only from one.

The heartbeat answers one question: does the person who can stop the robot
still have a working link to it? Accepting it from any known bearer meant the
agent's own credential could keep the robot movable after the person's link had
gone (review of #35, finding 2). A supervisor is a heartbeat-only credential:
`role: supervisor` in bearers.yaml, read tier, so on /v1/invoke it can stop the
robot and read its state and can never move it. No credential that can move
the robot is accepted as a heartbeat, and bearers.yaml cannot make one that is
both.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest
import yaml
from fastapi.testclient import TestClient

from robot_md_gateway.actuator import ActuatorOutcome
from robot_md_gateway.auth import SUPERVISOR, BearerStore, _BearerEntry
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.cert.safety import SafetyMonitor
from robot_md_gateway.receiver import make_app

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "manifests"


class _Resolver:
    def __init__(self):
        self.kid = (FIXTURES / "signing-key.kid").read_text().strip()
        self.pub_pem = (FIXTURES / "signing-key.pub").read_bytes()

    def resolve_public_key_pem(self, kid):
        return self.pub_pem if kid == self.kid else None


class _Arm:
    name = "arm"
    description = "test arm"
    config_schema: ClassVar[dict] = {}
    motion_capabilities = frozenset({"arm.move_to"})
    stop_capabilities = frozenset({"arm.estop"})

    def __init__(self):
        self.calls: list[str] = []

    def execute(self, *, envelope, manifest_path, tier, config):
        self.calls.append(envelope["tool_name"])
        return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})


def _write(tmp_path: Path, rows) -> Path:
    path = tmp_path / "bearers.yaml"
    path.write_text(yaml.safe_dump({"bearers": rows}))
    return path


# --- bearers.yaml -------------------------------------------------------------


def test_a_supervisor_entry_loads_as_read_tier(tmp_path):
    store = BearerStore.from_yaml(_write(tmp_path, [
        {"token": "s" * 43, "role": "supervisor", "caller": "craig-pendant"},
        {"token": "a" * 43, "tier": "actuate", "caller": "agent"},
    ]))
    supervisor = store.resolve("s" * 43)
    assert (supervisor.role, supervisor.tier, supervisor.caller_id) == (
        SUPERVISOR, "read", "craig-pendant")
    assert store.resolve("a" * 43).role is None


@pytest.mark.parametrize("tier", ["actuate", "commission"])
def test_a_supervisor_that_could_move_the_robot_is_refused(tmp_path, tier):
    path = _write(tmp_path, [{"token": "s" * 43, "role": "supervisor", "tier": tier}])
    with pytest.raises(ValueError, match="must not be able to move the robot"):
        BearerStore.from_yaml(path)


def test_an_unknown_role_is_refused(tmp_path):
    path = _write(tmp_path, [{"token": "s" * 43, "role": "admin", "tier": "read"}])
    with pytest.raises(ValueError, match="unknown role"):
        BearerStore.from_yaml(path)


def test_one_token_cannot_be_both_a_supervisor_and_an_actuator(tmp_path):
    path = _write(tmp_path, [
        {"token": "same" * 11, "role": "supervisor", "caller": "pendant"},
        {"token": "same" * 11, "tier": "actuate", "caller": "agent"},
    ])
    with pytest.raises(ValueError, match="listed more than once"):
        BearerStore.from_yaml(path)


def test_make_app_refuses_a_supervisor_entry_with_a_moving_tier():
    """For embedders that build entries themselves rather than load bearers.yaml."""
    bad = _BearerEntry(token="t", tier="actuate", caller_id="x", role=SUPERVISOR)
    with pytest.raises(ValueError, match="supervisor"):
        make_app(resolver=_Resolver(), bearers={"t": bad},
                 safety_monitor=SafetyMonitor(heartbeat_staleness_s=60))


# --- the routes ----------------------------------------------------------------

BEARERS = {"read-token": "read", "actuate-token": "actuate", "commission-token": "commission"}
SUP = {"sup-token": _BearerEntry(token="sup-token", tier="read", caller_id="pendant",
                                 role=SUPERVISOR)}


def _client(arm):
    app = make_app(
        resolver=_Resolver(),
        tool_allowlist=ToolAllowlist(allowed_tools=("arm.move_to", "arm.estop")),
        bearer_tiers=BEARERS, bearers=SUP,
        safety_monitor=SafetyMonitor(heartbeat_staleness_s=60),
        actuator=arm, actuator_config={},
    )
    return TestClient(app)


def _post(client, tool, scope, token):
    return client.post(
        "/v1/invoke",
        json={"msg_id": f"m-{tool}-{token}", "type": "rcan/v1/invoke",
              "ruri": "rcan://RRN-test/arm", "scope": scope, "tool_name": tool,
              "tool_args": {}, "manifest_path": str(FIXTURES / "signed-good.md")},
        headers={"Authorization": f"Bearer {token}"},
    )


@pytest.mark.parametrize("token", ["read-token", "actuate-token", "commission-token"])
def test_no_other_credential_is_accepted_as_a_heartbeat(token):
    with _client(_Arm()) as client:
        response = client.post("/v1/safety/heartbeat",
                               headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert response.json()["detail"]["deny"] == "not_a_supervisor"


def test_the_supervisor_heartbeat_is_accepted():
    with _client(_Arm()) as client:
        response = client.post("/v1/safety/heartbeat",
                               headers={"Authorization": "Bearer sup-token"})
    assert response.status_code == 200


def test_the_supervisor_cannot_move_the_robot():
    arm = _Arm()
    with _client(arm) as client:
        response = _post(client, "arm.move_to", "MANIPULATE", "sup-token")
    assert response.status_code == 403
    assert response.json()["detail"]["deny"] == "tier_policy"
    assert arm.calls == []


def test_the_supervisor_can_stop_the_robot():
    arm = _Arm()
    with _client(arm) as client:
        response = _post(client, "arm.estop", "SAFETY", "sup-token")
    assert response.status_code == 200, response.text
    assert arm.calls == ["arm.estop"]
