"""A tool that moves the robot must be invoked under a scope that says so.

EV-03's software-in-the-loop run (October 2026) sent `arm.move_to` in an
envelope whose `scope` said OBSERVE, holding an actuate bearer, and it executed:
the tier gate and the HiTL gates key off the caller-written scope, and nothing
compared it with the tool. These tests pin the gate that does.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import ClassVar

import pytest
from fastapi.testclient import TestClient

from robot_md_gateway.__main__ import _claim_devices
from robot_md_gateway.actuator import ActuatorOutcome
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.policy import ToolAllowlist, check_tier, check_tool_scope
from robot_md_gateway.receiver import make_app

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "manifests"


class _Resolver:
    def __init__(self):
        self.kid = (FIXTURES / "signing-key.kid").read_text().strip()
        self.pub_pem = (FIXTURES / "signing-key.pub").read_bytes()

    def resolve_kid_for_robot(self, ruri: str) -> str | None:
        return self.kid

    def resolve_public_key_pem(self, kid: str) -> bytes | None:
        return self.pub_pem if kid == self.kid else None


class _Arm:
    """An actuator that declares which of its tools move the robot."""

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


class _Undeclared(_Arm):
    """An actuator written before motion_capabilities existed."""

    motion_capabilities = None


def _client(actuator, chain=None):
    app = make_app(
        resolver=_Resolver(),
        tool_allowlist=ToolAllowlist(allowed_tools=("arm.move_to", "arm.home", "arm.estop")),
        bearer_tiers={"actuate-token": "actuate"},
        actuator=actuator,
        actuator_config={},
        audit_chain=chain,
    )
    return TestClient(app)


def _post(client, tool, scope):
    return client.post(
        "/v1/invoke",
        json={
            "msg_id": f"m-{tool}-{scope}",
            "type": "rcan/v1/invoke",
            "ruri": "rcan://RRN-test/arm",
            "scope": scope,
            "tool_name": tool,
            "tool_args": {},
            "manifest_path": str(FIXTURES / "signed-good.md"),
        },
        headers={"Authorization": "Bearer actuate-token"},
    )


@pytest.mark.parametrize("scope", ["OBSERVE", "READ", "status", "observe", ""])
def test_a_motion_tool_under_a_scope_that_does_not_move_is_denied_and_signed(scope):
    arm, chain = _Arm(), AuditChain()
    with _client(arm, chain) as client:
        response = _post(client, "arm.move_to", scope)

    assert response.status_code == 403, response.text
    assert response.json()["detail"]["deny"] == "tool_scope"
    assert arm.calls == []
    # A refusal is a policy decision, so it is audited like every other deny.
    assert [e.decision for e in chain.entries] == ["deny"]
    assert "tool_scope" in chain.entries[0].decision_reason


@pytest.mark.parametrize("scope", ["MANIPULATE", "manipulate", "Actuate", "EXECUTE"])
def test_a_motion_tool_under_an_actuation_scope_runs(scope):
    arm = _Arm()
    with _client(arm) as client:
        response = _post(client, "arm.move_to", scope)
    assert response.status_code == 200, response.text
    assert arm.calls == ["arm.move_to"]


def test_the_stop_is_never_held_to_a_motion_scope():
    """Stopping is not motion: a stop under OBSERVE scope still runs."""
    arm = _Arm()
    with _client(arm) as client:
        response = _post(client, "arm.estop", "OBSERVE")
    assert response.status_code == 200, response.text
    assert arm.calls == ["arm.estop"]


def test_an_actuator_that_declares_no_motion_tools_is_unaffected():
    arm = _Undeclared()
    with _client(arm) as client:
        response = _post(client, "arm.move_to", "OBSERVE")
    assert response.status_code == 200, response.text


def test_check_tool_scope_is_pure():
    assert check_tool_scope("arm.move_to", "OBSERVE", {"arm.move_to"}, msg_id="m")[0] is False
    assert check_tool_scope("arm.move_to", "MANIPULATE", {"arm.move_to"}, msg_id="m")[0] is True
    assert check_tool_scope("arm.state", "OBSERVE", {"arm.move_to"}, msg_id="m")[0] is True


@pytest.mark.parametrize("scope", ["manipulate", "Manipulate", "commission"])
def test_the_tier_gate_reads_scope_names_in_any_case(scope):
    """Lower case used to walk straight past GW-003."""
    assert check_tier("read", scope, msg_id="m")[0] is False


def test_lower_case_commission_still_needs_the_commission_tier():
    assert check_tier("actuate", "commission", msg_id="m")[0] is False
    assert check_tier("commission", "commission", msg_id="m")[0] is True


# --- claiming the device at startup -------------------------------------------


class _Claims(_Arm):
    def __init__(self, fail: OSError | None = None):
        super().__init__()
        self.claimed: list[dict] = []
        self._fail = fail

    def claim(self, config):
        if self._fail is not None:
            raise self._fail
        self.claimed.append(config)


def test_actuators_that_can_claim_their_device_do_so_with_their_config():
    first, second = _Claims(), _Arm()
    _claim_devices([(first, {"port": "/dev/ttyACM0", "baud": 1_000_000}), (second, {})])
    assert first.claimed == [{"port": "/dev/ttyACM0", "baud": 1_000_000}]


def test_a_device_that_cannot_be_claimed_is_logged_not_fatal(caplog):
    busy = _Claims(fail=OSError(16, "Device or resource busy"))
    with caplog.at_level(logging.ERROR, logger="robot_md_gateway.claim"):
        _claim_devices([(busy, {"port": "/dev/ttyACM0"})])
    assert "device_claim_failed" in caplog.text
    assert "busy" in caplog.text
