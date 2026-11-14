"""A refusal is recorded as a deny, wherever the gateway records an outcome.

Every gate before dispatch already records its refusal as ``decision="deny"``
with ``"<gate>: <reason>"``. The one that did not was the driver's own policy
gate. An actuator that answers ``outcome_kind="denied"`` (out_of_workspace,
estop_latched, no approval open) reached the caller as a signed 403
``deny: actuator_policy``, but the record written for it said
``decision="allow"``, ``decision_reason="ok"`` in the audit chain and
``status: "failure"`` in the signed receipt. Read back, the evidence filed a
refusal as an action that ran and failed.

These tests drive the real request path and read the records the gateway
writes: the audit chain, the receipt on the wire, and the NDJSON export.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from robot_md_gateway.actuator import ActuatorOutcome
from robot_md_gateway.attestation import SigningIdentity
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.receiver import make_app

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "manifests"
REFUSAL = "out_of_workspace: x=500mm is outside the declared workspace (-200 to 340mm)"


class _Resolver:
    def __init__(self):
        self.kid = (FIXTURES / "signing-key.kid").read_text().strip()
        self.pub_pem = (FIXTURES / "signing-key.pub").read_bytes()

    def resolve_public_key_pem(self, kid: str) -> bytes | None:
        return self.pub_pem if kid == self.kid else None


class _Arm:
    """Answers with whatever outcome the test gives it."""

    name = "arm"
    description = "test arm"
    config_schema: ClassVar[dict] = {}

    def __init__(self, outcome: ActuatorOutcome | Exception):
        self._outcome = outcome

    def execute(self, *, envelope, manifest_path, tier, config):
        if isinstance(self._outcome, Exception):
            raise self._outcome
        return self._outcome


def _refused() -> ActuatorOutcome:
    return ActuatorOutcome(
        success=False,
        outcome_kind="denied",
        error_message=REFUSAL,
        telemetry={"deny": "out_of_workspace", "reason": "x=500mm is outside"},
    )


def _app(actuator, chain=None, **extra):
    return make_app(
        resolver=_Resolver(),
        tool_allowlist=ToolAllowlist(allowed_tools=("arm.move_to",)),
        bearer_tiers={"actuate-token": "actuate"},
        actuator=actuator,
        actuator_config={},
        audit_chain=chain,
        **extra,
    )


def _move(client):
    return client.post(
        "/v1/invoke",
        json={
            "msg_id": "move-1",
            "type": "rcan/v1/invoke",
            "ruri": "rcan://RRN-test/arm",
            "scope": "MANIPULATE",
            "tool_name": "arm.move_to",
            "tool_args": {"x_mm": 500, "y_mm": 0, "z_mm": 100},
            "manifest_path": str(FIXTURES / "signed-good.md"),
        },
        headers={"Authorization": "Bearer actuate-token"},
    )


def _outcome_entry(chain: AuditChain):
    [entry] = [e for e in chain.entries if e.entry_kind == "outcome"]
    return entry


@pytest.fixture
def identity():
    return SigningIdentity(priv=Ed25519PrivateKey.generate(), kid="gw-kid", ran=None)


def test_an_actuator_refusal_is_audited_as_a_deny_with_its_reason():
    chain = AuditChain()
    with TestClient(_app(_Arm(_refused()), chain)) as client:
        response = _move(client)

    assert response.status_code == 403, response.text
    assert response.json()["detail"]["deny"] == "actuator_policy"
    entry = _outcome_entry(chain)
    assert entry.decision == "deny"
    assert entry.decision_reason == f"actuator_policy: {REFUSAL}"
    # The driver's own account still rides along, unchanged.
    assert entry.actuator_name == "arm"
    assert entry.actuator_outcome_kind == "denied"


def test_the_intent_written_before_the_refusal_still_reads_as_an_intent():
    """The pre-dispatch record is not rewritten: the gates did pass and the
    gateway did dispatch. What changed is only the record of how it went."""
    chain = AuditChain()
    with TestClient(_app(_Arm(_refused()), chain)) as client:
        _move(client)

    [intent] = [e for e in chain.entries if e.entry_kind == "intent"]
    assert intent.decision == "allow"
    assert intent.decision_reason.startswith("dispatching:")
    assert _outcome_entry(chain).intent_chain_hash == intent.chain_hash


def test_an_actuator_refusal_is_signed_as_denied_on_the_wire_and_in_the_export(
    tmp_path, identity
):
    export = tmp_path / "trace.ndjsonl"
    app = _app(
        _Arm(_refused()), AuditChain(),
        signing_identity=identity, attestation_export_file=export,
    )
    with TestClient(app) as client:
        response = _move(client)

    receipt = response.json()["detail"]["outcome"]
    assert receipt["status"] == "denied"
    assert receipt["error"] == {"kind": "actuator_policy", "message": f"actuator_policy: {REFUSAL}"}

    lines = [json.loads(x) for x in export.read_text().splitlines() if x.strip()]
    [line] = [r for r in lines if r["record_kind"] == "outcome"]
    assert line["outcome"] == receipt  # the export carries the same signed bytes


def test_an_action_that_ran_is_still_recorded_as_allow_ok(tmp_path, identity):
    chain = AuditChain()
    ran = ActuatorOutcome(success=True, outcome_kind="executed", telemetry={"reached": True})
    app = _app(_Arm(ran), chain, signing_identity=identity)
    with TestClient(app) as client:
        response = _move(client)

    assert response.status_code == 200, response.text
    assert response.json()["outcome"]["status"] == "ok"
    entry = _outcome_entry(chain)
    assert (entry.decision, entry.decision_reason) == ("allow", "ok")


def test_an_actuator_that_crashed_is_not_recorded_as_a_refusal(identity):
    """A fault is not a decision. The gates allowed it and the driver broke,
    so it stays an allow with an error outcome and a 500, never a deny."""
    chain = AuditChain()
    app = _app(_Arm(RuntimeError("bus timeout")), chain, signing_identity=identity)
    with TestClient(app, raise_server_exceptions=False) as client:
        response = _move(client)

    assert response.status_code == 500
    entry = _outcome_entry(chain)
    assert entry.decision == "allow"
    assert entry.actuator_error_kind == "RuntimeError"
