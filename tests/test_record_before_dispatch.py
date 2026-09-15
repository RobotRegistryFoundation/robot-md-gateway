"""OC-M-04: the gateway records BEFORE it dispatches, and the record says so.

Until v0.5.0a8 the allow path wrote nothing between "every gate passed" and
``target_actuator.execute()``. That was deliberate once: a record written after
the dispatch can say what happened, and one written before it cannot. RCAN 6.3
makes the write before driver dispatch normative anyway, and the reason is the
case the late record cannot cover at all: a driver that hangs, a process that is
killed mid-motion, or a robot unplugged between the gate and the wire left no
trace that anything had been attempted.

So both are written now, and the pair is the answer. These tests pin the four
things that make the pair honest:

  1. the intent is in the chain BEFORE the actuator is touched,
  2. the outcome points back at it,
  3. an intent with no outcome is named as a dispatch that never reported,
     NOT counted as an action and NOT reported as a gap in the record,
  4. a signing failure anywhere in here changes nothing about actuation.

Point 4 is the one to keep. A record is evidence, not enforcement. The day the
record can stop a robot is the day an operator turns the record off.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from robot_md_gateway.attestation import SigningIdentity
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.receiver import make_app

FIX = Path(__file__).parent / "fixtures" / "manifests"
MANIFEST_KID = (FIX / "signing-key.kid").read_text().strip()
MANIFEST_PUB = (FIX / "signing-key.pub").read_bytes()
GOOD_MANIFEST = str(FIX / "signed-good.md")
VERIFY_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_receipt.py"


class _Resolver:
    def __init__(self, mapping):
        self._m = mapping

    def resolve_public_key_pem(self, kid):
        return self._m.get(kid)


@pytest.fixture
def identity():
    return SigningIdentity(
        priv=Ed25519PrivateKey.generate(), kid="gw-kid", ran="RAN-000000000020"
    )


def _envelope(msg_id="msg-intent-1", **over):
    body = {
        "msg_id": msg_id,
        "type": "INVOKE",
        "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "READ",
        "tool_name": "mcp__robot__render",
        "tool_args": {},
        "manifest_path": GOOD_MANIFEST,
        "nonce": "nonce-abc",
        "envelope_id": "env-abc",
    }
    body.update(over)
    return body


def _app(actuator, chain, *, identity=None, export=None):
    return make_app(
        resolver=_Resolver({MANIFEST_KID: MANIFEST_PUB}),
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
        audit_chain=chain,
        actuator=actuator,
        signing_identity=identity,
        attestation_export_file=export,
    )


def _lines(export: Path):
    return [json.loads(x) for x in export.read_text().splitlines() if x.strip()]


def test_intent_entry_precedes_actuator_execute(identity, tmp_path):
    """The actuator itself is the witness: by the time execute() is running, the
    chain already holds an intent entry for this msg_id."""
    chain = AuditChain()
    seen: dict = {}

    class _Witness:
        name = "witness"

        def execute(self, **kw):
            from robot_md_gateway.actuator import ActuatorOutcome

            # Snapshot what the chain says AT THE MOMENT OF DISPATCH. Anything
            # asserted after the request returns cannot tell "written before"
            # from "written after".
            seen["kinds"] = [e.entry_kind for e in chain.entries]
            seen["intent"] = next(
                (e for e in chain.entries
                 if e.entry_kind == "intent" and e.msg_id == "msg-intent-1"),
                None,
            )
            return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})

    export = tmp_path / "traces.ndjson"
    app = _app(_Witness(), chain, identity=identity, export=export)
    r = TestClient(app).post("/v1/invoke", json=_envelope())
    assert r.status_code == 200

    assert seen["kinds"] == ["intent"], "no outcome may exist yet at dispatch time"
    intent = seen["intent"]
    assert intent is not None
    assert intent.tool_name == "mcp__robot__render"
    assert intent.actuator_name == "witness"
    assert intent.envelope_id == "env-abc"
    assert intent.nonce == "nonce-abc"
    assert intent.tier == "anon"          # no bearer on this request
    assert intent.caller is None
    # AN INTENT IS NOT AN OUTCOME. It carries no actuator result of any kind,
    # because at the moment it was written there was none to carry.
    assert intent.actuator_outcome_kind is None
    assert intent.actuator_error_kind is None
    assert intent.actuator_telemetry_sha256 is None

    # And the same thing is durable: the intent line is in the export, ahead of
    # the outcome line, with no `outcome` key on it.
    lines = _lines(export)
    assert [ln.get("record_kind") for ln in lines] == ["intent", "outcome"]
    assert "outcome" not in lines[0]
    assert lines[0]["intent"]["status"] == "dispatching"
    assert lines[0]["intent"]["envelope_signature"]["kid"] == "gw-kid"


def test_outcome_references_intent_hash(identity, tmp_path):
    from robot_md_gateway.actuator import ActuatorOutcome

    class _Ok:
        name = "ok"

        def execute(self, **kw):
            return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})

    chain = AuditChain()
    export = tmp_path / "traces.ndjson"
    app = _app(_Ok(), chain, identity=identity, export=export)
    assert TestClient(app).post("/v1/invoke", json=_envelope()).status_code == 200

    intent, outcome = chain.entries
    assert intent.entry_kind == "intent"
    assert outcome.entry_kind == "outcome"
    assert intent.intent_chain_hash is None       # an intent points at nothing
    assert outcome.intent_chain_hash == intent.chain_hash
    assert outcome.chain_prev == intent.chain_hash  # and they are adjacent

    # The NDJSON side carries the same pointer as an UNSIGNED HINT (it is not
    # inside the outcome's signed bytes, and the docstring says so). The signed
    # linkage is the audit chain's.
    lines = _lines(export)
    assert lines[1]["intent_chain_hash"] == intent.chain_hash
    assert "intent_chain_hash" not in lines[1]["outcome"]


def test_an_intent_for_a_failed_action_does_not_read_as_a_success(identity, tmp_path):
    """The whole hazard of recording early, pinned: the actuator raises, and
    nothing in the intent line claims anything happened."""
    class _Boom:
        name = "boom"

        def execute(self, **kw):
            raise RuntimeError("the arm was unplugged")

    chain = AuditChain()
    export = tmp_path / "traces.ndjson"
    app = _app(_Boom(), chain, identity=identity, export=export)
    r = TestClient(app).post("/v1/invoke", json=_envelope("msg-boom"))
    assert r.status_code == 500

    lines = _lines(export)
    assert lines[0]["intent"]["status"] == "dispatching"   # never "ok"
    assert lines[1]["outcome"]["status"] == "error"
    assert lines[1]["outcome"]["error"]["kind"] == "RuntimeError"


def test_intent_without_outcome_is_reported_by_verifier(identity, tmp_path):
    """Truncate the export after the intent line: the walk names it as a
    dispatch that never reported, which is what it is. It is NOT a gap (no seq
    is missing) and it is NOT an action that happened."""
    from robot_md_gateway.actuator import ActuatorOutcome

    class _Ok:
        name = "ok"

        def execute(self, **kw):
            return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})

    export = tmp_path / "traces.ndjson"
    app = _app(_Ok(), AuditChain(), identity=identity, export=export)
    assert TestClient(app).post(
        "/v1/invoke", json=_envelope("msg-cut")
    ).status_code == 200

    raw = export.read_text().splitlines()
    assert len(raw) == 2
    cut = tmp_path / "cut.ndjson"
    cut.write_text(raw[0] + "\n")          # the intent, and nothing after it

    proc = subprocess.run(
        [sys.executable, str(VERIFY_SCRIPT), "--walk", str(cut)],
        capture_output=True, text=True,
    )
    out = proc.stdout + proc.stderr
    assert "dispatch never reported" in out
    assert "msg-cut" in out
    assert "GAP" not in out                # a missing outcome is not a gap
    assert proc.returncode == 3            # findings, not an integrity failure


def test_signing_failure_does_not_block_actuation(tmp_path):
    """A signing or attestation failure must never crash the request or alter
    actuation. This is the gateway's existing best-effort contract, kept
    verbatim for the new record: the actuator still runs, the client still gets
    its 200, and the only cost is the record that could not be written.

    The failure is injected at the key itself (a signing key that raises, which
    is what a yanked HSM or a revoked handle looks like from here) rather than
    by patching a module attribute, so the test does not depend on which module
    object the app happened to close over."""
    from robot_md_gateway.actuator import ActuatorOutcome

    class _DeadKey:
        def sign(self, data):
            raise RuntimeError("HSM went away")

    identity = SigningIdentity(priv=_DeadKey(), kid="gw-kid", ran="RAN-000000000020")

    calls: list[dict] = []

    class _Counting:
        name = "counting"

        def execute(self, **kw):
            calls.append(kw)
            return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})

    chain = AuditChain()
    export = tmp_path / "traces.ndjson"
    app = _app(_Counting(), chain, identity=identity, export=export)
    r = TestClient(app).post("/v1/invoke", json=_envelope("msg-nosig"))

    assert r.status_code == 200                       # the request did not crash
    assert len(calls) == 1                            # the robot still moved
    # The intent AUDIT entry survives: it is written before any signing happens,
    # for the same reason the outcome audit entry is (evidence must not be
    # suppressed by a downstream signing failure).
    assert [e.entry_kind for e in chain.entries] == ["intent", "outcome"]
    # Nothing could be signed, so nothing was exported, and the wire receipt
    # says unattested rather than pretending.
    assert not export.exists()
    assert r.json()["attestation"] == "unattested"
