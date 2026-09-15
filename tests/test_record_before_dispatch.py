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
    # Adjacent HERE, with one invoke in flight. Adjacency is NOT the contract
    # and must not be relied on: see
    # test_two_invokes_at_once_are_linked_by_the_pointer_not_by_adjacency.
    assert outcome.chain_prev == intent.chain_hash

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


# ---------------------------------------------------------------------------
# 5. Two invokes at once. The pair only means anything if the outcome points at
#    ITS OWN intent, and the chain only means anything if it does not fork.
# ---------------------------------------------------------------------------


def test_audit_chain_append_returns_the_entry_it_stored():
    """The receiver has to read the hash off the RETURNED entry. `entries[-1]`
    is whatever landed last, which under two concurrent invokes is not
    necessarily this thread's intent, and an outcome pointing at somebody
    else's dispatch is worse evidence than an outcome pointing at nothing."""
    from robot_md_gateway.cert.audit import AuditEntry

    chain = AuditChain()
    stored = chain.append(AuditEntry(
        msg_id="m1", timestamp_ms=0, decision="allow", decision_reason="d",
        envelope_kid=None, entry_kind="intent",
    ))
    assert stored is chain.entries[-1]
    assert stored.msg_id == "m1"
    assert len(stored.chain_hash) == 64
    assert stored.chain_prev == "0" * 64


def test_concurrent_appends_do_not_fork_the_audit_chain():
    """Every entry's chain_prev is the previous entry's chain_hash.

    `append` used to read `entries[-1].chain_hash`, hash, and then append, with
    bytecode boundaries between the three. Two Starlette worker threads read the
    same predecessor and both linked to it. Measured on this Pi with the switch
    interval turned down: 257 to 302 of 400 entries carried a chain_prev that was
    not the previous entry's chain_hash. The entries were all still there; what
    stopped being provable was their order, which is the one thing a hash chain
    is for.
    """
    import sys as _sys
    import threading as _t

    from robot_md_gateway.cert.audit import AuditEntry

    chain = AuditChain()
    n_threads, per_thread = 8, 25
    start = _t.Barrier(n_threads)
    mine_came_back: list[bool] = []

    def worker(i: int) -> None:
        start.wait()
        for j in range(per_thread):
            stored = chain.append(AuditEntry(
                msg_id=f"{i}-{j}", timestamp_ms=0, decision="allow",
                decision_reason="d" * 200, envelope_kid="k", entry_kind="intent",
            ))
            mine_came_back.append(stored.msg_id == f"{i}-{j}")

    old = _sys.getswitchinterval()
    _sys.setswitchinterval(1e-6)  # make the interleaving reliable, not lucky
    try:
        ts = [_t.Thread(target=worker, args=(i,)) for i in range(n_threads)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
    finally:
        _sys.setswitchinterval(old)

    assert len(chain.entries) == n_threads * per_thread
    assert all(mine_came_back), "append returned another thread's entry"
    breaks = [
        k for k in range(1, len(chain.entries))
        if chain.entries[k].chain_prev != chain.entries[k - 1].chain_hash
    ]
    assert not breaks, f"the chain forked at {len(breaks)} entries"


# ---------------------------------------------------------------------------
# 6. A full disk, a read-only filesystem, a permission change. The record path
#    is best effort BY CONTRACT: the robot still moves and the caller still
#    gets its signed outcome. A record that can stop a robot is a record an
#    operator turns off.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target,err",
    [
        ("write_trace_head", OSError(28, "No space left on device")),
        ("write_trace_head", OSError(30, "Read-only file system")),
        ("append_trace_line", OSError(13, "Permission denied")),
        ("append_trace_line", OSError(28, "No space left on device")),
    ],
)
def test_a_failed_evidence_write_still_dispatches_and_still_signs(
    identity, tmp_path, monkeypatch, target, err,
):
    """The disk is gone in four different ways and none of them reaches the
    robot or the caller. The actuator is still called exactly once, the response
    is still 200, and the outcome in it is still signed. The only thing lost is
    the record, which is the only thing that MAY be lost."""
    from robot_md_gateway import attestation as attn
    from robot_md_gateway import receiver as rcv
    from robot_md_gateway.actuator import ActuatorOutcome

    calls: list[dict] = []

    class _Counting:
        name = "counting"

        def execute(self, **kw):
            calls.append(kw)
            return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})

    def boom(*a, **kw):
        raise err

    # Patch BOTH module objects. receiver.py does `from .attestation import
    # append_trace_line`, so it holds its own reference and patching only the
    # attestation module would leave the test passing while injecting nothing.
    monkeypatch.setattr(attn, target, boom)
    if hasattr(rcv, target):
        monkeypatch.setattr(rcv, target, boom)

    chain = AuditChain()
    export = tmp_path / "traces.ndjson"
    app = _app(_Counting(), chain, identity=identity, export=export)
    r = TestClient(app).post("/v1/invoke", json=_envelope("msg-nodisk"))

    assert r.status_code == 200, "an unwritable export must not fail the request"
    assert len(calls) == 1, "an unwritable export must not change actuation"
    body = r.json()
    assert body["attestation"] == "attested"
    assert "envelope_signature" in body["outcome"]
    # The audit chain is in memory and survives a dead disk, both halves of it.
    assert [e.entry_kind for e in chain.entries] == ["intent", "outcome"]
    assert chain.entries[1].intent_chain_hash == chain.entries[0].chain_hash


# ---------------------------------------------------------------------------
# 7. Five new fields on AuditEntry. Nothing that already exists may stop
#    verifying because of them.
# ---------------------------------------------------------------------------


def test_an_audit_bundle_exported_before_these_fields_still_verifies():
    """`verify_audit_bundle` recomputes each entry's hash from the DICT in the
    bundle, not from an AuditEntry rebuilt out of it, so a bundle whose entries
    predate `entry_kind` is hashed over exactly the bytes it was hashed over
    when it was signed. That is the property that makes adding a field safe, and
    it is worth a test because the obvious alternative implementation (rehydrate
    into the dataclass, then hash) would have silently invalidated every bundle
    ever exported."""
    import base64
    import hashlib

    from rcan.audit_bundle import canonical_json

    from robot_md_gateway.cert.audit import verify_audit_bundle

    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # A v0.5.0a7 entry: the field set as it was, and NOT one field more.
    old_entry = {
        "msg_id": "m-old", "timestamp_ms": 1, "decision": "allow",
        "decision_reason": "ok", "envelope_kid": "k", "actuator_name": None,
        "actuator_outcome_kind": None, "actuator_telemetry_sha256": None,
        "actuator_telemetry_path": None, "actuator_error_kind": None,
        "caller": "readonly-probe", "tier": "read", "chain_prev": "0" * 64,
    }
    old_entry["chain_hash"] = hashlib.sha256(canonical_json(old_entry)).hexdigest()
    body = {
        "schema_version": "1.0", "exported_at": "2026-09-01T00:00:00+00:00",
        "entry_count": 1, "entries": [old_entry],
    }
    bundle = {
        **body,
        "signature": {
            "kid": "gw-old", "alg": "Ed25519",
            "sig": base64.b64encode(priv.sign(canonical_json(body))).decode(),
        },
    }
    assert verify_audit_bundle(bundle, kid_to_pem={"gw-old": pub_pem}) is True


def test_a_new_entry_defaults_to_outcome_so_old_entries_keep_their_meaning():
    from robot_md_gateway.cert.audit import AuditEntry

    e = AuditEntry(msg_id="m", timestamp_ms=0, decision="allow",
                   decision_reason="r", envelope_kid=None)
    assert e.entry_kind == "outcome"
    assert (e.tool_name, e.envelope_id, e.nonce, e.intent_chain_hash) == (
        None, None, None, None)


def test_the_audit_last_route_is_not_a_fixed_field_set():
    """`GET /v1/audit/last` returns the entry's `__dict__`, and the iOS client
    decodes it into CanonicalValue, a schema-free JSON value. Five new keys ride
    along and nothing there has a field list to fall out of date. Pinned so the
    route is not 'tidied' into a response model that would start dropping the
    fields the entry's own chain hash was computed over."""
    import inspect

    from robot_md_gateway import receiver as rcv

    src = inspect.getsource(rcv.make_app)
    assert "return last.__dict__" in src


def test_two_invokes_at_once_are_linked_by_the_pointer_not_by_adjacency(identity, tmp_path):
    """With one invoke in flight the pair is physically adjacent in the chain.
    WITH TWO IT IS NOT, and it was never going to be: A's intent, B's intent,
    A's outcome, B's outcome is a perfectly ordinary interleaving of two
    Starlette worker threads.

    So `intent_chain_hash` is the linkage and adjacency is a coincidence. This
    test holds the actuator open until both requests are inside it, which forces
    the interleaving rather than hoping for it, and then asserts that each
    outcome points at ITS OWN intent across the gap.
    """
    import threading

    from robot_md_gateway.actuator import ActuatorOutcome

    both_in = threading.Barrier(2, timeout=10)

    class _Slow:
        name = "slow"

        def execute(self, **kw):
            both_in.wait()          # neither returns until both have dispatched
            return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})

    chain = AuditChain()
    export = tmp_path / "traces.ndjson"
    client = TestClient(_app(_Slow(), chain, identity=identity, export=export))

    results: list[int] = []

    def go(msg_id: str) -> None:
        results.append(client.post("/v1/invoke", json=_envelope(msg_id)).status_code)

    ts = [threading.Thread(target=go, args=(m,)) for m in ("msg-a", "msg-b")]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert results == [200, 200]

    kinds = [e.entry_kind for e in chain.entries]
    assert kinds == ["intent", "intent", "outcome", "outcome"], (
        "the actuator held both requests open, so the interleaving is forced"
    )
    by_id: dict[str, dict[str, object]] = {}
    for e in chain.entries:
        by_id.setdefault(e.msg_id, {})[e.entry_kind] = e
    adjacent = []
    for msg_id in ("msg-a", "msg-b"):
        intent, outcome = by_id[msg_id]["intent"], by_id[msg_id]["outcome"]
        # THE POINTER IS ALWAYS RIGHT. This is the whole contract.
        assert outcome.intent_chain_hash == intent.chain_hash
        adjacent.append(outcome.chain_prev == intent.chain_hash)
    # ADJACENCY IS NOT. With this interleaving the inner pair happens to sit
    # together and the outer pair cannot: at least one outcome has another
    # request's entry between it and its own intent. Nothing may read the pair
    # off the chain by position.
    assert not all(adjacent), "the interleaving did not separate either pair"

    # The chain itself is still unbroken, and the export still has four lines
    # numbered 1..4 with no duplicate and no break.
    assert all(
        chain.entries[k].chain_prev == chain.entries[k - 1].chain_hash
        for k in range(1, 4)
    )
    assert [ln["seq"] for ln in _lines(export)] == [1, 2, 3, 4]
