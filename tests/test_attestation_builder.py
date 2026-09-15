"""Status mapping + outcome builder + trace wrapper (§3.4/§3.5/§3.7)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from rcan.audit_bundle import canonical_json

from robot_md_gateway import attestation
from robot_md_gateway.actuator import ActuatorOutcome
from robot_md_gateway.attestation import (
    CHAIN_NOTE_HEAD_RECOVERED,
    CHAIN_NOTE_UNNUMBERED_HISTORY,
    GENESIS_CHAIN_PREV,
    append_trace_line,
    build_action_trace,
    build_intent,
    build_intent_trace,
    build_outcome,
    head_file_for,
    outcome_status,
    telemetry_sha256_of,
)


def test_status_deny_maps_to_denied():
    assert outcome_status(decision="deny", success=None, error_kind=None) == "denied"
    assert outcome_status(decision="deny", success=None, error_kind="X") == "denied"


def test_status_allow_success_maps_to_ok():
    assert outcome_status(decision="allow", success=True, error_kind=None) == "ok"


def test_status_allow_clean_failure_maps_to_failure():
    assert outcome_status(decision="allow", success=False, error_kind=None) == "failure"


def test_status_allow_exception_maps_to_error():
    assert outcome_status(decision="allow", success=False, error_kind="ValueError") == "error"


def test_telemetry_sha256_of_inmemory_dict_matches_canonical_json_hash():
    outcome = ActuatorOutcome(success=True, outcome_kind="executed", telemetry={"b": 2, "a": 1})
    expected = hashlib.sha256(canonical_json({"b": 2, "a": 1})).hexdigest()
    assert telemetry_sha256_of(outcome) == expected


def test_telemetry_sha256_of_file_hashes_file_bytes(tmp_path):
    p = tmp_path / "telem.bin"
    p.write_bytes(b"raw-telemetry-bytes")
    outcome = ActuatorOutcome(
        success=True, outcome_kind="executed", telemetry={}, telemetry_path=p
    )
    assert telemetry_sha256_of(outcome) == hashlib.sha256(b"raw-telemetry-bytes").hexdigest()


def test_telemetry_sha256_of_returns_none_when_empty():
    outcome = ActuatorOutcome(success=True, outcome_kind="no_op", telemetry={})
    assert telemetry_sha256_of(outcome) is None


def test_telemetry_sha256_of_returns_none_when_outcome_is_none():
    assert telemetry_sha256_of(None) is None


def test_build_action_trace_shape_and_hints():
    invoke = {"msg_id": "m1", "ruri": "rcan://lab/x/bot/0", "envelope_signature": {"kid": "op"}}
    outcome = {"corr_id": "m1", "rrn": "RRN-000000000011", "status": "ok",
               "envelope_signature": {"kid": "gw"}}

    rec = build_action_trace(
        invoke=invoke, outcome=outcome, ruri="rcan://lab/x/bot/0", rrn="RRN-000000000011"
    )

    assert rec == {
        "v": "rcan-action-trace/1",
        "record_kind": "outcome",
        "invoke": invoke,
        "outcome": outcome,
        "corr_id": "m1",
        "ruri": "rcan://lab/x/bot/0",
        "rrn": "RRN-000000000011",
    }
    # seq and chain_prev are properties of a POSITION IN A FILE, not of a
    # record, so the pure builder never invents them. append_trace_line does.
    assert "seq" not in rec and "chain_prev" not in rec


def test_build_action_trace_passes_invoke_verbatim():
    invoke = {"msg_id": "z", "extra_unknown_field": [1, 2, 3]}
    rec = build_action_trace(invoke=invoke, outcome={"corr_id": "z"}, ruri=None, rrn="RRN-1")
    assert rec["invoke"] is invoke  # verbatim, no copy/mutation
    assert rec["corr_id"] == "z"
    assert rec["ruri"] is None


def test_build_outcome_allow_ok_has_required_fields_no_error():
    out = build_outcome(
        corr_id="m1",
        rrn="RRN-000000000011",
        status="ok",
        started_at="2026-06-06T00:00:00+00:00",
        ended_at="2026-06-06T00:00:00.120000+00:00",
        duration_ms=120,
        telemetry_sha256="0" * 64,
        error=None,
        result_summary=None,
    )
    # v2 receipt shape: receipt_version + caller + tier are ALWAYS written,
    # null included, so a reader can tell "no caller declared for that bearer"
    # from "this gateway was not recording callers at all". Everything else
    # keeps the omit-when-None rule.
    assert out == {
        "receipt_version": 2,
        "corr_id": "m1",
        "rrn": "RRN-000000000011",
        "status": "ok",
        "started_at": "2026-06-06T00:00:00+00:00",
        "ended_at": "2026-06-06T00:00:00.120000+00:00",
        "duration_ms": 120,
        "telemetry_sha256": "0" * 64,
        "caller": None,
        "tier": None,
    }
    assert "error" not in out
    assert "envelope_signature" not in out


def test_build_outcome_denied_includes_error_kind_and_message():
    out = build_outcome(
        corr_id="m2",
        rrn="RRN-000000000011",
        status="denied",
        started_at="2026-06-06T00:00:00+00:00",
        ended_at="2026-06-06T00:00:00+00:00",
        duration_ms=None,
        telemetry_sha256=None,
        error={"kind": "hitl_required", "message": "destructive scope"},
        result_summary=None,
    )
    assert out["status"] == "denied"
    assert out["error"] == {"kind": "hitl_required", "message": "destructive scope"}
    # Optional fields that are None must be omitted entirely (clean signed shape).
    assert "duration_ms" not in out
    assert "telemetry_sha256" not in out
    assert "result_summary" not in out


def test_build_outcome_omits_all_none_optionals():
    out = build_outcome(
        corr_id="m3",
        rrn="RRN-000000000011",
        status="failure",
        started_at="2026-06-06T00:00:00+00:00",
        ended_at="2026-06-06T00:00:00+00:00",
        duration_ms=None,
        telemetry_sha256=None,
        error={"kind": "actuator_failure", "message": "clean false"},
        result_summary="partial",
    )
    assert set(out) == {
        "receipt_version", "corr_id", "rrn", "status", "started_at", "ended_at",
        "error", "result_summary", "caller", "tier",
    }


# --------------------------------------------------------------------------
# OC-10: seq, chain_prev and the head file.
# --------------------------------------------------------------------------


def test_trace_line_carries_seq_and_chain_prev(tmp_path):
    """Every line written from v0.5.0a8 is numbered and linked to the one
    before it, so a removed line leaves a hole a verifier can see."""
    export = tmp_path / "traces.ndjson"

    first = append_trace_line(export, build_action_trace(
        invoke={"msg_id": "a"}, outcome={"corr_id": "a"}, ruri=None, rrn="RRN-1",
    ))
    second = append_trace_line(export, build_action_trace(
        invoke={"msg_id": "b"}, outcome={"corr_id": "b"}, ruri=None, rrn="RRN-1",
    ))

    assert first["seq"] == 1
    assert first["chain_prev"] == GENESIS_CHAIN_PREV
    assert second["seq"] == 2

    raw = export.read_text().splitlines()
    # The link is over the bytes actually on disk, without the newline, so a
    # third party recomputes it from the file and nothing else.
    assert second["chain_prev"] == hashlib.sha256(raw[0].encode("utf-8")).hexdigest()
    assert json.loads(raw[1]) == second


def test_head_file_written_before_line(tmp_path, monkeypatch):
    """The head is persisted BEFORE the line it describes. Crash in between and
    the head is one AHEAD of the file, which a walk reports as a line that never
    landed. The other order would leave the head one BEHIND, the next line would
    reuse a seq, and the sequence would have restarted inside itself with
    nothing to show for it."""
    export = tmp_path / "traces.ndjson"
    order: list[str] = []

    real_write_head = attestation.write_trace_head

    def spy_head(export_file, *, seq, chain_hash):
        order.append("head")
        return real_write_head(export_file, seq=seq, chain_hash=chain_hash)

    monkeypatch.setattr(attestation, "write_trace_head", spy_head)

    real_open = Path.open

    def spy_open(self, *a, **k):
        if self == export and a and "a" in a[0]:
            order.append("line")
        return real_open(self, *a, **k)

    monkeypatch.setattr(Path, "open", spy_open)

    append_trace_line(export, build_action_trace(
        invoke={"msg_id": "a"}, outcome={"corr_id": "a"}, ruri=None, rrn="RRN-1",
    ))

    assert order == ["head", "line"]
    head = json.loads(head_file_for(export).read_text())
    assert head["v"] == "rcan-trace-head/1"
    assert head["seq"] == 1
    assert head["chain_hash"] == hashlib.sha256(
        export.read_text().splitlines()[0].encode("utf-8")
    ).hexdigest()


def test_unnumbered_history_starts_at_one_and_says_so(tmp_path):
    """The real upgrade case: an export already holding v1 lines with no seq.
    The first numbered line starts at 1, binds the last v1 line's bytes, and
    carries the marker that says everything before it binds nothing."""
    export = tmp_path / "traces.ndjson"
    old = json.dumps({"v": "rcan-action-trace/1", "corr_id": "old-1"})
    export.write_text(old + "\n")

    rec = append_trace_line(export, build_action_trace(
        invoke={"msg_id": "new"}, outcome={"corr_id": "new"}, ruri=None, rrn="RRN-1",
    ))

    assert rec["seq"] == 1
    assert rec["chain_prev"] == hashlib.sha256(old.encode("utf-8")).hexdigest()
    assert rec["chain_note"] == CHAIN_NOTE_UNNUMBERED_HISTORY


def test_a_missing_head_is_reported_on_the_line_not_silently_restarted(tmp_path):
    """A head file deleted beside a numbered export. The gateway appends (the
    record path is best effort and must never refuse), continues from what the
    file itself still proves, and NAMES the recovery on the line. It does not
    restart at seq 1 with a genesis link, which is the one shape that would
    make a deleted history invisible."""
    export = tmp_path / "traces.ndjson"
    for msg in ("a", "b"):
        append_trace_line(export, build_action_trace(
            invoke={"msg_id": msg}, outcome={"corr_id": msg}, ruri=None, rrn="RRN-1",
        ))
    head_file_for(export).unlink()

    rec = append_trace_line(export, build_action_trace(
        invoke={"msg_id": "c"}, outcome={"corr_id": "c"}, ruri=None, rrn="RRN-1",
    ))

    assert rec["seq"] == 3                      # not 1
    assert rec["chain_prev"] != GENESIS_CHAIN_PREV
    assert rec["chain_note"] == CHAIN_NOTE_HEAD_RECOVERED
    # And the head is back, so the NEXT line is ordinary again.
    nxt = append_trace_line(export, build_action_trace(
        invoke={"msg_id": "d"}, outcome={"corr_id": "d"}, ruri=None, rrn="RRN-1",
    ))
    assert nxt["seq"] == 4
    assert "chain_note" not in nxt


def test_an_unreadable_head_is_treated_as_a_missing_one(tmp_path):
    """A head this code cannot parse is a head that is gone. Treating it as
    anything else would let one corrupt byte silently restart the sequence."""
    export = tmp_path / "traces.ndjson"
    append_trace_line(export, build_action_trace(
        invoke={"msg_id": "a"}, outcome={"corr_id": "a"}, ruri=None, rrn="RRN-1",
    ))
    head_file_for(export).write_text("{not json")

    rec = append_trace_line(export, build_action_trace(
        invoke={"msg_id": "b"}, outcome={"corr_id": "b"}, ruri=None, rrn="RRN-1",
    ))
    assert rec["seq"] == 2
    assert rec["chain_note"] == CHAIN_NOTE_HEAD_RECOVERED


def test_build_intent_never_says_an_action_happened():
    intent = build_intent(
        corr_id="m1", envelope_id="e1", rrn="RRN-1", tool="drive.stop",
        actuator="rc-car", nonce="n1", caller="craig-iphone", tier="actuate",
        recorded_at="2026-09-14T00:00:00+00:00",
    )
    assert intent["status"] == "dispatching"
    assert intent["record_kind"] == "intent"
    # Every key is always written, null included, for the same reason the v2
    # receipt always writes caller: absent and unknown must not be one shape.
    assert set(intent) == {
        "intent_version", "record_kind", "status", "corr_id", "envelope_id",
        "rrn", "tool", "actuator", "nonce", "caller", "tier", "recorded_at",
    }
    assert "envelope_signature" not in intent


def test_intent_trace_line_has_no_outcome_key():
    rec = build_intent_trace(
        invoke={"msg_id": "m1"}, intent={"status": "dispatching"},
        ruri=None, rrn="RRN-1",
    )
    assert rec["record_kind"] == "intent"
    assert "outcome" not in rec
    assert rec["corr_id"] == "m1"
