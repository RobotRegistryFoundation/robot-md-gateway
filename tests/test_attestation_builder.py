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
    CHAIN_NOTE_PARTIAL_PREVIOUS,
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


# ---------------------------------------------------------------------------
# Two invokes at once. `/v1/invoke` is a SYNC FastAPI path operation, so
# Starlette runs it in a worker thread and two invokes with different msg_ids
# are genuinely concurrent OS threads. Everything below is about that.
# ---------------------------------------------------------------------------


def _append_from_threads(export: Path, *, threads: int, per_thread: int) -> list[bytes]:
    import threading as _t

    start = _t.Barrier(threads)
    errors: list[BaseException] = []

    def worker(i: int) -> None:
        start.wait()
        for j in range(per_thread):
            try:
                append_trace_line(
                    export,
                    {"v": "rcan-action-trace/1", "record_kind": "outcome",
                     "corr_id": f"{i}-{j}"},
                )
            except BaseException as exc:  # noqa: BLE001 - the test is the report
                errors.append(exc)

    ts = [_t.Thread(target=worker, args=(i,)) for i in range(threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors, f"append_trace_line raised under concurrency: {errors[:3]}"
    return [ln for ln in export.read_bytes().split(b"\n") if ln.strip()]


def test_concurrent_appends_do_not_lose_a_line(tmp_path):
    """EVERY line lands. Before the lock and the per-writer temp name, two
    threads shared one `<export>.head.tmp`: the first renamed it away and the
    second's os.replace raised FileNotFoundError, which the gateway's
    best-effort wrapper swallows. The request still succeeded and the record
    was simply gone. 8 threads x 6 lines left 6 of 48 on this Pi."""
    export = tmp_path / "e.ndjsonl"
    lines = _append_from_threads(export, threads=8, per_thread=6)
    assert len(lines) == 48


def test_concurrent_appends_do_not_reuse_a_seq(tmp_path):
    """No two lines carry the same seq, and the numbering is 1..N with no hole.
    Without the lock, two threads both read seq N and both wrote N+1, and a walk
    then reports a duplicate on a file nobody touched."""
    export = tmp_path / "e.ndjsonl"
    lines = _append_from_threads(export, threads=8, per_thread=6)
    seqs = [json.loads(ln)["seq"] for ln in lines]
    assert sorted(seqs) == list(range(1, 49))
    assert seqs == sorted(seqs), "lines are not in seq order in the file"


def test_concurrent_appends_leave_no_chain_break(tmp_path):
    """Every chain_prev is the sha256 of the line physically before it, so
    `--walk` on a concurrently written file reports nothing. An integrity
    report that is not about integrity is the worst failure this file has."""
    export = tmp_path / "e.ndjsonl"
    lines = _append_from_threads(export, threads=8, per_thread=6)
    prev = None
    for ln in lines:
        want = hashlib.sha256(prev).hexdigest() if prev is not None else GENESIS_CHAIN_PREV
        assert json.loads(ln)["chain_prev"] == want
        prev = ln


def test_concurrent_appends_leave_the_head_on_the_last_line(tmp_path):
    export = tmp_path / "e.ndjsonl"
    lines = _append_from_threads(export, threads=8, per_thread=6)
    head = json.loads(head_file_for(export).read_text())
    assert head["seq"] == 48
    assert head["chain_hash"] == hashlib.sha256(lines[-1]).hexdigest()


def test_no_stray_temp_files_are_left_behind(tmp_path):
    export = tmp_path / "e.ndjsonl"
    _append_from_threads(export, threads=8, per_thread=6)
    assert not list(tmp_path.glob("*.tmp"))


# ---------------------------------------------------------------------------
# The fsync budget. Every one of these runs BEFORE target_actuator.execute(),
# so it is time a drive.stop spends waiting on an SD card before the robot is
# told anything. Measured on a Pi 5, ext4 on the card, per line: three fsyncs
# was 16.3 ms mean / 21.8 ms p95, one is 8.3 / 12.2. An invoke writes two
# lines, so that is 32.7 ms versus 16.6 ms of added blocking IO per invoke.
# ---------------------------------------------------------------------------


def test_one_fsync_per_line_on_the_hot_path(tmp_path, monkeypatch):
    import os as _os

    calls: list[int] = []
    real = _os.fsync
    monkeypatch.setattr(
        attestation.os, "fsync", lambda fd: (calls.append(fd), real(fd))[1]
    )
    export = tmp_path / "e.ndjsonl"
    append_trace_line(export, {"v": "rcan-action-trace/1", "corr_id": "m1"})
    assert len(calls) == 1, (
        f"{len(calls)} fsync(s) per trace line. This is pre-dispatch latency on "
        f"every invoke; read write_trace_head's docstring before adding one."
    )


def test_the_one_fsync_is_the_head_not_the_export(tmp_path, monkeypatch):
    """If only one write is made durable it has to be the head, because the
    whole design is 'head before line': a durable line under a lost head is the
    ordering this format exists to rule out."""
    import os as _os

    synced: list[str] = []
    real = _os.fsync

    def spy(fd):
        try:
            synced.append(_os.readlink(f"/proc/self/fd/{fd}"))
        except OSError:
            synced.append("?")
        return real(fd)

    monkeypatch.setattr(attestation.os, "fsync", spy)
    export = tmp_path / "e.ndjsonl"
    append_trace_line(export, {"v": "rcan-action-trace/1", "corr_id": "m1"})
    assert len(synced) == 1
    assert ".head" in synced[0]
    assert not synced[0].endswith("e.ndjsonl")


def test_a_failed_head_write_does_not_stop_the_line_from_being_attempted(tmp_path, monkeypatch):
    """append_trace_line raises rather than half-writing, and the CALLER's
    best-effort wrapper is what swallows it. Pinned here so nobody 'helpfully'
    catches OSError inside append_trace_line and leaves a line with no head."""
    export = tmp_path / "e.ndjsonl"

    def boom(*a, **kw):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(attestation, "write_trace_head", boom)
    try:
        append_trace_line(export, {"v": "rcan-action-trace/1", "corr_id": "m1"})
    except OSError as exc:
        assert exc.errno == 28
    else:
        raise AssertionError("expected the OSError to reach the caller")


# ---------------------------------------------------------------------------
# A torn last line. The process died between the first byte of a record and its
# newline. More likely since the per-line fsync went, and it used to destroy
# evidence twice: it restarted the sequence at 1 on a numbered file, and the
# next record was welded onto the broken one.
# ---------------------------------------------------------------------------


def _torn(tmp_path, *, lines: int = 5, lose_head: bool = True) -> Path:
    export = tmp_path / "e.ndjsonl"
    for i in range(lines):
        append_trace_line(export, {"v": "rcan-action-trace/1", "corr_id": f"m{i}"})
    export.write_bytes(export.read_bytes()[:-40])   # crash mid-line
    if lose_head:
        head_file_for(export).unlink()              # and lose the head with it
    return export


def test_a_torn_last_line_does_not_restart_the_sequence(tmp_path):
    """seq 1..5 with a torn line 5 used to come back as (1, unnumbered_history):
    a numbered file silently restarting at 1 AND saying on the record that it had
    never been numbered. It continues from the last line whose number can be
    read, and names why."""
    export = _torn(tmp_path)
    seq, _chain_prev, note = attestation.next_trace_link(export)
    assert seq == 5, "the sequence restarted on a numbered file"
    assert note == CHAIN_NOTE_PARTIAL_PREVIOUS
    assert note != CHAIN_NOTE_UNNUMBERED_HISTORY


def test_a_torn_last_line_binds_its_own_bytes_not_the_line_above_it(tmp_path):
    """chain_prev has to be the bytes PHYSICALLY last in the file, torn or not,
    or a walk comparing each line with the one above it reports a chain break on
    a file nobody touched."""
    export = _torn(tmp_path)
    _seq, chain_prev, _note = attestation.next_trace_link(export)
    torn_bytes = export.read_bytes().split(b"\n")[-1]
    assert chain_prev == hashlib.sha256(torn_bytes).hexdigest()


def test_the_next_record_is_not_welded_onto_a_torn_line(tmp_path):
    """Appending onto a file that does not end in a newline used to join the
    torn record and the whole new record into one unparseable line, so a crash
    cost two records instead of one."""
    export = _torn(tmp_path)
    written = append_trace_line(export, {"v": "rcan-action-trace/1", "corr_id": "after"})
    lines = [ln for ln in export.read_bytes().split(b"\n") if ln.strip()]
    assert json.loads(lines[-1])["corr_id"] == "after"
    assert json.loads(lines[-1])["seq"] == written["seq"] == 5
    # The torn line is still its own line, still broken, and still there to be
    # reported. It is not silently repaired and it is not silently removed.
    try:
        json.loads(lines[-2])
    except ValueError:
        pass
    else:
        raise AssertionError("the torn line was rewritten; it must be left alone")


def test_ends_with_newline_reads_the_last_byte(tmp_path):
    export = tmp_path / "e.ndjsonl"
    assert attestation.ends_with_newline(export)          # missing file
    export.write_bytes(b"")
    assert attestation.ends_with_newline(export)          # empty file
    export.write_bytes(b'{"a":1}\n')
    assert attestation.ends_with_newline(export)
    export.write_bytes(b'{"a":1}')
    assert not attestation.ends_with_newline(export)
