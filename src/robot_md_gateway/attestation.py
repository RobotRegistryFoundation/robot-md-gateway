"""U1a producer logic: signing identity, outcome builder, status map, trace wrapper.

Pure functions + one dataclass; no FastAPI. The receiver imports these and the
__main__ serve path loads the identity from env. Absence of the identity disables
attestation (the gateway still runs as verifier).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from rcan.audit_bundle import canonical_json

from .actuator import ActuatorOutcome

logger = logging.getLogger(__name__)

#: Receipt payload version carried in every signed outcome this gateway emits.
#:
#: v1 (implicit, no ``receipt_version`` key): corr_id, rrn, status, started_at,
#:    ended_at and the optional duration_ms / telemetry_sha256 / error /
#:    result_summary. Every receipt signed before v0.5.0a7.
#: v2 (this): adds ``receipt_version``, ``caller`` and ``tier``, all three
#:    INSIDE the signed bytes, so an edited caller breaks the signature.
#:
#: Verifiers must accept BOTH for at least one release: the iOS app, the
#: PlatAtlas console and the shipper all read receipts, and receipts already on
#: disk are v1 forever. scripts/verify_receipt.py distinguishes them by the
#: presence of the ``receipt_version`` key.
RECEIPT_VERSION = 2


@dataclass(frozen=True)
class SigningIdentity:
    """The gateway's persistent attestation identity (Ed25519 only at runtime)."""

    priv: Ed25519PrivateKey
    kid: str
    ran: str | None


def load_signing_identity_from_env() -> SigningIdentity | None:
    """Load the attestation identity from ROBOT_MD_ATTESTATION_* env vars.

    Requires ROBOT_MD_ATTESTATION_KEY_FILE (path to an Ed25519 PKCS8 PEM private
    key) and ROBOT_MD_ATTESTATION_KID. ROBOT_MD_ATTESTATION_RAN is optional
    (traceability/logging only). Any missing/invalid input -> returns None and
    logs a WARNING ("attestation disabled"); the gateway keeps running as verifier.
    """
    key_file = os.environ.get("ROBOT_MD_ATTESTATION_KEY_FILE")
    kid = os.environ.get("ROBOT_MD_ATTESTATION_KID")
    ran = os.environ.get("ROBOT_MD_ATTESTATION_RAN")
    if not key_file or not kid:
        logger.warning(
            "attestation disabled: ROBOT_MD_ATTESTATION_KEY_FILE and "
            "ROBOT_MD_ATTESTATION_KID must both be set (gateway runs verifier-only)"
        )
        return None
    path = Path(key_file)
    if not path.exists():
        logger.warning("attestation disabled: key file %s not found", key_file)
        return None
    try:
        priv = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (ValueError, OSError, TypeError) as exc:
        # TypeError: an encrypted PKCS8 key loaded with password=None. Any
        # missing/invalid input -> graceful verifier-only (per the docstring).
        logger.warning("attestation disabled: cannot load key file %s: %s", key_file, exc)
        return None
    if not isinstance(priv, Ed25519PrivateKey):
        logger.warning(
            "attestation disabled: key file %s is not an Ed25519 private key", key_file
        )
        return None
    logger.info("attestation enabled: kid=%s ran=%s", kid, ran or "<unset>")
    return SigningIdentity(priv=priv, kid=kid, ran=ran)


def outcome_status(*, decision: str, success: bool | None, error_kind: str | None) -> str:
    """Map a gateway decision to an S3 status enum value (§3.5).

    deny (any gate)            -> "denied"
    allow + success            -> "ok"
    allow + clean failure      -> "failure"   (success is False, no exception)
    allow + exception          -> "error"     (error_kind set)
    timeout has no wrapper in v1 and surfaces as "error".
    """
    if decision == "deny":
        return "denied"
    if success:
        return "ok"
    if error_kind is not None:
        return "error"
    return "failure"


def telemetry_sha256_of(outcome: ActuatorOutcome | None) -> str | None:
    """sha256 of the actuator telemetry, matching receiver.py's audit recipe.

    If ``telemetry_path`` is set (even if the file does not exist), the path
    branch is taken: hash file bytes when the file exists, else return None.
    Only when ``telemetry_path`` is None does the in-memory branch run:
    canonical JSON of the ``telemetry`` dict. This mirrors the elif structure
    in receiver.py (lines 191-202) so the signed value equals the audit value.
    """
    if outcome is None:
        return None
    if outcome.telemetry_path is not None:
        if outcome.telemetry_path.exists():
            return hashlib.sha256(outcome.telemetry_path.read_bytes()).hexdigest()
        return None
    elif outcome.telemetry:
        return hashlib.sha256(canonical_json(outcome.telemetry)).hexdigest()
    return None


def build_action_trace(
    *,
    invoke: dict,
    outcome: dict,
    ruri: str | None,
    rrn: str,
    intent_chain_hash: str | None = None,
) -> dict:
    """Wrap the verified invoke + signed outcome in an rcan-action-trace/1 record (§3.7).

    The invoke is passed verbatim (the raw verified envelope). corr_id is taken
    from invoke.msg_id; ruri/rrn are top-level hints S3 checks against the signed
    fields (binding_ok).

    ``record_kind`` is written on every line from v0.5.0a8 so a reader never has
    to infer what a line is from which keys happen to be present. Lines written
    before that release carry no ``record_kind`` and mean ``"outcome"``.

    ``intent_chain_hash`` is an UNSIGNED HINT, and it is labelled that here so
    nobody quotes it as if it were covered by the outcome's signature. It is the
    audit-chain hash of the intent entry written before dispatch. The signed
    linkage between the pair lives in the audit chain (both entries are inside
    the bundle the gateway signs at export); on the NDJSON side the pair shares
    a ``corr_id`` and this hint says which entry to look for.

    ``seq`` and ``chain_prev`` are NOT set here. They are properties of a
    position in one export file, not of a record, so ``append_trace_line`` adds
    them at the moment it writes the line and nowhere else.
    """
    record = {
        "v": "rcan-action-trace/1",
        "record_kind": "outcome",
        "invoke": invoke,
        "outcome": outcome,
        "corr_id": invoke.get("msg_id"),
        "ruri": ruri,
        "rrn": rrn,
    }
    if intent_chain_hash is not None:
        record["intent_chain_hash"] = intent_chain_hash
    return record


def build_intent_trace(*, invoke: dict, intent: dict, ruri: str | None, rrn: str) -> dict:
    """Wrap the verified invoke + signed intent in an rcan-action-trace/1 line.

    THE LINE HAS NO ``outcome`` KEY, ON PURPOSE. At the moment it is written the
    actuator has not been called, so there is no outcome to report and inventing
    a placeholder would be the one mistake this whole record exists to avoid: an
    intent line for an action that then fails must not read as an action that
    happened. ``record_kind: "intent"`` says what the line is, and the absence of
    an outcome says the rest.

    Downstream note, so the shape is not a surprise. PlatAtlas's rcan ingest
    reads ``rec.outcome ?? {}`` and verifies it, so an intent line lands with
    ``exec_verdict: "verify_failed"``. That is literally true for this line (there
    is no verified execution envelope in it), consumers are already told to gate
    attribution on ``exec_verdict === "verified"``, and the ingest never rejects a
    record. So an intent line is stored and can never be counted as an execution.
    Teaching that ingest to read ``record_kind`` is a follow-up, not a blocker.
    """
    return {
        "v": "rcan-action-trace/1",
        "record_kind": "intent",
        "invoke": invoke,
        "intent": intent,
        "corr_id": invoke.get("msg_id"),
        "ruri": ruri,
        "rrn": rrn,
    }


#: Payload version carried in every signed intent this gateway emits.
INTENT_VERSION = 1


def build_intent(
    *,
    corr_id: str,
    envelope_id: str | None,
    rrn: str,
    tool: str | None,
    actuator: str | None,
    nonce: str | None,
    caller: str | None,
    tier: str | None,
    recorded_at: str,
) -> dict:
    """Build the flat intent payload, WITHOUT envelope_signature.

    Signed by exactly the same recipe the outcome is: the caller passes the
    returned dict to ``sign_envelope(priv, intent, kid)``, which attaches a
    detached Ed25519 ``envelope_signature`` over ``canonical_json(intent)``. No
    new crypto, no second key, no second format.

    ``status`` is ``"dispatching"`` and is never any other value. It is not an
    outcome status and it must not be read as one: it says the gateway had
    cleared every gate and was about to call the actuator. Whether the actuator
    ran is answered by the outcome record that shares this ``corr_id``, and by
    nothing in here.

    Every key is always written, null included, for the same reason the v2
    receipt always writes ``caller``: a reader has to be able to tell "this
    envelope carried no nonce" from "this gateway was not recording nonces".

    ``caller`` NAMES A CREDENTIAL, NEVER A PERSON, exactly as in the receipt.
    """
    return {
        "intent_version": INTENT_VERSION,
        "record_kind": "intent",
        "status": "dispatching",
        "corr_id": corr_id,
        "envelope_id": envelope_id,
        "rrn": rrn,
        "tool": tool,
        "actuator": actuator,
        "nonce": nonce,
        "caller": caller,
        "tier": tier,
        "recorded_at": recorded_at,
    }


# --------------------------------------------------------------------------
# OC-10: ordering the durable trace.
#
# Until v0.5.0a8 every rcan-action-trace/1 line stood alone: delete one, or cut
# the file short, and nothing in what remained showed a hole. seq + chain_prev
# make a removal visible, and the .head file is what stops a restart of the
# sequence from looking like a fresh file.
# --------------------------------------------------------------------------

#: Schema tag of the sibling ``<export>.head`` file.
TRACE_HEAD_VERSION = "rcan-trace-head/1"

#: chain_prev of the first line of a file that had no history at all.
GENESIS_CHAIN_PREV = "0" * 64

#: Named markers written onto the ONE line where the chain could not be
#: continued from a head file. A verifier reports these by name; they are never
#: silent, and they are never invented to paper over a real gap.
#:
#: unnumbered_history  the export already held lines and NONE of them carried a
#:                     seq. This is the first numbered line after an upgrade
#:                     from the v1 format. Its chain_prev binds the last v1
#:                     line's bytes, so from that line forward a removal is
#:                     visible. EVERY LINE BEFORE IT BINDS NOTHING: the v1
#:                     format had no links, and this release cannot retroactively
#:                     give it any. Say that rather than implying otherwise.
#: head_recovered      the export held NUMBERED lines and the .head file was
#:                     gone. seq and chain_prev were rebuilt from the file's own
#:                     last line. That is honest about what is knowable locally
#:                     and honest about what is not: if the head AND the tail
#:                     were removed together, the rebuilt seq is the truncated
#:                     file's, and only an off-box copy can show it. The marker
#:                     is what tells a reader to go and compare.
CHAIN_NOTE_UNNUMBERED_HISTORY = "unnumbered_history"
CHAIN_NOTE_HEAD_RECOVERED = "head_recovered_from_file"


def head_file_for(export_file: Path) -> Path:
    """The sibling head file: ``attestation-export.ndjsonl.head``."""
    return export_file.with_suffix(export_file.suffix + ".head")


def read_trace_head(export_file: Path) -> dict | None:
    """The persisted head, or None if there is not a usable one.

    Unreadable, unparseable and structurally wrong heads all return None, which
    routes into the same reported recovery path a missing head takes. A head
    this code cannot read is a head that is gone, and treating it as anything
    else would let a corrupt byte silently restart the sequence.
    """
    path = head_file_for(export_file)
    try:
        head = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(head, dict):
        return None
    seq, chain_hash = head.get("seq"), head.get("chain_hash")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        return None
    if not isinstance(chain_hash, str) or len(chain_hash) != 64:
        return None
    return head


def _last_line_bytes(export_file: Path) -> bytes | None:
    """The last non-empty line of the export, without its newline."""
    try:
        data = export_file.read_bytes()
    except OSError:
        return None
    lines = [ln for ln in data.split(b"\n") if ln.strip()]
    return lines[-1] if lines else None


def next_trace_link(export_file: Path) -> tuple[int, str, str | None]:
    """Where the next line goes: ``(seq, chain_prev, chain_note)``.

    THE MISSING-HEAD DECISION, and why it is this one. A missing ``.head`` file
    beside a non-empty export has three possible answers:

      refuse to append        rejected. The export is evidence, and the gateway's
                              record path is best effort by contract: a record
                              failure must never crash a request or change what
                              the robot does. Refusing to append would destroy
                              evidence to protect the appearance of an unbroken
                              chain, and it would do it silently, because the
                              request still has to succeed.
      restart at seq 1 with   rejected outright. That is the failure this whole
      a genesis chain_prev    item exists to end: it makes a deleted history
                              indistinguishable from a fresh file.
      append with a named     CHOSEN. The line is written, the chain is continued
      marker                  from whatever the file itself still proves, and the
                              line carries a ``chain_note`` saying the head was
                              not there. The record survives, and the gap in what
                              can be proved is stated on the record rather than
                              hidden by it.

    A file with no head and no history is an ordinary first line: seq 1, genesis
    chain_prev, no marker. Nothing was lost, so nothing is claimed.
    """
    head = read_trace_head(export_file)
    if head is not None:
        return int(head["seq"]) + 1, str(head["chain_hash"]), None
    last = _last_line_bytes(export_file)
    if last is None:
        return 1, GENESIS_CHAIN_PREV, None
    prev_hash = hashlib.sha256(last).hexdigest()
    last_seq = None
    try:
        parsed = json.loads(last)
        if isinstance(parsed, dict):
            last_seq = parsed.get("seq")
    except ValueError:
        last_seq = None
    if isinstance(last_seq, int) and not isinstance(last_seq, bool) and last_seq >= 1:
        return last_seq + 1, prev_hash, CHAIN_NOTE_HEAD_RECOVERED
    return 1, prev_hash, CHAIN_NOTE_UNNUMBERED_HISTORY


def write_trace_head(export_file: Path, *, seq: int, chain_hash: str) -> None:
    """Persist the head atomically: temp file, fsync, rename, fsync the dir.

    Written BEFORE the line it describes. The crash window is therefore always
    "head is one ahead of the file", which a walk reports as a line that never
    landed. The other order would leave the head one BEHIND, the next line would
    reuse a seq, and the sequence would have silently restarted inside itself,
    which is the exact thing this file exists to make impossible.
    """
    path = head_file_for(export_file)
    tmp = path.with_suffix(path.suffix + ".tmp")
    body = {
        "v": TRACE_HEAD_VERSION,
        "seq": seq,
        "chain_hash": chain_hash,
        "export": export_file.name,
        "updated_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(body, sort_keys=True, separators=(",", ":")))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    try:
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def append_trace_line(export_file: Path, record: dict) -> dict:
    """Number, link and append one rcan-action-trace/1 line. Returns the line.

    The line's chain hash is ``sha256`` of its own canonical bytes WITHOUT the
    trailing newline, which is exactly the bytes written to the file, so a
    verifier can recompute it from the file and nothing else.
    """
    export_file.parent.mkdir(parents=True, exist_ok=True)
    seq, chain_prev, note = next_trace_link(export_file)
    line_record = dict(record)
    line_record["seq"] = seq
    line_record["chain_prev"] = chain_prev
    if note is not None:
        line_record["chain_note"] = note
    canon = canonical_json(line_record)
    write_trace_head(
        export_file, seq=seq, chain_hash=hashlib.sha256(canon).hexdigest()
    )
    with export_file.open("a", encoding="utf-8") as fh:
        fh.write(canon.decode("utf-8") + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return line_record


def build_outcome(
    *,
    corr_id: str,
    rrn: str,
    status: str,
    started_at: str,
    ended_at: str,
    duration_ms: int | None,
    telemetry_sha256: str | None,
    error: dict | None,
    result_summary: str | None,
    caller: str | None = None,
    tier: str | None = None,
) -> dict:
    """Build the flat outcome payload (§3.4), WITHOUT envelope_signature.

    Required fields are always present. Optional fields are omitted when None so
    the signed shape stays clean (the absence of a field is signed, not a null).
    The caller signs the returned dict with sign_envelope(priv, outcome, kid).

    ``caller`` and ``tier`` are the v2 additions and they break that omission
    rule ON PURPOSE: both keys are always written, null included. A receipt
    whose caller is absent and a receipt whose caller is unknown must not be
    the same bytes, because a reader has to be able to tell "this gateway had
    no bearer entry for that token" from "this gateway was not recording
    callers at all". The version key answers the second question and the null
    answers the first.

    ``caller`` NAMES A CREDENTIAL, NEVER A PERSON. It is the `caller` field of
    the bearer entry in bearers.yaml that authorised the request. It says which
    token was presented. It does not say who was holding the device, and no
    field in this receipt does.
    """
    outcome: dict = {
        "receipt_version": RECEIPT_VERSION,
        "corr_id": corr_id,
        "rrn": rrn,
        "status": status,
        "started_at": started_at,
        "ended_at": ended_at,
        "caller": caller,
        "tier": tier,
    }
    if duration_ms is not None:
        outcome["duration_ms"] = duration_ms
    if telemetry_sha256 is not None:
        outcome["telemetry_sha256"] = telemetry_sha256
    if error is not None:
        outcome["error"] = error
    if result_summary is not None:
        outcome["result_summary"] = result_summary
    return outcome
