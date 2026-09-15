#!/usr/bin/env python3
"""Independent verifier for a robot-md-gateway signed receipt (T-001).

Given a /v1/invoke receipt (an ALLOW body, a 403 DENY body, an NDJSON
action-trace line, or a bare signed outcome) and the signing kid's Ed25519
PUBLIC key, verify the detached ``envelope_signature`` over the canonical bytes
of the outcome — then flip one byte and prove verification fails.

This is deliberately STANDALONE: it imports only the Python stdlib and
``cryptography``. It does NOT import robot_md_gateway or rcan, so it exercises
the same contract a third party (e.g. the iOS app) implements from scratch:

    sig covers  canonical_json(outcome, exclude="envelope_signature")

where canonical_json = UTF-8 JSON, sorted keys, compact separators, no ASCII
escaping, whole-number floats normalized to ints (rcan canonical form).

RECEIPT VERSIONS. Both are accepted, and which one a receipt is is decided by
one key:

    no ``receipt_version`` key  -> v1. Signed before v0.5.0a7. Carries no
                                   caller and no tier; this verifier says so
                                   rather than inventing one.
    ``receipt_version: 2``      -> v2. Also carries ``caller`` and ``tier``
                                   INSIDE the signed bytes. The tamper check
                                   flips ``caller`` for these, so a receipt
                                   whose caller has been edited by hand fails
                                   verification and this script exits non-zero.

``caller`` NAMES A CREDENTIAL, NEVER A PERSON: it is the name the operator
wrote beside a bearer token in bearers.yaml ("craig-iphone", "readonly-probe").
It says which token was presented. It does not say who was holding the device.

What a pass here means: the bytes carry a signature made by the private key
matching the public key you supplied, and they have not changed since. It does
not mean the action was safe, correct, or authorised by anyone in particular.
It is an accountability artifact, and reading it is the check; this script
asserts, it does not bless.

WALK MODE (--walk <file>) reads a whole NDJSON export instead of one receipt
and answers a different question: is anything MISSING. Each line written by
v0.5.0a8 or later carries a ``seq`` (monotonic within one export file) and a
``chain_prev`` (sha256 of the previous line's bytes), so a deleted or truncated
line leaves a hole that this mode names. It needs no key and no network: a third
party handed the file can run it and check the operator's arithmetic.

What walk mode reports, and what each report is worth:

    GAP          a seq is missing. Lines were removed, or a line the head file
                 promised never landed. This is an integrity failure.
    CHAIN BREAK  a line's chain_prev does not match the previous line's bytes.
                 Something was edited or reordered. Integrity failure.
    UNNUMBERED   the file begins with lines written before this format existed.
                 They carry no links and THEY BIND NOTHING. Walk mode says how
                 many and refuses to imply otherwise.
    chain_note   a line says its own link was rebuilt because the head file was
                 missing. Reported by name; read it with an off-box copy.
    dispatch never reported
                 an intent line with no outcome line for the same corr_id. The
                 gateway recorded that it was about to dispatch and no outcome
                 followed: a crash, a kill, a power cut, or a driver that never
                 returned. IT IS NOT A GAP AND IT IS NOT AN ACTION THAT
                 HAPPENED. It is an open question, and it is reported as one.

A clean walk means the numbering and the links are consistent with each other.
It does not mean the file is complete: a line removed from the END of a file,
with the head file removed too, leaves nothing local to notice. Only comparing
with an off-box copy answers that, which is the whole point of shipping it.

Usage:
    python scripts/verify_receipt.py --receipt allow.json --pubkey gw.pub
    python scripts/verify_receipt.py --receipt deny.json  --pubkey gw.pub
    # verify only, no tamper assertion:
    python scripts/verify_receipt.py --receipt r.json --pubkey gw.pub --no-tamper-check
    # order + completeness of a whole export (no key needed):
    python scripts/verify_receipt.py --walk attestation-export.ndjsonl

Exit codes:
    0  authentic signature verified AND (unless --no-tamper-check) a
       one-byte-flipped copy failed to verify — both directions asserted.
       In walk mode: no gap, no chain break, no findings.
    1  bad signature / could not verify, or tamper check did not fail as expected.
       In walk mode: a gap or a chain break.
    2  usage / input error (no receipt, no signature, unreadable key, ...).
    3  walk mode only: no integrity failure, but named findings a person has to
       read (a dispatch that never reported, a rebuilt chain link, unnumbered
       history). Deliberately not 0: "nothing is provably missing" and "nothing
       needs looking at" are different answers.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import sys
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _normalize(v: Any) -> Any:
    """Match rcan's canonical normalization: whole-number floats -> int."""
    if isinstance(v, bool):
        return v
    if isinstance(v, float) and v.is_integer():
        return int(v)
    if isinstance(v, dict):
        return {k: _normalize(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_normalize(x) for x in v]
    return v


def canonical_json(body: dict, *, exclude: str | None = None) -> bytes:
    """Canonical UTF-8 bytes: sorted keys, compact, no ASCII escaping.

    Reimplemented here (not imported) so this verifier stands alone.
    """
    if exclude is not None and isinstance(body, dict):
        body = {k: v for k, v in body.items() if k != exclude}
    return json.dumps(
        _normalize(body), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def extract_outcome(receipt: dict) -> dict:
    """Locate the signed outcome inside any supported receipt shape."""
    # 0. An INTENT record is not an outcome and must never be checked as one.
    # It says a dispatch was about to happen; it carries no status for the
    # action. Refusing here, by name, is the difference between a reader being
    # told that and a reader seeing "status=dispatching  PASS" and filing it.
    if receipt.get("record_kind") == "intent" or (
        isinstance(receipt.get("intent"), dict) and "outcome" not in receipt
    ):
        raise SystemExit2(
            "this is an INTENT record, not an outcome: it says a dispatch was "
            "about to happen and says nothing about whether it did. Verify the "
            "outcome record with the same corr_id, or use --walk on the export "
            "to see whether one exists at all"
        )
    # 1. ALLOW body (or bare outcome): outcome carries its own signature.
    out = receipt.get("outcome")
    if isinstance(out, dict) and "envelope_signature" in out:
        return out
    # 2. 403 DENY body from FastAPI: {"detail": {..., "outcome": {...}}}.
    detail = receipt.get("detail")
    if isinstance(detail, dict):
        dout = detail.get("outcome")
        if isinstance(dout, dict) and "envelope_signature" in dout:
            return dout
    # 3. The receipt itself is a bare signed outcome / action-trace outcome.
    if "envelope_signature" in receipt and "status" in receipt:
        return receipt
    raise SystemExit2("no signed outcome (with envelope_signature) found in receipt")


class SystemExit2(SystemExit):
    def __init__(self, msg: str) -> None:
        super().__init__(2)
        self.msg = msg


#: Receipt payload versions this verifier understands.
SUPPORTED_RECEIPT_VERSIONS = (1, 2)


def receipt_version(outcome: dict) -> int:
    """Which receipt schema this outcome is.

    A missing ``receipt_version`` key means v1 (the shape every receipt signed
    before v0.5.0a7 has). Anything present must be an int this build knows, or
    the honest answer is "this verifier is too old to check that", not a guess.
    """
    raw = outcome.get("receipt_version")
    if raw is None:
        return 1
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise SystemExit2(f"receipt_version {raw!r} is not an integer")
    if raw not in SUPPORTED_RECEIPT_VERSIONS:
        raise SystemExit2(
            f"receipt_version {raw} is newer than this verifier understands "
            f"(knows {list(SUPPORTED_RECEIPT_VERSIONS)}); upgrade "
            f"robot-md-gateway and re-run"
        )
    return raw


def load_pubkey(path: str) -> Ed25519PublicKey:
    try:
        with open(path, "rb") as fh:
            pem = fh.read()
    except OSError as exc:
        raise SystemExit2(f"cannot read pubkey {path}: {exc}") from exc
    try:
        pub = serialization.load_pem_public_key(pem)
    except ValueError as exc:
        raise SystemExit2(f"bad public key PEM {path}: {exc}") from exc
    if not isinstance(pub, Ed25519PublicKey):
        raise SystemExit2(f"{path} is not an Ed25519 public key")
    return pub


def verify(outcome: dict, pub: Ed25519PublicKey) -> bool:
    sig_block = outcome.get("envelope_signature")
    if not isinstance(sig_block, dict) or "sig" not in sig_block:
        return False
    try:
        pub.verify(
            base64.b64decode(sig_block["sig"]),
            canonical_json(outcome, exclude="envelope_signature"),
        )
        return True
    except (InvalidSignature, ValueError):
        return False


#: Exit code for walk mode when nothing is provably missing but something named
#: needs a person's eyes. See the module docstring.
EXIT_FINDINGS = 3


def walk(path: str) -> int:
    """Walk an NDJSON export: report the first gap by seq, and any chain break.

    Needs no key. Reads the file's own bytes and its own arithmetic, which is
    precisely the check a third party can run on a handed-over file without
    trusting whoever handed it over.
    """
    try:
        with open(path, "rb") as fh:
            raw_lines = fh.read().split(b"\n")
    except OSError as exc:
        print(f"ERROR: cannot read {path}: {exc}", file=sys.stderr)
        return 2

    lines = [ln for ln in raw_lines if ln.strip()]
    print(f"walking {path}: {len(lines)} lines")
    if not lines:
        print("=> empty file: nothing to check, and nothing is claimed.")
        return 0

    findings: list[str] = []
    failures: list[str] = []
    unnumbered = 0
    expected_seq: int | None = None
    prev_bytes: bytes | None = None
    intents: dict[str, int] = {}   # corr_id -> line number of the intent
    outcomes: set[str] = set()

    for lineno, raw in enumerate(lines, start=1):
        try:
            rec = json.loads(raw)
        except ValueError as exc:
            failures.append(f"line {lineno}: not JSON ({exc})")
            prev_bytes = raw
            continue
        if not isinstance(rec, dict):
            failures.append(f"line {lineno}: not a JSON object")
            prev_bytes = raw
            continue

        kind = rec.get("record_kind", "outcome")
        corr = rec.get("corr_id")
        if isinstance(corr, str):
            if kind == "intent":
                intents.setdefault(corr, lineno)
            else:
                outcomes.add(corr)

        seq = rec.get("seq")
        if isinstance(seq, bool) or not isinstance(seq, int):
            if expected_seq is None:
                unnumbered += 1
            else:
                failures.append(
                    f"line {lineno}: no seq, after line {lineno - 1} carried one. "
                    f"Numbering does not restart mid-file."
                )
            prev_bytes = raw
            continue

        if expected_seq is not None and seq != expected_seq:
            if seq > expected_seq:
                missing = (
                    f"{expected_seq}"
                    if seq == expected_seq + 1
                    else f"{expected_seq}..{seq - 1}"
                )
                failures.append(
                    f"GAP: line {lineno} has seq {seq}, expected {expected_seq} "
                    f"(missing seq {missing})"
                )
            else:
                failures.append(
                    f"GAP: line {lineno} has seq {seq}, expected {expected_seq} "
                    f"(the sequence went backwards; lines were reordered or "
                    f"numbering restarted)"
                )

        chain_prev = rec.get("chain_prev")
        note = rec.get("chain_note")
        if prev_bytes is None:
            # First line of the file. A genesis prev is the only clean answer;
            # anything else is a claim about a line this file does not contain.
            if chain_prev not in (None, "0" * 64):
                findings.append(
                    f"line {lineno}: first line claims chain_prev {chain_prev} but "
                    f"there is no line before it in this file. The lines it binds "
                    f"to are somewhere else, or gone."
                )
        else:
            want = hashlib.sha256(prev_bytes).hexdigest()
            if chain_prev != want:
                failures.append(
                    f"CHAIN BREAK: line {lineno} chain_prev {chain_prev} does not "
                    f"match sha256 of line {lineno - 1} ({want})"
                )
        if note is not None:
            findings.append(
                f"line {lineno}: chain_note {note!r}. "
                + (
                    "This is the first numbered line after unnumbered history; "
                    "every line before it carries no links and binds nothing."
                    if note == "unnumbered_history"
                    else "The head file was missing, so seq and chain_prev were "
                         "rebuilt from this file's own last line. If the tail was "
                         "removed along with the head, only an off-box copy shows it."
                )
            )
        expected_seq = seq + 1
        prev_bytes = raw

    if unnumbered:
        print(
            f"UNNUMBERED: the first {unnumbered} line(s) carry no seq. They were "
            f"written before this format existed, they carry no links, and THEY "
            f"BIND NOTHING. Completeness is only checkable from the first "
            f"numbered line onward."
        )
        findings.append(f"{unnumbered} unnumbered line(s) at the head of the file")

    for corr, lineno in sorted(intents.items(), key=lambda kv: kv[1]):
        if corr not in outcomes:
            findings.append(
                f"dispatch never reported: line {lineno} records an intent for "
                f"corr_id {corr} and no outcome line follows it. The gateway was "
                f"about to dispatch; nothing in this file says it did."
            )

    for f in failures:
        print(f)
    for f in findings:
        print(f"FINDING: {f}")

    if failures:
        print(f"=> {len(failures)} integrity failure(s): this file is not whole.",
              file=sys.stderr)
        return 1
    if findings:
        print(
            f"=> no gap and no chain break, and {len(findings)} finding(s) above "
            f"that a person has to read."
        )
        return EXIT_FINDINGS
    print(
        "=> seq is unbroken and every chain_prev matches. That is consistency, "
        "not completeness: compare with an off-box copy to check the tail."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--receipt", help="path to receipt JSON")
    ap.add_argument("--pubkey", help="path to the kid's Ed25519 PUBLIC key PEM")
    ap.add_argument(
        "--walk", metavar="FILE",
        help="walk an NDJSON export and report the first gap by seq and any "
             "chain break (no key needed)",
    )
    ap.add_argument(
        "--no-tamper-check", action="store_true",
        help="verify only; do not also assert a flipped byte fails",
    )
    args = ap.parse_args(argv)

    if args.walk:
        if args.receipt:
            print("ERROR: --walk and --receipt do different jobs; pass one",
                  file=sys.stderr)
            return 2
        return walk(args.walk)

    if not args.receipt or not args.pubkey:
        print("ERROR: --receipt and --pubkey are both required (or use --walk)",
              file=sys.stderr)
        return 2

    try:
        with open(args.receipt, encoding="utf-8") as fh:
            receipt = json.loads(fh.read())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read/parse receipt: {exc}", file=sys.stderr)
        return 2

    try:
        outcome = extract_outcome(receipt)
        version = receipt_version(outcome)
        pub = load_pubkey(args.pubkey)
    except SystemExit2 as exc:
        print(f"ERROR: {exc.msg}", file=sys.stderr)
        return 2

    kid = outcome["envelope_signature"].get("kid")
    authentic = verify(outcome, pub)
    print(f"kid={kid}  status={outcome.get('status')}  corr_id={outcome.get('corr_id')}")
    if version >= 2:
        # Printed from the SIGNED body, so these are the values the signature
        # covers. caller is a credential name, not a person's name.
        caller = outcome.get("caller")
        print(
            f"receipt_version={version}  "
            f"caller={caller if caller is not None else '<none declared>'}  "
            f"tier={outcome.get('tier') or '<none>'}"
        )
    else:
        print("receipt_version=1  caller=<not carried by v1 receipts>  tier=<not carried>")
    print(f"[1] authentic signature verifies: {'PASS' if authentic else 'FAIL'}")
    if not authentic:
        print("=> signature did NOT verify against the supplied public key", file=sys.stderr)
        return 1

    if version >= 2:
        # A v2 receipt that lost its caller/tier keys is not a v2 receipt; it is
        # a v2 receipt someone edited, and the signature check above would have
        # caught that. Say which anyway, so the failure names itself.
        missing = [k for k in ("caller", "tier") if k not in outcome]
        if missing:
            print(
                f"ERROR: receipt_version {version} but signed body is missing {missing}",
                file=sys.stderr,
            )
            return 1

    if args.no_tamper_check:
        print("=> receipt is authentic (tamper check skipped).")
        return 0

    # Flip one byte of a signed field and re-verify: it MUST now fail. On a v2
    # receipt the flipped field is `caller`, which is the whole point of the
    # version bump: it proves the caller is inside the signed bytes, so an
    # operator who hand-edits it cannot hand you a receipt that still verifies.
    tampered = copy.deepcopy(outcome)
    if version >= 2:
        tampered["caller"] = _flip_one_byte(str(outcome.get("caller") or "x"))
        flipped_field = "caller"
    else:
        tampered["corr_id"] = _flip_one_byte(str(outcome.get("corr_id", "x")))
        flipped_field = "corr_id"
    tamper_rejected = not verify(tampered, pub)
    print(
        f"[2] one-byte-flipped copy rejected (field: {flipped_field}): "
        f"{'PASS' if tamper_rejected else 'FAIL'}"
    )
    if not tamper_rejected:
        print("=> DANGER: a tampered receipt still verified — signature is not binding",
              file=sys.stderr)
        return 1

    print("=> receipt is authentic AND tamper-evident (both directions asserted).")
    return 0


def _flip_one_byte(s: str) -> str:
    if not s:
        return "X"
    b = bytearray(s.encode("utf-8"))
    b[0] ^= 0x01
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return s + "!"  # fall back to a length change if the flip broke UTF-8


if __name__ == "__main__":
    raise SystemExit(main())
