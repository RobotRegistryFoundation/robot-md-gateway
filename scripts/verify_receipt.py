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

Usage:
    python scripts/verify_receipt.py --receipt allow.json --pubkey gw.pub
    python scripts/verify_receipt.py --receipt deny.json  --pubkey gw.pub
    # verify only, no tamper assertion:
    python scripts/verify_receipt.py --receipt r.json --pubkey gw.pub --no-tamper-check

Exit codes:
    0  authentic signature verified AND (unless --no-tamper-check) a
       one-byte-flipped copy failed to verify — both directions asserted.
    1  bad signature / could not verify, or tamper check did not fail as expected.
    2  usage / input error (no receipt, no signature, unreadable key, ...).
"""

from __future__ import annotations

import argparse
import base64
import copy
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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--receipt", required=True, help="path to receipt JSON")
    ap.add_argument("--pubkey", required=True, help="path to the kid's Ed25519 PUBLIC key PEM")
    ap.add_argument(
        "--no-tamper-check", action="store_true",
        help="verify only; do not also assert a flipped byte fails",
    )
    args = ap.parse_args(argv)

    try:
        with open(args.receipt, encoding="utf-8") as fh:
            receipt = json.loads(fh.read())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read/parse receipt: {exc}", file=sys.stderr)
        return 2

    try:
        outcome = extract_outcome(receipt)
        pub = load_pubkey(args.pubkey)
    except SystemExit2 as exc:
        print(f"ERROR: {exc.msg}", file=sys.stderr)
        return 2

    kid = outcome["envelope_signature"].get("kid")
    authentic = verify(outcome, pub)
    print(f"kid={kid}  status={outcome.get('status')}  corr_id={outcome.get('corr_id')}")
    print(f"[1] authentic signature verifies: {'PASS' if authentic else 'FAIL'}")
    if not authentic:
        print("=> signature did NOT verify against the supplied public key", file=sys.stderr)
        return 1

    if args.no_tamper_check:
        print("=> receipt is authentic (tamper check skipped).")
        return 0

    # Flip one byte of a signed field and re-verify: it MUST now fail.
    tampered = copy.deepcopy(outcome)
    tampered["corr_id"] = _flip_one_byte(str(outcome.get("corr_id", "x")))
    tamper_rejected = not verify(tampered, pub)
    print(f"[2] one-byte-flipped copy rejected: {'PASS' if tamper_rejected else 'FAIL'}")
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
