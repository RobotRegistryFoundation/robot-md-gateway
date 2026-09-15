"""End-to-end coverage for scripts/verify_receipt.py (the independent verifier).

Captures a REAL signed receipt from the gateway via TestClient, writes it and the
gateway public key to disk, then runs the standalone script as a subprocess:

  * correct pubkey  -> exit 0 (authentic verifies AND a flipped byte is rejected)
  * wrong pubkey    -> exit 1

The script imports only stdlib + cryptography, so this proves a third party can
verify a receipt without the gateway package.
"""

from __future__ import annotations

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
SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify_receipt.py"


class _Resolver:
    def __init__(self, mapping):
        self._m = mapping

    def resolve_public_key_pem(self, kid):
        return self._m.get(kid)


def _envelope(msg_id, **over):
    body = {
        "msg_id": msg_id, "type": "INVOKE", "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "READ", "tool_name": "mcp__robot__render", "tool_args": {},
        "manifest_path": GOOD_MANIFEST,
    }
    body.update(over)
    return body


def _pub_pem(priv):
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _capture(tmp_path, envelope) -> tuple[Path, Path, Path]:
    priv = Ed25519PrivateKey.generate()
    app = make_app(
        resolver=_Resolver({MANIFEST_KID: MANIFEST_PUB}),
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
        audit_chain=AuditChain(),
        signing_identity=SigningIdentity(priv=priv, kid="gw-kid", ran=None),
        attestation_export_file=None,
    )
    r = TestClient(app).post("/v1/invoke", json=envelope)
    receipt = tmp_path / "receipt.json"
    receipt.write_bytes(r.content)
    good = tmp_path / "gw.pub"
    good.write_bytes(_pub_pem(priv))
    wrong = tmp_path / "wrong.pub"
    wrong.write_bytes(_pub_pem(Ed25519PrivateKey.generate()))
    return receipt, good, wrong


def _run(receipt: Path, pubkey: Path) -> int:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--receipt", str(receipt), "--pubkey", str(pubkey)],
        capture_output=True, text=True,
    ).returncode


@pytest.mark.parametrize(
    "envelope",
    [
        _envelope("script-allow"),
        _envelope("script-deny", tool_name="mcp__robot__execute_capability"),
    ],
    ids=["allow", "deny"],
)
def test_script_verifies_real_receipt_and_detects_tamper(tmp_path, envelope):
    receipt, good, wrong = _capture(tmp_path, envelope)
    assert _run(receipt, good) == 0     # authentic + tamper-evident (both directions)
    assert _run(receipt, wrong) == 1    # wrong key must not verify


# --------------------------------------------------------------------------
# OC-10: --walk. Order and completeness of a whole export, with no key.
# --------------------------------------------------------------------------


def _walk(path: Path):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--walk", str(path)],
        capture_output=True, text=True,
    )


def _write(path: Path, records):
    """Write records the way the gateway does: canonical bytes, chained."""
    import hashlib
    import json

    lines = []
    prev = None
    for rec in records:
        rec = dict(rec)
        rec.setdefault("chain_prev", "0" * 64 if prev is None else prev)
        body = json.dumps(rec, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False)
        prev = hashlib.sha256(body.encode("utf-8")).hexdigest()
        lines.append(body)
    path.write_text("\n".join(lines) + "\n")
    return lines


def _outcome(seq, corr):
    return {"v": "rcan-action-trace/1", "record_kind": "outcome", "seq": seq,
            "corr_id": corr, "outcome": {"corr_id": corr, "status": "ok"}}


def _intent(seq, corr):
    return {"v": "rcan-action-trace/1", "record_kind": "intent", "seq": seq,
            "corr_id": corr, "intent": {"corr_id": corr, "status": "dispatching"}}


def test_walk_clean_file_exits_zero(tmp_path):
    f = tmp_path / "clean.ndjson"
    _write(f, [_intent(1, "m1"), _outcome(2, "m1"), _intent(3, "m2"),
               _outcome(4, "m2")])
    r = _walk(f)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "seq is unbroken" in r.stdout
    # A clean walk is consistency, never completeness, and it says so.
    assert "not completeness" in r.stdout


def test_walk_names_the_first_missing_seq(tmp_path):
    f = tmp_path / "gap.ndjson"
    lines = _write(f, [_outcome(1, "m1"), _outcome(2, "m2"), _outcome(3, "m3"),
                       _outcome(4, "m4")])
    # Cut the middle out, exactly as deleting a row would.
    f.write_text("\n".join([lines[0], lines[3]]) + "\n")
    r = _walk(f)
    assert r.returncode == 1
    assert "GAP" in r.stdout
    assert "missing seq 2..3" in r.stdout


def test_walk_names_a_chain_break(tmp_path):
    f = tmp_path / "break.ndjson"
    lines = _write(f, [_outcome(1, "m1"), _outcome(2, "m2")])
    # Same count, same numbering, one edited line: only the link shows it.
    edited = lines[0].replace('"status":"ok"', '"status":"denied"')
    f.write_text("\n".join([edited, lines[1]]) + "\n")
    r = _walk(f)
    assert r.returncode == 1
    assert "CHAIN BREAK" in r.stdout


def test_walk_says_unnumbered_lines_bind_nothing(tmp_path):
    f = tmp_path / "mixed.ndjson"
    import hashlib
    import json

    old = json.dumps({"v": "rcan-action-trace/1", "corr_id": "old"},
                     sort_keys=True, separators=(",", ":"))
    new = dict(_outcome(1, "m1"))
    new["chain_prev"] = hashlib.sha256(old.encode("utf-8")).hexdigest()
    new["chain_note"] = "unnumbered_history"
    f.write_text(old + "\n" + json.dumps(new, sort_keys=True,
                                         separators=(",", ":")) + "\n")
    r = _walk(f)
    assert r.returncode == 3
    assert "BIND NOTHING" in r.stdout
    assert "unnumbered_history" in r.stdout


def test_walk_reports_a_rebuilt_head_link(tmp_path):
    f = tmp_path / "recovered.ndjson"
    recs = [_outcome(1, "m1"), dict(_outcome(2, "m2"),
                                    chain_note="head_recovered_from_file")]
    _write(f, recs)
    r = _walk(f)
    assert r.returncode == 3
    assert "head_recovered_from_file" in r.stdout
    assert "off-box copy" in r.stdout


def test_walk_flags_an_intent_with_no_outcome_without_calling_it_a_gap(tmp_path):
    f = tmp_path / "orphan.ndjson"
    _write(f, [_intent(1, "m1"), _outcome(2, "m1"), _intent(3, "m2")])
    r = _walk(f)
    assert r.returncode == 3
    assert "dispatch never reported" in r.stdout
    assert "m2" in r.stdout
    assert "GAP" not in r.stdout


def test_a_bare_intent_record_is_refused_by_the_receipt_path(tmp_path):
    """--receipt on an intent must not print a PASS. An intent carries no
    statement about whether the action happened, and a reader who saw
    "status=dispatching PASS" would file it as one."""
    import json

    p = tmp_path / "intent.json"
    p.write_text(json.dumps(_intent(1, "m1")))
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--receipt", str(p), "--pubkey", str(p)],
        capture_output=True, text=True,
    )
    assert r.returncode == 2
    assert "INTENT record" in r.stderr
