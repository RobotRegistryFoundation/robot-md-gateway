"""Locks the signed-DENY demo's invariants so it can't silently rot:
a MOVE at READ tier is DENIED, the refusal verifies offline against the
operator key, and a tampered refusal is rejected. Imports the example module
by path (it lives in examples/, not the package)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_DEMO = Path(__file__).resolve().parent.parent / "examples" / "signed_deny_demo.py"
_spec = importlib.util.spec_from_file_location("signed_deny_demo", _DEMO)
demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo)


def test_move_at_read_tier_is_denied():
    invoke = demo.move_invoke_at_read_tier()
    decision, reasons = demo.gate(invoke, demo.READ_ONLY_ALLOWLIST)
    assert decision == "deny"
    # both gates fire: not in allowlist AND read-tier can't actuate
    assert any("allowlist" in r for r in reasons)
    assert any("read-tier" in r for r in reasons)


def test_signed_refusal_verifies_offline_and_status_is_denied():
    priv, pub_pem = demo.mint_operator_key()
    invoke = demo.move_invoke_at_read_tier()
    _, reasons = demo.gate(invoke, demo.READ_ONLY_ALLOWLIST)
    trace = demo.sign_refusal(priv, invoke, reasons)
    signed = trace["outcome"]
    assert signed["status"] == "denied"
    assert signed["envelope_signature"]["alg"] == "Ed25519"
    assert demo.verify_offline(signed, pub_pem) is True


def test_tampered_refusal_is_rejected():
    priv, pub_pem = demo.mint_operator_key()
    invoke = demo.move_invoke_at_read_tier()
    _, reasons = demo.gate(invoke, demo.READ_ONLY_ALLOWLIST)
    signed = demo.sign_refusal(priv, invoke, reasons)["outcome"]
    # flip the verdict; the signature must no longer verify
    import json
    tampered = json.loads(json.dumps(signed))
    tampered["status"] = "ok"
    assert demo.verify_offline(tampered, pub_pem) is False


def test_wrong_key_does_not_verify():
    priv, _ = demo.mint_operator_key()
    _, other_pub = demo.mint_operator_key()  # a DIFFERENT operator's key
    invoke = demo.move_invoke_at_read_tier()
    _, reasons = demo.gate(invoke, demo.READ_ONLY_ALLOWLIST)
    signed = demo.sign_refusal(priv, invoke, reasons)["outcome"]
    assert demo.verify_offline(signed, other_pub) is False


def test_run_demo_all_invariants_hold():
    r = demo.run_demo()
    assert r["decision"] == "deny"
    assert r["authentic"] is True
    assert r["tamper_detected"] is True
