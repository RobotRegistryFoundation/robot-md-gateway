"""Interop gates (spec §7 gates 1+2).

Gate 1: the PRODUCTION canonical_json (rcan.audit_bundle.canonical_json — the
        exact one the outcome-signer uses) is byte-exact on every rcan-spec
        canonical-json-v1 vector.
Gate 2: a real gateway-signed outcome verifies the way S3's verifyEnvelope does.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from rcan.audit_bundle import canonical_json

FIXTURE = Path(__file__).parent / "fixtures" / "canonical-json-v1.json"


def test_gate1_canonical_json_byte_exact_on_all_vectors():
    fixture = json.loads(FIXTURE.read_text())
    assert fixture["format"] == "rcan-canonical-json-v1"
    assert fixture["cases"], "fixture must contain vectors"
    for case in fixture["cases"]:
        actual = canonical_json(case["input"])
        expected = base64.b64decode(case["expected_bytes_base64"])
        assert actual == expected, (
            f"canonical_json drift on case {case['name']!r}:\n"
            f"  expected: {expected!r}\n  actual:   {actual!r}"
        )


from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from robot_md_gateway.attestation import build_outcome
from robot_md_gateway.cert.envelope import sign_envelope


def _s3_verify_envelope(env: dict, ed25519_pem: bytes) -> str:
    """Python mirror of proxy-worker src/crypto/rcan-verify.ts::verifyEnvelope.

    Returns 'verified' | 'verify_failed'. Preimage is canonicalBytes(env,
    'envelope_signature') == canonical_json(env, exclude='envelope_signature').
    """
    try:
        sig_block = env.get("envelope_signature") or {}
        sig_b64 = sig_block.get("sig")
        if not sig_b64:
            return "verify_failed"
        pub = serialization.load_pem_public_key(ed25519_pem)
        if not isinstance(pub, Ed25519PublicKey):
            return "verify_failed"
        pub.verify(base64.b64decode(sig_b64), canonical_json(env, exclude="envelope_signature"))
        return "verified"
    except (InvalidSignature, ValueError, KeyError):
        return "verify_failed"


def test_gate2_gateway_signed_outcome_verifies_s3_style():
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    outcome = build_outcome(
        corr_id="m1", rrn="RRN-000000000011", status="ok",
        started_at="2026-06-06T00:00:00+00:00", ended_at="2026-06-06T00:00:00.120000+00:00",
        duration_ms=120, telemetry_sha256="0" * 64, error=None, result_summary=None,
    )
    signed = sign_envelope(priv, outcome, "gateway-kid")

    assert _s3_verify_envelope(signed, pub_pem) == "verified"


def test_gate2_tampered_outcome_fails_s3_verify():
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    outcome = build_outcome(
        corr_id="m1", rrn="RRN-000000000011", status="ok",
        started_at="2026-06-06T00:00:00+00:00", ended_at="2026-06-06T00:00:00+00:00",
        duration_ms=None, telemetry_sha256=None, error=None, result_summary=None,
    )
    signed = sign_envelope(priv, outcome, "gateway-kid")
    signed["rrn"] = "RRN-999999999999"  # tamper a signed field

    assert _s3_verify_envelope(signed, pub_pem) == "verify_failed"
