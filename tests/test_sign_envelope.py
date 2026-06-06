"""Public sign_envelope — promoted from scripts/emit_gateway_authority_report.py:_sign_envelope."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from robot_md_gateway.cert.envelope import canonical_json, sign_envelope, verify_envelope


def _keypair() -> tuple[Ed25519PrivateKey, bytes]:
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem


def test_sign_envelope_round_trips_through_verify_envelope():
    priv, pub_pem = _keypair()
    body = {"corr_id": "m1", "rrn": "RRN-000000000011", "status": "ok"}

    signed = sign_envelope(priv, body, "gateway-kid")

    assert signed["envelope_signature"]["kid"] == "gateway-kid"
    assert signed["envelope_signature"]["alg"] == "Ed25519"

    class R:
        def resolve_public_key_pem(self, k):
            return pub_pem if k == "gateway-kid" else None

    assert verify_envelope(signed, resolver=R()).accepted is True


def test_sign_envelope_signs_over_canonical_json_without_signature_field():
    priv, pub_pem = _keypair()
    body = {"b": 2, "a": 1}

    signed = sign_envelope(priv, dict(body), "k")

    # The signature must cover canonical_json(body) computed BEFORE the
    # envelope_signature was attached (the exclude-on-verify contract).
    expected_sig = priv.sign(canonical_json(body))
    assert base64.b64decode(signed["envelope_signature"]["sig"]) == expected_sig


def test_sign_envelope_uses_standard_not_urlsafe_base64():
    priv, _ = _keypair()
    # A body whose signature bytes contain a byte that differs between
    # standard and urlsafe base64 alphabets ('+'/'/' vs '-'/'_'). Re-encoding
    # with standard b64 must reproduce the stored value exactly.
    signed = sign_envelope(priv, {"x": "y"}, "k")
    raw = base64.b64decode(signed["envelope_signature"]["sig"])
    assert base64.b64encode(raw).decode() == signed["envelope_signature"]["sig"]
