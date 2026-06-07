"""RCAN INVOKE envelope verification (RC-001) + replay protection (RC-002)."""

from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from rcan.audit_bundle import canonical_json

from ..manifest_provenance import RRFResolver
from . import report as cert_report

__all__ = [
    "EnvelopeVerificationResult",
    "ReplayCache",
    "canonical_json",
    "check_replay",
    "sign_envelope",
    "verify_envelope",
]


@dataclass(frozen=True)
class EnvelopeVerificationResult:
    accepted: bool
    kid: str | None
    reason: str


def verify_envelope(envelope: dict, *, resolver: RRFResolver) -> EnvelopeVerificationResult:
    sig = envelope.get("envelope_signature")
    if sig is None:
        return EnvelopeVerificationResult(
            accepted=False, kid=None, reason="no envelope_signature field",
        )
    kid = sig.get("kid")
    pem = resolver.resolve_public_key_pem(kid)
    if pem is None:
        return EnvelopeVerificationResult(
            accepted=False, kid=kid, reason=f"kid {kid} not registered",
        )
    try:
        pub = serialization.load_pem_public_key(pem)
    except ValueError as exc:
        return EnvelopeVerificationResult(
            accepted=False, kid=kid, reason=f"bad PEM: {exc}",
        )
    if not isinstance(pub, Ed25519PublicKey):
        return EnvelopeVerificationResult(
            accepted=False, kid=kid, reason="not Ed25519",
        )
    try:
        pub.verify(
            base64.b64decode(sig["sig"]),
            canonical_json(envelope, exclude="envelope_signature"),
        )
    except InvalidSignature:
        return EnvelopeVerificationResult(
            accepted=False, kid=kid, reason="signature did not verify",
        )
    cert_report.record_property_pass(
        property_id="RC-001",
        evidence={"kid": kid, "msg_id": envelope.get("msg_id")},
    )
    return EnvelopeVerificationResult(accepted=True, kid=kid, reason="ok")


def sign_envelope(priv: Ed25519PrivateKey, body: dict, kid: str) -> dict:
    """Attach a detached Ed25519 ``envelope_signature`` over ``canonical_json(body)``.

    ``body`` MUST NOT already contain an ``envelope_signature`` key. The signature
    covers the canonical bytes of ``body`` as-is; verification recomputes
    ``canonical_json(envelope, exclude="envelope_signature")``, which strips the
    block this function attaches. Standard (not urlsafe) base64; ``alg="Ed25519"``.

    Promoted verbatim from ``scripts/emit_gateway_authority_report.py:_sign_envelope``
    so the production outcome-signer and the CI evidence-signer share one recipe.
    Mutates and returns ``body``.
    """
    sig = priv.sign(canonical_json(body))
    body["envelope_signature"] = {
        "kid": kid,
        "alg": "Ed25519",
        "sig": base64.b64encode(sig).decode(),
    }
    return body


class ReplayCache:
    """In-memory bounded set of seen msg_ids. Production deployments use a
    persistent store (sqlite or redis); this default is fine for HIL +
    short-lived test runs.
    """

    def __init__(self, max_size: int = 100_000) -> None:
        self._seen: set[str] = set()
        self._max = max_size

    def has_seen(self, msg_id: str) -> bool:
        return msg_id in self._seen

    def record(self, msg_id: str) -> None:
        if len(self._seen) >= self._max:
            self._seen.pop()
        self._seen.add(msg_id)


def check_replay(envelope: dict, cache: ReplayCache) -> tuple[bool, str]:
    msg_id = envelope.get("msg_id")
    if not msg_id:
        return False, "missing msg_id"
    if cache.has_seen(msg_id):
        cert_report.record_property_pass(
            property_id="RC-002",
            evidence={"msg_id": msg_id, "outcome": "denied (replay)"},
        )
        return False, f"replay rejected (msg_id {msg_id} already seen)"
    cache.record(msg_id)
    cert_report.record_property_pass(
        property_id="RC-002",
        evidence={"msg_id": msg_id, "outcome": "accepted (fresh)"},
    )
    return True, "ok"
