"""RCAN INVOKE envelope verification (RC-001) + replay protection (RC-002)."""

from __future__ import annotations

import base64
import time
from collections import OrderedDict
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from rcan.audit_bundle import canonical_json

from ..manifest_provenance import RRFResolver
from . import report as cert_report

__all__ = [
    "MISSING_TIMESTAMP",
    "STALE_TIMESTAMP",
    "EnvelopeVerificationResult",
    "FreshnessPolicy",
    "ReplayCache",
    "canonical_json",
    "check_freshness",
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
    cert_report.record_property(
        property_id="RC-001",
        outcome="pass",
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
    """In-memory bounded FIFO window of seen msg_ids. Production deployments use
    a persistent store (sqlite or redis); this default is fine for HIL +
    short-lived test runs.

    THE EVICTION ORDER IS THE WHOLE POINT. This was a ``set`` whose overflow
    branch called ``set.pop()``, which removes an ARBITRARY member: the id it
    dropped could be the one seen a millisecond ago, and dropping an id is
    exactly what re-enables its replay. So a caller who wanted one envelope
    replayed only had to push traffic through the gateway until the cache
    overflowed and hope. An ``OrderedDict`` used as an insertion-ordered queue
    evicts the OLDEST id instead, which is the only eviction a window can make
    and still mean anything: everything inside the window stays rejected, and
    what leaves is what is furthest out of date.

    The honest limit, unchanged: this is a WINDOW, not a permanent ledger. An
    id evicted after ``max_size`` newer ids can be replayed again. The
    timestamp freshness check below is what bounds how long an evicted id
    remains useful to an attacker; together they are the replay story, and
    neither alone is.
    """

    def __init__(self, max_size: int = 100_000) -> None:
        # Values are unused; OrderedDict is the ordered set the stdlib has.
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._max = max_size

    def __len__(self) -> int:
        return len(self._seen)

    def has_seen(self, msg_id: str) -> bool:
        return msg_id in self._seen

    def record(self, msg_id: str) -> None:
        if msg_id in self._seen:
            # Keep the ORIGINAL insertion position. Re-recording must not
            # refresh an id's place in the queue, or a repeatedly-replayed id
            # would keep itself alive in the window forever while genuinely
            # newer ids aged out around it.
            return
        while len(self._seen) >= self._max:
            self._seen.popitem(last=False)  # oldest first
        self._seen[msg_id] = None


@dataclass(frozen=True)
class FreshnessPolicy:
    """Bounded acceptance window for an envelope's ``timestamp_ms``.

    ``max_skew_s`` is deliberately generous (five minutes by default, in both
    directions) because the failure it must not cause is a robot refusing every
    command on a Pi whose clock drifted. It is a bound on how long a captured
    envelope stays useful, not a precise clock check.

    ``require_timestamp`` is OFF by default and that is a compatibility choice,
    not an oversight: the iOS client signs ``timestamp_ms`` into its envelope
    pre-image, but the bring-up harness and the older CLI signers do not send
    the field at all, and turning it on for them would refuse every envelope
    they have ever produced. With it off, an envelope carrying a timestamp is
    held to the window and an envelope without one is not -- so this check
    covers the clients that already provide the field, and says so rather than
    implying a coverage it does not have. Operators who know all their clients
    send it can set ``require_timestamp=True`` and get the strict rule.
    """

    max_skew_s: float = 300.0
    require_timestamp: bool = False


#: Named deny reason for an envelope outside the freshness window. Named rather
#: than prose because what an operator does with it is grep for it.
STALE_TIMESTAMP = "stale_timestamp"
MISSING_TIMESTAMP = "missing_timestamp"


def check_freshness(
    envelope: dict,
    policy: FreshnessPolicy,
    *,
    now_ms: int | None = None,
) -> tuple[bool, str]:
    """RC-002 (freshness half) -- is this envelope's timestamp inside the window?

    Returns ``(ok, reason)``. Records a cert-property fail on every deny branch
    and nothing on the accept branch (the replay check that follows records the
    accept, so one accepted envelope does not file two RC-002 passes).
    """
    raw = envelope.get("timestamp_ms")
    msg_id = envelope.get("msg_id")
    if raw is None:
        if not policy.require_timestamp:
            return True, "ok (no timestamp_ms; freshness not checked)"
        cert_report.record_property(
            property_id="RC-002",
            outcome="fail",
            evidence={"msg_id": msg_id, "outcome": f"denied ({MISSING_TIMESTAMP})"},
        )
        return False, f"{MISSING_TIMESTAMP}: envelope carries no timestamp_ms"
    try:
        ts_ms = int(raw)
    except (TypeError, ValueError):
        cert_report.record_property(
            property_id="RC-002",
            outcome="fail",
            evidence={"msg_id": msg_id, "timestamp_ms": raw,
                      "outcome": "denied (timestamp_ms not an integer)"},
        )
        return False, f"{STALE_TIMESTAMP}: timestamp_ms {raw!r} is not an integer"
    current_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    skew_s = (current_ms - ts_ms) / 1000.0
    if abs(skew_s) > policy.max_skew_s:
        cert_report.record_property(
            property_id="RC-002",
            outcome="fail",
            evidence={
                "msg_id": msg_id,
                "timestamp_ms": ts_ms,
                "skew_s": skew_s,
                "max_skew_s": policy.max_skew_s,
                "outcome": f"denied ({STALE_TIMESTAMP})",
            },
        )
        return False, (
            f"{STALE_TIMESTAMP}: envelope timestamp_ms is {skew_s:.1f}s from this "
            f"gateway's clock, outside the +/-{policy.max_skew_s:.0f}s window"
        )
    return True, "ok"


def check_replay(envelope: dict, cache: ReplayCache) -> tuple[bool, str]:
    msg_id = envelope.get("msg_id")
    if not msg_id:
        return False, "missing msg_id"
    if cache.has_seen(msg_id):
        cert_report.record_property(
            property_id="RC-002",
            outcome="fail",
            evidence={"msg_id": msg_id, "outcome": "denied (replay)"},
        )
        return False, f"replay rejected (msg_id {msg_id} already seen)"
    cache.record(msg_id)
    cert_report.record_property(
        property_id="RC-002",
        outcome="pass",
        evidence={"msg_id": msg_id, "outcome": "accepted (fresh)"},
    )
    return True, "ok"
