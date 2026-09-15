"""Audit-bundle export for cert property EV-001.

This is the gateway's per-session message audit chain — a hash-linked
list of allow/deny decisions, signed once with the gateway's Ed25519
key, verifiable offline.

Distinct from rcan-spec's compliance `audit-bundle-v1` (which carries
cert artifacts with nested signatures). Both are 'audit bundles' in
the colloquial sense; only `canonical_json` is shared via rcan-py.
"""

from __future__ import annotations

import base64
import hashlib
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from rcan.audit_bundle import canonical_json

from . import report as cert_report


@dataclass
class AuditEntry:
    msg_id: str
    timestamp_ms: int
    decision: str  # "allow" or "deny"
    decision_reason: str
    envelope_kid: str | None
    # NEW v0.5.0a1 — actuator outcome fields. None for v0.4.x entries.
    actuator_name: str | None = None
    actuator_outcome_kind: str | None = None  # "executed" | "no_op" | "deferred" | "error"
    actuator_telemetry_sha256: str | None = None  # sha256 of canonical(telemetry)
    actuator_telemetry_path: str | None = None  # filesystem path if persisted
    actuator_error_kind: str | None = None  # exception class name on actuator error
    # NEW v0.5.0a7 (OC-09): who presented the credential, and at what tier.
    #
    # `caller` IS THE NAME OF A CREDENTIAL, NEVER THE NAME OF A PERSON. It is
    # the `caller` field of the bearer entry in bearers.yaml that authorised
    # this request ("craig-iphone", "host-config", "readonly-probe"). It says
    # which token was presented; it does not say who was holding the device,
    # and nothing in this gateway can. None when the request carried no bearer,
    # an unknown bearer, or a bearer entry with no `caller` declared.
    caller: str | None = None
    tier: str | None = None  # "read" | "actuate" | "commission" | "anon"
    # NEW v0.5.0a8 (OC-M-04): record before dispatch.
    #
    # `entry_kind` says WHEN in the request this entry was written, and it is
    # the field that keeps an intent from reading as an action that happened:
    #
    #   "intent"   written after every gate passed and BEFORE the actuator was
    #              called. It says the gateway was about to dispatch. It says
    #              NOTHING about whether the actuator ran, succeeded, or was
    #              even reachable. An intent entry alone is an open question,
    #              not a completed action.
    #   "outcome"  written after the actuator returned (or raised). This is the
    #              entry that says what happened, and it is the DEFAULT so every
    #              entry written before this release keeps exactly the meaning
    #              it already had.
    #
    # An intent entry never carries actuator_outcome_kind, telemetry or an
    # error kind, because at the moment it is written none of those exist yet.
    entry_kind: str = "outcome"
    tool_name: str | None = None  # the RCAN tool the envelope asked for
    envelope_id: str | None = None  # envelope-level id when the client sends one
    nonce: str | None = None  # the envelope's replay nonce, when it carries one
    # On an "outcome" entry: the chain_hash of the "intent" entry written for
    # the same dispatch, so the pair is linkable in one hop. None on an intent
    # entry, and None on an outcome whose intent could not be written (the
    # record path is best effort and must never alter actuation).
    intent_chain_hash: str | None = None
    # Chain linkage — must remain last; AuditChain.append fills these in.
    chain_prev: str = ""  # filled by AuditChain.append; sha256 of prior entry's canonical bytes
    chain_hash: str = ""  # filled by AuditChain.append; sha256 of this entry's canonical bytes


@dataclass
class AuditChain:
    entries: list[AuditEntry] = field(default_factory=list)
    #: Serialises `append`. NOT a dataclass comparison or repr field: it is
    #: machinery, not content.
    #:
    #: WHY A LOCK IS NEEDED AT ALL. The gateway's `/v1/invoke` is a SYNC FastAPI
    #: path operation, so Starlette runs it in a worker thread and two invokes
    #: with different msg_ids are genuinely concurrent. `append` reads
    #: `entries[-1].chain_hash`, hashes, and then appends: three steps with
    #: bytecode boundaries between them, and the interpreter may switch threads
    #: at any of them. Without the lock two threads read the SAME predecessor
    #: hash and both link to it, which forks the chain. Measured on this Pi with
    #: 16 threads appending 25 entries each: 257 to 302 of 400 entries ended up
    #: with a `chain_prev` that was not the previous entry's `chain_hash`, so a
    #: reader walking the chain sees a break on most lines. The entries were all
    #: still there; it was their ORDER that stopped being provable, which is the
    #: one thing a hash chain is for.
    #:
    #: `threading.Lock` and not an asyncio lock, because the contending callers
    #: are OS threads from Starlette's threadpool, not coroutines on one loop.
    _lock: threading.Lock = field(
        default_factory=threading.Lock, repr=False, compare=False,
    )

    def append(self, entry: AuditEntry) -> AuditEntry:
        """Link and store one entry. Returns THE STORED ENTRY, chain hash filled.

        Returning it is not a convenience. A caller that needs the hash of the
        entry it just wrote (the intent record does, so the outcome can point at
        it) cannot get it from `entries[-1]`: by the time that read runs, another
        thread's invoke may have appended. Read the return value, never the tail.
        """
        with self._lock:
            if not self.entries:
                entry = AuditEntry(**{**entry.__dict__, "chain_prev": "0" * 64})
            else:
                entry = AuditEntry(**{**entry.__dict__, "chain_prev": self.entries[-1].chain_hash})
            canon = canonical_json({k: v for k, v in entry.__dict__.items() if k != "chain_hash"})
            h = hashlib.sha256(canon).hexdigest()
            stored = AuditEntry(**{**entry.__dict__, "chain_hash": h})
            self.entries.append(stored)
            return stored

    def export_signed(self, *, signing_key_pem: bytes, kid: str) -> dict:
        priv = serialization.load_pem_private_key(signing_key_pem, password=None)
        body = {
            "schema_version": "1.0",
            "exported_at": datetime.now(tz=timezone.utc).isoformat(),
            "entry_count": len(self.entries),
            "entries": [e.__dict__ for e in self.entries],
        }
        sig = priv.sign(canonical_json(body))
        bundle = {
            **body,
            "signature": {
                "kid": kid,
                "alg": "Ed25519",
                "sig": base64.b64encode(sig).decode(),
            },
        }
        cert_report.record_property_pass(
            property_id="EV-001",
            evidence={"entry_count": len(self.entries), "kid": kid, "outcome": "exported"},
        )
        return bundle


def verify_audit_bundle(bundle: dict, *, kid_to_pem: dict[str, bytes]) -> bool:
    """Offline verifier — does NOT call cert_report (offline tooling)."""
    sig = bundle.get("signature")
    if sig is None:
        return False
    try:
        pem = kid_to_pem.get(sig["kid"])
        if pem is None:
            return False
        pub = serialization.load_pem_public_key(pem)
        if not isinstance(pub, Ed25519PublicKey):
            return False
        body = {k: v for k, v in bundle.items() if k != "signature"}
        pub.verify(base64.b64decode(sig["sig"]), canonical_json(body))
    except Exception:
        return False

    # Verify chain
    prev_hash = "0" * 64
    for entry in bundle["entries"]:
        if entry["chain_prev"] != prev_hash:
            return False
        canon = canonical_json({k: v for k, v in entry.items() if k != "chain_hash"})
        if hashlib.sha256(canon).hexdigest() != entry["chain_hash"]:
            return False
        prev_hash = entry["chain_hash"]
    return True
