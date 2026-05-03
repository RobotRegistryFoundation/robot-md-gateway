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
    chain_prev: str = ""  # filled by AuditChain.append; sha256 of prior entry's canonical bytes
    chain_hash: str = ""  # filled by AuditChain.append; sha256 of this entry's canonical bytes


@dataclass
class AuditChain:
    entries: list[AuditEntry] = field(default_factory=list)

    def append(self, entry: AuditEntry) -> None:
        if not self.entries:
            entry = AuditEntry(**{**entry.__dict__, "chain_prev": "0" * 64})
        else:
            entry = AuditEntry(**{**entry.__dict__, "chain_prev": self.entries[-1].chain_hash})
        canon = canonical_json({k: v for k, v in entry.__dict__.items() if k != "chain_hash"})
        h = hashlib.sha256(canon).hexdigest()
        self.entries.append(AuditEntry(**{**entry.__dict__, "chain_hash": h}))

    def export_signed(self, *, signing_key_pem: bytes, kid: str) -> dict:
        priv = serialization.load_pem_private_key(signing_key_pem, password=None)
        body = {
            "schema_version": "1.0",
            "exported_at": datetime.now(tz=timezone.utc).isoformat(),
            "entry_count": len(self.entries),
            "entries": [e.__dict__ for e in self.entries],
        }
        sig = priv.sign(canonical_json(body))
        bundle = {**body, "signature": {"kid": kid, "alg": "Ed25519", "sig": base64.b64encode(sig).decode()}}
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
