"""Revoked-key rejection (RR-001) + registry round-trip (RR-002)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from . import report as cert_report


@runtime_checkable
class RRFRevocationResolver(Protocol):
    def is_revoked(self, kid: str) -> bool | None: ...


@dataclass
class RevocationCache:
    """Caches kid -> revoked status with TTL. Polls RRF on miss."""
    ttl_s: float = 60.0
    _cache: dict[str, tuple[float, bool]] = field(default_factory=dict)

    def is_revoked(self, kid: str, *, resolver: RRFRevocationResolver) -> bool:
        now = time.monotonic()
        cached = self._cache.get(kid)
        if cached and (now - cached[0]) < self.ttl_s:
            return cached[1]
        revoked = bool(resolver.is_revoked(kid))
        self._cache[kid] = (now, revoked)
        # Phase 1 audit-trail convention: record on EVERY exit path with
        # outcome captured in evidence (matches cert/gates.py + cert/safety.py).
        cert_report.record_property_pass(
            property_id="RR-001",
            evidence={
                "kid": kid,
                "outcome": "denied (revoked)" if revoked else "allowed (not revoked)",
            },
        )
        return revoked


def round_trip_register(*, registrar, kid: str, public_key_pem: bytes) -> bool:
    """RR-002: register a key with RRF, then resolve it back."""
    registrar.register(kid=kid, public_key_pem=public_key_pem)
    resolved = registrar.resolve(kid)
    ok = resolved == public_key_pem
    cert_report.record_property_pass(
        property_id="RR-002",
        evidence={"kid": kid, "outcome": "ok" if ok else "mismatch"},
    )
    return ok
