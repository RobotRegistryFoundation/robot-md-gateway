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
        # Phase 1 audit-trail convention: record on EVERY exit path with
        # outcome captured in evidence (matches cert/gates.py + cert/safety.py).
        # Four exit paths: cache-hit (pass), resolver-error (fail+raise),
        # resolver-None (fail+raise), resolver-bool (pass). All must record.
        if cached and (now - cached[0]) < self.ttl_s:
            cert_report.record_property_pass(
                property_id="RR-001",
                evidence={
                    "kid": kid,
                    "outcome": "denied (revoked)" if cached[1] else "allowed (not revoked)",
                    "source": "cache",
                },
            )
            return cached[1]
        try:
            raw = resolver.is_revoked(kid)
        except Exception as exc:
            cert_report.record_property_fail(
                property_id="RR-001",
                evidence={
                    "kid": kid,
                    "outcome": "error",
                    "error": str(exc),
                    "source": "resolver",
                },
            )
            raise
        if raw is None:
            # Fail-closed: a None response means RRF couldn't tell us.
            # Allowing the request would be fail-open on a safety gateway.
            cert_report.record_property_fail(
                property_id="RR-001",
                evidence={"kid": kid, "outcome": "unresolvable", "source": "resolver"},
            )
            raise RuntimeError(
                f"revocation resolver returned None for kid {kid!r}; "
                f"cannot determine status (treat as failure to verify)"
            )
        revoked = raw  # already a bool
        self._cache[kid] = (now, revoked)
        cert_report.record_property_pass(
            property_id="RR-001",
            evidence={
                "kid": kid,
                "outcome": "denied (revoked)" if revoked else "allowed (not revoked)",
                "source": "resolver",
            },
        )
        return revoked


def round_trip_register(*, registrar, kid: str, public_key_pem: bytes) -> bool:
    """RR-002: register a key with RRF, then resolve it back."""
    registrar.register(kid=kid, public_key_pem=public_key_pem)
    resolved = registrar.resolve(kid)
    ok = resolved == public_key_pem
    if ok:
        cert_report.record_property_pass(
            property_id="RR-002",
            evidence={"kid": kid, "outcome": "ok"},
        )
    else:
        cert_report.record_property_fail(
            property_id="RR-002",
            evidence={"kid": kid, "outcome": "mismatch"},
        )
    return ok
