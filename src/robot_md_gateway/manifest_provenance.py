"""Manifest provenance verification for cert properties MF-001 / MF-002.

Reads a ROBOT.md, extracts its signature footer, resolves the signing
key's public-key PEM via an RRF resolver, and verifies the body
signature. Returns a typed result.

Signature footer format (transitional — to be reconciled with the
robot-md spec's canonical scheme in Plan 6 Phase 1):

    <!-- ROBOT-MD-SIG kid=<kid> sig=<base64> -->

The signed body is everything *before* the footer's leading blank line:
specifically, the file's content up to (but not including) the trailing
newline that immediately precedes the footer comment. This must agree
exactly with the canonicalization the signer uses.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_SIG_RE = re.compile(
    r"\n<!--\s*ROBOT-MD-SIG\s+kid=(?P<kid>\S+)\s+sig=(?P<sig>[A-Za-z0-9+/=]+)\s*-->\s*\Z",
)


@runtime_checkable
class RRFResolver(Protocol):
    """Minimal interface for the RRF public-key lookup."""

    def resolve_public_key_pem(self, kid: str) -> bytes | None: ...


@dataclass(frozen=True)
class ManifestProvenanceResult:
    accepted: bool
    kid: str | None
    reason: str


def verify_manifest(path: Path, *, resolver: RRFResolver) -> ManifestProvenanceResult:
    text = path.read_text()
    match = _SIG_RE.search(text)
    if match is None:
        return ManifestProvenanceResult(
            accepted=False, kid=None,
            reason="no ROBOT-MD-SIG footer (signature absent)",
        )
    kid = match.group("kid")
    sig = base64.b64decode(match.group("sig"))
    body = text[: match.start()].encode("utf-8")

    pub_pem = resolver.resolve_public_key_pem(kid)
    if pub_pem is None:
        return ManifestProvenanceResult(
            accepted=False, kid=kid,
            reason=f"signing kid {kid} not registered with resolver",
        )

    try:
        pub = serialization.load_pem_public_key(pub_pem)
    except ValueError as exc:
        return ManifestProvenanceResult(
            accepted=False, kid=kid,
            reason=f"public key PEM invalid: {exc}",
        )
    if not isinstance(pub, Ed25519PublicKey):
        return ManifestProvenanceResult(
            accepted=False, kid=kid,
            reason="public key is not Ed25519",
        )

    try:
        pub.verify(sig, body)
    except InvalidSignature:
        return ManifestProvenanceResult(
            accepted=False, kid=kid,
            reason="signature did not verify against the body",
        )
    return ManifestProvenanceResult(accepted=True, kid=kid, reason="ok")
