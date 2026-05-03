"""Tests for manifest_provenance — MF-001 (accept) + MF-002 (reject) prep."""

from __future__ import annotations

from pathlib import Path

import pytest

from robot_md_gateway.manifest_provenance import (
    ManifestProvenanceResult,
    verify_manifest,
)

FIXTURES = Path(__file__).parent / "fixtures" / "manifests"


class _FakeRRFResolver:
    """In-memory resolver that returns the public key for a known kid."""

    def __init__(self, kid_to_pubkey_pem: dict[str, bytes]) -> None:
        self._map = kid_to_pubkey_pem

    def resolve_public_key_pem(self, kid: str) -> bytes | None:
        return self._map.get(kid)


@pytest.fixture
def resolver() -> _FakeRRFResolver:
    kid = (FIXTURES / "signing-key.kid").read_text().strip()
    pub_pem = (FIXTURES / "signing-key.pub").read_bytes()
    return _FakeRRFResolver({kid: pub_pem})


def test_signed_good_manifest_accepted(resolver):
    result = verify_manifest(FIXTURES / "signed-good.md", resolver=resolver)
    assert result.accepted, f"expected accept, got reject: {result.reason}"
    assert result.kid is not None


def test_tampered_manifest_rejected(resolver):
    result = verify_manifest(FIXTURES / "signed-tampered.md", resolver=resolver)
    assert not result.accepted
    assert "signature" in result.reason.lower() or "verify" in result.reason.lower()


def test_unknown_kid_rejected():
    """If the resolver doesn't know the kid, reject."""
    empty_resolver = _FakeRRFResolver({})
    result = verify_manifest(FIXTURES / "signed-good.md", resolver=empty_resolver)
    assert not result.accepted
    assert "kid" in result.reason.lower() or "key" in result.reason.lower()


def test_missing_signature_block_rejected(tmp_path):
    """A manifest without a `<!-- ROBOT-MD-SIG ... -->` footer is rejected."""
    unsigned = tmp_path / "unsigned.md"
    unsigned.write_text("---\nrrn: RRN-000\n---\n\n# Unsigned\n")
    empty_resolver = _FakeRRFResolver({})
    result = verify_manifest(unsigned, resolver=empty_resolver)
    assert not result.accepted
    assert "signature" in result.reason.lower()


def test_result_is_typed():
    """The return value is a ManifestProvenanceResult dataclass."""
    empty_resolver = _FakeRRFResolver({})
    result = verify_manifest(FIXTURES / "signed-good.md", resolver=empty_resolver)
    assert isinstance(result, ManifestProvenanceResult)
    assert hasattr(result, "accepted")
    assert hasattr(result, "kid")
    assert hasattr(result, "reason")
