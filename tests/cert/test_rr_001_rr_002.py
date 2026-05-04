"""RR-001 + RR-002 — Revocation rejection + registry round-trip (library tests)."""

from __future__ import annotations

import pytest

from robot_md_gateway.cert import report as cert_report
from robot_md_gateway.cert.revocation import RevocationCache, round_trip_register


@pytest.fixture(autouse=True)
def _reset():
    cert_report.reset()
    yield


def test_rr_001_revoked_kid_blocked():
    class R:
        def is_revoked(self, kid):
            return kid == "bad-kid"

    cache = RevocationCache()
    assert cache.is_revoked("bad-kid", resolver=R()) is True
    assert cache.is_revoked("good-kid", resolver=R()) is False


def test_rr_001_records_on_both_exit_paths():
    """Phase 1 audit-trail convention — every exit path records with outcome."""
    class R:
        def is_revoked(self, kid):
            return kid == "bad-kid"

    cache = RevocationCache()
    cache.is_revoked("bad-kid", resolver=R())
    cache.is_revoked("good-kid", resolver=R())
    rr_001 = [
        p for p in cert_report._GLOBAL_REPORT.properties if p.property_id == "RR-001"
    ]
    assert len(rr_001) == 2
    outcomes = {p.evidence["outcome"] for p in rr_001}
    assert outcomes == {"denied (revoked)", "allowed (not revoked)"}


def test_rr_001_cached_after_first_check():
    calls = []

    class R:
        def is_revoked(self, kid):
            calls.append(kid)
            return False

    cache = RevocationCache(ttl_s=10.0)
    cache.is_revoked("k1", resolver=R())
    cache.is_revoked("k1", resolver=R())
    assert calls == ["k1"]  # second call hit cache


def test_rr_002_round_trip_ok():
    class Reg:
        def __init__(self):
            self._db = {}

        def register(self, *, kid, public_key_pem):
            self._db[kid] = public_key_pem

        def resolve(self, kid):
            return self._db.get(kid)

    assert round_trip_register(
        registrar=Reg(), kid="kid-rr-002", public_key_pem=b"PEM-BODY",
    )


def test_rr_002_mismatch_detected():
    class FailingReg:
        def register(self, *, kid, public_key_pem):
            pass

        def resolve(self, kid):
            return b"DIFFERENT"

    assert not round_trip_register(
        registrar=FailingReg(), kid="x", public_key_pem=b"PEM",
    )
