"""OC-09 - the replay window evicts the OLDEST id, and stale envelopes are denied.

The cache was a ``set`` whose overflow branch called ``set.pop()``, which
removes an ARBITRARY member. The id it dropped could be the one seen a
millisecond earlier, and dropping an id is exactly what re-enables its replay:
a caller who wanted one envelope replayed had only to push traffic through the
gateway until the cache overflowed. FIFO eviction is the only eviction a window
can make and still mean anything - everything inside the window stays rejected,
and what leaves is what is furthest out of date.

The freshness check is the other half. The window is bounded, so an id that
ages out can be presented again; the timestamp bound is what limits how long a
captured envelope stays useful after that.
"""

from __future__ import annotations

import base64
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from robot_md_gateway.cert import report as cert_report
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.envelope import (
    MISSING_TIMESTAMP,
    STALE_TIMESTAMP,
    FreshnessPolicy,
    ReplayCache,
    canonical_json,
    check_freshness,
    check_replay,
)
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.receiver import make_app


@pytest.fixture(autouse=True)
def _clean_report():
    cert_report.reset()
    yield
    cert_report.reset()


class TestReplayCacheFifo:
    def test_replay_cache_fifo_keeps_old_ids_rejected(self):
        """Flood 100k unique ids, then prove the window still holds.

        Three claims, in order:
          1. after exactly `max_size` ids, the FIRST one flooded is still
             rejected - nothing inside a full window has been let go;
          2. pushing 10 more evicts exactly those 10 OLDEST ids and nothing
             else - this is what the arbitrary set.pop() got wrong;
          3. the most recently seen id is still rejected, which is the id an
             attacker would actually be replaying.
        """
        cache = ReplayCache()  # default window: 100_000
        for i in range(100_000):
            cache.record(f"flood-{i}")

        assert len(cache) == 100_000
        assert cache.has_seen("flood-0"), "a full window must not have evicted anything"
        assert cache.has_seen("flood-99999")

        for i in range(100_000, 100_010):
            cache.record(f"flood-{i}")

        # The ten oldest, and ONLY the ten oldest, are gone.
        for i in range(10):
            assert not cache.has_seen(f"flood-{i}")
        for i in range(10, 100_010):
            assert cache.has_seen(f"flood-{i}"), (
                f"flood-{i} was evicted out of order; eviction is not FIFO"
            )

    def test_the_oldest_id_is_the_one_evicted(self):
        cache = ReplayCache(max_size=3)
        for i in range(4):
            cache.record(f"m{i}")
        assert not cache.has_seen("m0")
        assert [cache.has_seen(f"m{i}") for i in (1, 2, 3)] == [True, True, True]

    def test_re_recording_does_not_refresh_an_ids_place_in_the_queue(self):
        """A repeatedly replayed id must not keep itself alive in the window
        while genuinely newer ids age out around it."""
        cache = ReplayCache(max_size=3)
        cache.record("old")
        cache.record("a")
        cache.record("old")  # re-record: must NOT move it to the back
        cache.record("b")
        cache.record("c")    # evicts the oldest, which is "old"
        assert not cache.has_seen("old")
        assert cache.has_seen("a") and cache.has_seen("b") and cache.has_seen("c")

    def test_a_recently_seen_id_stays_rejected_through_check_replay(self):
        cache = ReplayCache(max_size=1_000)
        assert check_replay({"msg_id": "target"}, cache)[0] is True
        for i in range(500):
            check_replay({"msg_id": f"noise-{i}"}, cache)
        ok, reason = check_replay({"msg_id": "target"}, cache)
        assert ok is False
        assert "already seen" in reason


class TestFreshness:
    def test_stale_timestamp_rejected(self):
        now_ms = int(time.time() * 1000)
        ok, reason = check_freshness(
            {"msg_id": "stale-1", "timestamp_ms": now_ms - 3_600_000},
            FreshnessPolicy(max_skew_s=300.0),
        )
        assert ok is False
        assert STALE_TIMESTAMP in reason

    def test_a_timestamp_far_in_the_future_is_rejected_too(self):
        now_ms = int(time.time() * 1000)
        ok, reason = check_freshness(
            {"msg_id": "future-1", "timestamp_ms": now_ms + 3_600_000},
            FreshnessPolicy(max_skew_s=300.0),
        )
        assert ok is False
        assert STALE_TIMESTAMP in reason

    def test_a_timestamp_inside_the_window_is_accepted(self):
        now_ms = int(time.time() * 1000)
        ok, _ = check_freshness(
            {"msg_id": "fresh-1", "timestamp_ms": now_ms - 30_000},
            FreshnessPolicy(max_skew_s=300.0),
        )
        assert ok is True
        # The accept branch records nothing: check_replay records the accept, so
        # one accepted envelope must not file two RC-002 passes.
        assert cert_report._GLOBAL_REPORT.properties == []

    def test_an_envelope_without_a_timestamp_is_let_through_by_default(self):
        """The compatibility limit, stated as a test.

        The iOS client signs timestamp_ms into its pre-image; the bring-up
        harness and the older CLI signers do not send the field at all. With
        require_timestamp off (the default) those clients keep working and the
        check covers the ones that do carry the field. It is not a claim that
        every envelope is checked for freshness.
        """
        ok, reason = check_freshness({"msg_id": "no-ts"}, FreshnessPolicy())
        assert ok is True
        assert "not checked" in reason

    def test_require_timestamp_denies_an_envelope_without_one(self):
        ok, reason = check_freshness(
            {"msg_id": "no-ts"}, FreshnessPolicy(require_timestamp=True),
        )
        assert ok is False
        assert MISSING_TIMESTAMP in reason

    def test_a_non_integer_timestamp_is_denied(self):
        ok, reason = check_freshness(
            {"msg_id": "bad-ts", "timestamp_ms": "yesterday"}, FreshnessPolicy(),
        )
        assert ok is False
        assert STALE_TIMESTAMP in reason

    def test_the_window_is_configurable(self):
        now_ms = int(time.time() * 1000)
        env = {"msg_id": "w-1", "timestamp_ms": now_ms - 600_000}  # 10 minutes old
        assert check_freshness(env, FreshnessPolicy(max_skew_s=300.0))[0] is False
        assert check_freshness(env, FreshnessPolicy(max_skew_s=1800.0))[0] is True


# --------------------------------------------------------------------------- #
# Receiver wiring: a stale envelope is a named 403, and it is recorded.
# --------------------------------------------------------------------------- #

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "manifests"


def _signed_client(freshness_policy: FreshnessPolicy):
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    manifest_kid = (_FIXTURES / "signing-key.kid").read_text().strip()
    manifest_pub = (_FIXTURES / "signing-key.pub").read_bytes()

    class _R:
        def resolve_public_key_pem(self, k):
            return {manifest_kid: manifest_pub, "principal-kid": pub_pem}.get(k)

    chain = AuditChain()
    app = make_app(
        resolver=_R(),
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
        require_envelope_signature=True,
        freshness_policy=freshness_policy,
        audit_chain=chain,
    )

    def make(msg_id, **over):
        body = {
            "msg_id": msg_id, "type": "INVOKE", "ruri": "rcan://lab/test/bot/0",
            "scope": "READ", "tool_name": "mcp__robot__render", "tool_args": {},
            "manifest_path": str(_FIXTURES / "signed-good.md"),
        }
        body.update(over)
        sig = priv.sign(canonical_json(body))
        body["envelope_signature"] = {
            "kid": "principal-kid", "alg": "Ed25519",
            "sig": base64.b64encode(sig).decode(),
        }
        return body

    return TestClient(app), make, chain


def test_receiver_denies_a_stale_envelope_with_a_named_reason():
    client, make, chain = _signed_client(FreshnessPolicy(max_skew_s=300.0))
    stale = make("stale-wire-1", timestamp_ms=int(time.time() * 1000) - 3_600_000)
    r = client.post("/v1/invoke", json=stale)
    assert r.status_code == 403
    assert r.json()["detail"]["deny"] == "envelope_freshness"
    assert STALE_TIMESTAMP in r.json()["detail"]["reason"]
    assert chain.entries[-1].decision == "deny"


def test_receiver_accepts_a_fresh_envelope_that_carries_a_timestamp():
    client, make, _ = _signed_client(FreshnessPolicy(max_skew_s=300.0))
    fresh = make("fresh-wire-1", timestamp_ms=int(time.time() * 1000))
    r = client.post("/v1/invoke", json=fresh)
    assert r.status_code == 200, r.text


def test_receiver_still_accepts_an_envelope_with_no_timestamp():
    """The clients that predate the field keep working. This is the whole
    reason require_timestamp defaults to off."""
    client, make, _ = _signed_client(FreshnessPolicy(max_skew_s=300.0))
    r = client.post("/v1/invoke", json=make("no-ts-wire-1"))
    assert r.status_code == 200, r.text


def test_a_stale_envelope_does_not_consume_a_slot_in_the_replay_window():
    """Freshness runs BEFORE the replay cache records the id, so a flood of
    stale envelopes cannot push live ids out of the window."""
    client, make, _ = _signed_client(FreshnessPolicy(max_skew_s=300.0))
    old_ms = int(time.time() * 1000) - 3_600_000
    for i in range(5):
        client.post("/v1/invoke", json=make(f"stale-flood-{i}", timestamp_ms=old_ms))
    # The same msg_ids are still unseen, so they were never recorded.
    fresh = make("stale-flood-0", timestamp_ms=int(time.time() * 1000))
    assert client.post("/v1/invoke", json=fresh).status_code == 200
