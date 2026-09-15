"""Tests for AuditEntry's actuator_* fields (added in v0.5.0a1)."""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
from rcan.audit_bundle import canonical_json

from robot_md_gateway.attestation import RECEIPT_VERSION, SigningIdentity, build_outcome
from robot_md_gateway.auth import BearerStore, _BearerEntry
from robot_md_gateway.cert.audit import AuditChain, AuditEntry, verify_audit_bundle
from robot_md_gateway.cert.envelope import sign_envelope
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.receiver import make_app


class TestAuditEntryActuatorFields:
    def test_default_fields_are_none(self):
        e = AuditEntry(
            msg_id="m1",
            timestamp_ms=1000,
            decision="allow",
            decision_reason="ok",
            envelope_kid=None,
        )
        assert e.actuator_name is None
        assert e.actuator_outcome_kind is None
        assert e.actuator_telemetry_sha256 is None
        assert e.actuator_telemetry_path is None
        assert e.actuator_error_kind is None

    def test_chain_hash_includes_actuator_fields(self):
        # Two entries identical except for actuator_outcome_kind must produce
        # different chain_hash values.
        chain_a = AuditChain()
        chain_a.append(AuditEntry(
            msg_id="m1", timestamp_ms=1000,
            decision="allow", decision_reason="ok", envelope_kid=None,
            actuator_name="foo", actuator_outcome_kind="executed",
        ))
        chain_b = AuditChain()
        chain_b.append(AuditEntry(
            msg_id="m1", timestamp_ms=1000,
            decision="allow", decision_reason="ok", envelope_kid=None,
            actuator_name="foo", actuator_outcome_kind="no_op",
        ))
        assert chain_a.entries[0].chain_hash != chain_b.entries[0].chain_hash

    def test_populated_fields_round_trip(self):
        e = AuditEntry(
            msg_id="m1",
            timestamp_ms=1000,
            decision="allow",
            decision_reason="ok",
            envelope_kid=None,
            actuator_name="my-actuator",
            actuator_outcome_kind="executed",
            actuator_telemetry_sha256="a" * 64,
            actuator_telemetry_path="/tmp/telem.json",
            actuator_error_kind=None,
        )
        d = e.__dict__
        # canonical_json must accept the dict (no unhashable types)
        canonical_json(d)


def _build_v0_4_x_bundle():
    """Construct a TRUE v0.4.x-shaped audit bundle (no actuator_* fields) signed
    with a fresh test key. Returns (bundle_dict, kid_to_pem).

    v0.4.x entries have ONLY these 7 keys:
    - msg_id
    - timestamp_ms
    - decision
    - decision_reason
    - envelope_kid
    - chain_prev
    - chain_hash

    No actuator_* keys are present (they didn't exist in v0.4.x).
    """
    # Build entries as plain dicts with only the 7 legacy keys.
    # Compute chain hashes using the same logic as the verifier.
    entries = []

    # Entry 0: chain_prev = "0" * 64
    entry0_dict = {
        "msg_id": "m1",
        "timestamp_ms": 1700000000000,
        "decision": "allow",
        "decision_reason": "ok",
        "envelope_kid": "fixture-kid",
        "chain_prev": "0" * 64,
    }
    entry0_hash = hashlib.sha256(
        canonical_json(entry0_dict)
    ).hexdigest()
    entry0_dict["chain_hash"] = entry0_hash
    entries.append(entry0_dict)

    # Entry 1: chain_prev = entry0's chain_hash
    entry1_dict = {
        "msg_id": "m2",
        "timestamp_ms": 1700000001000,
        "decision": "deny",
        "decision_reason": "tool_allowlist: denied",
        "envelope_kid": "fixture-kid",
        "chain_prev": entry0_hash,
    }
    entry1_hash = hashlib.sha256(
        canonical_json(entry1_dict)
    ).hexdigest()
    entry1_dict["chain_hash"] = entry1_hash
    entries.append(entry1_dict)

    # Build the bundle body (v0.4.x shape).
    body = {
        "schema_version": "0.4.x",
        "exported_at": 1700000002000,
        "entry_count": len(entries),
        "entries": entries,
    }

    # Sign the body using Ed25519.
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Sign the canonical JSON of the body.
    body_bytes = canonical_json(body)
    signature = priv.sign(body_bytes)
    signature_b64 = base64.b64encode(signature).decode("utf-8")

    # Build the final signed bundle.
    bundle = {
        "schema_version": "0.4.x",
        "exported_at": 1700000002000,
        "entry_count": len(entries),
        "entries": entries,
        "signature": {
            "kid": "fixture-bundle-kid",
            "sig": signature_b64,
        },
    }

    return bundle, {"fixture-bundle-kid": pub}


class TestAuditBackwardCompat:
    def test_v0_5_chain_verifies(self):
        """A chain produced by v0.5.0a1 (with actuator_* fields populated)
        verifies under the v0.5.0a1 verifier."""
        chain = AuditChain()
        chain.append(AuditEntry(
            msg_id="m1", timestamp_ms=1700000000000,
            decision="allow", decision_reason="ok", envelope_kid="fixture-kid",
            actuator_name="noop", actuator_outcome_kind="no_op",
        ))
        priv = Ed25519PrivateKey.generate()
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        bundle = chain.export_signed(signing_key_pem=pem, kid="kid-2026")
        assert verify_audit_bundle(bundle, kid_to_pem={"kid-2026": pub}) is True

    def test_v0_4_x_shape_chain_verifies_with_none_actuator_fields(self):
        """A v0.4.x-shaped bundle (entries with NO actuator_* keys at all)
        must verify cleanly under the v0.5.0a1 verifier."""
        bundle, kid_to_pem = _build_v0_4_x_bundle()
        # Verify under the v0.5.0a1 verifier (current code path).
        assert verify_audit_bundle(bundle, kid_to_pem=kid_to_pem) is True
        # Sanity: NO actuator fields in any entry (they didn't exist in v0.4.x).
        for entry in bundle["entries"]:
            assert "actuator_name" not in entry
            assert "actuator_outcome_kind" not in entry
            assert "actuator_telemetry_sha256" not in entry
            assert "actuator_telemetry_path" not in entry
            assert "actuator_error_kind" not in entry

    def test_tampered_chain_rejects(self):
        chain = AuditChain()
        chain.append(AuditEntry(
            msg_id="m1", timestamp_ms=1700000000000,
            decision="allow", decision_reason="ok", envelope_kid="fixture-kid",
            actuator_name="noop", actuator_outcome_kind="no_op",
        ))
        priv = Ed25519PrivateKey.generate()
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        bundle = chain.export_signed(signing_key_pem=pem, kid="kid-2026")
        # Tamper with telemetry_sha256.
        bundle["entries"][0]["actuator_telemetry_sha256"] = "f" * 64
        assert verify_audit_bundle(bundle, kid_to_pem={"kid-2026": pub}) is False


# --------------------------------------------------------------------------- #
# OC-09: caller + tier on the audit entry and inside the signed receipt.
#
# `caller` NAMES A CREDENTIAL, NEVER A PERSON. It is the `caller` field of the
# bearer entry in bearers.yaml that authorised the request ("craig-iphone",
# "readonly-probe"). It says which token was presented. Nothing here says who
# was holding the device, and no assertion below should be read as saying so.
# --------------------------------------------------------------------------- #

_FIX = Path(__file__).parent / "fixtures" / "manifests"
_MANIFEST_KID = (_FIX / "signing-key.kid").read_text().strip()
_MANIFEST_PUB = (_FIX / "signing-key.pub").read_bytes()
_GOOD_MANIFEST = str(_FIX / "signed-good.md")
_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify_receipt.py"


class _Resolver:
    def __init__(self, mapping):
        self._m = mapping

    def resolve_public_key_pem(self, kid):
        return self._m.get(kid)


def _pub_pem(priv):
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _app_with_bearers(bearers: dict, priv) -> tuple[TestClient, AuditChain]:
    chain = AuditChain()
    app = make_app(
        resolver=_Resolver({_MANIFEST_KID: _MANIFEST_PUB}),
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
        bearers=bearers,
        audit_chain=chain,
        signing_identity=SigningIdentity(priv=priv, kid="gw-kid", ran=None),
    )
    return TestClient(app), chain


def _envelope(msg_id: str, **over) -> dict:
    body = {
        "msg_id": msg_id, "type": "INVOKE", "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "READ", "tool_name": "mcp__robot__render", "tool_args": {},
        "manifest_path": _GOOD_MANIFEST,
    }
    body.update(over)
    return body


def _run_verifier(receipt: Path, pubkey: Path) -> int:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), "--receipt", str(receipt), "--pubkey", str(pubkey)],
        capture_output=True, text=True,
    ).returncode


class TestCallerAndTierOnTheEntry:
    def test_caller_and_tier_default_to_none(self):
        e = AuditEntry(
            msg_id="m1", timestamp_ms=1000, decision="allow",
            decision_reason="ok", envelope_kid=None,
        )
        assert e.caller is None
        assert e.tier is None

    def test_invoke_records_the_credential_name_and_tier(self):
        priv = Ed25519PrivateKey.generate()
        client, chain = _app_with_bearers(
            {"tok-phone": _BearerEntry(
                token="tok-phone", tier="actuate", caller_id="craig-iphone")},
            priv,
        )
        r = client.post(
            "/v1/invoke",
            headers={"Authorization": "Bearer tok-phone"},
            json=_envelope("oc09-allow"),
        )
        assert r.status_code == 200
        entry = chain.entries[-1]
        assert entry.caller == "craig-iphone"
        assert entry.tier == "actuate"

    def test_bearer_entry_with_no_caller_still_works(self):
        """A bearers.yaml written before `castor up` generated the field.

        It must start the gateway and produce a receipt, with caller null. The
        loader used to do row["caller"] and take the whole gateway down at boot
        on a file that was valid the day it was written.
        """
        priv = Ed25519PrivateKey.generate()
        client, chain = _app_with_bearers(
            {"tok-old": _BearerEntry(token="tok-old", tier="actuate")}, priv,
        )
        r = client.post(
            "/v1/invoke",
            headers={"Authorization": "Bearer tok-old"},
            json=_envelope("oc09-nocaller"),
        )
        assert r.status_code == 200
        assert chain.entries[-1].caller is None
        assert chain.entries[-1].tier == "actuate"
        assert r.json()["outcome"]["caller"] is None

    def test_bearers_yaml_without_caller_loads(self, tmp_path):
        path = tmp_path / "bearers.yaml"
        path.write_text("bearers:\n  - token: t1\n    tier: read\n")
        store = BearerStore.from_yaml(path)
        assert store.resolve("t1").caller_id is None

    def test_unknown_bearer_is_anon_with_no_caller(self):
        priv = Ed25519PrivateKey.generate()
        client, chain = _app_with_bearers(
            {"tok-phone": _BearerEntry(
                token="tok-phone", tier="actuate", caller_id="craig-iphone")},
            priv,
        )
        client.post(
            "/v1/invoke",
            headers={"Authorization": "Bearer not-a-real-token"},
            json=_envelope("oc09-anon"),
        )
        entry = chain.entries[-1]
        assert entry.caller is None
        assert entry.tier == "anon"

    def test_audit_last_shows_the_caller(self):
        priv = Ed25519PrivateKey.generate()
        client, _ = _app_with_bearers(
            {
                "tok-phone": _BearerEntry(
                    token="tok-phone", tier="actuate", caller_id="craig-iphone"),
                "tok-read": _BearerEntry(
                    token="tok-read", tier="read", caller_id="readonly-probe"),
            },
            priv,
        )
        client.post(
            "/v1/invoke",
            headers={"Authorization": "Bearer tok-phone"},
            json=_envelope("oc09-auditlast"),
        )
        r = client.get("/v1/audit/last", headers={"Authorization": "Bearer tok-read"})
        assert r.status_code == 200
        assert r.json()["caller"] == "craig-iphone"
        assert r.json()["tier"] == "actuate"

    def test_deny_carries_the_caller_too(self):
        """A refusal names the credential that was refused.

        The deny path is the one an operator reads first, so it is the one that
        most needs to say which token asked.
        """
        priv = Ed25519PrivateKey.generate()
        client, chain = _app_with_bearers(
            {"tok-phone": _BearerEntry(
                token="tok-phone", tier="actuate", caller_id="craig-iphone")},
            priv,
        )
        r = client.post(
            "/v1/invoke",
            headers={"Authorization": "Bearer tok-phone"},
            json=_envelope("oc09-deny", tool_name="mcp__robot__execute_capability"),
        )
        assert r.status_code == 403
        assert chain.entries[-1].decision == "deny"
        assert chain.entries[-1].caller == "craig-iphone"
        assert r.json()["detail"]["outcome"]["caller"] == "craig-iphone"


class TestCallerInsideTheSignedReceipt:
    def _receipt(self, tmp_path: Path) -> tuple[Path, Path, dict]:
        priv = Ed25519PrivateKey.generate()
        client, _ = _app_with_bearers(
            {"tok-phone": _BearerEntry(
                token="tok-phone", tier="actuate", caller_id="craig-iphone")},
            priv,
        )
        r = client.post(
            "/v1/invoke",
            headers={"Authorization": "Bearer tok-phone"},
            json=_envelope("oc09-receipt"),
        )
        receipt = tmp_path / "receipt.json"
        receipt.write_bytes(r.content)
        pub = tmp_path / "gw.pub"
        pub.write_bytes(_pub_pem(priv))
        return receipt, pub, r.json()

    def test_receipt_is_version_2_and_carries_caller_and_tier(self, tmp_path):
        _, _, body = self._receipt(tmp_path)
        outcome = body["outcome"]
        assert outcome["receipt_version"] == RECEIPT_VERSION == 2
        assert outcome["caller"] == "craig-iphone"
        assert outcome["tier"] == "actuate"

    def test_verifier_accepts_the_v2_receipt(self, tmp_path):
        receipt, pub, _ = self._receipt(tmp_path)
        assert _run_verifier(receipt, pub) == 0

    def test_hand_editing_the_caller_makes_the_verifier_exit_non_zero(self, tmp_path):
        """The point of the version bump.

        caller is inside the signed bytes, so an operator cannot hand you a
        receipt with someone else's credential on it and have it still verify.
        """
        receipt, pub, body = self._receipt(tmp_path)
        edited = json.loads(receipt.read_text())
        edited["outcome"]["caller"] = "host-config"
        receipt.write_text(json.dumps(edited))
        # 1, not 2: the signature check is what refuses it, not a shape check.
        assert _run_verifier(receipt, pub) == 1

    def test_hand_editing_the_tier_makes_the_verifier_exit_non_zero(self, tmp_path):
        receipt, pub, _ = self._receipt(tmp_path)
        edited = json.loads(receipt.read_text())
        edited["outcome"]["tier"] = "commission"
        receipt.write_text(json.dumps(edited))
        assert _run_verifier(receipt, pub) == 1

    def test_verifier_still_accepts_a_v1_receipt(self, tmp_path):
        """Receipts already on disk are v1 forever.

        The iOS app, the console and the shipper all read receipts, so the
        verifier accepts both shapes for at least one release. A v1 receipt has
        no receipt_version key at all.
        """
        priv = Ed25519PrivateKey.generate()
        v1 = {
            "corr_id": "legacy-1",
            "rrn": "RRN-000000000011",
            "status": "ok",
            "started_at": "2026-06-06T00:00:00+00:00",
            "ended_at": "2026-06-06T00:00:00.120000+00:00",
            "duration_ms": 120,
        }
        sign_envelope(priv, v1, "gw-kid")
        assert "receipt_version" not in v1
        receipt = tmp_path / "v1.json"
        receipt.write_text(json.dumps(v1))
        pub = tmp_path / "gw.pub"
        pub.write_bytes(_pub_pem(priv))
        assert _run_verifier(receipt, pub) == 0

    def test_verifier_refuses_a_receipt_version_it_does_not_know(self, tmp_path):
        """Honest about its own limit rather than guessing at a newer shape."""
        priv = Ed25519PrivateKey.generate()
        future = build_outcome(
            corr_id="future-1", rrn="RRN-000000000011", status="ok",
            started_at="2026-06-06T00:00:00+00:00",
            ended_at="2026-06-06T00:00:00+00:00",
            duration_ms=None, telemetry_sha256=None, error=None,
            result_summary=None, caller="craig-iphone", tier="actuate",
        )
        future["receipt_version"] = 99
        sign_envelope(priv, future, "gw-kid")
        receipt = tmp_path / "v99.json"
        receipt.write_text(json.dumps(future))
        pub = tmp_path / "gw.pub"
        pub.write_bytes(_pub_pem(priv))
        assert _run_verifier(receipt, pub) == 2


@pytest.mark.parametrize("caller", [None, "craig-iphone"])
def test_caller_is_part_of_the_chain_hash(caller):
    """Two otherwise identical entries that differ only in caller must differ
    in chain_hash, or the caller is decoration rather than evidence."""
    def _hash(c):
        chain = AuditChain()
        chain.append(AuditEntry(
            msg_id="m1", timestamp_ms=1000, decision="allow",
            decision_reason="ok", envelope_kid=None, caller=c, tier="actuate",
        ))
        return chain.entries[0].chain_hash

    assert _hash(caller) != _hash("someone-else")
