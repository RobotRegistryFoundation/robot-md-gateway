"""Tests for AuditEntry's actuator_* fields (added in v0.5.0a1)."""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from rcan.audit_bundle import canonical_json

from robot_md_gateway.cert.audit import AuditChain, AuditEntry, verify_audit_bundle


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
