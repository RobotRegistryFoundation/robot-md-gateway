"""EV-001 — Audit bundle offline-verifiable."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from robot_md_gateway.cert.audit import AuditChain, AuditEntry, verify_audit_bundle


def _ed25519_pair() -> tuple[bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def test_ev_001_signed_chain_verifies_offline():
    priv_pem, pub_pem = _ed25519_pair()
    chain = AuditChain()
    chain.append(AuditEntry(msg_id="m1", timestamp_ms=1, decision="allow",
                            decision_reason="ok", envelope_kid="x"))
    chain.append(AuditEntry(msg_id="m2", timestamp_ms=2, decision="deny",
                            decision_reason="replay", envelope_kid="x"))

    bundle = chain.export_signed(signing_key_pem=priv_pem, kid="gateway-test")
    assert verify_audit_bundle(bundle, kid_to_pem={"gateway-test": pub_pem})


def test_ev_001_tampered_entry_breaks_chain():
    priv_pem, pub_pem = _ed25519_pair()
    chain = AuditChain()
    chain.append(AuditEntry(msg_id="m1", timestamp_ms=1, decision="allow",
                            decision_reason="ok", envelope_kid="x"))

    bundle = chain.export_signed(signing_key_pem=priv_pem, kid="gateway-test")
    bundle["entries"][0]["decision"] = "deny"  # tamper
    assert not verify_audit_bundle(bundle, kid_to_pem={"gateway-test": pub_pem})
