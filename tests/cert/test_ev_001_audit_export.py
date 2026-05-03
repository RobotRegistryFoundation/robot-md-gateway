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


def test_ev_001_malformed_signature_returns_false_not_raises():
    """Verifier returns False on malformed signature dict — does not raise."""
    priv_pem, pub_pem = _ed25519_pair()
    chain = AuditChain()
    chain.append(AuditEntry(msg_id="m1", timestamp_ms=1, decision="allow",
                            decision_reason="ok", envelope_kid="x"))
    bundle = chain.export_signed(signing_key_pem=priv_pem, kid="gw")

    # Drop the "kid" subkey
    bundle_no_kid = {**bundle, "signature": {k: v for k, v in bundle["signature"].items() if k != "kid"}}
    assert verify_audit_bundle(bundle_no_kid, kid_to_pem={"gw": pub_pem}) is False

    # Drop the "sig" subkey
    bundle_no_sig = {**bundle, "signature": {k: v for k, v in bundle["signature"].items() if k != "sig"}}
    assert verify_audit_bundle(bundle_no_sig, kid_to_pem={"gw": pub_pem}) is False


def test_ev_001_non_ed25519_key_rejected():
    """Non-Ed25519 PEM in kid_to_pem must be rejected, not crash on verify."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    priv_pem, _ = _ed25519_pair()
    chain = AuditChain()
    chain.append(AuditEntry(msg_id="m1", timestamp_ms=1, decision="allow",
                            decision_reason="ok", envelope_kid="x"))
    bundle = chain.export_signed(signing_key_pem=priv_pem, kid="gw")

    # Build an RSA public key PEM
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub_pem = rsa_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    assert verify_audit_bundle(bundle, kid_to_pem={"gw": rsa_pub_pem}) is False
