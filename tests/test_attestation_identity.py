"""ROBOT_MD_ATTESTATION_* signing-identity loader (mirrors load_bearer_store_from_env)."""

from __future__ import annotations

import logging

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from robot_md_gateway.attestation import SigningIdentity, load_signing_identity_from_env


def _write_key(tmp_path):
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = tmp_path / "attest.key"
    path.write_bytes(pem)
    return path


def test_loads_identity_when_all_env_present(tmp_path, monkeypatch):
    key_path = _write_key(tmp_path)
    monkeypatch.setenv("ROBOT_MD_ATTESTATION_KEY_FILE", str(key_path))
    monkeypatch.setenv("ROBOT_MD_ATTESTATION_KID", "gw-kid-1")
    monkeypatch.setenv("ROBOT_MD_ATTESTATION_RAN", "RAN-000000000020")

    ident = load_signing_identity_from_env()

    assert isinstance(ident, SigningIdentity)
    assert ident.kid == "gw-kid-1"
    assert ident.ran == "RAN-000000000020"
    assert isinstance(ident.priv, Ed25519PrivateKey)


def test_disabled_with_warning_when_key_file_absent(monkeypatch, caplog):
    monkeypatch.delenv("ROBOT_MD_ATTESTATION_KEY_FILE", raising=False)
    monkeypatch.setenv("ROBOT_MD_ATTESTATION_KID", "gw-kid-1")

    with caplog.at_level(logging.WARNING):
        ident = load_signing_identity_from_env()

    assert ident is None
    assert any("attestation disabled" in r.message.lower() for r in caplog.records)


def test_disabled_with_warning_when_kid_absent(tmp_path, monkeypatch, caplog):
    key_path = _write_key(tmp_path)
    monkeypatch.setenv("ROBOT_MD_ATTESTATION_KEY_FILE", str(key_path))
    monkeypatch.delenv("ROBOT_MD_ATTESTATION_KID", raising=False)

    with caplog.at_level(logging.WARNING):
        ident = load_signing_identity_from_env()

    assert ident is None
    assert any("attestation disabled" in r.message.lower() for r in caplog.records)


def test_disabled_when_key_file_missing_on_disk(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("ROBOT_MD_ATTESTATION_KEY_FILE", str(tmp_path / "nope.key"))
    monkeypatch.setenv("ROBOT_MD_ATTESTATION_KID", "gw-kid-1")

    with caplog.at_level(logging.WARNING):
        ident = load_signing_identity_from_env()

    assert ident is None
    assert any("attestation disabled" in r.message.lower() for r in caplog.records)
