"""serve wires ROBOT_MD_ATTESTATION_* + ROBOT_MD_ATTESTATION_EXPORT_FILE into make_app."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _write_key(tmp_path: Path) -> Path:
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    p = tmp_path / "attest.key"
    p.write_bytes(pem)
    return p


def test_serve_passes_signing_identity_and_export_file(tmp_path, monkeypatch):
    key = _write_key(tmp_path)
    export = tmp_path / "traces.ndjson"
    monkeypatch.setenv("ROBOT_MD_ATTESTATION_KEY_FILE", str(key))
    monkeypatch.setenv("ROBOT_MD_ATTESTATION_KID", "gw-kid")
    monkeypatch.setenv("ROBOT_MD_ATTESTATION_EXPORT_FILE", str(export))

    import robot_md_gateway.__main__ as m

    captured = {}

    def fake_make_app(**kwargs):
        captured.update(kwargs)
        return mock.MagicMock()

    monkeypatch.setattr(m, "main", m.main)  # no-op; keep symbol
    with mock.patch("robot_md_gateway.receiver.make_app", side_effect=fake_make_app), \
         mock.patch("uvicorn.run"), \
         mock.patch("sys.argv", ["robot-md-gateway", "serve"]):
        m.main()

    # main() lazily (re)imports robot_md_gateway.attestation; fetch the class from
    # the same live module so isinstance is robust to sys.modules churn from
    # earlier tests (test_backward_compat_shim purges robot_md_gateway.*).
    from robot_md_gateway.attestation import SigningIdentity

    assert isinstance(captured["signing_identity"], SigningIdentity)
    assert captured["signing_identity"].kid == "gw-kid"
    assert captured["attestation_export_file"] == export
