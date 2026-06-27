"""RCAN invoke `context` — manifest extraction + the signed round-trip proving
context rides the SAME canonical preimage the signature covers (so PlatAtlas, which
re-verifies that preimage, gets tamper-evident parts/model/harness per action)."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from robot_md_gateway.cert.envelope import sign_envelope, verify_envelope
from robot_md_gateway.context import config_hash_for, context_from_manifest, with_context


MANIFEST = {
    "metadata": {
        "rrn": "RRN-000000000011",
        "rcn_ids": ["RCN-000000000042", "RCN-000000000051"],
        "rmn": "RMN-000000000007",
        "rhn_ids": ["RHN-000000000003", "RHN-000000000004"],
    }
}


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem


class _Resolver:
    def __init__(self, pem, kid):
        self._pem, self._kid = pem, kid

    def resolve_public_key_pem(self, k):
        return self._pem if k == self._kid else None


# ── extraction + honesty ──────────────────────────────────────────────────────

def test_context_from_manifest_maps_metadata_ids():
    ctx = context_from_manifest(MANIFEST)
    assert ctx == {
        "rrn": "RRN-000000000011",
        "rcns": ["RCN-000000000042", "RCN-000000000051"],
        "rmn": "RMN-000000000007",
        "rhn": "RHN-000000000003",  # first declared harness by default
    }


def test_active_rhn_must_be_declared_else_falls_back():
    assert context_from_manifest(MANIFEST, active_rhn="RHN-000000000004")["rhn"] == "RHN-000000000004"
    # an undeclared harness is NEVER stamped — falls back to the first declared
    assert context_from_manifest(MANIFEST, active_rhn="RHN-999999999999")["rhn"] == "RHN-000000000003"


def test_absent_dimensions_are_omitted_never_guessed():
    partial = context_from_manifest({"metadata": {"rmn": "RMN-7"}})
    assert partial == {"rmn": "RMN-7"}            # no rrn/rcns/rhn invented
    assert context_from_manifest({"metadata": {}}) is None
    assert context_from_manifest({}) is None       # nothing declared → no context


def test_config_hash_is_stable_and_prefixed():
    h1 = config_hash_for(MANIFEST)
    h2 = config_hash_for({"metadata": MANIFEST["metadata"]})  # same content, new dict
    assert h1.startswith("sha256:") and len(h1) == len("sha256:") + 64
    assert h1 == h2                                # canonical → order-independent
    assert config_hash_for({"metadata": {"rmn": "RMN-9"}}) != h1


# ── the signed round-trip (context is covered by the signature) ───────────────

def _invoke_body():
    return {
        "msg_id": "m1", "type": "invoke", "ruri": "rcan://so-arm101/bob-0001",
        "scope": "actuate.move", "tool_name": "move", "tool_args": {"joint": 1, "deg": 30.0},
    }


def test_signed_invoke_with_context_verifies():
    priv, pem = _keypair()
    body = with_context(_invoke_body(), MANIFEST)
    assert "context" in body and body["context"]["rmn"] == "RMN-000000000007"
    assert "config_hash" in body["context"]                      # stamped by with_context

    signed = sign_envelope(priv, body, "op-kid")
    assert verify_envelope(signed, resolver=_Resolver(pem, "op-kid")).accepted is True


def test_tampering_context_after_signing_breaks_verification():
    priv, pem = _keypair()
    signed = sign_envelope(priv, with_context(_invoke_body(), MANIFEST), "op-kid")

    signed["context"]["rmn"] = "RMN-EVIL"                         # post-sign mutation
    result = verify_envelope(signed, resolver=_Resolver(pem, "op-kid"))
    assert result.accepted is False                              # context IS in the signed preimage


def test_with_context_is_a_noop_when_nothing_declared():
    body = with_context(_invoke_body(), {"metadata": {}})
    assert "context" not in body                                 # no over-claim, no empty block
