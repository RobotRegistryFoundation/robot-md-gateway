"""Tests for scripts/emit_gateway_authority_report.py — Track 2 NORMATIVE coverage.

Catches a regression that would silently drop a cert property from the report,
or cause the signed body to drift from the canonical_json shape that downstream
verifiers will use.
"""

from __future__ import annotations

import base64
import importlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from rcan.audit_bundle import canonical_json

FIXTURES = Path(__file__).parent / "fixtures" / "manifests"


def _load_emit_module():
    """(Re)load the emit script and return (emit_module, cert_report_module).

    Each call resolves to the live `robot_md_gateway.cert.report` instance —
    important because `tests/test_backward_compat_shim.py::_force_clean_imports`
    drops `robot_md_gateway.*` from sys.modules between tests. If we cache an
    older module reference, our `_GLOBAL_REPORT` view diverges from the one
    that `udev_policy.generate_rules` records into during the run.
    """
    # Drop any stale cached references so we end up bound to the same module
    # instances the emit script's downstream imports will resolve to.
    for key in list(sys.modules):
        if key == "robot_md_gateway" or key.startswith("robot_md_gateway."):
            del sys.modules[key]
        if key == "emit_gateway_authority_report":
            del sys.modules[key]

    spec = importlib.util.spec_from_file_location(
        "emit_gateway_authority_report",
        Path(__file__).parent.parent / "scripts" / "emit_gateway_authority_report.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["emit_gateway_authority_report"] = module
    spec.loader.exec_module(module)
    cert_report_module = importlib.import_module("robot_md_gateway.cert.report")
    return module, cert_report_module


@pytest.fixture
def emit():
    """Reload the emit script + return (emit_module, cert_report_module)."""
    module, cert_report_module = _load_emit_module()
    cert_report_module.reset()
    return module, cert_report_module


EXPECTED_PROPERTY_IDS = frozenset({
    "MF-001", "MF-002",
    "GW-001", "GW-002", "GW-003",
    "RC-001", "RC-002", "RC-003", "RC-004",
    "SF-001", "SF-002",
    "EV-001",
    "RR-001", "RR-002",
})


def test_run_evidence_collection_records_all_14_properties(emit):
    """Track 2 NORMATIVE invariant: emitter must drive all 14 cert properties."""
    emit_module, cert_report = emit
    emit_module._run_evidence_collection(FIXTURES)
    recorded = {p.property_id for p in cert_report._GLOBAL_REPORT.properties}
    assert recorded == EXPECTED_PROPERTY_IDS, (
        f"Missing: {EXPECTED_PROPERTY_IDS - recorded}; "
        f"Extra: {recorded - EXPECTED_PROPERTY_IDS}"
    )


def test_signed_report_round_trips_through_canonical_json(emit, tmp_path: Path):
    """A signed report must verify against the same canonicalization shape it was signed with.

    Catches drift between the emitter's signing and any downstream verifier.
    """
    emit_module, cert_report = emit
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_path = tmp_path / "key.pem"
    pem_path.write_bytes(priv_pem)

    out_dir = tmp_path / "cert"
    out_dir.mkdir()

    # Drive evidence + write the unsigned report.
    emit_module._run_evidence_collection(FIXTURES)
    out_path = out_dir / "gateway-authority-test-test-sha.json"
    cert_report.write(out_path, repo="test", sha="test-sha")

    # Sign it.
    emit_module._sign_report(out_path, signing_key_pem=pem_path, kid="test-kid")

    # Load, verify.
    body = json.loads(out_path.read_text())
    sig = body.pop("signature")
    pub = priv.public_key()
    pub.verify(base64.b64decode(sig["sig"]), canonical_json(body))
    assert sig["kid"] == "test-kid"
    assert sig["alg"] == "Ed25519"
    # Signed reports bump schema_version to 1.0.
    assert body["schema_version"] == "1.0"
