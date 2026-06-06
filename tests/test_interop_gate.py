"""Interop gates (spec §7 gates 1+2).

Gate 1: the PRODUCTION canonical_json (rcan.audit_bundle.canonical_json — the
        exact one the outcome-signer uses) is byte-exact on every rcan-spec
        canonical-json-v1 vector.
Gate 2: a real gateway-signed outcome verifies the way S3's verifyEnvelope does.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from rcan.audit_bundle import canonical_json

FIXTURE = Path(__file__).parent / "fixtures" / "canonical-json-v1.json"


def test_gate1_canonical_json_byte_exact_on_all_vectors():
    fixture = json.loads(FIXTURE.read_text())
    assert fixture["format"] == "rcan-canonical-json-v1"
    assert fixture["cases"], "fixture must contain vectors"
    for case in fixture["cases"]:
        actual = canonical_json(case["input"])
        expected = base64.b64decode(case["expected_bytes_base64"])
        assert actual == expected, (
            f"canonical_json drift on case {case['name']!r}:\n"
            f"  expected: {expected!r}\n  actual:   {actual!r}"
        )
