#!/usr/bin/env python3
"""Generate the committed cross-plan interop fixture consumed by U1c's proxy-worker test.

Writes ONE gateway-signed rcan-action-trace/1 line + a kid->pem keys file into the
proxy-worker fixtures dir. Both invoke and outcome are signed (binding_ok in S3
requires BOTH to verify — rcan-ingest.ts:39-44). Run once; the output is committed.

The U1c proxy-worker test loads gateway_signed.json, resolves u1c-operator-kid
and u1c-gateway-kid from gateway_signed.keys.json, runs the REAL annotateRcanBody,
and asserts authz_verdict==exec_verdict=='verified' and binding_ok===True.
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from robot_md_gateway.attestation import build_action_trace, build_outcome
from robot_md_gateway.cert.envelope import sign_envelope

# Deterministic seed keys would be ideal, but Ed25519PrivateKey.generate() is
# fine: the keys are committed alongside the signed record, so the fixture is
# self-consistent regardless of the actual key material.
OP_KID = "u1c-operator-kid"
GW_KID = "u1c-gateway-kid"
RRN = "RRN-000000000011"
RURI = "rcan://so-arm101/bob-rpi5-hailo-0001"

OUT_DIR = Path("/home/craigm26/wa-u1/proxy-worker/test/fixtures/rcan")


def _pem(priv: Ed25519PrivateKey) -> str:
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def main() -> None:
    op_priv = Ed25519PrivateKey.generate()
    gw_priv = Ed25519PrivateKey.generate()

    invoke = sign_envelope(
        op_priv,
        {
            "msg_id": "u1c-m1", "type": "invoke", "ruri": RURI,
            "scope": "actuate.move", "tool_name": "move",
            "tool_args": {"joint": 1, "deg": 30.0},
        },
        OP_KID,
    )
    outcome = build_outcome(
        corr_id="u1c-m1", rrn=RRN, status="ok",
        started_at="2026-06-06T00:00:00+00:00",
        ended_at="2026-06-06T00:00:00.120000+00:00",
        duration_ms=120, telemetry_sha256="0" * 64, error=None, result_summary=None,
    )
    outcome = sign_envelope(gw_priv, outcome, GW_KID)

    record = build_action_trace(invoke=invoke, outcome=outcome, ruri=RURI, rrn=RRN)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "gateway_signed.json").write_text(json.dumps(record, indent=2) + "\n")
    (OUT_DIR / "gateway_signed.keys.json").write_text(
        json.dumps(
            {
                OP_KID: {
                    "public_key_pem": _pem(op_priv),
                    "ran": "RAN-000000000019",
                    "status": "active",
                },
                GW_KID: {
                    "public_key_pem": _pem(gw_priv),
                    "ran": "RAN-000000000020",
                    "status": "active",
                },
            },
            indent=2,
        )
        + "\n"
    )
    print("wrote", OUT_DIR / "gateway_signed.json")
    print("wrote", OUT_DIR / "gateway_signed.keys.json")


if __name__ == "__main__":
    main()
