#!/usr/bin/env python3
"""Emit gateway-authority-<repo>-<sha>.json with all 14 cert properties.

Runs the canonical evidence-generating actions for the full Plan 6 Phase 2 set
(MF-001, MF-002, GW-001, GW-002, GW-003, RC-001, RC-002, RC-003, RC-004,
SF-001, SF-002, EV-001, RR-001, RR-002) deterministically (independent of the
pytest run, which has its own per-test isolation), and serializes the resulting
cert report.

When ``--signing-key-pem`` is supplied, the resulting JSON is signed in-place
with an Ed25519 release key (with ``--kid`` set to the matching key id) using
the same ``rcan.audit_bundle.canonical_json`` shape that ``cert/audit.py``
uses for its EV-001 audit bundles.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from fastapi.testclient import TestClient
from rcan.audit_bundle import canonical_json

from robot_md_gateway.cert import report as cert_report
from robot_md_gateway.cert.audit import AuditChain, AuditEntry
from robot_md_gateway.cert.gates import (
    ConfidencePolicy,
    HiTLPolicy,
    check_confidence,
    check_hitl,
)
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.cert.revocation import RevocationCache, round_trip_register
from robot_md_gateway.cert.safety import GatewayState, SafetyMonitor
from robot_md_gateway.receiver import make_app
from robot_md_gateway.udev_policy import generate_rules


class _FakeResolver:
    def __init__(self, mapping: dict[str, bytes]) -> None:
        self._mapping = mapping

    def resolve_public_key_pem(self, kid: str) -> bytes | None:
        return self._mapping.get(kid)


class _FakeRevocationResolver:
    def __init__(self, revoked: set[str]) -> None:
        self._revoked = revoked

    def is_revoked(self, kid: str) -> bool:
        return kid in self._revoked


class _FakeRegistrar:
    def __init__(self) -> None:
        self._db: dict[str, bytes] = {}

    def register(self, *, kid: str, public_key_pem: bytes) -> None:
        self._db[kid] = public_key_pem

    def resolve(self, kid: str) -> bytes | None:
        return self._db.get(kid)


def _ed25519_keypair() -> tuple[Ed25519PrivateKey, bytes, bytes]:
    """Returns (priv_obj, priv_pem, pub_pem). Used both for envelope signing
    (needs the live key object) and audit-bundle export (needs PEM bytes)."""
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
    return priv, priv_pem, pub_pem


def _sign_envelope(priv: Ed25519PrivateKey, body: dict, kid: str) -> dict:
    """Attach an envelope_signature block over canonical_json(body)."""
    sig = priv.sign(canonical_json(body))
    body["envelope_signature"] = {
        "kid": kid,
        "alg": "Ed25519",
        "sig": base64.b64encode(sig).decode(),
    }
    return body


def _run_evidence_collection(fixtures: Path) -> None:
    """Trigger the cert reporter via real code paths, in a single process."""
    cert_report.reset()

    # GW-001 — udev rules generated.
    generate_rules(
        service_account="robot-md-gateway",
        tty_vendor_hex="2341",
        emit_evidence=True,
    )

    manifest_kid = (fixtures / "signing-key.kid").read_text().strip()
    manifest_pub = (fixtures / "signing-key.pub").read_bytes()

    # MF-001 + MF-002 — manifest accept + tampered manifest reject. Receiver
    # path with default policies (no envelope-sig, no tier, etc.) so the
    # request reaches the manifest verifier.
    app_mf = make_app(resolver=_FakeResolver({manifest_kid: manifest_pub}))
    client_mf = TestClient(app_mf)

    base_envelope = {
        "msg_id": "ci-cert-emit",
        "type": "INVOKE",
        "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "READ",
        "tool_name": "mcp__robot__render",
        "tool_args": {},
    }

    client_mf.post("/v1/invoke", json={
        **base_envelope,
        "msg_id": "ci-mf-001",
        "manifest_path": str(fixtures / "signed-good.md"),
    })

    client_mf.post("/v1/invoke", json={
        **base_envelope,
        "msg_id": "ci-mf-002",
        "manifest_path": str(fixtures / "signed-tampered.md"),
    })

    # GW-002 — tool allowlist deny path. Posts a tool_name not in the list.
    app_gw002 = make_app(
        resolver=_FakeResolver({manifest_kid: manifest_pub}),
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
    )
    TestClient(app_gw002).post("/v1/invoke", json={
        "msg_id": "ci-gw-002",
        "type": "INVOKE",
        "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "MANIPULATE",
        "tool_name": "mcp__robot__execute_capability",
        "tool_args": {},
        "manifest_path": str(fixtures / "signed-good.md"),
    })

    # GW-003 — tier policy deny: read-tier principal requesting MANIPULATE.
    app_gw003 = make_app(
        resolver=_FakeResolver({manifest_kid: manifest_pub}),
        tool_allowlist=ToolAllowlist(
            allowed_tools=("mcp__robot__execute_capability", "mcp__robot__render"),
        ),
        bearer_tiers={"read-token": "read"},
    )
    TestClient(app_gw003).post(
        "/v1/invoke",
        headers={"Authorization": "Bearer read-token"},
        json={
            "msg_id": "ci-gw-003",
            "type": "INVOKE",
            "ruri": "rcan://lab.local/test/bot/00000999",
            "scope": "MANIPULATE",
            "tool_name": "mcp__robot__execute_capability",
            "tool_args": {},
            "manifest_path": str(fixtures / "signed-good.md"),
        },
    )

    # RC-001 + RC-002 — signed envelope accepted, replay rejected. Receiver
    # path with require_envelope_signature=True. Posting the same envelope
    # twice exercises both properties in one configuration.
    principal_priv, _, principal_pub = _ed25519_keypair()
    principal_kid = "ci-rc-principal-kid"
    app_rc = make_app(
        resolver=_FakeResolver({
            manifest_kid: manifest_pub,
            principal_kid: principal_pub,
        }),
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
        require_envelope_signature=True,
    )
    client_rc = TestClient(app_rc)
    rc_body = {
        "msg_id": "ci-rc-001",
        "type": "INVOKE",
        "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "READ",
        "tool_name": "mcp__robot__render",
        "tool_args": {},
        "manifest_path": str(fixtures / "signed-good.md"),
    }
    rc_body = _sign_envelope(principal_priv, rc_body, principal_kid)
    # First post: RC-001 records (signed envelope accepted).
    client_rc.post("/v1/invoke", json=rc_body)
    # Second post (same msg_id): RC-002 records (replay rejected).
    client_rc.post("/v1/invoke", json=rc_body)

    # RC-003 — confidence threshold gate. Direct call (matches unit-test
    # pattern) — gate records cert evidence on every exit path.
    check_confidence(
        {
            "msg_id": "ci-rc-003",
            "scope": "MANIPULATE",
            "payload": {"inference_confidence": 0.5},
        },
        ConfidencePolicy(),
    )

    # RC-004 — HiTL chain required.
    check_hitl(
        {"msg_id": "ci-rc-004", "scope": "MANIPULATE", "delegation_chain": []},
        HiTLPolicy(),
    )

    # SF-001 — ESTOP wire transition records when state moves to ESTOP_ACTIVE.
    sm_estop = SafetyMonitor()
    sm_estop.on_estop_wire(tripped=True, msg_id="ci-sf-001")

    # SF-002 — heartbeat staleness records when state moves to SAFE_STOP.
    sm_safe = SafetyMonitor(heartbeat_staleness_s=0.05)
    sm_safe.last_heartbeat_at = time.monotonic() - 1.0
    sm_safe.tick()
    assert sm_safe.state == GatewayState.SAFE_STOP

    # EV-001 — audit bundle export records on success.
    _, audit_priv_pem, _ = _ed25519_keypair()
    chain = AuditChain()
    chain.append(AuditEntry(
        msg_id="ci-ev-001",
        timestamp_ms=1,
        decision="allow",
        decision_reason="ok",
        envelope_kid=principal_kid,
    ))
    chain.export_signed(signing_key_pem=audit_priv_pem, kid="ci-ev-001-kid")

    # RR-001 — revocation cache: exercise both revoked + non-revoked paths.
    rev_resolver = _FakeRevocationResolver(revoked={"ci-rr-001-bad"})
    rev_cache = RevocationCache()
    rev_cache.is_revoked("ci-rr-001-bad", resolver=rev_resolver)
    rev_cache.is_revoked("ci-rr-001-good", resolver=rev_resolver)

    # RR-002 — registry round-trip register + resolve.
    round_trip_register(
        registrar=_FakeRegistrar(),
        kid="ci-rr-002",
        public_key_pem=b"PEM-BODY",
    )


def _sign_report(out_path: Path, *, signing_key_pem: Path, kid: str) -> None:
    """Sign the report JSON in place with an Ed25519 release key.

    The signed body is the serialized report with ``schema_version`` bumped to
    ``"1.0"`` and a ``signature`` block appended. The signature covers
    ``canonical_json(body)`` over the body BEFORE the signature is added —
    matching the pattern in ``cert/audit.py``'s ``export_signed`` so signing
    is reproducible.
    """
    priv = serialization.load_pem_private_key(signing_key_pem.read_bytes(), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise SystemExit(
            f"Expected Ed25519 private key, got {type(priv).__name__}"
        )
    body = json.loads(out_path.read_text())
    body["schema_version"] = "1.0"  # bump from unsigned (0.1) to signed (1.0)
    sig = priv.sign(canonical_json(body))
    body["signature"] = {
        "kid": kid,
        "alg": "Ed25519",
        "sig": base64.b64encode(sig).decode(),
    }
    out_path.write_text(json.dumps(body, indent=2))
    print(f"Signed {out_path} with kid={kid}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="robot-md-gateway")
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument("--out-dir", type=Path, default=Path("dist/cert-reports"))
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=Path(__file__).parent.parent / "tests" / "fixtures" / "manifests",
    )
    parser.add_argument(
        "--signing-key-pem",
        type=Path,
        default=None,
        help="Optional Ed25519 PEM private key. When provided, the emitted JSON "
             "is signed in place and --kid is required.",
    )
    parser.add_argument(
        "--kid",
        default=None,
        help="kid label for the release-signing key. Required when "
             "--signing-key-pem is provided.",
    )
    args = parser.parse_args()

    if args.signing_key_pem is not None and not args.kid:
        parser.error("--kid is required when --signing-key-pem is provided")

    sha = args.sha or _git_sha()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    _run_evidence_collection(args.fixtures)
    out = args.out_dir / f"gateway-authority-{args.repo}-{sha}.json"
    cert_report.write(out, repo=args.repo, sha=sha)
    print(f"Wrote {out}")

    if args.signing_key_pem is not None:
        _sign_report(out, signing_key_pem=args.signing_key_pem, kid=args.kid)


def _git_sha() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()


if __name__ == "__main__":
    main()
