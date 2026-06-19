"""Signed-DENY demo — the offline-verifiable refusal, no hardware, no network.

The single most legible thing the accountability rail does: an AI (Claude Code)
asks the robot to MOVE while holding only a READ-tier bearer; the gateway's
default-deny gate REFUSES it, signs the refusal with the operator's key, and ANY
third party can verify that refusal offline — proving both *that the gateway
refused* and *that the refusal wasn't altered*. Tamper a byte and verification
fails.

This uses the gateway's REAL code — the same policy gate (`cert.policy`) and the
same Ed25519 signer/verifier (`cert.envelope`) that run in production — not a
reimplementation. It needs no robot, no serial bus, and no internet.

SAFETY HONESTY: a signed refusal proves a command was blocked AT THE GATE. It
does NOT prove a moving machine physically stopped — that is a hardware e-stop's
job. The gateway is an accountability rail, never a safety controller.

Run:  python examples/signed_deny_demo.py
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from robot_md_gateway.attestation import build_action_trace, build_outcome, outcome_status
from robot_md_gateway.cert.envelope import sign_envelope, verify_envelope
from robot_md_gateway.cert.policy import ToolAllowlist, check_tier, check_tool

KID = "demo-operator-2026"
RRN = "RRN-000000000011"  # Bob, for narrative flavor (no hardware touched)
# A read-only operator policy: the only tool allowed is read_state.
READ_ONLY_ALLOWLIST = ToolAllowlist(allowed_tools=("read_state",))


class LocalKeyResolver:
    """An offline stand-in for the RRF registry: resolves a kid to its public
    PEM from an in-memory map. The point of the demo is that verification needs
    only the operator's public key — no network, no live registry."""

    def __init__(self, mapping: dict[str, bytes]) -> None:
        self._m = mapping

    def resolve_public_key_pem(self, kid: str) -> bytes | None:
        return self._m.get(kid)


def mint_operator_key() -> tuple[Ed25519PrivateKey, bytes]:
    """Generate an operator Ed25519 keypair; return (private, public_pem_bytes)."""
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem


def move_invoke_at_read_tier() -> dict:
    """An RCAN invoke: Claude Code asks to MOVE (scope MANIPULATE) at READ tier."""
    return {
        "v": "rcan-invoke/1",
        "msg_id": "demo-deny-0001",
        "rrn": RRN,
        "tool_name": "move",
        "scope": "MANIPULATE",
        "tier": "read",
        "tool_args": {"joint_positions": {"shoulder_pan": 0.6}},
    }


def gate(invoke: dict, allowlist: ToolAllowlist) -> tuple[str, list[str]]:
    """Run the real default-deny gates. Returns ('deny'|'allow', [reasons])."""
    reasons: list[str] = []
    tool_ok, tool_reason = check_tool(invoke["tool_name"], allowlist, msg_id=invoke["msg_id"])
    if not tool_ok:
        reasons.append(tool_reason)
    tier_ok, tier_reason = check_tier(invoke["tier"], invoke["scope"], msg_id=invoke["msg_id"])
    if not tier_ok:
        reasons.append(tier_reason)
    return ("allow" if (tool_ok and tier_ok) else "deny"), reasons


def sign_refusal(priv: Ed25519PrivateKey, invoke: dict, reasons: list[str]) -> dict:
    """Build + sign the denied outcome, wrapped in an rcan-action-trace/1 record."""
    outcome = build_outcome(
        corr_id=invoke["msg_id"],
        rrn=invoke["rrn"],
        status=outcome_status(decision="deny", success=None, error_kind=None),
        started_at="2026-06-19T00:00:00Z",
        ended_at="2026-06-19T00:00:00Z",
        duration_ms=0,
        telemetry_sha256=None,
        error={"kind": "policy_denied", "reasons": reasons},
        result_summary="refused at gate (default-deny)",
    )
    signed_outcome = sign_envelope(priv, outcome, KID)
    return build_action_trace(invoke=invoke, outcome=signed_outcome, ruri=None, rrn=invoke["rrn"])


def verify_offline(signed_outcome: dict, pub_pem: bytes) -> bool:
    """Verify the signed refusal against the operator's public key — no network."""
    resolver = LocalKeyResolver({KID: pub_pem})
    return verify_envelope(signed_outcome, resolver=resolver).accepted


def run_demo() -> dict:
    """Execute the whole flow; return the artifacts (used by the test too)."""
    priv, pub_pem = mint_operator_key()
    invoke = move_invoke_at_read_tier()
    decision, reasons = gate(invoke, READ_ONLY_ALLOWLIST)
    trace = sign_refusal(priv, invoke, reasons)
    signed_outcome = trace["outcome"]
    authentic = verify_offline(signed_outcome, pub_pem)

    # Tamper: flip the signed verdict from denied → ok. The signature must reject it.
    tampered = json.loads(json.dumps(signed_outcome))
    tampered["status"] = "ok"
    tamper_detected = not verify_offline(tampered, pub_pem)

    return {
        "decision": decision,
        "reasons": reasons,
        "trace": trace,
        "authentic": authentic,
        "tamper_detected": tamper_detected,
    }


def main() -> int:
    print("PlatAtlas · robot-md-gateway — SIGNED DENY demo (offline; no hardware, no network)\n")
    r = run_demo()
    print(f"1. Operator key minted          kid={KID}")
    print(f"2. Claude Code requests         move (scope MANIPULATE) at READ tier  [robot {RRN}]")
    print(f"3. Default-deny GATE → {r['decision'].upper()}")
    for why in r["reasons"]:
        print(f"     · {why}")
    out = Path("signed_refusal.json")
    out.write_text(json.dumps(r["trace"], indent=2))
    print(f"4. Refusal SIGNED (Ed25519) and written → {out}")
    print(f"5. Offline verify vs operator's public key (network OFF): "
          f"{'✓ AUTHENTIC' if r['authentic'] else '✗ FAILED'}")
    print(f"6. Tamper test (flip status denied→ok): "
          f"{'✓ REJECTED (signature no longer verifies)' if r['tamper_detected'] else '✗ NOT DETECTED'}")
    ok = r["decision"] == "deny" and r["authentic"] and r["tamper_detected"]
    print("\n=> A third party can prove the gateway refused this action — and that the "
          "refusal was not altered." if ok else "\n=> DEMO INVARIANT FAILED")
    print("   (A signed refusal proves a block at the gate; it is NOT a hardware e-stop.)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
