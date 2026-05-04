"""Receive-only RCAN INVOKE envelope handler.

Default operating mode of the gateway in v0.3.x+: accept signed RCAN
INVOKE envelopes over HTTP, run them through manifest provenance + tier
policy + tool allowlist + cert gates, and dispatch to a local actuation
tool.

Phase 3 ships the skeleton:
- HTTP route /v1/invoke (FastAPI),
- envelope schema + validation,
- manifest provenance check (MF-001/MF-002),
- placeholders for tier policy + tool allowlist (Plan 6 Phase 1).

Subsequent plans fill in:
- envelope signature verification (RC-001) — DONE Plan 6 Phase 0
  (opt-in via require_envelope_signature),
- replay protection (RC-002) — DONE Plan 6 Phase 0 (opt-in via replay_cache),
- confidence + HiTL gates (RC-003 / RC-004) — DONE Plan 6 Phase 1
  (opt-in via confidence_policy / hitl_policy),
- ESTOP precedence (SF-001) + safe-stop (SF-002) — DONE Plan 6 Phase 4
  (opt-in via safety_monitor),
- audit bundle export (EV-001) — DONE Plan 6 Phase 4 (opt-in via audit_chain),
- key revocation polling (RR-001 / RR-002) — DONE Plan 6 Phase 2
  (opt-in via revocation_resolver).
"""

from __future__ import annotations

import time
from pathlib import Path

from fastapi import Body, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, ValidationError

from .cert import report as cert_report
from .cert.audit import AuditChain, AuditEntry
from .cert.envelope import ReplayCache, check_replay, verify_envelope
from .cert.gates import ConfidencePolicy, HiTLPolicy, check_confidence, check_hitl
from .cert.policy import ToolAllowlist, check_tier, check_tool
from .cert.revocation import RevocationCache, RRFRevocationResolver
from .cert.safety import SafetyMonitor
from .manifest_provenance import RRFResolver, verify_manifest

_DEFAULT_ALLOWLIST = ToolAllowlist(allowed_tools=("mcp__robot__render", "mcp__robot__validate"))


class InvokeEnvelope(BaseModel):
    """Minimal RCAN INVOKE envelope shape — subset Phase 3 actually validates.

    Plan 6 expands this to include nonce/replay fields, confidence,
    HiTL chain, and ESTOP-precedence fields.
    Forward-compatible note: extra fields are silently DROPPED by Pydantic v2's
    default extra='ignore'. For Plan 6 cert-property fields not yet declared on
    this model (`inference_confidence`, `delegation_chain`, etc.), the receiver
    reads from the raw `envelope_dict` instead — see the gate-call sites in
    `make_app` for the contract.
    """

    msg_id: str = Field(...)
    type: str = Field(...)
    ruri: str = Field(..., description="rcan:// robot URI")
    scope: str = Field(...)
    tool_name: str = Field(...)
    tool_args: dict = Field(default_factory=dict)
    manifest_path: str = Field(..., description="Local path to ROBOT.md being actuated against")


def make_app(
    *,
    resolver: RRFResolver,
    tool_allowlist: ToolAllowlist | None = None,
    bearer_tiers: dict[str, str] | None = None,
    require_envelope_signature: bool = False,
    replay_cache: ReplayCache | None = None,
    confidence_policy: ConfidencePolicy | None = None,
    hitl_policy: HiTLPolicy | None = None,
    safety_monitor: SafetyMonitor | None = None,
    audit_chain: AuditChain | None = None,
    revocation_resolver: RRFRevocationResolver | None = None,
    revocation_cache: RevocationCache | None = None,
) -> FastAPI:
    if tool_allowlist is None:
        tool_allowlist = _DEFAULT_ALLOWLIST
    bearer_tiers = bearer_tiers or {}
    if replay_cache is None:
        replay_cache = ReplayCache()
    # Default the revocation cache at make_app level (parallel to replay_cache):
    # if the operator opts into revocation_resolver but doesn't pass an explicit
    # cache, build one here so it's shared across requests instead of being
    # constructed fresh on every call (which would defeat caching entirely).
    if revocation_resolver is not None and revocation_cache is None:
        revocation_cache = RevocationCache()
    app = FastAPI(title="robot-md-gateway", version="0.4.0a1")
    # Operators access these via app.state for ESTOP wire integration,
    # heartbeat injection, and audit-bundle export. ESTOP and heartbeat are
    # conceptually GPIO/transport-level signals — not exposed as HTTP routes
    # because that conflates physical-wire semantics (SF-001 cert claim) with
    # HTTP-layer auth.
    app.state.safety_monitor = safety_monitor
    app.state.audit_chain = audit_chain
    app.state.revocation_cache = revocation_cache

    def _record(decision: str, reason: str, kid: str | None, msg_id: str) -> None:
        if audit_chain is None:
            return
        audit_chain.append(AuditEntry(
            msg_id=msg_id,
            timestamp_ms=int(time.time() * 1000),
            decision=decision,
            decision_reason=reason,
            envelope_kid=kid,
        ))

    @app.post("/v1/invoke")
    def invoke(
        envelope_dict: dict = Body(...),
        authorization: str | None = Header(default=None),
    ):
        tier = "anon"
        if authorization and authorization.startswith("Bearer "):
            tier = bearer_tiers.get(authorization[7:], "anon")

        # SF-001/SF-002: safety state preempts all other gates. Per-request
        # tick is sufficient — if no requests are arriving, no actuation can
        # occur, so missing a tick during idle is safe by construction.
        # FastAPI guarantees envelope_dict is a dict — Body(...) typed dict
        # rejects non-object JSON with 422 before the handler runs, so we
        # can read msg_id directly with a default for the missing-field case.
        raw_msg_id = envelope_dict.get("msg_id", "<unknown>")

        if safety_monitor is not None:
            safety_monitor.tick()
            if not safety_monitor.can_actuate():
                reason = f"gateway state={safety_monitor.state.value}"
                _record("deny", f"safety_state: {reason}", None, raw_msg_id)
                raise HTTPException(status_code=403, detail={
                    "deny": "safety_state",
                    "reason": reason,
                })

        if require_envelope_signature:
            env_result = verify_envelope(envelope_dict, resolver=resolver)
            if not env_result.accepted:
                _record(
                    "deny",
                    f"envelope_signature: {env_result.reason}",
                    env_result.kid,
                    raw_msg_id,
                )
                raise HTTPException(status_code=403, detail={
                    "deny": "envelope_signature",
                    "reason": env_result.reason,
                })
            ok, reason = check_replay(envelope_dict, replay_cache)
            if not ok:
                _record("deny", f"replay: {reason}", env_result.kid, raw_msg_id)
                raise HTTPException(status_code=403, detail={
                    "deny": "replay",
                    "reason": reason,
                })
            if (
                revocation_resolver is not None
                and env_result.kid
                and revocation_cache.is_revoked(
                    env_result.kid, resolver=revocation_resolver,
                )
            ):
                _record(
                    "deny",
                    f"revoked_key: kid={env_result.kid}",
                    env_result.kid,
                    raw_msg_id,
                )
                raise HTTPException(status_code=403, detail={
                    "deny": "revoked_key",
                    "reason": f"kid {env_result.kid} is revoked",
                })

        try:
            envelope = InvokeEnvelope(**envelope_dict)
        except ValidationError as exc:
            # Schema fails are parser errors, not policy decisions — not audited.
            raise HTTPException(status_code=422, detail=exc.errors()) from exc

        manifest_result = verify_manifest(Path(envelope.manifest_path), resolver=resolver)
        if not manifest_result.accepted:
            cert_report.record_property_fail(
                property_id="MF-002",
                evidence={
                    "manifest_path": envelope.manifest_path,
                    "reason": manifest_result.reason,
                    "msg_id": envelope.msg_id,
                },
            )
            _record(
                "deny",
                f"manifest_provenance: {manifest_result.reason}",
                manifest_result.kid,
                envelope.msg_id,
            )
            raise HTTPException(status_code=403, detail={
                "deny": "manifest_provenance",
                "reason": manifest_result.reason,
                "kid": manifest_result.kid,
            })

        cert_report.record_property_pass(
            property_id="MF-001",
            evidence={
                "manifest_kid": manifest_result.kid,
                "manifest_path": envelope.manifest_path,
                "msg_id": envelope.msg_id,
            },
        )

        ok, reason = check_tier(tier, envelope.scope, msg_id=envelope.msg_id)
        if not ok:
            _record("deny", f"tier_policy: {reason}", manifest_result.kid, envelope.msg_id)
            raise HTTPException(status_code=403, detail={
                "deny": "tier_policy",
                "reason": reason,
            })

        allowed, reason = check_tool(envelope.tool_name, tool_allowlist, msg_id=envelope.msg_id)
        if not allowed:
            _record("deny", f"tool_allowlist: {reason}", manifest_result.kid, envelope.msg_id)
            raise HTTPException(status_code=403, detail={
                "deny": "tool_allowlist",
                "reason": reason,
            })

        if confidence_policy is not None:
            ok, reason = check_confidence(envelope_dict, confidence_policy)
            if not ok:
                _record(
                    "deny",
                    f"confidence_threshold: {reason}",
                    manifest_result.kid,
                    envelope.msg_id,
                )
                raise HTTPException(status_code=403, detail={
                    "deny": "confidence_threshold",
                    "reason": reason,
                })

        if hitl_policy is not None:
            ok, reason = check_hitl(envelope_dict, hitl_policy)
            if not ok:
                _record(
                    "deny",
                    f"hitl_required: {reason}",
                    manifest_result.kid,
                    envelope.msg_id,
                )
                raise HTTPException(status_code=403, detail={
                    "deny": "hitl_required",
                    "reason": reason,
                })

        _record("allow", "ok", manifest_result.kid, envelope.msg_id)
        return {
            "ok": True,
            "manifest_kid": manifest_result.kid,
            "scope": envelope.scope,
            "tool_name": envelope.tool_name,
            "next_gates": [],
        }

    return app
