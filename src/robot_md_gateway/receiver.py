"""Receive-only RCAN INVOKE envelope handler.

Default operating mode of the gateway in v0.3.x+: accept signed RCAN
INVOKE envelopes over HTTP, run them through manifest provenance + tier
policy + tool allowlist + (Phase 4 of Plan 3) the first 3 Gateway
Authority cert properties, and dispatch to a local actuation tool.
Plan 6 Phase 4 fills in the remaining 9 cert properties; this module's
contract is forward-compatible with that.

Phase 3 ships the skeleton:
- HTTP route /v1/invoke (FastAPI),
- envelope schema + validation,
- manifest provenance check (MF-001/MF-002),
- placeholders for tier policy + tool allowlist (Plan 6 Phase 1).

Subsequent plans fill in:
- envelope signature verification (RC-001) — Plan 6 Phase 1,
- replay protection (RC-002) — Plan 6 Phase 1,
- confidence + HiTL gates (RC-003 / RC-004) — Plan 6 Phase 2,
- ESTOP precedence (SF-001) + safe-stop (SF-002) — Plan 6 Phase 2,
- audit bundle export (EV-001) — Plan 6 Phase 2,
- key revocation polling (RR-001 / RR-002) — Plan 6 Phase 3.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .cert import report as cert_report
from .cert.policy import ToolAllowlist, check_tier, check_tool
from .manifest_provenance import RRFResolver, verify_manifest

_DEFAULT_ALLOWLIST = ToolAllowlist(allowed_tools=("mcp__robot__render", "mcp__robot__validate"))


class InvokeEnvelope(BaseModel):
    """Minimal RCAN INVOKE envelope shape — subset Phase 3 actually validates.

    Plan 6 expands this to include nonce/replay fields, confidence,
    HiTL chain, and ESTOP-precedence fields. Forward-compatible:
    extra fields are silently accepted by FastAPI's Pydantic-v2 model.
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
) -> FastAPI:
    if tool_allowlist is None:
        tool_allowlist = _DEFAULT_ALLOWLIST
    bearer_tiers = bearer_tiers or {}
    app = FastAPI(title="robot-md-gateway", version="0.3.0a1")

    @app.post("/v1/invoke")
    def invoke(envelope: InvokeEnvelope, authorization: str | None = Header(default=None)):
        tier = "anon"
        if authorization and authorization.startswith("Bearer "):
            tier = bearer_tiers.get(authorization[7:], "anon")

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
            raise HTTPException(status_code=403, detail={
                "deny": "tier_policy",
                "reason": reason,
            })

        allowed, reason = check_tool(envelope.tool_name, tool_allowlist, msg_id=envelope.msg_id)
        if not allowed:
            raise HTTPException(status_code=403, detail={
                "deny": "tool_allowlist",
                "reason": reason,
            })

        return {
            "ok": True,
            "manifest_kid": manifest_result.kid,
            "scope": envelope.scope,
            "tool_name": envelope.tool_name,
            "next_gates": ["RC-001", "RC-002", "RC-003", "RC-004", "SF-001", "SF-002", "EV-001"],
        }

    return app
