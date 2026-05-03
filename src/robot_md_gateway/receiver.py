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

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .manifest_provenance import RRFResolver, verify_manifest


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


def make_app(*, resolver: RRFResolver) -> FastAPI:
    app = FastAPI(title="robot-md-gateway", version="0.3.0a1")

    @app.post("/v1/invoke")
    def invoke(envelope: InvokeEnvelope):
        manifest_result = verify_manifest(Path(envelope.manifest_path), resolver=resolver)
        if not manifest_result.accepted:
            raise HTTPException(status_code=403, detail={
                "deny": "manifest_provenance",
                "reason": manifest_result.reason,
                "kid": manifest_result.kid,
            })

        return {
            "ok": True,
            "manifest_kid": manifest_result.kid,
            "scope": envelope.scope,
            "next_gates": ["RC-001", "RC-002", "RC-003", "RC-004", "SF-001", "SF-002", "EV-001"],
        }

    return app
