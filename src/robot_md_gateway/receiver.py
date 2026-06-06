"""Receive-only RCAN INVOKE envelope handler.

Default operating mode of the gateway in v0.3.x+: accept signed RCAN
INVOKE envelopes over HTTP, run them through manifest provenance + tier
policy + tool allowlist + cert gates, and dispatch to a local actuation
tool.

Phase 3 shipped the skeleton:
- HTTP route /v1/invoke (FastAPI),
- envelope schema + validation,
- manifest provenance check (MF-001/MF-002),
- tier policy + tool allowlist enforcement (GW-002/GW-003) —
  DONE Plan 6 Phase 0.

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

import hashlib
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml
from fastapi import Body, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, ValidationError
from rcan.audit_bundle import canonical_json

from .actuator import Actuator, ActuatorOutcome, NoOpActuator
from .attestation import (
    SigningIdentity,
    build_action_trace,
    build_outcome,
    outcome_status,
    telemetry_sha256_of,
)
from .cert import report as cert_report
from .cert.audit import AuditChain, AuditEntry
from .cert.envelope import ReplayCache, check_replay, sign_envelope, verify_envelope
from .cert.gates import ConfidencePolicy, HiTLPolicy, check_confidence, check_hitl
from .cert.policy import ToolAllowlist, check_tier, check_tool
from .cert.revocation import RevocationCache, RRFRevocationResolver
from .cert.rrn_binding import verify_rrn_binding
from .cert.safety import SafetyMonitor
from .manifest_provenance import RRFResolver, verify_manifest

_DEFAULT_ALLOWLIST = ToolAllowlist(allowed_tools=("mcp__robot__render", "mcp__robot__validate"))

# Manifest frontmatter cache keyed by path -> (mtime, frontmatter dict). Used by the
# RRN-binding (B4) and manifest-driven HiTL (B3) gates so they read the manifest's
# metadata.rrn / safety.hitl_gates without re-parsing on every invoke; refreshes when
# the deployed manifest's mtime changes (e.g. after `resign_and_deploy`).
_MANIFEST_FM_CACHE: dict[str, tuple[float, dict]] = {}


def _manifest_frontmatter(path: str) -> dict:
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {}
    cached = _MANIFEST_FM_CACHE.get(path)
    if cached is not None and cached[0] == mtime:
        return cached[1]
    fm: dict = {}
    try:
        text = Path(path).read_text()
        if text.startswith("---"):
            end = text.find("\n---", 3)
            if end != -1:
                fm = yaml.safe_load(text[3:end]) or {}
    except (OSError, yaml.YAMLError):
        fm = {}
    _MANIFEST_FM_CACHE[path] = (mtime, fm)
    return fm


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
    # Optional. When the gateway is configured with multiple actuators
    # (`make_app(actuators={...})`), the dispatcher routes by this name.
    # In single-actuator mode this field is ignored.
    actuator_name: str | None = Field(default=None)


def make_app(
    *,
    resolver: RRFResolver,
    tool_allowlist: ToolAllowlist | None = None,
    bearer_tiers: dict[str, str] | None = None,
    require_envelope_signature: bool = False,
    replay_cache: ReplayCache | None = None,
    confidence_policy: ConfidencePolicy | None = None,
    hitl_policy: HiTLPolicy | None = None,
    hitl_from_manifest: bool = False,
    require_rrn_binding: bool = False,
    safety_monitor: SafetyMonitor | None = None,
    audit_chain: AuditChain | None = None,
    revocation_resolver: RRFRevocationResolver | None = None,
    revocation_cache: RevocationCache | None = None,
    actuator: Actuator | None = None,
    actuator_config: dict | None = None,
    actuators: dict[str, Actuator] | None = None,
    actuator_configs: dict[str, dict] | None = None,
    signing_identity: SigningIdentity | None = None,
    attestation_export_file: Path | None = None,
) -> FastAPI:
    if tool_allowlist is None:
        tool_allowlist = _DEFAULT_ALLOWLIST
    bearer_tiers = bearer_tiers or {}
    # Multi-actuator mode is on when `actuators` is provided (even if empty
    # dict — that's a misconfiguration the operator made; loud failure at
    # request time is better than silent fallback to single).
    multi_actuator_mode = actuators is not None
    if multi_actuator_mode:
        if actuator_configs is None:
            actuator_configs = {}
        # In multi-actuator mode the single-actuator slots are unused; null
        # them so anyone reading app.state.actuator gets a clear sentinel.
        actuator = None
        actuator_config = {}
    else:
        if actuator is None:
            actuator = NoOpActuator()
        if actuator_config is None:
            actuator_config = {}
        actuators = {}
        actuator_configs = {}
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
    app.state.actuator = actuator
    app.state.actuator_config = actuator_config
    app.state.actuators = actuators
    app.state.actuator_configs = actuator_configs
    app.state.multi_actuator_mode = multi_actuator_mode

    def _emit_attestation(
        *,
        decision: str,
        reason: str,
        msg_id: str,
        envelope_dict: dict | None,
        ruri: str | None,
        rrn: str | None,
        started_at: str | None,
        ended_at: str | None,
        outcome: ActuatorOutcome | None,
        error_kind: str | None,
    ) -> None:
        # Attestation is independent of the audit chain: it must fire even when
        # audit_chain is None. Disabled when no signing identity / no export path.
        if signing_identity is None or attestation_export_file is None:
            return
        # An unparseable invoke (422) never reaches a _record call, so any
        # envelope_dict here has at least the signed fields we were given.
        invoke = envelope_dict if envelope_dict is not None else {"msg_id": msg_id}
        status = outcome_status(
            decision=decision,
            success=(outcome.success if outcome is not None else None),
            error_kind=error_kind,
        )
        error: dict | None = None
        if status != "ok":
            if decision == "deny":
                # reason is "<gate>: <detail>"; the gate name is the error kind.
                kind = reason.split(":", 1)[0].strip() or "denied"
                error = {"kind": kind, "message": reason}
            elif error_kind is not None:
                error = {"kind": error_kind, "message": outcome.error_message or ""}
            else:  # clean actuator failure
                error = {"kind": "actuator_failure", "message": outcome.error_message or ""}
        now_iso = datetime.now(tz=timezone.utc).isoformat()
        s_at = started_at or now_iso
        e_at = ended_at or now_iso
        duration_ms: int | None = None
        if started_at is not None and ended_at is not None:
            duration_ms = int(
                (datetime.fromisoformat(ended_at) - datetime.fromisoformat(started_at))
                .total_seconds() * 1000
            )
        body = build_outcome(
            corr_id=msg_id,
            rrn=rrn or "",
            status=status,
            started_at=s_at,
            ended_at=e_at,
            duration_ms=duration_ms,
            telemetry_sha256=telemetry_sha256_of(outcome),
            error=error,
            result_summary=None,
        )
        signed_outcome = sign_envelope(signing_identity.priv, body, signing_identity.kid)
        record = build_action_trace(
            invoke=invoke, outcome=signed_outcome, ruri=ruri, rrn=rrn or "",
        )
        attestation_export_file.parent.mkdir(parents=True, exist_ok=True)
        with attestation_export_file.open("a", encoding="utf-8") as fh:
            fh.write(canonical_json(record).decode("utf-8") + "\n")

    def _record_with_outcome(
        decision: str,
        reason: str,
        kid: str | None,
        msg_id: str,
        outcome: ActuatorOutcome | None = None,
        error_kind: str | None = None,
        actuator_name: str | None = None,
        *,
        envelope_dict: dict | None = None,
        ruri: str | None = None,
        rrn: str | None = None,
        started_at: str | None = None,
        ended_at: str | None = None,
    ) -> None:
        _emit_attestation(
            decision=decision, reason=reason, msg_id=msg_id,
            envelope_dict=envelope_dict, ruri=ruri, rrn=rrn,
            started_at=started_at, ended_at=ended_at,
            outcome=outcome, error_kind=error_kind,
        )
        if audit_chain is None:
            return
        entry_kwargs = dict(
            msg_id=msg_id,
            timestamp_ms=int(time.time() * 1000),
            decision=decision,
            decision_reason=reason,
            envelope_kid=kid,
        )
        if outcome is not None:
            telem_sha: str | None = None
            telem_path: str | None = None
            if outcome.telemetry_path is not None:
                # Hash the file's bytes for tamper-evidence; record path as string.
                telem_path = str(outcome.telemetry_path)
                if outcome.telemetry_path.exists():
                    telem_sha = hashlib.sha256(
                        outcome.telemetry_path.read_bytes()
                    ).hexdigest()
            elif outcome.telemetry:
                # Hash the canonical JSON of the in-memory telemetry dict.
                telem_sha = hashlib.sha256(
                    canonical_json(outcome.telemetry)
                ).hexdigest()
            entry_kwargs.update(
                actuator_name=actuator_name,
                actuator_outcome_kind=outcome.outcome_kind,
                actuator_telemetry_sha256=telem_sha,
                actuator_telemetry_path=telem_path,
                actuator_error_kind=error_kind,
            )
        audit_chain.append(AuditEntry(**entry_kwargs))

    # Backward-compat shim: existing deny-path call sites still call _record.
    def _record(
        decision: str,
        reason: str,
        kid: str | None,
        msg_id: str,
        *,
        envelope_dict: dict | None = None,
        ruri: str | None = None,
        rrn: str | None = None,
        started_at: str | None = None,
        ended_at: str | None = None,
    ) -> None:
        _record_with_outcome(
            decision=decision, reason=reason, kid=kid, msg_id=msg_id,
            envelope_dict=envelope_dict, ruri=ruri, rrn=rrn,
            started_at=started_at, ended_at=ended_at,
        )

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
        started_at = datetime.now(tz=timezone.utc).isoformat()

        if safety_monitor is not None:
            safety_monitor.tick()
            if not safety_monitor.can_actuate():
                reason = f"gateway state={safety_monitor.state.value}"
                _record(
                    "deny", f"safety_state: {reason}", None, raw_msg_id,
                    envelope_dict=envelope_dict, ruri=envelope_dict.get("ruri"),
                    rrn="", started_at=started_at,
                )
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
                    envelope_dict=envelope_dict, ruri=envelope_dict.get("ruri"),
                    rrn="", started_at=started_at,
                )
                raise HTTPException(status_code=403, detail={
                    "deny": "envelope_signature",
                    "reason": env_result.reason,
                })
            ok, reason = check_replay(envelope_dict, replay_cache)
            if not ok:
                _record(
                    "deny", f"replay: {reason}", env_result.kid, raw_msg_id,
                    envelope_dict=envelope_dict, ruri=envelope_dict.get("ruri"),
                    rrn="", started_at=started_at,
                )
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
                    envelope_dict=envelope_dict, ruri=envelope_dict.get("ruri"),
                    rrn="", started_at=started_at,
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
                envelope_dict=envelope_dict, ruri=envelope.ruri,
                rrn="", started_at=started_at,
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

        # Hoisted so the emitter has the robot's authoritative RRN on the allow
        # path and all POST-manifest denies, independent of the rrn-binding toggle.
        _fm = _manifest_frontmatter(envelope.manifest_path)
        manifest_rrn = (_fm.get("metadata") or {}).get("rrn") or _fm.get("rrn") or ""

        # MF-003 — RRN binding (flagged). Bind the envelope identity to the robot's
        # registered RRN so a correctly-signed envelope for robot A can't actuate B.
        if require_rrn_binding:
            rb = verify_rrn_binding(envelope.ruri, manifest_rrn, msg_id=envelope.msg_id)
            if not rb.accepted:
                _record(
                    "deny", f"rrn_binding: {rb.reason}", manifest_result.kid, envelope.msg_id,
                    envelope_dict=envelope_dict, ruri=envelope.ruri,
                    rrn=manifest_rrn, started_at=started_at,
                )
                raise HTTPException(status_code=403, detail={
                    "deny": "rrn_binding",
                    "reason": rb.reason,
                })

        ok, reason = check_tier(tier, envelope.scope, msg_id=envelope.msg_id)
        if not ok:
            _record(
                "deny", f"tier_policy: {reason}", manifest_result.kid, envelope.msg_id,
                envelope_dict=envelope_dict, ruri=envelope.ruri,
                rrn=manifest_rrn, started_at=started_at,
            )
            raise HTTPException(status_code=403, detail={
                "deny": "tier_policy",
                "reason": reason,
            })

        allowed, reason = check_tool(envelope.tool_name, tool_allowlist, msg_id=envelope.msg_id)
        if not allowed:
            _record(
                "deny", f"tool_allowlist: {reason}", manifest_result.kid, envelope.msg_id,
                envelope_dict=envelope_dict, ruri=envelope.ruri,
                rrn=manifest_rrn, started_at=started_at,
            )
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
                    envelope_dict=envelope_dict, ruri=envelope.ruri,
                    rrn=manifest_rrn, started_at=started_at,
                )
                raise HTTPException(status_code=403, detail={
                    "deny": "confidence_threshold",
                    "reason": reason,
                })

        # RC-004 — HiTL. When hitl_from_manifest is on, the manifest's declared
        # safety.hitl_gates are authoritative (built per-request, cached by mtime);
        # otherwise fall back to the policy passed at make_app time.
        effective_hitl = hitl_policy
        if hitl_from_manifest:
            fm = _manifest_frontmatter(envelope.manifest_path)
            gates = (fm.get("safety") or {}).get("hitl_gates")
            effective_hitl = HiTLPolicy.from_manifest_gates(gates)
        if effective_hitl is not None:
            ok, reason = check_hitl(envelope_dict, effective_hitl)
            if not ok:
                _record(
                    "deny",
                    f"hitl_required: {reason}",
                    manifest_result.kid,
                    envelope.msg_id,
                    envelope_dict=envelope_dict, ruri=envelope.ruri,
                    rrn=manifest_rrn, started_at=started_at,
                )
                raise HTTPException(status_code=403, detail={
                    "deny": "hitl_required",
                    "reason": reason,
                })

        # All gates passed — pick the actuator. In multi-actuator mode, route
        # by `envelope.actuator_name`. In single-actuator mode, use the one
        # configured at make_app time. Routing failures are 4xx (parser-level)
        # and not audited; gate failures above are audit-tracked.
        if multi_actuator_mode:
            if envelope.actuator_name is None:
                raise HTTPException(status_code=422, detail={
                    "deny": "actuator_name_required",
                    "reason": "gateway is configured for multiple actuators; "
                              "envelope must set actuator_name",
                })
            target_actuator = actuators.get(envelope.actuator_name)
            if target_actuator is None:
                raise HTTPException(status_code=404, detail={
                    "deny": "unknown_actuator",
                    "reason": f"no actuator named {envelope.actuator_name!r} is "
                              f"registered on this gateway",
                    "known": sorted(actuators.keys()),
                })
            target_config = actuator_configs.get(envelope.actuator_name, {})
        else:
            target_actuator = actuator
            target_config = actuator_config

        # Capture outcome regardless of success so the audit entry records
        # what actually happened.
        try:
            outcome = target_actuator.execute(
                envelope=envelope_dict,
                manifest_path=Path(envelope.manifest_path),
                tier=tier,
                config=target_config,
            )
            error_kind: str | None = None
        except Exception as exc:  # noqa: BLE001  intentionally broad — actuator is operator code
            outcome = ActuatorOutcome(
                success=False, outcome_kind="error",
                error_message=str(exc),
            )
            error_kind = type(exc).__name__
        ended_at = datetime.now(tz=timezone.utc).isoformat()

        _record_with_outcome(
            decision="allow", reason="ok",
            kid=manifest_result.kid, msg_id=envelope.msg_id,
            outcome=outcome, error_kind=error_kind,
            actuator_name=target_actuator.name,
            envelope_dict=envelope_dict, ruri=envelope.ruri, rrn=manifest_rrn,
            started_at=started_at, ended_at=ended_at,
        )

        if not outcome.success:
            raise HTTPException(status_code=500, detail={
                "actuator_error": outcome.error_message,
                "actuator_error_kind": error_kind,
            })

        return {
            "ok": True,
            "manifest_kid": manifest_result.kid,
            "scope": envelope.scope,
            "tool_name": envelope.tool_name,
            "actuator_name": target_actuator.name,
            "outcome_kind": outcome.outcome_kind,
            "telemetry": outcome.telemetry,
        }

    @app.get("/v1/audit/last")
    def audit_last(authorization: str | None = Header(default=None)):
        # Auth: require a valid bearer mapped to a known tier (any tier OK
        # for read-only access — operator chooses tier-tightening via bearers).
        if authorization is None or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing Authorization header")
        token = authorization[7:]
        if token not in bearer_tiers:
            raise HTTPException(status_code=403, detail="unknown bearer")

        if audit_chain is None or not audit_chain.entries:
            raise HTTPException(status_code=404, detail="audit chain empty")
        last = audit_chain.entries[-1]
        return last.__dict__

    return app
