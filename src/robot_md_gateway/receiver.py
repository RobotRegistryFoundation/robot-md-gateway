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
  (opt-in via safety_monitor for make_app; `serve` always passes one, and a
  watchdog enforces staleness and stops the actuators on a trip),
- audit bundle export (EV-001) — DONE Plan 6 Phase 4 (opt-in via audit_chain),
- key revocation polling (RR-001 / RR-002) — DONE Plan 6 Phase 2
  (opt-in via revocation_resolver).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import threading
import time
import uuid
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import anyio
import yaml
from fastapi import Body, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, ValidationError
from rcan.audit_bundle import canonical_json

from .actuator import Actuator, ActuatorOutcome, NoOpActuator
from .attestation import (
    SigningIdentity,
    append_trace_line,
    build_action_trace,
    build_intent,
    build_intent_trace,
    build_outcome,
    outcome_status,
    telemetry_sha256_of,
)
from .auth import SUPERVISOR
from .cert import report as cert_report
from .cert.audit import AuditChain, AuditEntry
from .cert.envelope import (
    FreshnessPolicy,
    ReplayCache,
    check_freshness,
    check_replay,
    sign_envelope,
    verify_envelope,
)
from .cert.gates import ConfidencePolicy, HiTLPolicy, check_confidence, check_hitl
from .cert.policy import (
    ToolAllowlist,
    as_tool_set,
    audit_allowlist_for_stop,
    check_tier,
    check_tool,
    check_tool_scope,
    check_tool_tier,
)
from .cert.revocation import RevocationCache, RRFRevocationResolver
from .cert.rrn_binding import verify_rrn_binding
from .cert.safety import GatewayState, SafetyMonitor
from .manifest_provenance import RRFResolver, verify_manifest

_DEFAULT_ALLOWLIST = ToolAllowlist(allowed_tools=("mcp__robot__render", "mcp__robot__validate"))

#: Worker threads reserved for stop tools (an actuator's `stop_capabilities`).
#: Every other request shares the default pool of 40. A stop is quick and
#: idempotent, so a handful is plenty, and a burst of stops only queues stops.
STOP_LANES = 8

#: How often the safety watchdog ticks the monitor, in seconds. SF-002's bench
#: criterion is SAFE_STOP within 3.5 s of the last heartbeat under a 3 s
#: staleness rule, so the tick has to land well inside the remaining 0.5 s. An
#: ESTOP wire trip set through app.state.safety_monitor is acted on within one
#: tick as well.
SAFETY_TICK_S = 0.1

#: The tier the gateway passes to an actuator when it sends that actuator's
#: stop itself. No caller credential is involved in that stop, so this is not a
#: bearer's tier; it is the lowest tier a bearer can hold, because a stop is the
#: one act no bearer tier may be refused (so-arm101-actuator gives `arm.estop`
#: to read, actuate and commission) and nothing on this path may need more.
SAFETY_STOP_TIER = "read"

#: The watchdog counts as stuck when it has not ticked for this long, in real
#: time. A stuck watchdog fails closed: the gateway enters SAFE_STOP and sends
#: its stops, and the heartbeat stops answering 200 (review of #35, finding 6).
WATCHDOG_STALE_S = 1.0

#: How long the gateway waits for one actuator's stop to answer before it
#: records that stop as failed and stops waiting for it. Each stop runs on a
#: thread of its own, so a slow or hung stop delays nothing else; this bounds
#: only how long a clear is refused on its account. so-arm101-actuator can wait
#: STOP_BUS_WAIT_S (5 s) for its bus before it answers.
STOP_TIMEOUT_S = 10.0


@dataclass
class _StopSend:
    """One actuator's stop for one trip: what the gateway sends, and how it went."""

    name: str
    actuator: object
    config: dict
    tool: str
    msg_id: str
    status: str = "pending"        # pending -> running -> done, or running -> timed_out
    started: float | None = None   # the app's clock() when its thread started


@dataclass
class _Trip:
    """One departure from READY, and the stops the gateway owes for it."""

    seq: int
    state: GatewayState
    why: str
    sends: list[_StopSend]

    def settled(self) -> bool:
        """Every stop has answered, or the gateway has stopped waiting for it."""
        return all(s.status in ("done", "timed_out") for s in self.sends)


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
    except Exception:
        # NOTHING ESCAPES THIS. It used to catch only OSError and YAMLError, so
        # one non-UTF-8 byte (UnicodeDecodeError) in a hand-edited ROBOT.md
        # raised out of the gateway's own trip path and cancelled its stop
        # (review of #35, finding 1). An unreadable manifest reads as empty.
        fm = {}
    if not isinstance(fm, dict):
        fm = {}  # frontmatter that is a string or a list is no frontmatter
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
    tool_tier_requirements: dict[str, frozenset[str]] | None = None,
    bearer_tiers: dict[str, str] | None = None,
    bearers: dict[str, object] | None = None,
    require_envelope_signature: bool = False,
    replay_cache: ReplayCache | None = None,
    freshness_policy: FreshnessPolicy | None = None,
    confidence_policy: ConfidencePolicy | None = None,
    hitl_policy: HiTLPolicy | None = None,
    hitl_from_manifest: bool = False,
    require_rrn_binding: bool = False,
    pinned_manifest_path: Path | None = None,
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
    clock: Callable[[], float] | None = None,
) -> FastAPI:
    # The clock heartbeat staleness and the stop timeout are judged on:
    # time.monotonic, unless a test passes a fake one. Whether the watchdog
    # itself is still ticking is always judged in real time.
    clock = clock or time.monotonic
    if tool_allowlist is None:
        tool_allowlist = _DEFAULT_ALLOWLIST
    tool_tier_requirements = tool_tier_requirements or {}
    bearer_tiers = bearer_tiers or {}
    # THE BEARER INDEX: token -> (tier, caller). `bearers` carries whole bearer
    # entries (anything with .tier and .caller_id, i.e. auth._BearerEntry) and is
    # what the serve path now passes; `bearer_tiers` is the old {token: tier}
    # shape, kept because tests and embedders pass it and it must keep working.
    # An entry in `bearers` wins over the same token in `bearer_tiers`.
    #
    # The collapse this replaces threw the caller away one step before the only
    # record in the ecosystem that gets signed outside the agent's process, so
    # every receipt said a tier acted and none said which credential did.
    _bearer_index: dict[str, tuple[str, str | None]] = {
        token: (tier, None) for token, tier in bearer_tiers.items()
    }
    for token, entry in (bearers or {}).items():
        _bearer_index[token] = (
            getattr(entry, "tier", "anon"),
            getattr(entry, "caller_id", None),
        )
    # The tokens SF-002's heartbeat is accepted from: entries with role
    # supervisor, and only those. A supervisor is read tier, so no credential
    # that can move the robot can also keep its heartbeat alive.
    _supervisors: set[str] = set()
    for token, entry in (bearers or {}).items():
        if getattr(entry, "role", None) == SUPERVISOR:
            if getattr(entry, "tier", None) != "read":
                raise ValueError(
                    f"supervisor credential {getattr(entry, 'caller_id', None)!r} has "
                    f"tier {getattr(entry, 'tier', None)!r}; a supervisor must hold "
                    f"the read tier"
                )
            _supervisors.add(token)

    def _principal(authorization: str | None) -> tuple[str, str | None]:
        """Resolve an Authorization header to (tier, caller).

        Unknown or absent bearer -> ("anon", None). `caller` names a CREDENTIAL,
        never a person: it is the name the operator wrote beside the token in
        bearers.yaml.
        """
        if authorization and authorization.startswith("Bearer "):
            return _bearer_index.get(authorization[7:], ("anon", None))
        return "anon", None
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
    # Every tool any configured actuator says moves the robot. Known before an
    # actuator is chosen, so the scope, confidence and HiTL gates below can treat
    # a motion as a motion whatever the envelope calls it.
    _motion_tools = frozenset().union(*(
        as_tool_set(getattr(a, "motion_capabilities", None))
        for a in ([*actuators.values()] if multi_actuator_mode else [actuator])
        if a is not None
    ))
    # And every tool any of them says stops it: these get their own worker
    # threads (see invoke), so a stop never queues behind other requests.
    _stop_tools = frozenset().union(*(
        as_tool_set(getattr(a, "stop_capabilities", None))
        for a in ([*actuators.values()] if multi_actuator_mode else [actuator])
        if a is not None
    ))
    # Each actuator that declares a stop, and the stop the gateway sends it on a
    # trip: (name, actuator, config, tool), resolved ONCE, here. The trip path
    # reads nothing that can fail at the moment it matters, not ROBOT.md and
    # not a declaration (review of #35, finding 1).
    _stop_targets: list[tuple[str, object, dict, str]] = []
    for _name, _act in (sorted(actuators.items()) if multi_actuator_mode
                        else [(getattr(actuator, "name", "actuator"), actuator)]):
        _declared = sorted(as_tool_set(getattr(_act, "stop_capabilities", None)))
        if _declared:
            _config = actuator_configs.get(_name, {}) if multi_actuator_mode else actuator_config
            _stop_targets.append((_name, _act, _config, _declared[0]))
    # The robot's RRN for the gateway's own records (trips, stops, clears),
    # read once from the pinned manifest. Best effort: "" if it cannot be read.
    _pinned_rrn = ""
    if pinned_manifest_path is not None:
        _fm0 = _manifest_frontmatter(str(pinned_manifest_path))
        _md0 = _fm0.get("metadata")
        _pinned_rrn = str((_md0.get("rrn") if isinstance(_md0, dict) else None)
                          or _fm0.get("rrn") or "")
    _stop_lane: list = [None, None]          # (weakref to the event loop, its limiter)

    def _stop_limiter() -> anyio.CapacityLimiter:
        # One limiter per event loop: an anyio limiter belongs to the loop that
        # first used it, and tests run one app under several loops.
        loop = asyncio.get_running_loop()
        if _stop_lane[0] is None or _stop_lane[0]() is not loop:
            _stop_lane[:] = [weakref.ref(loop), anyio.CapacityLimiter(STOP_LANES)]
        return _stop_lane[1]

    # Startup invariant: a gateway allowlisted to MOVE a robot and not to STOP
    # it is a misconfiguration, and it is the one this whole change exists to
    # stop recurring. Logged loudly under a named reason, NOT refused: the
    # gateway that refuses to start is a gateway an operator restarts without
    # the check, and a robot that will not answer `status.report` is not safer
    # than one that will. The stop is what has to be reachable, not the boot.
    _stop_findings = audit_allowlist_for_stop(
        tool_allowlist,
        list(actuators.items()) if multi_actuator_mode
        else ([(getattr(actuator, "name", "actuator"), actuator)] if actuator is not None else []),
    )
    for _finding in _stop_findings:
        logging.getLogger(__name__).error(
            "%s: actuator %r is allowlisted for motion (%s) but the allowlist "
            "carries none of its stop tools (%s). Add a stop to "
            "ROBOT_MD_TOOL_ALLOWLIST and restart the gateway.",
            _finding["reason"],
            _finding["actuator"],
            ", ".join(_finding["allowed_motion_tools"]),
            ", ".join(_finding["stop_tools_declared"]) or "none declared",
        )
    if replay_cache is None:
        replay_cache = ReplayCache()
    if freshness_policy is None:
        freshness_policy = FreshnessPolicy()
    # Default the revocation cache at make_app level (parallel to replay_cache):
    # if the operator opts into revocation_resolver but doesn't pass an explicit
    # cache, build one here so it's shared across requests instead of being
    # constructed fresh on every call (which would defeat caching entirely).
    if revocation_resolver is not None and revocation_cache is None:
        revocation_cache = RevocationCache()
    if safety_monitor is None:
        # The opt-out is for tests and embedders, and it is loud. `serve`
        # always passes a monitor and has no switch to drop it.
        logging.getLogger(__name__).warning(
            "no_safety_monitor: this gateway enforces no heartbeat staleness "
            "(SF-002) and will not stop its actuators if its clients go silent. "
            "`robot-md-gateway serve` always runs one; pass "
            "make_app(safety_monitor=SafetyMonitor()) anywhere else that drives "
            "hardware."
        )

    @contextlib.asynccontextmanager
    async def _lifespan(_app: FastAPI):
        # The watchdog runs for exactly as long as the app is served. It is a
        # thread, not a task on the event loop, because a stop it sends is a
        # blocking call into a driver (a serial bus, say), and the loop must
        # keep answering heartbeats and stops while one is in progress.
        if safety_monitor is None:
            yield
            return
        stopping = threading.Event()
        watchdog = threading.Thread(
            target=_safety_watchdog, args=(stopping,),
            name="robot-md-gateway-safety-watchdog", daemon=True,
        )
        # Registered so that a watchdog which dies or stops ticking is noticed
        # by every request and every heartbeat, and fails closed.
        _safety.last_tick = time.monotonic()
        _safety.watchdog = watchdog
        watchdog.start()
        try:
            yield
        finally:
            stopping.set()
            watchdog.join(timeout=5)
            _safety.watchdog = None

    app = FastAPI(title="robot-md-gateway", version="0.4.0a1", lifespan=_lifespan)
    # Operators access these via app.state for ESTOP wire integration and
    # audit-bundle export. The ESTOP wire is a GPIO/transport-level signal and
    # stays off HTTP: putting it behind HTTP-layer auth would conflate
    # physical-wire semantics (the SF-001 claim) with a bearer check. The
    # heartbeat and the operator's clear are HTTP routes (/v1/safety/*) because
    # SF-002 is a network-loss rule: the heartbeat has to cross the same network
    # whose loss it detects, and nothing else delivered one to this process.
    app.state.safety_monitor = safety_monitor
    app.state.audit_chain = audit_chain
    app.state.revocation_cache = revocation_cache
    app.state.actuator = actuator
    app.state.actuator_config = actuator_config
    app.state.actuators = actuators
    app.state.actuator_configs = actuator_configs
    app.state.multi_actuator_mode = multi_actuator_mode
    # Kept so an operator (or a test) can read the boot-time finding back
    # rather than having to have been watching the log when it scrolled by.
    app.state.allowlist_stop_findings = _stop_findings

    def _build_signed_outcome(
        *,
        decision: str,
        reason: str,
        msg_id: str,
        rrn: str | None,
        started_at: str | None,
        ended_at: str | None,
        outcome: ActuatorOutcome | None,
        error_kind: str | None,
        caller: str | None,
        tier: str | None,
    ) -> tuple[dict | None, str]:
        """Build the Ed25519-signed outcome for BOTH the wire receipt and the
        NDJSON attestation export.

        Returns ``(signed_outcome, marker)``. ``marker`` is ``"attested"`` when a
        signing identity is configured (ROBOT_MD_ATTESTATION_KEY_FILE/KID) and a
        signature was produced, else ``"unattested"`` (the gateway runs
        verifier-only; the wire carries ``envelope_signature: null``).

        Reuses the exact ``build_outcome`` + ``sign_envelope`` recipe the file
        export used, so the wire receipt is byte-identical to the file trace's
        ``outcome`` — no new crypto is introduced.
        """
        if signing_identity is None:
            return None, "unattested"
        # An allow with no actuator outcome is something the gateway did itself,
        # with no actuator call that could fail (a safety clear): ok, unless an
        # error_kind says it failed (a stop that never answered). Signing one
        # used to raise on `outcome.error_message`, so it went out unattested.
        status = outcome_status(
            decision=decision,
            success=(outcome.success if outcome is not None
                     else decision == "allow" and error_kind is None),
            error_kind=error_kind,
        )
        error: dict | None = None
        if status != "ok":
            if decision == "deny":
                # reason is "<gate>: <detail>"; the gate name is the error kind.
                kind = reason.split(":", 1)[0].strip() or "denied"
                error = {"kind": kind, "message": reason}
            elif outcome is None:
                error = {"kind": error_kind, "message": reason}
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
            caller=caller,
            tier=tier,
        )
        signed = sign_envelope(signing_identity.priv, body, signing_identity.kid)
        return signed, "attested"

    def _emit_attestation(
        *,
        signed_outcome: dict | None,
        msg_id: str,
        envelope_dict: dict | None,
        ruri: str | None,
        rrn: str | None,
        intent_chain_hash: str | None = None,
    ) -> None:
        # Attestation export is independent of the audit chain: it must fire even
        # when audit_chain is None. Disabled when no signing identity / no export
        # path / nothing was signed.
        if signing_identity is None or attestation_export_file is None:
            return
        if signed_outcome is None:
            return
        # An unparseable invoke (422) never reaches a _record call, so any
        # envelope_dict here has at least the signed fields we were given.
        invoke = envelope_dict if envelope_dict is not None else {"msg_id": msg_id}
        record = build_action_trace(
            invoke=invoke, outcome=signed_outcome, ruri=ruri, rrn=rrn or "",
            intent_chain_hash=intent_chain_hash,
        )
        append_trace_line(attestation_export_file, record)

    def _record_intent(
        *,
        msg_id: str,
        envelope_dict: dict,
        ruri: str | None,
        rrn: str | None,
        tool_name: str | None,
        actuator_name: str | None,
        kid: str | None,
        caller: str | None,
        tier: str | None,
    ) -> str | None:
        """Write the RECORD BEFORE DISPATCH, and return its audit chain hash.

        Called once, after every gate has passed and before the actuator is
        touched. It writes two things by the same recipes the outcome uses: an
        AuditEntry with ``entry_kind="intent"`` into the hash-linked chain, and a
        signed intent line into the NDJSON export.

        WHAT AN INTENT ENTRY MEANS, exactly: the gateway cleared every gate and
        was about to call this actuator with this tool on behalf of this
        credential. It does not say the actuator ran. It does not say anything
        succeeded. An intent with no outcome beside it is a dispatch that never
        reported back, and ``scripts/verify_receipt.py --walk`` names it as
        exactly that rather than counting it as an action.

        BEST EFFORT, verbatim the same contract the outcome path has carried
        since the export existed: every failure in here is caught, logged and
        swallowed. A signing error, a full disk or an unwritable export must
        never crash the request and must never change whether the robot moves.
        A record is evidence, not enforcement, and the day it becomes a new way
        to stop a robot is the day operators start turning it off.
        """
        intent_hash: str | None = None
        recorded_at = datetime.now(tz=timezone.utc).isoformat()
        envelope_id = envelope_dict.get("envelope_id")
        nonce = envelope_dict.get("nonce")
        # Audit FIRST, for the same reason the outcome path does it first:
        # tamper-evident evidence must not be suppressed by a downstream
        # attestation failure.
        try:
            if audit_chain is not None:
                # Read the hash off the RETURNED entry, never off
                # ``audit_chain.entries[-1]``. Two invokes run in two Starlette
                # worker threads; by the time this thread reads the tail, the
                # other one's intent may already be sitting on it, and this
                # outcome would then carry a pointer to somebody else's dispatch.
                # An evidence link that is wrong is worse than one that is absent.
                stored = audit_chain.append(AuditEntry(
                    msg_id=msg_id,
                    timestamp_ms=int(time.time() * 1000),
                    decision="allow",
                    decision_reason="dispatching: all gates passed, actuator not yet called",
                    envelope_kid=kid,
                    caller=caller,
                    tier=tier,
                    entry_kind="intent",
                    tool_name=tool_name,
                    envelope_id=envelope_id if isinstance(envelope_id, str) else None,
                    nonce=nonce if isinstance(nonce, str) else None,
                    actuator_name=actuator_name,
                ))
                intent_hash = stored.chain_hash
        except Exception:
            logging.getLogger(__name__).warning(
                "intent audit entry failed (non-fatal; dispatch proceeds)", exc_info=True
            )
        try:
            if signing_identity is not None and attestation_export_file is not None:
                intent = build_intent(
                    corr_id=msg_id,
                    envelope_id=envelope_id if isinstance(envelope_id, str) else None,
                    rrn=rrn or "",
                    tool=tool_name,
                    actuator=actuator_name,
                    nonce=nonce if isinstance(nonce, str) else None,
                    caller=caller,
                    tier=tier,
                    recorded_at=recorded_at,
                )
                signed_intent = sign_envelope(
                    signing_identity.priv, intent, signing_identity.kid
                )
                append_trace_line(
                    attestation_export_file,
                    build_intent_trace(
                        invoke=envelope_dict, intent=signed_intent,
                        ruri=ruri, rrn=rrn or "",
                    ),
                )
        except Exception:
            logging.getLogger(__name__).warning(
                "intent attestation emit failed (non-fatal; dispatch proceeds)",
                exc_info=True,
            )
        return intent_hash

    def _attach_signature(target: dict, signed_outcome: dict | None, marker: str) -> None:
        """Attach the wire-receipt signature to a response/deny-detail dict IN PLACE.

        Always sets ``attestation`` (``attested``|``unattested``). When attested,
        embeds the full signed ``outcome`` receipt and lifts its
        ``envelope_signature`` ({kid, alg, sig}) to the top level so a client can
        read it directly; when unattested, sets ``envelope_signature: null`` so the
        client can render honestly.
        """
        target["attestation"] = marker
        if signed_outcome is not None:
            target["outcome"] = signed_outcome
            target["envelope_signature"] = signed_outcome["envelope_signature"]
        else:
            target["envelope_signature"] = None

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
        caller: str | None = None,
        tier: str | None = None,
        intent_chain_hash: str | None = None,
    ) -> tuple[dict | None, str]:
        # Sign the outcome ONCE for both the wire receipt and the file export.
        # Best-effort: a signing failure must never crash the request (mirrors the
        # file-export best-effort contract) — fall back to an explicit unattested
        # marker so the caller can still return a well-formed (unsigned) response.
        try:
            signed_outcome, marker = _build_signed_outcome(
                decision=decision, reason=reason, msg_id=msg_id, rrn=rrn,
                started_at=started_at, ended_at=ended_at,
                outcome=outcome, error_kind=error_kind,
                caller=caller, tier=tier,
            )
        except Exception:
            logging.getLogger(__name__).warning(
                "wire outcome signing failed (non-fatal; returning unattested)",
                exc_info=True,
            )
            signed_outcome, marker = None, "unattested"
        # Audit FIRST — tamper-evident evidence (EV-001) must never be suppressed
        # by a downstream attestation failure.
        if audit_chain is not None:
            entry_kwargs = dict(
                msg_id=msg_id,
                timestamp_ms=int(time.time() * 1000),
                decision=decision,
                decision_reason=reason,
                envelope_kid=kid,
                caller=caller,
                tier=tier,
                # entry_kind defaults to "outcome"; spelled out here so the pair
                # reads as a pair at the one place both halves are written.
                entry_kind="outcome",
                intent_chain_hash=intent_chain_hash,
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
        # Attestation LAST + BEST-EFFORT: it fires even when audit_chain is None
        # (independent observability), but a signing / file-I/O error here must
        # NEVER propagate into the invoke result or alter actuation. A real
        # actuation that already executed must not be reported as a 500, and a
        # clean deny must not become a 500. The shipper + backfill backstop any
        # dropped record.
        try:
            _emit_attestation(
                signed_outcome=signed_outcome, msg_id=msg_id,
                envelope_dict=envelope_dict, ruri=ruri, rrn=rrn,
                intent_chain_hash=intent_chain_hash,
            )
        except Exception:
            logging.getLogger(__name__).warning(
                "attestation emit failed (non-fatal; audit already recorded)",
                exc_info=True,
            )
        return signed_outcome, marker

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
        caller: str | None = None,
        tier: str | None = None,
    ) -> tuple[dict | None, str]:
        return _record_with_outcome(
            decision=decision, reason=reason, kid=kid, msg_id=msg_id,
            envelope_dict=envelope_dict, ruri=ruri, rrn=rrn,
            started_at=started_at, ended_at=ended_at,
            caller=caller, tier=tier,
        )

    # ---- SF-001 / SF-002: what a trip does to the machine -------------------
    #
    # Refusing new requests is not stopping the machine. A paced move already
    # dispatched keeps going, and a goal an actuator holds stays set, until the
    # actuator is told to stop. So every time the monitor leaves READY (stale
    # heartbeat, ESTOP wire, a stuck watchdog) the gateway sends each actuator
    # in `_stop_targets` its own stop, whether or not any request is arriving.
    #
    # How a trip is handled, and why each part is the way it is:
    # - Observing the state and starting the stops happen under one lock, and
    #   so does a clear, which first acts on any trip not yet acted on. A clear
    #   can never discard a trip whose stops were not sent (finding 5).
    # - Each stop runs on a thread of its own. A stop that hangs (a serial
    #   write with no timeout) delays no other actuator's stop and does not
    #   wedge the watchdog (finding 6). After STOP_TIMEOUT_S the gateway records
    #   it as failed and stops waiting for it.
    # - A trip is handled when every stop has answered or timed out, not when
    #   it was noticed. A stop whose thread could not start is still owed and
    #   is tried again on the next tick (finding 1).
    # - Nothing on this path parses ROBOT.md or anything else that can fail:
    #   the targets and the RRN were resolved when the app was built.
    # - Records are written after the lock is released, and writing one never
    #   raises: evidence must never be the thing that stops a stop.
    _safety_lock = threading.Lock()
    _safety = SimpleNamespace(
        seen=safety_monitor.state if safety_monitor is not None else None,
        trip=None,              # the current _Trip, until a clear ends it
        trips=0,
        watchdog=None,          # the watchdog thread while the app is served
        last_tick=0.0,          # time.monotonic() of the watchdog's last tick
        last_heartbeat=None,    # (caller, clock()) of the last accepted heartbeat
    )

    def _watchdog_stuck() -> bool:
        """True when the watchdog of a served app has died or stopped ticking.
        An app that is not being served (no lifespan) has no watchdog; its
        requests tick the monitor themselves."""
        watchdog = _safety.watchdog
        if watchdog is None:
            return False
        return (not watchdog.is_alive()
                or time.monotonic() - _safety.last_tick > WATCHDOG_STALE_S)

    def _trip_reason(state: GatewayState, stuck: bool) -> str:
        if stuck:
            return f"the safety watchdog has not ticked for over {WATCHDOG_STALE_S:g} s"
        if state is GatewayState.SAFE_STOP:
            age = clock() - safety_monitor.last_heartbeat_at
            last = _safety.last_heartbeat
            source = (f"; the last one came from supervisor {last[0]!r}" if last
                      else "; no heartbeat had been accepted")
            return (f"no heartbeat for {age:.1f} s, limit "
                    f"{safety_monitor.heartbeat_staleness_s:g} s{source}")
        return "ESTOP wire tripped"

    def _observe_locked(records: list) -> GatewayState:
        """Tick the monitor and act on a change of state. Caller holds the lock."""
        safety_monitor.tick(now=clock())
        stuck = _watchdog_stuck()
        if stuck and safety_monitor.state is GatewayState.READY:
            safety_monitor.state = GatewayState.SAFE_STOP
        state = safety_monitor.state
        prev = _safety.seen
        if state is not prev:
            _safety.seen = state
            if state is not GatewayState.READY:
                # Every move into a stopped state sends the stops, SAFE_STOP ->
                # ESTOP_ACTIVE included: an ESTOP is never absorbed by an
                # earlier trip whose stop may have failed.
                _safety.trips += 1
                trip = _Trip(
                    seq=_safety.trips, state=state, why=_trip_reason(state, stuck),
                    sends=[_StopSend(name=n, actuator=a, config=c, tool=t,
                                     msg_id=f"safety-stop-{uuid.uuid4().hex[:12]}")
                           for n, a, c, t in _stop_targets],
                )
                _safety.trip = trip
                records.append(("trip", prev, trip))
            else:
                records.append(("state", prev, state))
        return state

    def _advance_locked(records: list) -> None:
        """Start the current trip's stops that have not started, and stop
        waiting for any that has not answered in STOP_TIMEOUT_S. Caller holds
        the lock."""
        trip = _safety.trip
        if trip is None:
            return
        for send in trip.sends:
            if send.status == "pending":
                thread = threading.Thread(
                    target=_send_stop, args=(trip, send),
                    name=f"robot-md-gateway-stop-{send.name}", daemon=True,
                )
                send.status, send.started = "running", clock()
                try:
                    thread.start()
                except Exception:
                    # No thread (resource exhaustion): the stop is still owed,
                    # and the next tick tries again.
                    send.status, send.started = "pending", None
                    logging.getLogger(__name__).exception(
                        "safety_stop: could not start the stop for %r; retrying on the "
                        "next tick", send.name,
                    )
            elif send.status == "running" and clock() - send.started > STOP_TIMEOUT_S:
                send.status = "timed_out"
                records.append(("timeout", trip, send))

    def _send_stop(trip: _Trip, send: _StopSend) -> None:
        """On its own thread: send one actuator its stop, as the gateway, and
        record what it answered. No caller credential is involved and no gate is
        consulted: the allowlist and the tiers decide what a CALLER may do, and
        nothing may decide that the gateway cannot stop its own machine. The
        manifest passed is the pinned one, never one a request named."""
        started = datetime.now(tz=timezone.utc).isoformat()
        envelope = {
            "msg_id": send.msg_id, "type": "rcan/v1/invoke", "scope": "SAFETY",
            "tool_name": send.tool, "tool_args": {}, "actuator_name": send.name,
            "manifest_path": str(pinned_manifest_path or ""),
        }
        error_kind: str | None = None
        try:
            outcome = send.actuator.execute(
                envelope=envelope, manifest_path=pinned_manifest_path,
                tier=SAFETY_STOP_TIER, config=send.config,
            )
            if not isinstance(outcome, ActuatorOutcome):
                raise TypeError(f"execute returned {type(outcome).__name__}, not an outcome")
        except Exception as exc:
            outcome = ActuatorOutcome(success=False, outcome_kind="error",
                                      error_message=f"{type(exc).__name__}: {exc}")
            error_kind = type(exc).__name__
        with _safety_lock:
            late = send.status == "timed_out"
            send.status = "done"
        log = logging.getLogger(__name__)
        try:
            refused = not outcome.success and outcome.outcome_kind == "denied"
            reason = (f"safety_stop: trip {trip.seq} ({trip.state.value}: {trip.why}); "
                      f"sent {send.tool} to {send.name}")
            if late:
                reason += (f"; it answered after the gateway stopped waiting "
                           f"({STOP_TIMEOUT_S:g} s)")
            if not outcome.success:
                reason += f"; it did not succeed: {outcome.error_message}"
            (log.warning if outcome.success else log.error)(
                "%s (outcome: %s)", reason, outcome.outcome_kind,
            )
            _record_with_outcome(
                decision="deny" if refused else "allow", reason=reason,
                kid=None, msg_id=send.msg_id, outcome=outcome, error_kind=error_kind,
                actuator_name=send.name, envelope_dict=envelope, ruri=None,
                rrn=_pinned_rrn, started_at=started,
                ended_at=datetime.now(tz=timezone.utc).isoformat(),
                caller=None, tier=None,
            )
        except Exception:
            log.warning("safety_stop: recording the stop for %r failed (non-fatal)",
                        send.name, exc_info=True)

    def _write_safety_records(records: list) -> None:
        """Record trips, other state changes and stop timeouts. Never raises."""
        log = logging.getLogger(__name__)
        for kind, first, second in records:
            try:
                error_kind = None
                if kind == "trip":
                    prev, trip = first, second
                    if trip.sends:
                        what = "sending " + ", ".join(f"{s.tool} to {s.name}"
                                                      for s in trip.sends)
                    else:
                        what = "no actuator declares a stop, so nothing was told to stop"
                    reason = (f"safety_trip: {prev.value} -> {trip.state.value} "
                              f"({trip.why}); {what}")
                    msg_id, decision = f"safety-trip-{trip.seq}", "deny"
                    (log.warning if trip.sends else log.error)("%s", reason)
                elif kind == "state":
                    # Back to READY by some path other than /v1/safety/clear
                    # (which records itself): an embedder calling
                    # SafetyMonitor.clear directly, say.
                    prev, state = first, second
                    reason = (f"safety_transition: {prev.value} -> {state.value} "
                              f"(not through /v1/safety/clear)")
                    msg_id = f"safety-transition-{uuid.uuid4().hex[:12]}"
                    decision = "allow" if state is GatewayState.READY else "deny"
                    log.warning("%s", reason)
                else:  # "timeout": a fault, not a decision
                    trip, send = first, second
                    reason = (f"safety_stop_timeout: trip {trip.seq}: {send.tool} to "
                              f"{send.name} did not answer within {STOP_TIMEOUT_S:g} s; "
                              f"the gateway stopped waiting for it")
                    msg_id, decision = f"{send.msg_id}-timeout", "allow"
                    error_kind = "StopTimeout"
                    log.error("%s", reason)
                _record_with_outcome(
                    decision=decision, reason=reason, kid=None, msg_id=msg_id,
                    error_kind=error_kind,
                    envelope_dict={"msg_id": msg_id, "type": "SAFETY"}, ruri=None,
                    rrn=_pinned_rrn, started_at=datetime.now(tz=timezone.utc).isoformat(),
                    caller=None, tier=None,
                )
            except Exception:
                log.warning("safety: recording a %s failed (non-fatal)", kind, exc_info=True)

    def _safety_check() -> GatewayState:
        """Tick the monitor, act on any trip, and return the state to act on.
        Called by the watchdog every SAFETY_TICK_S and by every request."""
        records: list = []
        with _safety_lock:
            state = _observe_locked(records)
            _advance_locked(records)
        _write_safety_records(records)
        return state

    def _safety_watchdog(stopping: threading.Event) -> None:
        """Tick the monitor while the app is served, requests or none."""
        while not stopping.wait(SAFETY_TICK_S):
            _safety.last_tick = time.monotonic()
            try:
                _safety_check()
            except Exception:
                logging.getLogger(__name__).exception(
                    "safety_watchdog: a tick failed; the next runs in %.1f s", SAFETY_TICK_S,
                )

    # For tests and in-process integrations: one synchronous tick.
    app.state.safety_tick = _safety_check

    def _dispatch(
        *,
        envelope_dict: dict,
        msg_id: str,
        ruri: str | None,
        scope: str,
        tool_name: str,
        target_actuator: Actuator,
        target_config: dict,
        manifest_path: Path | None,
        kid: str | None,
        rrn: str,
        tier: str,
        caller: str | None,
        started_at: str,
    ) -> dict:
        """Record, dispatch to the actuator, record again, and answer.

        Everything after the gates: the intent written before dispatch, the
        call into the actuator, the outcome record, and the 200, 403 or 500
        that goes back. Shared by the gated path and the stop path, so the
        records and the response cannot drift apart between them.
        """
        # RECORD BEFORE DISPATCH (RCAN 6.3). Every gate above has passed and the
        # actuator has been chosen; the next statement is the one that can move
        # the robot. This is the last moment at which a record can be written
        # that does not depend on the dispatch coming back, and that is exactly
        # why the spec puts it here: a driver that hangs, a process that is
        # killed mid-motion, or a robot that is unplugged all used to leave no
        # trace that anything had been attempted at all.
        #
        # THE LATE RECORD STAYS. The outcome entry below is not replaced by
        # this one, because the reason the late record existed is still true:
        # only a record written after the dispatch can say what happened. The
        # pair is the answer. The intent says what was about to be attempted,
        # the outcome says how it went, and the outcome carries the intent's
        # chain hash so the two are one hop apart.
        intent_chain_hash = _record_intent(
            msg_id=msg_id, envelope_dict=envelope_dict,
            ruri=ruri, rrn=rrn,
            tool_name=tool_name, actuator_name=target_actuator.name,
            kid=kid, caller=caller, tier=tier,
        )

        # Capture outcome regardless of success so the audit entry records
        # what actually happened.
        try:
            outcome = target_actuator.execute(
                envelope=envelope_dict,
                manifest_path=manifest_path,
                tier=tier,
                config=target_config,
            )
            error_kind: str | None = None
        except Exception as exc:
            outcome = ActuatorOutcome(
                success=False, outcome_kind="error",
                error_message=str(exc),
            )
            error_kind = type(exc).__name__
        ended_at = datetime.now(tz=timezone.utc).isoformat()

        # A DRIVER'S REFUSAL IS RECORDED AS A DENY. outcome_kind == "denied" is
        # the actuator's own policy gate saying no, and the caller is told so
        # with a signed 403 just below. This record used to say
        # decision="allow", reason="ok" whatever the driver answered, so the
        # audit chain and the signed receipt (status "failure") filed a refusal
        # as an action that ran and failed. Any other unsuccessful outcome is a
        # fault, not a decision: the gates allowed it and the driver broke, so it
        # stays an allow, with the error carried by the outcome fields.
        refused = not outcome.success and outcome.outcome_kind == "denied"
        if refused:
            decision, reason = "deny", f"actuator_policy: {outcome.error_message or 'refused'}"
        else:
            decision, reason = "allow", "ok"
        signed_outcome, marker = _record_with_outcome(
            decision=decision, reason=reason,
            kid=kid, msg_id=msg_id,
            outcome=outcome, error_kind=error_kind,
            actuator_name=target_actuator.name,
            envelope_dict=envelope_dict, ruri=ruri, rrn=rrn,
            started_at=started_at, ended_at=ended_at, caller=caller, tier=tier,
            intent_chain_hash=intent_chain_hash,
        )

        if refused:
            # A driver refusing on POLICY is a decision, not a fault, and it must
            # reach the caller the way every other decision does: a signed 403 the
            # client can render, verify, and keep. It used to fall into the 500
            # below — unsigned, and unreadable to clients that accept only
            # 200/403, so "no drive approval is open" arrived as a transport
            # error indistinguishable from the gateway falling over. Same fix as
            # the one made for an unreadable manifest_path.
            #
            # Only outcome_kind == "denied" takes this path. An actuator that
            # crashed still 500s: a fault dressed as a policy refusal would tell
            # the operator the robot decided something when in fact it broke.
            detail = {
                "deny": "actuator_policy",
                "reason": outcome.error_message,
                "actuator_name": target_actuator.name,
            }
            # The driver's own structured account of the refusal, when it has
            # one. `reason` is a sentence for a person; a harness deciding what
            # to do next needs a code it can branch on, and regexing the prose
            # is how a message becomes an accidental API.
            #
            # This is not new information reaching the client: telemetry is
            # already hashed into the signed outcome above (telemetry_sha256),
            # so the structure returned here is bound to the same signature the
            # sentence is — and the allow path has always returned it verbatim.
            if outcome.telemetry:
                detail["telemetry"] = outcome.telemetry
            _attach_signature(detail, signed_outcome, marker)
            raise HTTPException(status_code=403, detail=detail)

        if not outcome.success:
            raise HTTPException(status_code=500, detail={
                "actuator_error": outcome.error_message,
                "actuator_error_kind": error_kind,
            })

        response = {
            "ok": True,
            "manifest_kid": kid,
            "scope": scope,
            "tool_name": tool_name,
            "actuator_name": target_actuator.name,
            "outcome_kind": outcome.outcome_kind,
            "telemetry": outcome.telemetry,
        }
        # Embed the Ed25519-signed outcome so the client can verify the receipt on
        # the wire (envelope_signature: {kid, alg, sig}). When attestation is not
        # configured, this attaches attestation="unattested" + envelope_signature=null.
        _attach_signature(response, signed_outcome, marker)
        return response

    def _invoke(envelope_dict: dict, authorization: str | None):
        # `caller` rides every audit entry and every signed receipt from here
        # down. It is the CREDENTIAL's name, never a person's.
        tier, caller = _principal(authorization)

        # SF-001/SF-002: safety state preempts all other gates. The request
        # ticks the monitor too, so it never acts on a state older than itself;
        # the watchdog is what enforces staleness between requests, because a
        # motion already dispatched keeps going whether or not anyone is asking.
        # FastAPI guarantees envelope_dict is a dict — Body(...) typed dict
        # rejects non-object JSON with 422 before the handler runs, so we
        # can read msg_id directly with a default for the missing-field case.
        raw_msg_id = envelope_dict.get("msg_id", "<unknown>")
        started_at = datetime.now(tz=timezone.utc).isoformat()

        # A STOP ALWAYS GETS THROUGH THE SAFETY STATE. This check used to refuse
        # every request outside READY, the stop tools included, so a gateway in
        # SAFE_STOP or ESTOP_ACTIVE refused the one command an operator sends
        # when something is wrong. The exemption is exactly a tool some actuator
        # declares in `stop_capabilities`: nothing else, not the clear (it makes
        # the robot movable again), not a read. It skips this check and no
        # other; the stop still passes every gate below, and once the actuator
        # is chosen it must be one that declares this tool as its stop.
        stop_past_safety_state = False
        if safety_monitor is not None:
            state = _safety_check()
            tool = envelope_dict.get("tool_name")
            if state is GatewayState.READY:
                pass
            elif isinstance(tool, str) and tool in _stop_tools:
                stop_past_safety_state = True
            else:
                reason = f"gateway state={state.value}"
                signed, marker = _record(
                    "deny", f"safety_state: {reason}", None, raw_msg_id,
                    envelope_dict=envelope_dict, ruri=envelope_dict.get("ruri"),
                    rrn="", started_at=started_at, caller=caller, tier=tier,
                )
                detail = {"deny": "safety_state", "reason": reason}
                _attach_signature(detail, signed, marker)
                raise HTTPException(status_code=403, detail=detail)

        if require_envelope_signature:
            env_result = verify_envelope(envelope_dict, resolver=resolver)
            if not env_result.accepted:
                signed, marker = _record(
                    "deny",
                    f"envelope_signature: {env_result.reason}",
                    env_result.kid,
                    raw_msg_id,
                    envelope_dict=envelope_dict, ruri=envelope_dict.get("ruri"),
                    rrn="", started_at=started_at, caller=caller, tier=tier,
                )
                detail = {"deny": "envelope_signature", "reason": env_result.reason}
                _attach_signature(detail, signed, marker)
                raise HTTPException(status_code=403, detail=detail)
            # FRESHNESS BEFORE REPLAY, deliberately. The replay cache is a
            # bounded window: an id that falls out of it can be presented
            # again. Checking the timestamp first bounds how long a captured
            # envelope stays useful even after its id has aged out, and it
            # keeps a stale envelope from consuming a slot in the window.
            ok, reason = check_freshness(envelope_dict, freshness_policy)
            if not ok:
                signed, marker = _record(
                    "deny", f"envelope_freshness: {reason}", env_result.kid, raw_msg_id,
                    envelope_dict=envelope_dict, ruri=envelope_dict.get("ruri"),
                    rrn="", started_at=started_at, caller=caller, tier=tier,
                )
                detail = {"deny": "envelope_freshness", "reason": reason}
                _attach_signature(detail, signed, marker)
                raise HTTPException(status_code=403, detail=detail)
            ok, reason = check_replay(envelope_dict, replay_cache)
            if not ok:
                signed, marker = _record(
                    "deny", f"replay: {reason}", env_result.kid, raw_msg_id,
                    envelope_dict=envelope_dict, ruri=envelope_dict.get("ruri"),
                    rrn="", started_at=started_at, caller=caller, tier=tier,
                )
                detail = {"deny": "replay", "reason": reason}
                _attach_signature(detail, signed, marker)
                raise HTTPException(status_code=403, detail=detail)
            if (
                revocation_resolver is not None
                and env_result.kid
                and revocation_cache.is_revoked(
                    env_result.kid, resolver=revocation_resolver,
                )
            ):
                signed, marker = _record(
                    "deny",
                    f"revoked_key: kid={env_result.kid}",
                    env_result.kid,
                    raw_msg_id,
                    envelope_dict=envelope_dict, ruri=envelope_dict.get("ruri"),
                    rrn="", started_at=started_at, caller=caller, tier=tier,
                )
                detail = {
                    "deny": "revoked_key",
                    "reason": f"kid {env_result.kid} is revoked",
                }
                _attach_signature(detail, signed, marker)
                raise HTTPException(status_code=403, detail=detail)

        try:
            envelope = InvokeEnvelope(**envelope_dict)
        except ValidationError as exc:
            # Schema fails are parser errors, not policy decisions — not audited.
            raise HTTPException(status_code=422, detail=exc.errors()) from exc

        # MANIFEST PIN (#29). The envelope names the manifest it wants enforced,
        # and provenance alone only proves that file was signed by someone we
        # trust, not that it is the one the operator installed. An old signed
        # copy, or a signed manifest for a looser tier/allowlist posture, would
        # pass. When the operator has pinned ROBOT_MD_PATH, any other path is
        # denied before the caller-named file is even read.
        if pinned_manifest_path is not None and (
            os.path.realpath(envelope.manifest_path)
            != os.path.realpath(pinned_manifest_path)
        ):
            reason = (
                f"envelope names {envelope.manifest_path}; "
                f"this gateway enforces {pinned_manifest_path}"
            )
            signed, marker = _record(
                "deny", f"manifest_pin: {reason}", None, envelope.msg_id,
                envelope_dict=envelope_dict, ruri=envelope.ruri,
                rrn="", started_at=started_at, caller=caller, tier=tier,
            )
            detail = {"deny": "manifest_pin", "reason": reason}
            _attach_signature(detail, signed, marker)
            raise HTTPException(status_code=403, detail=detail)

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
            signed, marker = _record(
                "deny",
                f"manifest_provenance: {manifest_result.reason}",
                manifest_result.kid,
                envelope.msg_id,
                envelope_dict=envelope_dict, ruri=envelope.ruri,
                rrn="", started_at=started_at, caller=caller, tier=tier,
            )
            detail = {
                "deny": "manifest_provenance",
                "reason": manifest_result.reason,
                "kid": manifest_result.kid,
            }
            _attach_signature(detail, signed, marker)
            raise HTTPException(status_code=403, detail=detail)

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
        _md = _fm.get("metadata")
        manifest_rrn = str((_md.get("rrn") if isinstance(_md, dict) else None)
                           or _fm.get("rrn") or "")

        # MF-003 — RRN binding (flagged). Bind the envelope identity to the robot's
        # registered RRN so a correctly-signed envelope for robot A can't actuate B.
        if require_rrn_binding:
            rb = verify_rrn_binding(envelope.ruri, manifest_rrn, msg_id=envelope.msg_id)
            if not rb.accepted:
                signed, marker = _record(
                    "deny", f"rrn_binding: {rb.reason}", manifest_result.kid, envelope.msg_id,
                    envelope_dict=envelope_dict, ruri=envelope.ruri,
                    rrn=manifest_rrn, started_at=started_at, caller=caller, tier=tier,
                )
                detail = {"deny": "rrn_binding", "reason": rb.reason}
                _attach_signature(detail, signed, marker)
                raise HTTPException(status_code=403, detail=detail)

        ok, reason = check_tier(tier, envelope.scope, msg_id=envelope.msg_id)
        if not ok:
            signed, marker = _record(
                "deny", f"tier_policy: {reason}", manifest_result.kid, envelope.msg_id,
                envelope_dict=envelope_dict, ruri=envelope.ruri,
                rrn=manifest_rrn, started_at=started_at, caller=caller, tier=tier,
            )
            detail = {"deny": "tier_policy", "reason": reason}
            _attach_signature(detail, signed, marker)
            raise HTTPException(status_code=403, detail=detail)

        allowed, reason = check_tool(envelope.tool_name, tool_allowlist, msg_id=envelope.msg_id)
        if not allowed:
            signed, marker = _record(
                "deny", f"tool_allowlist: {reason}", manifest_result.kid, envelope.msg_id,
                envelope_dict=envelope_dict, ruri=envelope.ruri,
                rrn=manifest_rrn, started_at=started_at, caller=caller, tier=tier,
            )
            detail = {"deny": "tool_allowlist", "reason": reason}
            _attach_signature(detail, signed, marker)
            raise HTTPException(status_code=403, detail=detail)

        allowed, reason = check_tool_tier(
            envelope.tool_name, tier, tool_tier_requirements, msg_id=envelope.msg_id
        )
        if not allowed:
            signed, marker = _record(
                "deny", f"tool_tier: {reason}", manifest_result.kid, envelope.msg_id,
                envelope_dict=envelope_dict, ruri=envelope.ruri,
                rrn=manifest_rrn, started_at=started_at, caller=caller, tier=tier,
            )
            detail = {"deny": "tool_tier", "reason": reason}
            _attach_signature(detail, signed, marker)
            raise HTTPException(status_code=403, detail=detail)

        # SCOPE MUST NAME THE ACT. A tool an actuator declares as motion must be
        # invoked under an actuation scope; the same motion labelled OBSERVE is
        # refused, signed like every other deny. Scope is caller-written, and the
        # tier, confidence and HiTL gates key off it.
        is_motion = envelope.tool_name in _motion_tools
        allowed, reason = check_tool_scope(
            envelope.tool_name, envelope.scope, _motion_tools, msg_id=envelope.msg_id
        )
        if not allowed:
            signed, marker = _record(
                "deny", f"tool_scope: {reason}", manifest_result.kid, envelope.msg_id,
                envelope_dict=envelope_dict, ruri=envelope.ruri,
                rrn=manifest_rrn, started_at=started_at, caller=caller, tier=tier,
            )
            detail = {"deny": "tool_scope", "reason": reason}
            _attach_signature(detail, signed, marker)
            raise HTTPException(status_code=403, detail=detail)

        if confidence_policy is not None:
            ok, reason = check_confidence(envelope_dict, confidence_policy, motion=is_motion)
            if not ok:
                signed, marker = _record(
                    "deny",
                    f"confidence_threshold: {reason}",
                    manifest_result.kid,
                    envelope.msg_id,
                    envelope_dict=envelope_dict, ruri=envelope.ruri,
                    rrn=manifest_rrn, started_at=started_at, caller=caller, tier=tier,
                )
                detail = {"deny": "confidence_threshold", "reason": reason}
                _attach_signature(detail, signed, marker)
                raise HTTPException(status_code=403, detail=detail)

        # RC-004 — HiTL. When hitl_from_manifest is on, the manifest's declared
        # safety.hitl_gates are authoritative (built per-request, cached by mtime);
        # otherwise fall back to the policy passed at make_app time.
        effective_hitl = hitl_policy
        if hitl_from_manifest:
            fm = _manifest_frontmatter(envelope.manifest_path)
            safety_block = fm.get("safety") or {}
            try:
                gates = safety_block.get("hitl_gates")
                effective_hitl = HiTLPolicy.from_manifest_gates(gates)
            except (AttributeError, TypeError):
                # A safety block or hitl_gates that is not the declared shape:
                # fail closed with a signed deny, never a 500 and never "no
                # gates".
                reason = "the manifest's safety.hitl_gates could not be read"
                signed, marker = _record(
                    "deny", f"hitl_required: {reason}", manifest_result.kid,
                    envelope.msg_id, envelope_dict=envelope_dict, ruri=envelope.ruri,
                    rrn=manifest_rrn, started_at=started_at, caller=caller, tier=tier,
                )
                detail = {"deny": "hitl_required", "reason": reason}
                _attach_signature(detail, signed, marker)
                raise HTTPException(status_code=403, detail=detail) from None
        if effective_hitl is not None:
            ok, reason = check_hitl(envelope_dict, effective_hitl, motion=is_motion)
            if not ok:
                signed, marker = _record(
                    "deny",
                    f"hitl_required: {reason}",
                    manifest_result.kid,
                    envelope.msg_id,
                    envelope_dict=envelope_dict, ruri=envelope.ruri,
                    rrn=manifest_rrn, started_at=started_at, caller=caller, tier=tier,
                )
                detail = {"deny": "hitl_required", "reason": reason}
                _attach_signature(detail, signed, marker)
                raise HTTPException(status_code=403, detail=detail)

        # All gates passed — pick the actuator. In multi-actuator mode, route
        # by `envelope.actuator_name`. In single-actuator mode, use the one
        # configured at make_app time. Routing failures are 4xx (parser-level)
        # and not audited; gate failures above are audit-tracked.
        if multi_actuator_mode:
            # An explicit name always wins: a client that knows which actuator
            # it means is never second-guessed.
            if envelope.actuator_name is not None:
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
                # NO NAME: ROUTE BY WHICH ACTUATOR DECLARES THE TOOL.
                #
                # This used to be a flat 422, and that made turning on a second
                # actuator a BREAKING CHANGE for every existing client — an
                # operator adding a host actuator to a working robot would find
                # every arm and drive command refused at the parser, before any
                # gate ran, and routing failures are not audited so there would
                # not even be a receipt saying why. The upgrade path was "change
                # all your clients first", which nobody discovers until after.
                #
                # Actuators already declare their capabilities, and those sets
                # are disjoint in every real deployment (an arm driver does not
                # implement host.package.install). So the name is only actually
                # needed to break a TIE, and that is the only case left that
                # refuses.
                # `rcan_tools`, NOT `capabilities`. The existing attribute
                # already means different things in different actuators: the
                # rc-car driver lists RCAN tool names, while the so-arm101
                # driver lists internal verbs ("move", "home", "read_state").
                # Routing on it would be guessing at a vocabulary that is not
                # guaranteed to be tool names — and on this bench it guessed
                # wrong and 422'd every arm command. A new, single-purpose
                # attribute is an explicit OPT-IN whose meaning cannot drift.
                candidates = [
                    (name, act) for name, act in sorted(actuators.items())
                    if envelope.tool_name in getattr(act, "rcan_tools", ())
                ]
                if not candidates:
                    # NOTHING CLAIMS THE TOOL, SO FALL BACK TO WHATEVER CANNOT
                    # BE RULED OUT. An actuator that has not opted in — every
                    # actuator written before `rcan_tools` existed, which today
                    # is all of them but the host one — has made no claim about
                    # what it does NOT handle, so it stays a candidate for
                    # anything.
                    #
                    # Found by testing the regression rather than the feature:
                    # adding the host actuator to Bob broke `status.report` with
                    # a 422, which is exactly the breakage this whole branch
                    # exists to prevent. An actuator that declares its
                    # capabilities is only offered what it declares; one that
                    # declares nothing is the catch-all.
                    candidates = [
                        (name, act) for name, act in sorted(actuators.items())
                        if not getattr(act, "rcan_tools", ())
                    ]
                if len(candidates) == 1:
                    chosen, target_actuator = candidates[0]
                    target_config = actuator_configs.get(chosen, {})
                elif not candidates:
                    # Unchanged from before: inference simply did not apply.
                    # NOT a 404 — an actuator is free to declare no capabilities
                    # at all (the built-in no-op does, and third-party ones may),
                    # and "nothing advertises this tool" is indistinguishable
                    # from "nothing advertises anything". Turning that into "no
                    # such tool" would break working deployments on an inference
                    # that was never available to them.
                    raise HTTPException(status_code=422, detail={
                        "deny": "actuator_name_required",
                        "reason": "gateway is configured for multiple actuators "
                                  "and none declares this tool; envelope must "
                                  "set actuator_name",
                        "known": sorted(actuators.keys()),
                    })
                else:
                    raise HTTPException(status_code=422, detail={
                        "deny": "actuator_name_required",
                        "reason": f"{len(candidates)} actuators declare "
                                  f"{envelope.tool_name!r}; envelope must set "
                                  f"actuator_name to choose one",
                        "candidates": [name for name, _ in candidates],
                    })
        else:
            target_actuator = actuator
            target_config = actuator_config

        # The stop that passed the safety state above must be a stop for the
        # actuator that receives it. `arm.estop` is the arm's stop; routed to a
        # camera that declares no such stop, it is just a tool, and a tripped
        # gateway refuses it like any other.
        if stop_past_safety_state and envelope.tool_name not in as_tool_set(
            getattr(target_actuator, "stop_capabilities", None)
        ):
            reason = (
                f"gateway state={safety_monitor.state.value}; {envelope.tool_name} "
                f"is not a declared stop of actuator {target_actuator.name!r}"
            )
            signed, marker = _record(
                "deny", f"safety_state: {reason}", manifest_result.kid, envelope.msg_id,
                envelope_dict=envelope_dict, ruri=envelope.ruri,
                rrn=manifest_rrn, started_at=started_at, caller=caller, tier=tier,
            )
            detail = {"deny": "safety_state", "reason": reason}
            _attach_signature(detail, signed, marker)
            raise HTTPException(status_code=403, detail=detail)

        return _dispatch(
            envelope_dict=envelope_dict, msg_id=envelope.msg_id, ruri=envelope.ruri,
            scope=envelope.scope, tool_name=envelope.tool_name,
            target_actuator=target_actuator, target_config=target_config,
            manifest_path=Path(envelope.manifest_path), kid=manifest_result.kid,
            rrn=manifest_rrn, tier=tier, caller=caller, started_at=started_at,
        )

    @app.post("/v1/invoke")
    async def invoke(
        envelope_dict: dict = Body(...),
        authorization: str | None = Header(default=None),
    ):
        # The work is synchronous (signatures, the audit chain, the actuator)
        # and runs on a worker thread, as it did when this handler was a plain
        # `def`. A stop runs on threads of its own: FastAPI's shared pool is
        # first-come-first-served, so a burst of polls each holding a thread
        # left a stop queued behind them (5.9 s late under 120 looping
        # clients, found in EV-03's review). Nothing about the stop's checks
        # changes; only which threads it waits for.
        tool = envelope_dict.get("tool_name")
        limiter = _stop_limiter() if isinstance(tool, str) and tool in _stop_tools else None
        return await anyio.to_thread.run_sync(_invoke, envelope_dict, authorization,
                                              limiter=limiter)

    @app.get("/v1/audit/last")
    def audit_last(authorization: str | None = Header(default=None)):
        # Auth: require a valid bearer mapped to a known tier (any tier OK
        # for read-only access — operator chooses tier-tightening via bearers).
        if authorization is None or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing Authorization header")
        token = authorization[7:]
        if token not in _bearer_index:
            raise HTTPException(status_code=403, detail="unknown bearer")

        if audit_chain is None or not audit_chain.entries:
            raise HTTPException(status_code=404, detail="audit chain empty")
        last = audit_chain.entries[-1]
        return last.__dict__

    def _known_principal(authorization: str | None) -> tuple[str, str | None]:
        """(tier, caller) for a bearer this gateway knows; 401/403 otherwise,
        the same answers /v1/audit/last gives. Never anon: an unauthenticated
        heartbeat would let anyone who can reach the port keep a robot movable,
        and over Tailscale Funnel that is anyone at all."""
        if authorization is None or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing Authorization header")
        principal = _bearer_index.get(authorization[7:])
        if principal is None:
            raise HTTPException(status_code=403, detail="unknown bearer")
        return principal

    def _require_monitor() -> SafetyMonitor:
        if safety_monitor is None:
            raise HTTPException(status_code=404, detail="this gateway runs no safety monitor")
        return safety_monitor

    @app.post("/v1/safety/heartbeat")
    async def safety_heartbeat(authorization: str | None = Header(default=None)):
        """SF-002's heartbeat: send at least once per `heartbeat_staleness_s`
        (3 s), from the supervisor's device. Accepted ONLY from a supervisor
        credential (`role: supervisor`), which cannot move the robot; every
        credential that can is refused, so the agent being supervised can never
        keep its own heartbeat alive. It only keeps a READY gateway READY: it
        never resumes a tripped one. Runs on the event loop, not the worker
        pool, so a flood of blocking requests does not starve it.

        A heartbeat is answered 503, never 200, while the safety watchdog is not
        ticking, and that same check puts the gateway in SAFE_STOP: a supervisor
        must never be told all is well by a gateway that has stopped enforcing.
        """
        tier, caller = _known_principal(authorization)
        monitor = _require_monitor()
        if authorization[7:] not in _supervisors:
            raise HTTPException(status_code=403, detail={
                "deny": "not_a_supervisor",
                "reason": "heartbeats are accepted only from a supervisor credential "
                          "(role: supervisor in bearers.yaml), which cannot move the "
                          f"robot; this credential holds the {tier} tier",
            })
        if _watchdog_stuck():
            state = _safety_check()        # fails closed: SAFE_STOP, and the stops go out
            raise HTTPException(status_code=503, detail={
                "deny": "safety_watchdog",
                "reason": f"the safety watchdog has not ticked for over "
                          f"{WATCHDOG_STALE_S:g} s; the gateway is in {state.value}",
            })
        now = clock()
        monitor.on_heartbeat(now=now)
        _safety.last_heartbeat = (caller, now)
        return {"state": monitor.state.value,
                "heartbeat_staleness_s": monitor.heartbeat_staleness_s}

    @app.post("/v1/safety/clear")
    def safety_clear(authorization: str | None = Header(default=None)):
        """The operator's resume signal, after a safe-stop or an ESTOP.

        Conditions, in the order they are checked, all under the safety lock:
        - Any trip not yet acted on is acted on first: its stops are sent before
          anything is cleared. While a stop of the last trip has neither
          answered nor timed out, the clear is refused with 409 (finding 5).
        - While the safety watchdog is not ticking, it is refused with 503.
        - Recovery needs FRESH heartbeats (the pendant integration spec's rule):
          a clear sent into a silence is refused rather than allowed to drop
          straight back into SAFE_STOP on the next tick.
        - SafetyMonitor.clear needs the `commission` tier.

        Allowed or refused, it is recorded like any other decision: the audit
        chain, a signed receipt on the response, and a line in the export.

        It restores the gateway's state only. Each actuator keeps its own latch
        (so-arm101-actuator: `arm.estop.clear`, commission tier), so a resume is
        two explicit acts.
        """
        tier, caller = _known_principal(authorization)
        monitor = _require_monitor()
        msg_id = f"safety-clear-{uuid.uuid4().hex[:12]}"
        started_at = datetime.now(tz=timezone.utc).isoformat()
        records: list = []
        status = 200
        with _safety_lock:
            _observe_locked(records)
            _advance_locked(records)
            trip = _safety.trip
            age = clock() - monitor.last_heartbeat_at
            if trip is not None and not trip.settled():
                waiting = ", ".join(f"{s.tool} to {s.name}" for s in trip.sends
                                    if s.status not in ("done", "timed_out"))
                status, reason = 409, (
                    f"safety.clear: refused, the stop for trip {trip.seq} is still being "
                    f"sent ({waiting}); retry once it has answered"
                )
            elif _watchdog_stuck():
                status, reason = 503, (
                    f"safety.clear: refused, the safety watchdog has not ticked for over "
                    f"{WATCHDOG_STALE_S:g} s"
                )
            elif age > monitor.heartbeat_staleness_s:
                status, reason = 403, (
                    f"safety.clear: refused, the last heartbeat was {age:.1f} s ago "
                    f"(limit {monitor.heartbeat_staleness_s:g} s); send heartbeats, "
                    f"then clear"
                )
            else:
                cleared, reason = monitor.clear(tier=tier, msg_id=msg_id, caller=caller)
                if cleared:
                    _safety.seen = monitor.state
                    _safety.trip = None
                else:
                    status = 403
        _write_safety_records(records)
        signed, marker = _record(
            "allow" if status == 200 else "deny", reason, None, msg_id,
            envelope_dict={"msg_id": msg_id, "type": "ESTOP_CLEAR"}, ruri=None,
            rrn=_pinned_rrn, started_at=started_at, caller=caller, tier=tier,
        )
        if status != 200:
            detail = {"deny": "safety_clear", "reason": reason, "state": monitor.state.value}
            _attach_signature(detail, signed, marker)
            raise HTTPException(status_code=status, detail=detail)
        response = {"state": monitor.state.value, "reason": reason}
        _attach_signature(response, signed, marker)
        return response

    return app
