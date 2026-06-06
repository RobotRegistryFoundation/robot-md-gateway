"""U1a producer logic: signing identity, outcome builder, status map, trace wrapper.

Pure functions + one dataclass; no FastAPI. The receiver imports these and the
__main__ serve path loads the identity from env. Absence of the identity disables
attestation (the gateway still runs as verifier).
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from rcan.audit_bundle import canonical_json

from .actuator import ActuatorOutcome

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SigningIdentity:
    """The gateway's persistent attestation identity (Ed25519 only at runtime)."""

    priv: Ed25519PrivateKey
    kid: str
    ran: str | None


def load_signing_identity_from_env() -> SigningIdentity | None:
    """Load the attestation identity from ROBOT_MD_ATTESTATION_* env vars.

    Requires ROBOT_MD_ATTESTATION_KEY_FILE (path to an Ed25519 PKCS8 PEM private
    key) and ROBOT_MD_ATTESTATION_KID. ROBOT_MD_ATTESTATION_RAN is optional
    (traceability/logging only). Any missing/invalid input -> returns None and
    logs a WARNING ("attestation disabled"); the gateway keeps running as verifier.
    """
    key_file = os.environ.get("ROBOT_MD_ATTESTATION_KEY_FILE")
    kid = os.environ.get("ROBOT_MD_ATTESTATION_KID")
    ran = os.environ.get("ROBOT_MD_ATTESTATION_RAN")
    if not key_file or not kid:
        logger.warning(
            "attestation disabled: ROBOT_MD_ATTESTATION_KEY_FILE and "
            "ROBOT_MD_ATTESTATION_KID must both be set (gateway runs verifier-only)"
        )
        return None
    path = Path(key_file)
    if not path.exists():
        logger.warning("attestation disabled: key file %s not found", key_file)
        return None
    try:
        priv = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (ValueError, OSError) as exc:
        logger.warning("attestation disabled: cannot load key file %s: %s", key_file, exc)
        return None
    if not isinstance(priv, Ed25519PrivateKey):
        logger.warning(
            "attestation disabled: key file %s is not an Ed25519 private key", key_file
        )
        return None
    logger.info("attestation enabled: kid=%s ran=%s", kid, ran or "<unset>")
    return SigningIdentity(priv=priv, kid=kid, ran=ran)


def outcome_status(*, decision: str, success: bool | None, error_kind: str | None) -> str:
    """Map a gateway decision to an S3 status enum value (§3.5).

    deny (any gate)            -> "denied"
    allow + success            -> "ok"
    allow + clean failure      -> "failure"   (success is False, no exception)
    allow + exception          -> "error"     (error_kind set)
    timeout has no wrapper in v1 and surfaces as "error".
    """
    if decision == "deny":
        return "denied"
    if success:
        return "ok"
    if error_kind is not None:
        return "error"
    return "failure"


def telemetry_sha256_of(outcome: ActuatorOutcome | None) -> str | None:
    """sha256 of the actuator telemetry, matching receiver.py's audit recipe.

    If ``telemetry_path`` is set (even if the file does not exist), the path
    branch is taken: hash file bytes when the file exists, else return None.
    Only when ``telemetry_path`` is None does the in-memory branch run:
    canonical JSON of the ``telemetry`` dict. This mirrors the elif structure
    in receiver.py (lines 191-202) so the signed value equals the audit value.
    """
    if outcome is None:
        return None
    if outcome.telemetry_path is not None:
        if outcome.telemetry_path.exists():
            return hashlib.sha256(outcome.telemetry_path.read_bytes()).hexdigest()
        return None
    elif outcome.telemetry:
        return hashlib.sha256(canonical_json(outcome.telemetry)).hexdigest()
    return None


def build_action_trace(*, invoke: dict, outcome: dict, ruri: str | None, rrn: str) -> dict:
    """Wrap the verified invoke + signed outcome in an rcan-action-trace/1 record (§3.7).

    The invoke is passed verbatim (the raw verified envelope). corr_id is taken
    from invoke.msg_id; ruri/rrn are top-level hints S3 checks against the signed
    fields (binding_ok).
    """
    return {
        "v": "rcan-action-trace/1",
        "invoke": invoke,
        "outcome": outcome,
        "corr_id": invoke.get("msg_id"),
        "ruri": ruri,
        "rrn": rrn,
    }


def build_outcome(
    *,
    corr_id: str,
    rrn: str,
    status: str,
    started_at: str,
    ended_at: str,
    duration_ms: int | None,
    telemetry_sha256: str | None,
    error: dict | None,
    result_summary: str | None,
) -> dict:
    """Build the flat outcome payload (§3.4), WITHOUT envelope_signature.

    Required fields are always present. Optional fields are omitted when None so
    the signed shape stays clean (the absence of a field is signed, not a null).
    The caller signs the returned dict with sign_envelope(priv, outcome, kid).
    """
    outcome: dict = {
        "corr_id": corr_id,
        "rrn": rrn,
        "status": status,
        "started_at": started_at,
        "ended_at": ended_at,
    }
    if duration_ms is not None:
        outcome["duration_ms"] = duration_ms
    if telemetry_sha256 is not None:
        outcome["telemetry_sha256"] = telemetry_sha256
    if error is not None:
        outcome["error"] = error
    if result_summary is not None:
        outcome["result_summary"] = result_summary
    return outcome
