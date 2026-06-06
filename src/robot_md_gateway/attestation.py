"""U1a producer logic: signing identity, outcome builder, status map, trace wrapper.

Pure functions + one dataclass; no FastAPI. The receiver imports these and the
__main__ serve path loads the identity from env. Absence of the identity disables
attestation (the gateway still runs as verifier).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
