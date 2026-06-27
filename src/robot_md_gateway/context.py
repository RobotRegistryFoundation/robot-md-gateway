"""RCAN invoke ``context`` — resolve a robot's compliance-recall identity
dimensions (parts / model / harness) from its ROBOT.md manifest, for stamping
into the SIGNED ``invoke`` envelope so PlatAtlas can index "every action by
RRN-X that engaged RCN-P, ran on RMN-M / RHN-H".

The context dict goes INTO the invoke body *before* ``cert.envelope.sign_envelope``
(or any signer over ``canonical_json``), so the existing canonical signature
covers it with NO signing change — proven by the round-trip test. Shape matches
the PlatAtlas index (proxy-worker ``action_context``)::

    {"rrn", "rcns": [...], "rmn", "rhn", "config_hash", "confidence"}

Honesty: only DECLARED ids are included; an absent field is omitted, never
guessed; an ``active_rhn`` not declared in the manifest is never stamped.
``context_from_manifest`` returns ``None`` when nothing is declared, so the
caller simply omits ``context`` (the trace carries no provenance to over-claim).
"""

from __future__ import annotations

import hashlib
from typing import Any

from rcan.audit_bundle import canonical_json


def config_hash_for(frontmatter: dict[str, Any]) -> str:
    """Stable ``sha256:<hex>`` over the canonical manifest — proves WHICH config
    was live at action time, even if the manifest later changes."""
    digest = hashlib.sha256(canonical_json(frontmatter)).hexdigest()
    return f"sha256:{digest}"


def context_from_manifest(
    frontmatter: dict[str, Any],
    *,
    config_hash: str | None = None,
    confidence: float | None = None,
    active_rhn: str | None = None,
) -> dict[str, Any] | None:
    """Build the signed-invoke ``context`` from ROBOT.md ``metadata``.

    Reads ``metadata.{rrn, rcn_ids[], rmn, rhn_ids[]}``. ``active_rhn`` selects
    which declared harness actually executed (defaults to the first ``rhn_ids``
    entry); an ``active_rhn`` not present in ``rhn_ids`` is rejected — we never
    stamp an undeclared harness. Returns ``None`` when no identity dimension is
    declared, so the caller omits ``context`` entirely.
    """
    meta = (frontmatter or {}).get("metadata") or {}

    rrn = meta.get("rrn")
    rcns = [r for r in (meta.get("rcn_ids") or []) if isinstance(r, str) and r]
    rmn = meta.get("rmn")
    rhn_ids = [h for h in (meta.get("rhn_ids") or []) if isinstance(h, str) and h]

    if active_rhn is not None and rhn_ids and active_rhn not in rhn_ids:
        active_rhn = None  # honesty: never stamp a harness the manifest didn't declare
    rhn = active_rhn or (rhn_ids[0] if rhn_ids else None)

    ctx: dict[str, Any] = {}
    if isinstance(rrn, str) and rrn:
        ctx["rrn"] = rrn
    if rcns:
        ctx["rcns"] = rcns
    if isinstance(rmn, str) and rmn:
        ctx["rmn"] = rmn
    if isinstance(rhn, str) and rhn:
        ctx["rhn"] = rhn
    # context is meaningful only with an IDENTITY dimension — a config_hash /
    # confidence alone names nothing to recall (and PlatAtlas drops such a block).
    if not any(k in ctx for k in ("rrn", "rcns", "rmn", "rhn")):
        return None
    if config_hash:
        ctx["config_hash"] = config_hash
    if confidence is not None:
        ctx["confidence"] = float(confidence)
    return ctx


def with_context(
    invoke_body: dict[str, Any],
    frontmatter: dict[str, Any],
    *,
    confidence: float | None = None,
    active_rhn: str | None = None,
    stamp_config_hash: bool = True,
) -> dict[str, Any]:
    """Attach ``context`` to an ``invoke`` body (in place) BEFORE it is signed.

    Convenience over ``context_from_manifest`` that also stamps a ``config_hash``
    from the manifest by default. No-op (no ``context`` key) when the manifest
    declares no identity dimension. Returns the same dict for chaining into
    ``sign_envelope(priv, with_context(body, fm), kid)``.
    """
    cfg = config_hash_for(frontmatter) if stamp_config_hash else None
    ctx = context_from_manifest(
        frontmatter, config_hash=cfg, confidence=confidence, active_rhn=active_rhn,
    )
    if ctx is not None:
        invoke_body["context"] = ctx
    return invoke_body
