"""MF-003 — RRN binding.

Binds the invoke envelope's identity to the robot's registered RRN. The envelope's
`ruri` is the RRN-host form (`rcan://RRN-.../...`, as the CLI signer emits); the
manifest declares its identity in `metadata.rrn`. Mismatch ⇒ fail-closed (403): a
correctly-signed envelope for robot A must not actuate robot B.

NOTE: compare the ENVELOPE ruri's RRN against the manifest's `metadata.rrn` field —
NOT the manifest's own `metadata.ruri`, whose host is the RRF domain + robot slug
(e.g. `rcan://robotregistryfoundation.org/<slug>`), not an RRN.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from . import report as cert_report

_RRN_HOST_RE = re.compile(r"^rcan://(?P<rrn>RRN-[A-Za-z0-9]+)(?:/|$)")


@dataclass(frozen=True)
class RrnBindingResult:
    accepted: bool
    envelope_rrn: str | None
    manifest_rrn: str | None
    reason: str


def rrn_from_ruri(ruri: str | None) -> str | None:
    """Extract the RRN host from an envelope `rcan://RRN-.../...` ruri, or None."""
    if not ruri:
        return None
    m = _RRN_HOST_RE.match(ruri)
    return m.group("rrn") if m else None


def rrn_from_manifest(path: str | Path) -> str | None:
    """Read `metadata.rrn` from a ROBOT.md's YAML frontmatter (first `---` block)."""
    text = Path(path).read_text()
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    fm = yaml.safe_load(text[3:end]) or {}
    # Canonical location is metadata.rrn; some manifests/fixtures declare it top-level.
    rrn = (fm.get("metadata") or {}).get("rrn") or fm.get("rrn")
    return str(rrn) if rrn else None


def verify_rrn_binding(envelope_ruri: str | None, manifest_rrn: str | None, *, msg_id: str = "") -> RrnBindingResult:
    """Fail-closed unless the envelope's RRN host matches the manifest's metadata.rrn."""
    env_rrn = rrn_from_ruri(envelope_ruri)

    def _deny(reason: str) -> RrnBindingResult:
        cert_report.record_property_pass(
            property_id="MF-003",
            evidence={"msg_id": msg_id, "envelope_rrn": env_rrn,
                      "manifest_rrn": manifest_rrn, "outcome": f"denied ({reason})"},
        )
        return RrnBindingResult(False, env_rrn, manifest_rrn, reason)

    if env_rrn is None:
        return _deny("envelope ruri has no RRN host (expected rcan://RRN-.../...)")
    if not manifest_rrn:
        return _deny("manifest declares no metadata.rrn")
    if env_rrn != manifest_rrn:
        return _deny(f"envelope RRN {env_rrn} != manifest RRN {manifest_rrn}")

    cert_report.record_property_pass(
        property_id="MF-003",
        evidence={"msg_id": msg_id, "envelope_rrn": env_rrn,
                  "manifest_rrn": manifest_rrn, "outcome": "allowed"},
    )
    return RrnBindingResult(True, env_rrn, manifest_rrn, "ok")
