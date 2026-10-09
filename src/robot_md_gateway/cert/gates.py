"""Confidence + HiTL gates (RC-003, RC-004)."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import report as cert_report


@dataclass(frozen=True)
class ConfidencePolicy:
    """Per-scope confidence thresholds. Below threshold → deny."""
    thresholds: dict[str, float] = field(default_factory=lambda: {
        "READ": 0.5,
        "NAVIGATE": 0.85,
        "MANIPULATE": 0.90,
        "ESTOP": 0.50,  # ESTOP intentionally low — emergency actions always considered
    })

    def threshold_for(self, scope: str, *, motion: bool = False) -> float:
        """The threshold for ``scope`` (any case). For a tool that moves the
        robot, the strictest threshold of any motion scope applies as well, so
        relabelling a manipulation NAVIGATE cannot buy a lower bar."""
        key = scope.upper() if isinstance(scope, str) else scope
        threshold = self.thresholds.get(key, 0.95)  # default-strict for unknown scopes
        if motion:
            from .policy import MOTION_SCOPES

            threshold = max([threshold, *(self.thresholds[s] for s in MOTION_SCOPES
                                          if s in self.thresholds)])
        return threshold


def check_confidence(envelope: dict, policy: ConfidencePolicy, *, motion: bool = False
                     ) -> tuple[bool, str]:
    confidence = envelope.get("payload", {}).get("inference_confidence")
    if confidence is None:
        cert_report.record_property(
            property_id="RC-003",
            outcome="fail",
            evidence={"msg_id": envelope.get("msg_id"), "scope": envelope.get("scope"),
                      "outcome": "denied (missing inference_confidence)"},
        )
        return False, "envelope payload missing inference_confidence"
    threshold = policy.threshold_for(envelope.get("scope", "UNKNOWN"), motion=motion)
    if confidence < threshold:
        cert_report.record_property(
            property_id="RC-003",
            outcome="fail",
            evidence={
                "msg_id": envelope.get("msg_id"),
                "scope": envelope.get("scope"),
                "confidence": confidence,
                "threshold": threshold,
                "outcome": "denied (below threshold)",
            },
        )
        return False, (
            f"confidence {confidence} below threshold {threshold} "
            f"for scope {envelope.get('scope')}"
        )
    cert_report.record_property(
        property_id="RC-003",
        outcome="pass",
        evidence={"msg_id": envelope.get("msg_id"), "scope": envelope.get("scope"),
                  "confidence": confidence, "threshold": threshold, "outcome": "allowed"},
    )
    return True, "ok"


# RC-004 — HiTL authorization chain

# Maps a manifest `safety.hitl_gates[].scope` value to the RCAN invoke scope(s) it
# governs. The manifest speaks in operator terms (destructive/system/commission); the
# gate chain speaks in RCAN scopes (MANIPULATE/EXECUTE/ACTUATE/COMMISSION).
_MANIFEST_GATE_SCOPE_MAP: dict[str, frozenset[str]] = {
    "destructive": frozenset({"MANIPULATE"}),
    "system": frozenset({"EXECUTE", "ACTUATE"}),
    "commission": frozenset({"COMMISSION"}),
}


@dataclass(frozen=True)
class HiTLPolicy:
    """Scopes that require human-in-the-loop authorization.

    Default mirrors the historical hardcoded behaviour ({MANIPULATE}). Prefer
    `from_manifest_gates` so the manifest's declared `safety.hitl_gates` are
    authoritative instead of a hardcoded set (wired behind a flag in make_app).
    """
    required_for_scopes: frozenset[str] = frozenset({"MANIPULATE"})

    def requires(self, scope: object, *, motion: bool = False) -> bool:
        """Whether ``scope`` (any case) needs a HiTL chain. For a tool that moves
        the robot, HiTL on ANY motion scope means HiTL on all of them: the scope
        is caller-written, and a gate on MANIPULATE that NAVIGATE walks past is
        not a gate."""
        key = scope.upper() if isinstance(scope, str) else scope
        if key in self.required_for_scopes:
            return True
        if motion:
            from .policy import MOTION_SCOPES

            return bool(self.required_for_scopes & MOTION_SCOPES)
        return False

    @classmethod
    def from_manifest_gates(cls, gates: list[dict] | None) -> "HiTLPolicy":
        """Build a policy from a manifest's `safety.hitl_gates`. Only gates with
        `require_auth: true` contribute; their `scope` is mapped to RCAN scope(s).
        Unrecognized gate scopes are ignored (surfaced elsewhere as a gate-gap)."""
        scopes: set[str] = set()
        for gate in gates or []:
            if not gate.get("require_auth"):
                continue
            scopes |= _MANIFEST_GATE_SCOPE_MAP.get(gate.get("scope", ""), frozenset())
        return cls(required_for_scopes=frozenset(scopes))


def check_hitl(envelope: dict, policy: HiTLPolicy, *, motion: bool = False) -> tuple[bool, str]:
    scope = envelope.get("scope", "")
    if not policy.requires(scope, motion=motion):
        cert_report.record_property(
            property_id="RC-004",
            outcome="pass",
            evidence={"msg_id": envelope.get("msg_id"), "scope": scope, "outcome": "not required"},
        )
        return True, "ok (not required)"
    chain = envelope.get("delegation_chain", [])
    if not chain:
        cert_report.record_property(
            property_id="RC-004",
            outcome="fail",
            evidence={
                "msg_id": envelope.get("msg_id"),
                "scope": scope,
                "outcome": "denied (no HiTL chain)",
            },
        )
        return False, f"scope {scope} requires HiTL but envelope has no delegation_chain"
    last = chain[-1]
    last_scope = last.get("scope")
    if not (isinstance(last_scope, str) and isinstance(scope, str)
            and last_scope.upper() == scope.upper()):
        cert_report.record_property(
            property_id="RC-004",
            outcome="fail",
            evidence={"msg_id": envelope.get("msg_id"), "scope": scope,
                      "chain_final_scope": last.get("scope"),
                      "outcome": "denied (delegation_chain final scope mismatch)"},
        )
        return False, (
            f"HiTL delegation_chain final scope {last.get('scope')} ≠ "
            f"requested scope {scope}"
        )
    if not last.get("human_subject"):
        cert_report.record_property(
            property_id="RC-004",
            outcome="fail",
            evidence={"msg_id": envelope.get("msg_id"), "scope": scope,
                      "outcome": "denied (delegation_chain missing human_subject)"},
        )
        return False, "HiTL delegation_chain missing human_subject"
    cert_report.record_property(
        property_id="RC-004",
        outcome="pass",
        evidence={
            "msg_id": envelope.get("msg_id"),
            "scope": scope,
            "human": last.get("human_subject"),
            "outcome": "allowed",
        },
    )
    return True, "ok"
