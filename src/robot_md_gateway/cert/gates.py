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

    def threshold_for(self, scope: str) -> float:
        return self.thresholds.get(scope, 0.95)  # default-strict for unknown scopes


def check_confidence(envelope: dict, policy: ConfidencePolicy) -> tuple[bool, str]:
    confidence = envelope.get("payload", {}).get("inference_confidence")
    if confidence is None:
        cert_report.record_property_pass(
            property_id="RC-003",
            evidence={"msg_id": envelope.get("msg_id"), "scope": envelope.get("scope"),
                      "outcome": "denied (missing inference_confidence)"},
        )
        return False, "envelope payload missing inference_confidence"
    threshold = policy.threshold_for(envelope.get("scope", "UNKNOWN"))
    if confidence < threshold:
        cert_report.record_property_pass(
            property_id="RC-003",
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
    cert_report.record_property_pass(
        property_id="RC-003",
        evidence={"msg_id": envelope.get("msg_id"), "scope": envelope.get("scope"),
                  "confidence": confidence, "threshold": threshold, "outcome": "allowed"},
    )
    return True, "ok"


# RC-004 — HiTL authorization chain
@dataclass(frozen=True)
class HiTLPolicy:
    """Scopes that require human-in-the-loop authorization."""
    required_for_scopes: frozenset[str] = frozenset({"MANIPULATE"})


def check_hitl(envelope: dict, policy: HiTLPolicy) -> tuple[bool, str]:
    scope = envelope.get("scope", "")
    if scope not in policy.required_for_scopes:
        cert_report.record_property_pass(
            property_id="RC-004",
            evidence={"msg_id": envelope.get("msg_id"), "scope": scope, "outcome": "not required"},
        )
        return True, "ok (not required)"
    chain = envelope.get("delegation_chain", [])
    if not chain:
        cert_report.record_property_pass(
            property_id="RC-004",
            evidence={
                "msg_id": envelope.get("msg_id"),
                "scope": scope,
                "outcome": "denied (no HiTL chain)",
            },
        )
        return False, f"scope {scope} requires HiTL but envelope has no delegation_chain"
    last = chain[-1]
    if last.get("scope") != scope:
        cert_report.record_property_pass(
            property_id="RC-004",
            evidence={"msg_id": envelope.get("msg_id"), "scope": scope,
                      "chain_final_scope": last.get("scope"),
                      "outcome": "denied (delegation_chain final scope mismatch)"},
        )
        return False, (
            f"HiTL delegation_chain final scope {last.get('scope')} ≠ "
            f"requested scope {scope}"
        )
    if not last.get("human_subject"):
        cert_report.record_property_pass(
            property_id="RC-004",
            evidence={"msg_id": envelope.get("msg_id"), "scope": scope,
                      "outcome": "denied (delegation_chain missing human_subject)"},
        )
        return False, "HiTL delegation_chain missing human_subject"
    cert_report.record_property_pass(
        property_id="RC-004",
        evidence={
            "msg_id": envelope.get("msg_id"),
            "scope": scope,
            "human": last.get("human_subject"),
            "outcome": "allowed",
        },
    )
    return True, "ok"
