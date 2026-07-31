"""Tool allowlist + tier policy for cert properties GW-002 / GW-003."""

from __future__ import annotations

from dataclasses import dataclass

from . import report as cert_report


@dataclass(frozen=True)
class ToolAllowlist:
    """Default-deny tool allowlist. Operator policy lists tools that may be invoked.

    Anything not on the list is denied before any driver code runs.
    """
    allowed_tools: tuple[str, ...]

    def is_allowed(self, tool_name: str) -> bool:
        return tool_name in self.allowed_tools


def check_tool(tool_name: str, allowlist: ToolAllowlist, *, msg_id: str) -> tuple[bool, str]:
    if allowlist.is_allowed(tool_name):
        cert_report.record_property_pass(
            property_id="GW-002",
            evidence={"tool_name": tool_name, "msg_id": msg_id, "outcome": "allowed"},
        )
        return True, "ok"
    cert_report.record_property_pass(
        property_id="GW-002",
        evidence={"tool_name": tool_name, "msg_id": msg_id, "outcome": "denied (not in allowlist)"},
    )
    return False, f"tool {tool_name} not in operator allowlist"


# Scopes that move/alter the robot. COMMISSION covers the bring-up ops
# (raw_tick_move / commission_probe / set_torque / paced_move) — actuation-class, so
# read-tier is denied, AND it additionally requires the dedicated `commission` tier so
# the risky reality-check/teach motion sits behind its own bearer, not the general
# `actuate` one.
ACTUATION_SCOPES = {"MANIPULATE", "NAVIGATE", "ACTUATE", "EXECUTE", "COMMISSION"}


# Tiers that carry no actuation credential. `anon` is the receiver's fallback for
# a request with no bearer OR an unknown/insufficient bearer — it must be denied
# actuation just like `read` (fixing an anon fail-open where COMMAND-class scopes
# slipped through). Read/discover on non-actuation scopes stays open for both.
NON_ACTUATING_TIERS = {"read", "anon"}


def check_tool_tier(
    tool_name: str, tier: str, requirements: dict[str, frozenset[str]], *, msg_id: str
) -> tuple[bool, str]:
    """Bind the caller's tier to the TOOL, not to the envelope's scope.

    ``check_tier`` keys off ``scope``, which is a caller-supplied string, and
    ``check_tool`` never sees the tier — so an envelope naming an actuating tool
    while declaring ``scope: "OBSERVE"`` satisfies both gates. Operators close
    that by declaring, per tool, which tiers may invoke it; the mapping is
    operator-controlled and cannot be influenced by envelope contents.

    Tools absent from ``requirements`` are unconstrained here (the allowlist and
    scope gates still apply), so this is additive to existing deployments.

    Deliberately records no cert property: the Track 2 property set is fixed by
    the spec, and this is deployment policy rather than a certified property.
    Denials are still audited and signed by the receiver like any other gate.
    """
    required = requirements.get(tool_name)
    if required is None or tier in required:
        return True, "ok"
    return False, (
        f"{tier}-tier principal cannot invoke tool {tool_name} "
        f"(requires one of {sorted(required)})"
    )


def check_tier(tier: str, scope: str, *, msg_id: str) -> tuple[bool, str]:
    """GW-003 — read/anon principals denied actuation; COMMISSION needs the commission tier."""
    if tier in NON_ACTUATING_TIERS and scope in ACTUATION_SCOPES:
        cert_report.record_property_pass(
            property_id="GW-003",
            evidence={"tier": tier, "scope": scope, "msg_id": msg_id, "outcome": "denied"},
        )
        return False, f"{tier}-tier principal cannot invoke {scope}"
    if scope == "COMMISSION" and tier != "commission":
        cert_report.record_property_pass(
            property_id="GW-003",
            evidence={"tier": tier, "scope": scope, "msg_id": msg_id,
                      "outcome": "denied (commission tier required)"},
        )
        return False, f"scope COMMISSION requires the 'commission' tier, not {tier!r}"
    cert_report.record_property_pass(
        property_id="GW-003",
        evidence={"tier": tier, "scope": scope, "msg_id": msg_id, "outcome": "allowed"},
    )
    return True, "ok"
