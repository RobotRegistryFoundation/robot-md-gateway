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


def check_tier(tier: str, scope: str, *, msg_id: str) -> tuple[bool, str]:
    """GW-003 — read-tier principal denied actuation."""
    READ_ONLY_SCOPES = {"READ", "OBSERVE", "STATUS"}  # noqa: F841
    ACTUATION_SCOPES = {"MANIPULATE", "NAVIGATE", "ACTUATE", "EXECUTE"}
    if tier == "read" and scope in ACTUATION_SCOPES:
        cert_report.record_property_pass(
            property_id="GW-003",
            evidence={"tier": tier, "scope": scope, "msg_id": msg_id, "outcome": "denied"},
        )
        return False, f"read-tier principal cannot invoke {scope}"
    cert_report.record_property_pass(
        property_id="GW-003",
        evidence={"tier": tier, "scope": scope, "msg_id": msg_id, "outcome": "allowed"},
    )
    return True, "ok"
