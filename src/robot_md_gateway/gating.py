from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal

from .auth import AuthContext, Tier

log = logging.getLogger("robot_md_gateway.gate")


Decision = Literal["allow", "deny"]


@dataclass(frozen=True)
class GateResult:
    decision: Decision
    reason: str


@dataclass(frozen=True)
class TierPolicy:
    """Default-deny policy: read tier may ONLY call tools on the allowlist.

    The default list covers the read-safe tools exposed by robot-md's Python
    MCP server (`render`, `validate`, `vision_find`, `discover`) plus common
    observation-style prefixes (`get_`, `list_`, `describe_`, `status`) that
    future tools are likely to use. Every other tool — including `estop`,
    `execute_capability`, `execute_task`, `record_skill` — requires actuate
    tier. New tools added upstream are denied for read-tier callers by
    default, which is the safe direction to drift.

    Non-MCP tools (built-in SDK tools like Read, Bash) are always denied
    regardless of tier; the dispatcher is a robot control plane, not a
    general-purpose shell.
    """

    read_safe_prefixes: tuple[str, ...]
    mcp_prefix: str = "mcp__robot__"

    @classmethod
    def default(cls) -> TierPolicy:
        return cls(
            read_safe_prefixes=(
                "mcp__robot__render",
                "mcp__robot__validate",
                "mcp__robot__vision_find",
                "mcp__robot__discover",
                "mcp__robot__get_",
                "mcp__robot__list_",
                "mcp__robot__describe_",
                "mcp__robot__status",
            )
        )

    def is_read_safe(self, tool_name: str) -> bool:
        return any(tool_name.startswith(p) for p in self.read_safe_prefixes)

    def is_robot_tool(self, tool_name: str) -> bool:
        return tool_name.startswith(self.mcp_prefix)


def evaluate(tool_name: str, tier: Tier, policy: TierPolicy) -> GateResult:
    """Pure policy check — no side effects, no SDK coupling.

    Default-deny. Read tier may call allowlisted read-safe tools;
    actuate tier may call any robot tool. Non-robot tools are always denied.
    """
    if not policy.is_robot_tool(tool_name):
        return GateResult(
            decision="deny",
            reason=(
                f"tool {tool_name!r} is not on the 'robot' MCP server; "
                "dispatcher only exposes robot-md tools"
            ),
        )
    if tier == "actuate":
        return GateResult(decision="allow", reason="")
    if policy.is_read_safe(tool_name):
        return GateResult(decision="allow", reason="")
    return GateResult(
        decision="deny",
        reason=(
            f"tool {tool_name!r} requires actuate tier; "
            f"caller holds {tier!r}"
        ),
    )


def make_can_use_tool(auth: AuthContext, policy: TierPolicy):
    """Build the SDK `can_use_tool` callback for a single dispatch.

    Closes over the caller's AuthContext so each dispatch enforces that
    caller's tier.
    """

    async def can_use_tool(tool_name: str, tool_input: dict, context: object) -> dict:
        result = evaluate(tool_name, auth.tier, policy)
        if result.decision == "allow":
            return {"behavior": "allow", "updatedInput": tool_input}
        log.warning(
            "gate_deny caller=%s tier=%s tool=%s reason=%s",
            auth.caller_id,
            auth.tier,
            tool_name,
            result.reason,
        )
        return {
            "behavior": "deny",
            "message": result.reason,
            "interrupt": False,
        }

    return can_use_tool


def make_pre_tool_use_hook(auth: AuthContext):
    """Build the SDK PreToolUse hook that audit-logs each invocation."""

    async def hook(input_data: dict, tool_use_id: str | None, context: object) -> dict:
        tool_name = input_data.get("tool_name", "<unknown>")
        tool_input = input_data.get("tool_input", {})
        log.info(
            "tool_call caller=%s tier=%s key=%s tool=%s args=%s",
            auth.caller_id,
            auth.tier,
            auth.api_key_fingerprint,
            tool_name,
            tool_input,
        )
        return {}

    return hook
