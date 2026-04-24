"""Regression tests for the tier gate.

These MUST hold or actuation-tier enforcement has regressed:

1. Pure policy: evaluate() denies an actuation tool for a read-tier caller.
2. SDK callback: make_can_use_tool returns deny behavior with the same policy.
3. HTTP surface: a read-tier bearer that asks for actuation gets a 'deny' event
   in the streamed response — the gate fires end-to-end over FastAPI.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

from fastapi.testclient import TestClient

from robot_md_dispatcher.app import AppDeps, ClientFactory, create_app
from robot_md_dispatcher.auth import AuthContext
from robot_md_dispatcher.gating import (
    TierPolicy,
    evaluate,
    make_can_use_tool,
)

READ_ONLY_TOOL = "mcp__robot__get_state"
ACTUATE_TOOL = "mcp__robot__execute_task"

# Real robot-md-mcp tool names (from robot-md/cli/src/robot_md/mcp/server.py),
# pinned here so this test fails loudly if the upstream tool surface shifts in
# a way that inverts our allow/deny defaults.
REAL_ROBOT_MD_TOOLS_READ = (
    "mcp__robot__render",
    "mcp__robot__validate",
    "mcp__robot__vision_find",
    "mcp__robot__discover",
)
REAL_ROBOT_MD_TOOLS_ACTUATE = (
    "mcp__robot__estop",
    "mcp__robot__estop_clear",
    "mcp__robot__execute_capability",
    "mcp__robot__execute_task",
    "mcp__robot__record_skill",
)


# ---- Pure policy ----------------------------------------------------------


def test_evaluate_denies_actuation_for_read_tier(policy: TierPolicy) -> None:
    result = evaluate(ACTUATE_TOOL, "read", policy)
    assert result.decision == "deny"
    assert "actuate" in result.reason
    assert ACTUATE_TOOL in result.reason


def test_evaluate_allows_read_tool_for_read_tier(policy: TierPolicy) -> None:
    assert evaluate(READ_ONLY_TOOL, "read", policy).decision == "allow"


def test_evaluate_allows_actuation_for_actuate_tier(policy: TierPolicy) -> None:
    assert evaluate(ACTUATE_TOOL, "actuate", policy).decision == "allow"


def test_evaluate_allows_read_tool_for_actuate_tier(policy: TierPolicy) -> None:
    assert evaluate(READ_ONLY_TOOL, "actuate", policy).decision == "allow"


def test_evaluate_denies_non_robot_tool_for_both_tiers(policy: TierPolicy) -> None:
    for tier in ("read", "actuate"):
        result = evaluate("Bash", tier, policy)  # type: ignore[arg-type]
        assert result.decision == "deny"
        assert "not on the 'robot' MCP server" in result.reason


def test_evaluate_estop_requires_actuate(policy: TierPolicy) -> None:
    """estop is safety-critical actuation, not a read-safe observation.

    A read-tier caller triggering estop on a robot mid-task is still a
    disruption. Operators who want read-tier estop must install a custom
    policy — it is not the default.
    """
    assert evaluate("mcp__robot__estop", "read", policy).decision == "deny"
    assert evaluate("mcp__robot__estop_clear", "read", policy).decision == "deny"


def test_evaluate_real_robot_md_tools_partition_correctly(policy: TierPolicy) -> None:
    for tool in REAL_ROBOT_MD_TOOLS_READ:
        assert evaluate(tool, "read", policy).decision == "allow", (
            f"{tool} should be read-safe"
        )
    for tool in REAL_ROBOT_MD_TOOLS_ACTUATE:
        assert evaluate(tool, "read", policy).decision == "deny", (
            f"{tool} must require actuate tier"
        )
        assert evaluate(tool, "actuate", policy).decision == "allow"


# ---- SDK can_use_tool adapter --------------------------------------------


async def test_can_use_tool_read_tier_denies_actuation(
    read_auth: AuthContext, policy: TierPolicy
) -> None:
    cb = make_can_use_tool(read_auth, policy)
    result = await cb(ACTUATE_TOOL, {"joint": "wrist_flex", "angle": 0.3}, None)
    assert result["behavior"] == "deny"
    assert "actuate" in result["message"]


async def test_can_use_tool_actuate_tier_allows_actuation(
    actuate_auth: AuthContext, policy: TierPolicy
) -> None:
    cb = make_can_use_tool(actuate_auth, policy)
    result = await cb(ACTUATE_TOOL, {"joint": "wrist_flex", "angle": 0.3}, None)
    assert result["behavior"] == "allow"
    assert result["updatedInput"] == {"joint": "wrist_flex", "angle": 0.3}


# ---- HTTP end-to-end ------------------------------------------------------


class _FakeAgentFactory:
    """Simulates a Claude Agent SDK session: tries one tool call, streams the
    gate's decision as an NDJSON event so the test can assert on it.

    The key property this fake preserves: it invokes the *real* can_use_tool
    built from the *real* gating module against the *real* AuthContext that
    the auth dep produced. That's what makes this a regression test for the
    end-to-end wiring, not just the unit.
    """

    def __init__(self, tool_to_attempt: str) -> None:
        self.tool_to_attempt = tool_to_attempt

    async def run(
        self,
        goal: str,
        auth: AuthContext,
        policy: TierPolicy,
        system_prompt: str,
        max_turns: int,
        max_budget_usd: float,
        mcp_command: str,
        mcp_args: list[str],
    ) -> AsyncIterator[dict]:
        cb = make_can_use_tool(auth, policy)
        decision = await cb(self.tool_to_attempt, {"arg": 1}, None)
        yield {
            "type": "gate_decision",
            "tool": self.tool_to_attempt,
            "caller": auth.caller_id,
            "tier": auth.tier,
            "behavior": decision["behavior"],
            "message": decision.get("message", ""),
        }


assert isinstance(_FakeAgentFactory(ACTUATE_TOOL), ClientFactory)  # structural check


def _build_client(bearer_store, policy, factory):
    deps = AppDeps(
        bearer_store=bearer_store,
        policy=policy,
        system_prompt="test prompt",
        mcp_command="/usr/bin/true",
        mcp_args=[],
        client_factory=factory,
    )
    return TestClient(create_app(deps))


def _parse_ndjson(body: str) -> list[dict]:
    return [json.loads(line) for line in body.strip().splitlines() if line]


def test_http_read_tier_bearer_is_denied_actuation(bearer_store, policy) -> None:
    client = _build_client(bearer_store, policy, _FakeAgentFactory(ACTUATE_TOOL))
    resp = client.post(
        "/dispatch",
        headers={
            "Authorization": "Bearer read-token",
            "X-Anthropic-Api-Key": "sk-ant-test-123",
        },
        json={"goal": "move the wrist"},
    )
    assert resp.status_code == 200
    events = _parse_ndjson(resp.text)
    assert len(events) == 1
    evt = events[0]
    assert evt["behavior"] == "deny", f"read-tier actuation must be denied, got {evt}"
    assert evt["caller"] == "alice"
    assert evt["tier"] == "read"
    assert ACTUATE_TOOL in evt["message"]


def test_http_actuate_tier_bearer_is_allowed_actuation(bearer_store, policy) -> None:
    client = _build_client(bearer_store, policy, _FakeAgentFactory(ACTUATE_TOOL))
    resp = client.post(
        "/dispatch",
        headers={
            "Authorization": "Bearer actuate-token",
            "X-Anthropic-Api-Key": "sk-ant-test-456",
        },
        json={"goal": "move the wrist"},
    )
    assert resp.status_code == 200
    events = _parse_ndjson(resp.text)
    assert events[0]["behavior"] == "allow"
    assert events[0]["caller"] == "bob"


def test_http_missing_bearer_401(bearer_store, policy) -> None:
    client = _build_client(bearer_store, policy, _FakeAgentFactory(ACTUATE_TOOL))
    resp = client.post(
        "/dispatch",
        headers={"X-Anthropic-Api-Key": "sk-ant-test-123"},
        json={"goal": "x"},
    )
    assert resp.status_code == 401


def test_http_unknown_bearer_401(bearer_store, policy) -> None:
    client = _build_client(bearer_store, policy, _FakeAgentFactory(ACTUATE_TOOL))
    resp = client.post(
        "/dispatch",
        headers={
            "Authorization": "Bearer not-a-real-token",
            "X-Anthropic-Api-Key": "sk-ant-test-123",
        },
        json={"goal": "x"},
    )
    assert resp.status_code == 401


def test_http_missing_api_key_401(bearer_store, policy) -> None:
    client = _build_client(bearer_store, policy, _FakeAgentFactory(ACTUATE_TOOL))
    resp = client.post(
        "/dispatch",
        headers={"Authorization": "Bearer read-token"},
        json={"goal": "x"},
    )
    assert resp.status_code == 401


def test_http_malformed_api_key_401(bearer_store, policy) -> None:
    client = _build_client(bearer_store, policy, _FakeAgentFactory(ACTUATE_TOOL))
    resp = client.post(
        "/dispatch",
        headers={
            "Authorization": "Bearer read-token",
            "X-Anthropic-Api-Key": "not-a-real-key",
        },
        json={"goal": "x"},
    )
    assert resp.status_code == 401
