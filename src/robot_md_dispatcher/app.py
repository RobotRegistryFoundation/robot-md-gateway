from __future__ import annotations

import json
import logging
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from fastapi import Depends, FastAPI
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .auth import AuthContext, BearerStore, load_bearer_store_from_env, make_auth_dep
from .gating import TierPolicy, make_can_use_tool, make_pre_tool_use_hook

log = logging.getLogger("robot_md_dispatcher")


@runtime_checkable
class ClientFactory(Protocol):
    """Builds and runs a Claude Agent SDK session for one dispatch.

    Separated behind a Protocol so the regression test can inject a fake
    without spawning the `claude` CLI.
    """

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
    ) -> AsyncIterator[dict]: ...


class RealClientFactory:
    """Real implementation — imports claude_agent_sdk lazily so tests don't need it."""

    async def run(  # type: ignore[override]
        self,
        goal: str,
        auth: AuthContext,
        policy: TierPolicy,
        system_prompt: str,
        max_turns: int,
        max_budget_usd: float,
        mcp_command: str,
        mcp_args: list[str],
    ):
        from claude_agent_sdk import (  # type: ignore[import-not-found]
            ClaudeAgentOptions,
            ClaudeSDKClient,
            HookMatcher,
        )

        options = ClaudeAgentOptions(
            mcp_servers={
                "robot": {
                    "type": "stdio",
                    "command": mcp_command,
                    "args": mcp_args,
                }
            },
            system_prompt=system_prompt,
            max_turns=max_turns,
            max_budget_usd=max_budget_usd,
            permission_mode="default",
            can_use_tool=make_can_use_tool(auth, policy),
            hooks={
                "PreToolUse": [HookMatcher(matcher="*", hooks=[make_pre_tool_use_hook(auth)])],
            },
            env={"ANTHROPIC_API_KEY": auth.api_key},
        )

        async with ClaudeSDKClient(options=options) as client:
            await client.query(goal)
            async for msg in client.receive_response():
                yield _message_to_dict(msg)


def _message_to_dict(msg: object) -> dict:
    """Best-effort serialization of SDK message objects to JSON-safe dicts."""
    if hasattr(msg, "model_dump"):
        return msg.model_dump()  # type: ignore[no-any-return]
    if hasattr(msg, "__dict__"):
        return {"type": type(msg).__name__, "data": str(msg)}
    return {"type": "unknown", "data": str(msg)}


@dataclass
class AppDeps:
    bearer_store: BearerStore
    policy: TierPolicy
    system_prompt: str
    mcp_command: str
    mcp_args: list[str]
    client_factory: ClientFactory


class DispatchRequest(BaseModel):
    goal: str = Field(min_length=1, max_length=10_000)
    max_turns: int = Field(default=20, ge=1, le=100)
    max_budget_usd: float = Field(default=0.50, gt=0, le=50.0)


def build_system_prompt(robot_md_text: str | None) -> str:
    core = (
        "You are a robotics dispatcher operating a physical robot. "
        "Call MCP tools on the 'robot' server to observe and (when permitted) "
        "actuate the machine. Respect every safety gate in the ROBOT.md manifest "
        "below. If a requested action would violate a gate, refuse and explain why. "
        "If the caller's tier does not permit an action, you will receive a deny "
        "response from can_use_tool — do not retry with a different tool to bypass it."
    )
    if robot_md_text:
        return core + "\n\n=== ROBOT.md ===\n" + robot_md_text
    return core + "\n\n(no ROBOT.md provided — operate conservatively)"


def create_app(deps: AppDeps) -> FastAPI:
    app = FastAPI(title="robot-md-dispatcher", version="0.1.0")
    auth_dep = make_auth_dep(deps.bearer_store)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"ok": True}

    @app.post("/dispatch")
    async def dispatch(
        req: DispatchRequest,
        auth: AuthContext = Depends(auth_dep),
    ) -> StreamingResponse:
        log.info(
            "dispatch_start caller=%s tier=%s key=%s goal_len=%d",
            auth.caller_id,
            auth.tier,
            auth.api_key_fingerprint,
            len(req.goal),
        )

        async def stream() -> AsyncIterator[bytes]:
            try:
                async for event in deps.client_factory.run(
                    goal=req.goal,
                    auth=auth,
                    policy=deps.policy,
                    system_prompt=deps.system_prompt,
                    max_turns=req.max_turns,
                    max_budget_usd=req.max_budget_usd,
                    mcp_command=deps.mcp_command,
                    mcp_args=deps.mcp_args,
                ):
                    yield (json.dumps(event) + "\n").encode()
            except Exception as exc:
                log.exception("dispatch_error caller=%s", auth.caller_id)
                yield (
                    json.dumps({"type": "error", "message": str(exc)}) + "\n"
                ).encode()

        return StreamingResponse(stream(), media_type="application/x-ndjson")

    return app


def create_app_from_env() -> FastAPI:
    robot_md_path = os.environ.get("ROBOT_MD_PATH")
    robot_md_text = Path(robot_md_path).read_text() if robot_md_path else None

    mcp_command = os.environ.get("ROBOT_MD_MCP_COMMAND", "robot-md-mcp")
    mcp_args_raw = os.environ.get("ROBOT_MD_MCP_ARGS", "")
    mcp_args = mcp_args_raw.split() if mcp_args_raw else []

    deps = AppDeps(
        bearer_store=load_bearer_store_from_env(),
        policy=TierPolicy.default(),
        system_prompt=build_system_prompt(robot_md_text),
        mcp_command=mcp_command,
        mcp_args=mcp_args,
        client_factory=RealClientFactory(),
    )
    return create_app(deps)
