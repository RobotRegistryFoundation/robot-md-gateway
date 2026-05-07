"""Unit tests for ROBOT_MD_TOOL_ALLOWLIST env parsing in __main__.

The env var lets operators expand the gateway's default tool allowlist
without code changes — required for Plan 6 Phase 5 (HIL gated motion needs
mcp__robot__execute_capability, which the default allowlist excludes).
"""
from __future__ import annotations

import pytest

from robot_md_gateway.__main__ import _build_tool_allowlist_from_env
from robot_md_gateway.cert.policy import ToolAllowlist


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("ROBOT_MD_TOOL_ALLOWLIST", raising=False)


def test_env_unset_returns_none():
    assert _build_tool_allowlist_from_env() is None


def test_env_empty_string_returns_none(monkeypatch):
    monkeypatch.setenv("ROBOT_MD_TOOL_ALLOWLIST", "")
    assert _build_tool_allowlist_from_env() is None


def test_env_whitespace_only_returns_none(monkeypatch):
    monkeypatch.setenv("ROBOT_MD_TOOL_ALLOWLIST", "   ,  , ")
    assert _build_tool_allowlist_from_env() is None


def test_env_single_tool(monkeypatch):
    monkeypatch.setenv("ROBOT_MD_TOOL_ALLOWLIST", "mcp__robot__execute_capability")
    result = _build_tool_allowlist_from_env()
    assert isinstance(result, ToolAllowlist)
    assert result.allowed_tools == ("mcp__robot__execute_capability",)


def test_env_multiple_tools_csv(monkeypatch):
    monkeypatch.setenv(
        "ROBOT_MD_TOOL_ALLOWLIST",
        "mcp__robot__execute_capability,mcp__robot__render,mcp__robot__validate",
    )
    result = _build_tool_allowlist_from_env()
    assert result is not None
    assert result.allowed_tools == (
        "mcp__robot__execute_capability",
        "mcp__robot__render",
        "mcp__robot__validate",
    )


def test_env_strips_whitespace(monkeypatch):
    monkeypatch.setenv(
        "ROBOT_MD_TOOL_ALLOWLIST",
        "  mcp__robot__execute_capability , mcp__robot__render  ",
    )
    result = _build_tool_allowlist_from_env()
    assert result is not None
    assert result.allowed_tools == (
        "mcp__robot__execute_capability",
        "mcp__robot__render",
    )


def test_env_drops_empty_entries(monkeypatch):
    monkeypatch.setenv(
        "ROBOT_MD_TOOL_ALLOWLIST",
        "mcp__robot__execute_capability,,mcp__robot__render,",
    )
    result = _build_tool_allowlist_from_env()
    assert result is not None
    assert result.allowed_tools == (
        "mcp__robot__execute_capability",
        "mcp__robot__render",
    )


def test_env_preserves_order(monkeypatch):
    """The tuple order must match the operator's CSV input verbatim."""
    monkeypatch.setenv(
        "ROBOT_MD_TOOL_ALLOWLIST",
        "z_tool,a_tool,m_tool",
    )
    result = _build_tool_allowlist_from_env()
    assert result is not None
    assert result.allowed_tools == ("z_tool", "a_tool", "m_tool")
