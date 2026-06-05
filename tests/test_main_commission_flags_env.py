"""Unit tests for the commission-bringup gate env flags in __main__.

ROBOT_MD_HITL_FROM_MANIFEST and ROBOT_MD_REQUIRE_RRN_BINDING default to False
(receiver dev-mode behavior preserved); a production/HIL deployment flips them on
via the env var — no code change — so make_app turns the B3/B4 gates on.
"""

from __future__ import annotations

import pytest

from robot_md_gateway.__main__ import (
    _hitl_from_manifest_from_env,
    _require_rrn_binding_from_env,
)

_VARS = ("ROBOT_MD_HITL_FROM_MANIFEST", "ROBOT_MD_REQUIRE_RRN_BINDING")
_FNS = {
    "ROBOT_MD_HITL_FROM_MANIFEST": _hitl_from_manifest_from_env,
    "ROBOT_MD_REQUIRE_RRN_BINDING": _require_rrn_binding_from_env,
}


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    for v in _VARS:
        monkeypatch.delenv(v, raising=False)


@pytest.mark.parametrize("var", _VARS)
def test_unset_returns_false(var):
    assert _FNS[var]() is False


@pytest.mark.parametrize("var", _VARS)
def test_empty_and_whitespace_return_false(var, monkeypatch):
    monkeypatch.setenv(var, "   ")
    assert _FNS[var]() is False


@pytest.mark.parametrize("var", _VARS)
@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "ON", "  true  "])
def test_truthy_values(var, value, monkeypatch):
    monkeypatch.setenv(var, value)
    assert _FNS[var]() is True


@pytest.mark.parametrize("var", _VARS)
@pytest.mark.parametrize("value", ["0", "false", "no", "off", "maybe", "False "])
def test_falsy_values_safe_default(var, value, monkeypatch):
    monkeypatch.setenv(var, value)
    assert _FNS[var]() is False
