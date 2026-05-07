"""Unit tests for ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE env parsing.

The default (False) preserves the receiver's development-mode behavior;
production flips it on via the env var.
"""
from __future__ import annotations

import pytest

from robot_md_gateway.__main__ import _require_envelope_signature_from_env


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE", raising=False)


def test_unset_returns_false():
    assert _require_envelope_signature_from_env() is False


def test_empty_returns_false(monkeypatch):
    monkeypatch.setenv("ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE", "")
    assert _require_envelope_signature_from_env() is False


def test_whitespace_returns_false(monkeypatch):
    monkeypatch.setenv("ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE", "   ")
    assert _require_envelope_signature_from_env() is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "True", "yes", "YES", "on", "ON"])
def test_truthy_values(monkeypatch, value):
    monkeypatch.setenv("ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE", value)
    assert _require_envelope_signature_from_env() is True


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "disabled", "False ", " False"])
def test_falsy_values_safe_default(monkeypatch, value):
    """Anything not in the truthy set is False — including 'False '/' False'.

    Whitespace is stripped before comparison; arbitrary other strings (a typo,
    'maybe', etc.) all resolve to False — safe-by-default semantics.
    """
    monkeypatch.setenv("ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE", value)
    assert _require_envelope_signature_from_env() is False


def test_truthy_strips_whitespace(monkeypatch):
    monkeypatch.setenv("ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE", "  true  ")
    assert _require_envelope_signature_from_env() is True
