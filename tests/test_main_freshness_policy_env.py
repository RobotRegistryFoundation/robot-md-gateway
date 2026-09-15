"""Unit tests for the ROBOT_MD_ENVELOPE_MAX_SKEW_S / _REQUIRE_ENVELOPE_TIMESTAMP
env parsing behind the envelope freshness window (OC-09).

The shape of these tests is the shape of the risk. Every bad value an operator
can type has to land on a gateway that still answers the phone, because the
alternative failure mode is a robot that denies every command and looks healthy
doing it. So: unparseable falls back, non-positive falls back, and the only way
to get a narrow window is to ask for one explicitly.
"""
from __future__ import annotations

import pytest

from robot_md_gateway.__main__ import _freshness_policy_from_env


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("ROBOT_MD_ENVELOPE_MAX_SKEW_S", raising=False)
    monkeypatch.delenv("ROBOT_MD_REQUIRE_ENVELOPE_TIMESTAMP", raising=False)


def test_unset_is_the_generous_default():
    policy = _freshness_policy_from_env()
    assert policy.max_skew_s == 300.0
    assert policy.require_timestamp is False


def test_an_explicit_window_is_honoured(monkeypatch):
    monkeypatch.setenv("ROBOT_MD_ENVELOPE_MAX_SKEW_S", "45")
    assert _freshness_policy_from_env().max_skew_s == 45.0


@pytest.mark.parametrize("value", ["", "   "])
def test_empty_falls_back(monkeypatch, value):
    monkeypatch.setenv("ROBOT_MD_ENVELOPE_MAX_SKEW_S", value)
    assert _freshness_policy_from_env().max_skew_s == 300.0


@pytest.mark.parametrize("value", ["five minutes", "300s", "abc", "--"])
def test_an_unparseable_window_falls_back_rather_than_refusing_to_boot(
    monkeypatch, value,
):
    monkeypatch.setenv("ROBOT_MD_ENVELOPE_MAX_SKEW_S", value)
    assert _freshness_policy_from_env().max_skew_s == 300.0


@pytest.mark.parametrize("value", ["0", "0.0", "-1", "-300"])
def test_a_non_positive_window_falls_back(monkeypatch, value):
    """Zero or less would deny every envelope that carries a timestamp.

    The window is a HALF-WIDTH compared against abs(skew), so 0 rejects
    anything whose timestamp is not exactly the gateway's own millisecond, and
    a negative value rejects unconditionally. An operator typing 0 means "no
    window"; taking them literally would do the opposite and would present as
    a robot that stopped answering. Fall back to the default and log it.
    """
    monkeypatch.setenv("ROBOT_MD_ENVELOPE_MAX_SKEW_S", value)
    assert _freshness_policy_from_env().max_skew_s == 300.0


def test_a_non_positive_window_says_so_in_the_log(monkeypatch, caplog):
    monkeypatch.setenv("ROBOT_MD_ENVELOPE_MAX_SKEW_S", "0")
    with caplog.at_level("WARNING"):
        _freshness_policy_from_env()
    assert "not positive" in caplog.text


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_require_timestamp_truthy(monkeypatch, value):
    monkeypatch.setenv("ROBOT_MD_REQUIRE_ENVELOPE_TIMESTAMP", value)
    assert _freshness_policy_from_env().require_timestamp is True


@pytest.mark.parametrize("value", ["0", "false", "no", "off", ""])
def test_require_timestamp_defaults_off_for_anything_else(monkeypatch, value):
    """Off is the compatible answer: the clients that predate the field keep
    working, and the README says that is what the check does and does not do.
    """
    monkeypatch.setenv("ROBOT_MD_REQUIRE_ENVELOPE_TIMESTAMP", value)
    assert _freshness_policy_from_env().require_timestamp is False
