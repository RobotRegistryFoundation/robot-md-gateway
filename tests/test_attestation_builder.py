"""Status mapping + outcome builder + trace wrapper (§3.4/§3.5/§3.7)."""

from __future__ import annotations

from robot_md_gateway.attestation import outcome_status


def test_status_deny_maps_to_denied():
    assert outcome_status(decision="deny", success=None, error_kind=None) == "denied"
    assert outcome_status(decision="deny", success=None, error_kind="X") == "denied"


def test_status_allow_success_maps_to_ok():
    assert outcome_status(decision="allow", success=True, error_kind=None) == "ok"


def test_status_allow_clean_failure_maps_to_failure():
    assert outcome_status(decision="allow", success=False, error_kind=None) == "failure"


def test_status_allow_exception_maps_to_error():
    assert outcome_status(decision="allow", success=False, error_kind="ValueError") == "error"
