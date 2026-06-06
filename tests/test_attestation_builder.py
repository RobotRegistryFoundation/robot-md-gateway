"""Status mapping + outcome builder + trace wrapper (§3.4/§3.5/§3.7)."""

from __future__ import annotations

import hashlib

from rcan.audit_bundle import canonical_json

from robot_md_gateway.actuator import ActuatorOutcome
from robot_md_gateway.attestation import outcome_status, telemetry_sha256_of


def test_status_deny_maps_to_denied():
    assert outcome_status(decision="deny", success=None, error_kind=None) == "denied"
    assert outcome_status(decision="deny", success=None, error_kind="X") == "denied"


def test_status_allow_success_maps_to_ok():
    assert outcome_status(decision="allow", success=True, error_kind=None) == "ok"


def test_status_allow_clean_failure_maps_to_failure():
    assert outcome_status(decision="allow", success=False, error_kind=None) == "failure"


def test_status_allow_exception_maps_to_error():
    assert outcome_status(decision="allow", success=False, error_kind="ValueError") == "error"


def test_telemetry_sha256_of_inmemory_dict_matches_canonical_json_hash():
    outcome = ActuatorOutcome(success=True, outcome_kind="executed", telemetry={"b": 2, "a": 1})
    expected = hashlib.sha256(canonical_json({"b": 2, "a": 1})).hexdigest()
    assert telemetry_sha256_of(outcome) == expected


def test_telemetry_sha256_of_file_hashes_file_bytes(tmp_path):
    p = tmp_path / "telem.bin"
    p.write_bytes(b"raw-telemetry-bytes")
    outcome = ActuatorOutcome(
        success=True, outcome_kind="executed", telemetry={}, telemetry_path=p
    )
    assert telemetry_sha256_of(outcome) == hashlib.sha256(b"raw-telemetry-bytes").hexdigest()


def test_telemetry_sha256_of_returns_none_when_empty():
    outcome = ActuatorOutcome(success=True, outcome_kind="no_op", telemetry={})
    assert telemetry_sha256_of(outcome) is None


def test_telemetry_sha256_of_returns_none_when_outcome_is_none():
    assert telemetry_sha256_of(None) is None
