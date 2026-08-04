"""Integration tests: gates pass → actuator runs → audit captures outcome."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from robot_md_gateway.actuator import Actuator, ActuatorOutcome, NoOpActuator
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.manifest_provenance import RRFResolver
from robot_md_gateway.receiver import make_app


class _FakeResolver:
    """Resolver that validates manifest signatures using the fixture signing key."""
    def __init__(self):
        fixture_dir = Path(__file__).parent / "fixtures" / "manifests"
        self.kid = (fixture_dir / "signing-key.kid").read_text().strip()
        self.pub_pem = (fixture_dir / "signing-key.pub").read_bytes()

    def resolve_kid_for_robot(self, ruri: str) -> str | None:
        return self.kid

    def resolve_public_key_pem(self, kid: str) -> bytes | None:
        if kid == self.kid:
            return self.pub_pem
        return None


def _make_test_app(actuator=None, actuator_config=None, audit_chain=None):
    return make_app(
        resolver=_FakeResolver(),
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
        bearer_tiers={"actuate-token": "actuate"},
        actuator=actuator,
        actuator_config=actuator_config or {},
        audit_chain=audit_chain,
    )


class TestMakeAppAcceptsActuator:
    def test_actuator_param_optional_defaults_to_noop(self):
        # Should NOT raise; actuator defaults to NoOpActuator instance.
        app = _make_test_app()
        assert app is not None
        # The instantiated NoOpActuator is on app.state for inspection.
        assert isinstance(app.state.actuator, NoOpActuator)

    def test_explicit_actuator_passed_through(self):
        custom = NoOpActuator()
        app = _make_test_app(actuator=custom)
        assert app.state.actuator is custom

    def test_actuator_config_param_defaults_to_empty_dict(self):
        app = _make_test_app()
        assert app.state.actuator_config == {}


class _SpyActuator:
    """Test-only actuator that records calls and returns a configurable outcome."""
    name = "spy"
    description = "test spy"
    config_schema: dict = {}

    def __init__(self, outcome=None):
        self.calls: list[dict] = []
        self._outcome = outcome or ActuatorOutcome(
            success=True, outcome_kind="executed",
            telemetry={"spy_marker": "ok"},
        )

    def execute(self, *, envelope, manifest_path, tier, config):
        self.calls.append({
            "envelope_msg_id": envelope.get("msg_id"),
            "manifest_path": str(manifest_path),
            "tier": tier,
            "config": dict(config),
        })
        return self._outcome


def _valid_envelope(tmp_path):
    # Use the fixture signed manifest so no monkeypatch is needed.
    fixture_manifest = Path(__file__).parent / "fixtures" / "manifests" / "signed-good.md"
    return {
        "msg_id": "test-msg-1",
        "type": "rcan/v1/invoke",
        "ruri": "rcan://RRN-test/skill",
        "scope": "actuate",
        "tool_name": "mcp__robot__render",
        "tool_args": {},
        "manifest_path": str(fixture_manifest),
    }


class TestActuatorCalledAfterGates:
    def test_actuator_executed_when_all_gates_pass(self, tmp_path):
        spy = _SpyActuator()
        chain = AuditChain()
        app = _make_test_app(actuator=spy, audit_chain=chain)

        with TestClient(app) as client:
            response = client.post(
                "/v1/invoke",
                json=_valid_envelope(tmp_path),
                headers={"Authorization": "Bearer actuate-token"},
            )

        assert response.status_code == 200
        body = response.json()
        assert body["ok"] is True
        assert body["actuator_name"] == "spy"
        assert body["outcome_kind"] == "executed"

        # Spy was called with the envelope.
        assert len(spy.calls) == 1
        assert spy.calls[0]["envelope_msg_id"] == "test-msg-1"
        assert spy.calls[0]["tier"] == "actuate"

        # Audit chain has one entry with actuator outcome captured.
        assert len(chain.entries) == 1
        entry = chain.entries[0]
        assert entry.decision == "allow"
        assert entry.actuator_name == "spy"
        assert entry.actuator_outcome_kind == "executed"

    def test_actuator_not_called_when_gate_denies(self, tmp_path, monkeypatch):
        # Manifest provenance fails → gate denies → actuator must NOT be called.
        # Use a resolver that doesn't have the signing key so verification fails.
        class FailResolver:
            def resolve_public_key_pem(self, kid: str) -> bytes | None:
                return None

        spy = _SpyActuator()
        chain = AuditChain()
        app = make_app(
            resolver=FailResolver(),
            tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
            bearer_tiers={"actuate-token": "actuate"},
            actuator=spy,
            actuator_config={},
            audit_chain=chain,
        )

        with TestClient(app) as client:
            response = client.post(
                "/v1/invoke",
                json=_valid_envelope(tmp_path),
                headers={"Authorization": "Bearer actuate-token"},
            )

        assert response.status_code == 403
        assert spy.calls == []
        # Audit entry recorded a deny, no actuator fields populated.
        assert len(chain.entries) == 1
        assert chain.entries[0].decision == "deny"
        assert chain.entries[0].actuator_name is None


class _RaisingActuator:
    name = "raises"
    description = "test raiser"
    config_schema: dict = {}
    def execute(self, *, envelope, manifest_path, tier, config):
        raise ValueError("simulated driver failure")


class TestActuatorErrorHandling:
    def test_actuator_exception_returns_500_and_audits_error(self, tmp_path, monkeypatch):
        from robot_md_gateway import manifest_provenance
        monkeypatch.setattr(
            manifest_provenance, "verify_manifest",
            lambda path, *, resolver: type("R", (), {
                "accepted": True, "kid": "fake-kid", "reason": "ok",
            })(),
        )

        chain = AuditChain()
        app = _make_test_app(actuator=_RaisingActuator(), audit_chain=chain)

        with TestClient(app) as client:
            response = client.post(
                "/v1/invoke",
                json=_valid_envelope(tmp_path),
                headers={"Authorization": "Bearer actuate-token"},
            )

        assert response.status_code == 500
        body = response.json()
        assert body["detail"]["actuator_error"] == "simulated driver failure"
        assert body["detail"]["actuator_error_kind"] == "ValueError"

        # Audit entry: gate decision was allow, but actuator outcome is error.
        assert len(chain.entries) == 1
        entry = chain.entries[0]
        assert entry.decision == "allow"
        assert entry.actuator_name == "raises"
        assert entry.actuator_outcome_kind == "error"
        assert entry.actuator_error_kind == "ValueError"


import hashlib
import json as _json

from rcan.audit_bundle import canonical_json


class _ActuatorWithTelemetry:
    name = "telem"
    description = "telemetry test"
    config_schema: dict = {}
    def __init__(self, telemetry, telemetry_path=None):
        self._telemetry = telemetry
        self._telemetry_path = telemetry_path
    def execute(self, *, envelope, manifest_path, tier, config):
        return ActuatorOutcome(
            success=True, outcome_kind="executed",
            telemetry=self._telemetry,
            telemetry_path=self._telemetry_path,
        )


class TestTelemetryPersistence:
    def test_telemetry_dict_hashed_into_audit_entry(self, tmp_path, monkeypatch):
        from robot_md_gateway import manifest_provenance
        monkeypatch.setattr(
            manifest_provenance, "verify_manifest",
            lambda path, *, resolver: type("R", (), {
                "accepted": True, "kid": "fake-kid", "reason": "ok",
            })(),
        )

        telemetry = {"sample_count": 3, "duration_ms": 42}
        chain = AuditChain()
        app = _make_test_app(
            actuator=_ActuatorWithTelemetry(telemetry=telemetry),
            audit_chain=chain,
        )

        with TestClient(app) as client:
            client.post(
                "/v1/invoke",
                json=_valid_envelope(tmp_path),
                headers={"Authorization": "Bearer actuate-token"},
            )

        expected_sha = hashlib.sha256(canonical_json(telemetry)).hexdigest()
        entry = chain.entries[0]
        assert entry.actuator_telemetry_sha256 == expected_sha
        assert entry.actuator_telemetry_path is None

    def test_telemetry_path_recorded_and_file_hashed(self, tmp_path, monkeypatch):
        from robot_md_gateway import manifest_provenance
        monkeypatch.setattr(
            manifest_provenance, "verify_manifest",
            lambda path, *, resolver: type("R", (), {
                "accepted": True, "kid": "fake-kid", "reason": "ok",
            })(),
        )

        telem_file = tmp_path / "telemetry" / "msg-001.json"
        telem_file.parent.mkdir(parents=True)
        file_bytes = b'{"actually_ran": true}\n'
        telem_file.write_bytes(file_bytes)

        chain = AuditChain()
        app = _make_test_app(
            actuator=_ActuatorWithTelemetry(
                telemetry={"sample_count": 3},
                telemetry_path=telem_file,
            ),
            audit_chain=chain,
        )

        with TestClient(app) as client:
            client.post(
                "/v1/invoke",
                json=_valid_envelope(tmp_path),
                headers={"Authorization": "Bearer actuate-token"},
            )

        entry = chain.entries[0]
        # Path is recorded as string.
        assert entry.actuator_telemetry_path == str(telem_file)
        # sha256 reflects FILE BYTES (not the in-memory telemetry dict)
        # when telemetry_path is set.
        expected = hashlib.sha256(file_bytes).hexdigest()
        assert entry.actuator_telemetry_sha256 == expected


def test_invoke_response_includes_outcome_telemetry(tmp_path, monkeypatch):
    """Receiver should return outcome.telemetry in the 200 response so
    callers can verify actuator-level success (e.g., move().reached) without
    a second round-trip. Added in 0.5.0a2."""
    from robot_md_gateway import manifest_provenance

    monkeypatch.setattr(
        manifest_provenance, "verify_manifest",
        lambda path, *, resolver: type("R", (), {
            "accepted": True, "kid": "fake-kid", "reason": "ok",
        })(),
    )

    class TelemetryActuator:
        name = "telem"
        description = "fixture"
        config_schema: dict = {}

        def execute(self, *, envelope, manifest_path, tier, config):
            return ActuatorOutcome(
                success=True,
                outcome_kind="executed",
                telemetry={"reached": True, "elapsed_s": 0.42, "thing": "value"},
            )

    app = _make_test_app(actuator=TelemetryActuator())

    with TestClient(app) as client:
        resp = client.post(
            "/v1/invoke",
            json=_valid_envelope(tmp_path),
            headers={"Authorization": "Bearer actuate-token"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["outcome_kind"] == "executed"
    assert body["telemetry"] == {"reached": True, "elapsed_s": 0.42, "thing": "value"}


class _DenyingActuator:
    """An actuator that REFUSES on policy — the drive-envelope case.

    Distinct from _RaisingActuator: nothing broke here. The driver looked at its
    own rules and said no.
    """
    name = "refuser"
    description = "test policy refuser"
    config_schema: dict = {}

    def execute(self, *, envelope, manifest_path, tier, config):
        return ActuatorOutcome(
            success=False,
            outcome_kind="denied",
            error_message="no drive approval is open",
        )


class TestActuatorPolicyDenial:
    """A driver's refusal must arrive as a signed 403, not a bare 500.

    Actuator-level refusals used to fall through to the generic 500 path:
    unsigned, and unreadable to clients (the iOS app accepts only 200 and 403),
    so "the car has no approval to move" reached the operator as a transport
    error indistinguishable from the gateway crashing. Same class of defect as
    the unreadable-manifest 500 that became a signed manifest_provenance deny.
    """

    def test_denied_outcome_returns_403_with_reason(self, tmp_path):
        chain = AuditChain()
        app = _make_test_app(actuator=_DenyingActuator(), audit_chain=chain)

        with TestClient(app) as client:
            response = client.post(
                "/v1/invoke",
                json=_valid_envelope(tmp_path),
                headers={"Authorization": "Bearer actuate-token"},
            )

        assert response.status_code == 403
        detail = response.json()["detail"]
        assert detail["deny"] == "actuator_policy"
        assert detail["reason"] == "no drive approval is open"
        assert detail["actuator_name"] == "refuser"

        # The refusal is still a first-class audited outcome, not a dropped call.
        assert len(chain.entries) == 1
        entry = chain.entries[0]
        assert entry.decision == "allow"          # the GATES allowed it
        assert entry.actuator_name == "refuser"   # the DRIVER refused it
        assert entry.actuator_outcome_kind == "denied"

    def test_actuator_crash_still_returns_500(self, tmp_path, monkeypatch):
        """A fault must never be dressed up as a policy decision.

        Reporting a crash as a refusal would tell the operator the robot decided
        something when in fact it broke.
        """
        from robot_md_gateway import manifest_provenance
        monkeypatch.setattr(
            manifest_provenance, "verify_manifest",
            lambda path, *, resolver: type("R", (), {
                "accepted": True, "kid": "fake-kid", "reason": "ok",
            })(),
        )
        app = _make_test_app(actuator=_RaisingActuator(), audit_chain=AuditChain())

        with TestClient(app) as client:
            response = client.post(
                "/v1/invoke",
                json=_valid_envelope(tmp_path),
                headers={"Authorization": "Bearer actuate-token"},
            )

        assert response.status_code == 500
