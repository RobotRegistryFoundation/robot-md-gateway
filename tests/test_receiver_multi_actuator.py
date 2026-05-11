"""Multi-actuator dispatch: gateway routes /v1/invoke by envelope.actuator_name."""
from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from robot_md_gateway.actuator import ActuatorOutcome
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.receiver import make_app


class _FakeResolver:
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


class _NamedSpy:
    """Actuator that announces a configurable name + records calls."""
    description = "test spy"
    config_schema: dict = {}

    def __init__(self, name: str, telemetry_marker: str):
        self.name = name
        self._telemetry_marker = telemetry_marker
        self.calls: list[dict] = []

    def execute(self, *, envelope, manifest_path, tier, config):
        self.calls.append({
            "msg_id": envelope.get("msg_id"),
            "actuator_name": envelope.get("actuator_name"),
            "config": dict(config),
        })
        return ActuatorOutcome(
            success=True, outcome_kind="executed",
            telemetry={"served_by": self._telemetry_marker},
        )


def _envelope(actuator_name: str | None = None, msg_id: str = "m1"):
    fixture_manifest = Path(__file__).parent / "fixtures" / "manifests" / "signed-good.md"
    env = {
        "msg_id": msg_id,
        "type": "rcan/v1/invoke",
        "ruri": "rcan://RRN-test/skill",
        "scope": "actuate",
        "tool_name": "mcp__robot__render",
        "tool_args": {},
        "manifest_path": str(fixture_manifest),
    }
    if actuator_name is not None:
        env["actuator_name"] = actuator_name
    return env


def _make_app(actuators, actuator_configs=None, audit_chain=None):
    return make_app(
        resolver=_FakeResolver(),
        tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
        bearer_tiers={"actuate-token": "actuate"},
        actuators=actuators,
        actuator_configs=actuator_configs or {},
        audit_chain=audit_chain,
    )


class TestMultiActuatorDispatch:
    def test_routes_to_named_actuator(self):
        a = _NamedSpy("oak-d", "oak-d-spy")
        b = _NamedSpy("so-arm101", "so-arm101-spy")
        app = _make_app({"oak-d": a, "so-arm101": b})

        with TestClient(app) as client:
            r1 = client.post(
                "/v1/invoke",
                json=_envelope(actuator_name="oak-d", msg_id="r1"),
                headers={"Authorization": "Bearer actuate-token"},
            )
            r2 = client.post(
                "/v1/invoke",
                json=_envelope(actuator_name="so-arm101", msg_id="r2"),
                headers={"Authorization": "Bearer actuate-token"},
            )

        assert r1.status_code == 200, r1.text
        assert r1.json()["actuator_name"] == "oak-d"
        assert r1.json()["telemetry"] == {"served_by": "oak-d-spy"}
        assert r2.status_code == 200, r2.text
        assert r2.json()["actuator_name"] == "so-arm101"
        assert r2.json()["telemetry"] == {"served_by": "so-arm101-spy"}

        assert [c["msg_id"] for c in a.calls] == ["r1"]
        assert [c["msg_id"] for c in b.calls] == ["r2"]

    def test_missing_actuator_name_returns_422(self):
        a = _NamedSpy("oak-d", "x")
        app = _make_app({"oak-d": a})

        with TestClient(app) as client:
            r = client.post(
                "/v1/invoke",
                json=_envelope(actuator_name=None),
                headers={"Authorization": "Bearer actuate-token"},
            )

        assert r.status_code == 422
        body = r.json()
        assert body["detail"]["deny"] == "actuator_name_required"
        assert a.calls == []

    def test_unknown_actuator_name_returns_404(self):
        a = _NamedSpy("oak-d", "x")
        app = _make_app({"oak-d": a})

        with TestClient(app) as client:
            r = client.post(
                "/v1/invoke",
                json=_envelope(actuator_name="bogus"),
                headers={"Authorization": "Bearer actuate-token"},
            )

        assert r.status_code == 404
        body = r.json()
        assert body["detail"]["deny"] == "unknown_actuator"
        assert "oak-d" in body["detail"]["known"]
        assert a.calls == []

    def test_per_actuator_config_routed(self):
        a = _NamedSpy("oak-d", "x")
        b = _NamedSpy("so-arm101", "y")
        app = _make_app(
            {"oak-d": a, "so-arm101": b},
            actuator_configs={
                "oak-d": {"camera": "lite"},
                "so-arm101": {"tolerance": 0.07},
            },
        )

        with TestClient(app) as client:
            client.post(
                "/v1/invoke",
                json=_envelope(actuator_name="oak-d"),
                headers={"Authorization": "Bearer actuate-token"},
            )
            client.post(
                "/v1/invoke",
                json=_envelope(actuator_name="so-arm101"),
                headers={"Authorization": "Bearer actuate-token"},
            )

        assert a.calls[0]["config"] == {"camera": "lite"}
        assert b.calls[0]["config"] == {"tolerance": 0.07}

    def test_audit_records_target_actuator_name(self):
        a = _NamedSpy("oak-d", "x")
        b = _NamedSpy("so-arm101", "y")
        chain = AuditChain()
        app = _make_app({"oak-d": a, "so-arm101": b}, audit_chain=chain)

        with TestClient(app) as client:
            client.post(
                "/v1/invoke",
                json=_envelope(actuator_name="so-arm101"),
                headers={"Authorization": "Bearer actuate-token"},
            )

        assert len(chain.entries) == 1
        assert chain.entries[0].actuator_name == "so-arm101"


class TestSingleActuatorBackwardCompat:
    def test_single_actuator_path_unaffected_by_actuator_name_in_envelope(self):
        # In single-actuator mode, envelope.actuator_name is parsed but ignored.
        a = _NamedSpy("the-only", "single")
        app = make_app(
            resolver=_FakeResolver(),
            tool_allowlist=ToolAllowlist(allowed_tools=("mcp__robot__render",)),
            bearer_tiers={"actuate-token": "actuate"},
            actuator=a,
            actuator_config={"k": "v"},
        )

        with TestClient(app) as client:
            r = client.post(
                "/v1/invoke",
                # Caller sends a different actuator_name — single mode ignores it.
                json=_envelope(actuator_name="something-else"),
                headers={"Authorization": "Bearer actuate-token"},
            )

        assert r.status_code == 200, r.text
        assert r.json()["actuator_name"] == "the-only"
        assert a.calls[0]["config"] == {"k": "v"}
