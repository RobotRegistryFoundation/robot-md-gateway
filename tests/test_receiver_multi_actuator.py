"""Multi-actuator dispatch: gateway routes /v1/invoke by envelope.actuator_name."""
from __future__ import annotations

from pathlib import Path
from typing import ClassVar

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
    config_schema: ClassVar[dict] = {}

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

    def test_a_lone_actuator_needs_no_name(self):
        # CHANGED DELIBERATELY. This used to assert a 422, which encoded a
        # limitation rather than a safety property: with exactly one actuator
        # registered there is precisely one place the envelope could go, and
        # refusing gave the operator nothing to act on. Ambiguity still refuses
        # — see test_two_catch_alls_are_ambiguous_and_refuse.
        a = _NamedSpy("oak-d", "x")
        app = _make_app({"oak-d": a})

        with TestClient(app) as client:
            r = client.post(
                "/v1/invoke",
                json=_envelope(actuator_name=None),
                headers={"Authorization": "Bearer actuate-token"},
            )

        assert r.status_code == 200, r.text
        assert len(a.calls) == 1

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


class _CapableSpy(_NamedSpy):
    """A spy that declares which tools it implements, as real actuators do."""

    def __init__(self, name: str, marker: str, capabilities: tuple[str, ...]):
        super().__init__(name, marker)
        self.rcan_tools = capabilities


class TestCapabilityRouting:
    """Routing with no actuator_name, by which actuator declares the tool.

    Turning on a second actuator used to be a BREAKING CHANGE for every client:
    the gateway refused any envelope without a name, at the parser, before any
    gate ran — and routing failures are not audited, so there was not even a
    receipt explaining why the robot had gone silent. Actuators already declare
    disjoint capability sets, so the name is only genuinely needed to break a
    tie.
    """

    def test_an_unnamed_envelope_routes_to_the_actuator_that_declares_the_tool(self):
        arm = _CapableSpy("so-arm101", "arm", ("mcp__robot__render",))
        host = _CapableSpy("host", "host", ("host.status",))
        app = _make_app({"so-arm101": arm, "host": host})

        with TestClient(app) as client:
            r = client.post("/v1/invoke", json=_envelope(actuator_name=None),
                            headers={"Authorization": "Bearer actuate-token"})

        assert r.status_code == 200, r.text
        assert len(arm.calls) == 1, "the arm declares this tool"
        assert host.calls == [], "the host actuator must not see an arm command"

    def test_an_explicit_name_still_wins_over_inference(self):
        # A client that knows which actuator it means is never second-guessed.
        arm = _CapableSpy("so-arm101", "arm", ("mcp__robot__render",))
        other = _CapableSpy("spare", "spare", ("mcp__robot__render",))
        app = _make_app({"so-arm101": arm, "spare": other})

        with TestClient(app) as client:
            r = client.post("/v1/invoke", json=_envelope(actuator_name="spare"),
                            headers={"Authorization": "Bearer actuate-token"})

        assert r.status_code == 200, r.text
        assert len(other.calls) == 1
        assert arm.calls == []

    def test_a_genuine_TIE_is_the_only_thing_that_still_refuses(self):
        both_a = _CapableSpy("a", "a", ("mcp__robot__render",))
        both_b = _CapableSpy("b", "b", ("mcp__robot__render",))
        app = _make_app({"a": both_a, "b": both_b})

        with TestClient(app) as client:
            r = client.post("/v1/invoke", json=_envelope(actuator_name=None),
                            headers={"Authorization": "Bearer actuate-token"})

        assert r.status_code == 422
        body = r.json()
        assert body["detail"]["deny"] == "actuator_name_required"
        # Names the candidates, so the fix is obvious rather than a guess.
        assert sorted(body["detail"]["candidates"]) == ["a", "b"]
        assert both_a.calls == [] and both_b.calls == []

    def test_an_actuator_that_declares_nothing_still_receives_its_tools(self):
        # The built-in no-op declares no capabilities, and every actuator
        # written before that attribute existed declares none either. They must
        # keep working untouched.
        plain = _NamedSpy("legacy", "legacy")
        app = _make_app({"legacy": plain})

        with TestClient(app) as client:
            r = client.post("/v1/invoke", json=_envelope(actuator_name=None),
                            headers={"Authorization": "Bearer actuate-token"})

        assert r.status_code == 200, r.text
        assert len(plain.calls) == 1

    def test_adding_a_host_actuator_does_not_break_existing_arm_clients(self):
        # THE MIGRATION THIS EXISTS FOR, stated as the scenario: a working robot
        # gains host configuration, and every client that has never heard of
        # actuator_name keeps working untouched.
        arm = _CapableSpy("so-arm101", "arm", ("mcp__robot__render",))
        before = _make_app({"so-arm101": arm})
        with TestClient(before) as client:
            first = client.post("/v1/invoke", json=_envelope(msg_id="before"),
                                headers={"Authorization": "Bearer actuate-token"})

        host = _CapableSpy("host", "host", ("host.status",))
        after = _make_app({"so-arm101": arm, "host": host})
        with TestClient(after) as client:
            second = client.post("/v1/invoke", json=_envelope(msg_id="after"),
                                 headers={"Authorization": "Bearer actuate-token"})

        assert first.status_code == 200
        assert second.status_code == 200, "adding an actuator must not break the old client"

    def test_an_actuator_declaring_NOTHING_is_the_catch_all(self):
        # THE REGRESSION THIS RULE EXISTS FOR, found on live hardware. Bob's
        # so-arm101 driver predates the capabilities attribute and declares
        # none; adding the host actuator made every arm command 422 with
        # "no actuator declares this tool". An actuator that has made no claim
        # about what it does not handle stays a candidate for anything.
        legacy = _NamedSpy("so-arm101", "arm")            # declares nothing
        host = _CapableSpy("host", "host", ("host.status",))
        app = _make_app({"so-arm101": legacy, "host": host})

        with TestClient(app) as client:
            r = client.post("/v1/invoke", json=_envelope(actuator_name=None),
                            headers={"Authorization": "Bearer actuate-token"})

        assert r.status_code == 200, r.text
        assert len(legacy.calls) == 1
        assert host.calls == [], "a declared actuator is only offered what it declares"

    def test_the_catch_all_does_not_steal_a_tool_someone_DOES_declare(self):
        legacy = _NamedSpy("legacy", "legacy")
        owner = _CapableSpy("owner", "owner", ("mcp__robot__render",))
        app = _make_app({"legacy": legacy, "owner": owner})

        with TestClient(app) as client:
            r = client.post("/v1/invoke", json=_envelope(actuator_name=None),
                            headers={"Authorization": "Bearer actuate-token"})

        assert r.status_code == 200, r.text
        assert len(owner.calls) == 1
        assert legacy.calls == []

    def test_two_catch_alls_are_ambiguous_and_refuse(self):
        a, b = _NamedSpy("a", "a"), _NamedSpy("b", "b")
        app = _make_app({"a": a, "b": b})

        with TestClient(app) as client:
            r = client.post("/v1/invoke", json=_envelope(actuator_name=None),
                            headers={"Authorization": "Bearer actuate-token"})

        assert r.status_code == 422
        assert a.calls == [] and b.calls == []
