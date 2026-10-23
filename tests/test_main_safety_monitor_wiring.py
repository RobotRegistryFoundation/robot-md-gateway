"""`serve` must run a SafetyMonitor, in every actuator configuration, and boot held.

Regression: make_app took `safety_monitor` but the serve path never passed one,
so a deployed gateway had no heartbeat staleness rule (SF-002) at all, and
nothing ever moved it to SAFE_STOP. There is no flag to turn it off.

Regression (review of #35, finding 3): the monitor started READY, so a gateway
that restarted after a trip (a crash, systemd's Restart=on-failure, a reboot)
resumed the robot with no one deciding to. It now boots in SAFE_STOP, and only
a commission clear with fresh supervisor heartbeats arms it (decision G2).
"""

from __future__ import annotations

import sys

import pytest
import yaml

from robot_md_gateway import __main__ as gw_main


def _serve(monkeypatch, *argv: str):
    import uvicorn

    captured: dict = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: captured.__setitem__("app", app))
    monkeypatch.setattr(sys, "argv", ["robot-md-gateway", "serve", *argv])
    for v in ("ROBOT_MD_TOOL_ALLOWLIST", "ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE", "ROBOT_MD_PATH"):
        monkeypatch.delenv(v, raising=False)
    gw_main.main()
    return captured["app"]


def _assert_monitor(app):
    # Imported from the live module after main() ran: test_backward_compat_shim
    # purges robot_md_gateway.* from sys.modules, and main() imports lazily, so
    # a module-level import can hold a different class object.
    from robot_md_gateway.cert.safety import GatewayState, SafetyMonitor

    monitor = app.state.safety_monitor
    assert isinstance(monitor, SafetyMonitor), "serve must wire a SafetyMonitor"
    assert monitor.heartbeat_staleness_s == 3.0      # the pendant spec's 3-second rule
    assert monitor.state is GatewayState.SAFE_STOP   # boots held (G2)


def test_serve_wires_a_safety_monitor_with_no_bearers(monkeypatch):
    _assert_monitor(_serve(monkeypatch))


def test_serve_wires_a_safety_monitor_with_a_single_actuator(monkeypatch, tmp_path):
    bearers = tmp_path / "bearers.yaml"
    bearers.write_text(yaml.safe_dump({
        "bearers": [{"token": "t", "tier": "actuate", "caller": "c"}],
        "actuator": {"name": "noop"},
    }))
    _assert_monitor(_serve(monkeypatch, "--bearers", str(bearers)))


def test_serve_wires_a_safety_monitor_with_several_actuators(monkeypatch, tmp_path):
    bearers = tmp_path / "bearers.yaml"
    bearers.write_text(yaml.safe_dump({
        "bearers": [{"token": "t", "tier": "actuate", "caller": "c"}],
        "actuators": [{"name": "noop"}],
    }))
    app = _serve(monkeypatch, "--bearers", str(bearers))
    assert app.state.multi_actuator_mode is True
    _assert_monitor(app)


def test_serve_has_no_switch_to_turn_the_monitor_off(monkeypatch):
    for flag in ("--no-safety-monitor", "--no-heartbeat"):
        with pytest.raises(SystemExit):
            _serve(monkeypatch, flag)


PENDANT = "pendant-token-of-at-least-32-characters"
OPERATOR = "operator-token-of-at-least-32-characters"


def test_a_served_gateway_boots_held_until_a_commission_clear(monkeypatch, tmp_path):
    """The restart case end to end: nothing but a declared stop passes until a
    supervisor's heartbeats and a commission clear arm the gateway."""
    from fastapi.testclient import TestClient

    bearers = tmp_path / "bearers.yaml"
    bearers.write_text(yaml.safe_dump({"bearers": [
        {"token": "agent", "tier": "actuate", "caller": "agent"},
        # A supervisor or commission token must have at least 32 characters.
        {"token": PENDANT, "role": "supervisor", "caller": "pendant"},
        {"token": OPERATOR, "tier": "commission", "caller": "operator"},
    ]}))
    app = _serve(monkeypatch, "--bearers", str(bearers))

    def invoke(client):
        return client.post("/v1/invoke", headers={"Authorization": "Bearer agent"}, json={
            "msg_id": "m-1", "type": "rcan/v1/invoke", "ruri": "rcan://RRN-1/x",
            "scope": "MANIPULATE", "tool_name": "arm.move_to", "tool_args": {},
            "manifest_path": str(tmp_path / "ROBOT.md"),
        })

    with TestClient(app) as client:
        held = invoke(client)
        too_early = client.post("/v1/safety/clear",
                                headers={"Authorization": f"Bearer {OPERATOR}"})
        beat = client.post("/v1/safety/heartbeat", headers={"Authorization": f"Bearer {PENDANT}"})
        not_by_the_agent = client.post("/v1/safety/clear",
                                       headers={"Authorization": "Bearer agent"})
        cleared = client.post("/v1/safety/clear", headers={"Authorization": f"Bearer {OPERATOR}"})
        armed = invoke(client)

    assert held.status_code == 403
    assert held.json()["detail"] == {**held.json()["detail"], "deny": "safety_state",
                                     "reason": "gateway state=safe_stop"}
    # Before any heartbeat has arrived, even the commission credential cannot
    # clear: the gateway does not count its own start as a heartbeat.
    assert too_early.status_code == 403
    assert "no heartbeat has been received" in too_early.json()["detail"]["reason"]
    assert beat.status_code == 200 and beat.json()["state"] == "safe_stop"
    assert not_by_the_agent.status_code == 403
    assert "'commission' tier" in not_by_the_agent.json()["detail"]["reason"]
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["state"] == "ready"
    # Armed: the safety state no longer refuses it (a later gate may).
    assert armed.json()["detail"]["deny"] != "safety_state"
