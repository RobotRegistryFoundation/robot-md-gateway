"""`serve` must run a SafetyMonitor, in every actuator configuration.

Regression: make_app took `safety_monitor` but the serve path never passed one,
so a deployed gateway had no heartbeat staleness rule (SF-002) at all, and
nothing ever moved it to SAFE_STOP. There is no flag to turn it off.
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
    assert monitor.state is GatewayState.READY


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
