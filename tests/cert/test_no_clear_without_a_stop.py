"""The clear refuses to arm motion that no trip could stop (open question 2).

A gateway that trips sends each actuator its declared stop. An actuator that
declares none is sent nothing, and so-arm101-actuator 0.2.2, the latest on
PyPI, declares none: a move in flight ran to its goal after a trip (the second
review's R2-15). So while any configured actuator may move and declares no
stop, `POST /v1/safety/clear` answers 409 and the gateway stays held. A served
gateway starts held, so it never arms with such an actuator.

"May move" means it declares motion (`motion_capabilities`), or it says
nothing about motion at all, as 0.2.2 does. An actuator that declares an empty
`motion_capabilities` moves nothing and is exempt (castor-hal's read-only J1939
tap, the built-in no-op).
"""

from __future__ import annotations

import logging
from typing import ClassVar

from fastapi.testclient import TestClient

from robot_md_gateway.actuator import ActuatorOutcome, NoOpActuator
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.safety import GatewayState, SafetyMonitor
from robot_md_gateway.receiver import make_app

from .test_safe_stop_holds_the_machine import (
    STALE_S,
    FakeClock,
    _app,
    _clear,
    _heartbeat,
    _Resolver,
    _SimArm,
)


class _Declares:
    """An actuator double that declares exactly what it is given."""

    description = "test actuator"
    config_schema: ClassVar[dict] = {}

    def __init__(self, name="arm", **declared):
        self.name = name
        for attribute, tools in declared.items():
            setattr(self, attribute, tools)

    def execute(self, *, envelope, manifest_path, tier, config):
        return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})


def _held(clock):
    return SafetyMonitor(state=GatewayState.SAFE_STOP, heartbeat_staleness_s=STALE_S,
                         last_heartbeat_at=clock())


def _arm_it(actuator=None, *, actuators=None):
    clock, chain = FakeClock(), AuditChain()
    app, monitor, _ = _app(actuator, chain, clock=clock, monitor=_held(clock),
                           actuators=actuators)
    with TestClient(app) as client:
        assert _heartbeat(client).status_code == 200
        response = _clear(client)
    return response, monitor, chain


def test_a_clear_is_refused_while_an_actuator_that_moves_declares_no_stop():
    actuator = _Declares(motion_capabilities=frozenset({"arm.move_to"}),
                         stop_capabilities=frozenset())
    response, monitor, chain = _arm_it(actuator)
    assert response.status_code == 409
    reason = response.json()["detail"]["reason"]
    assert reason.startswith("safety.clear: refused, the gateway could not stop every "
                             "actuator on a trip: actuator 'arm' declares no stop")
    assert "declares motion (arm.move_to)" in reason
    assert monitor.state is GatewayState.SAFE_STOP
    [clear] = [e for e in chain.entries if e.decision_reason.startswith("safety.clear:")]
    assert clear.decision == "deny"


def test_an_actuator_that_declares_nothing_is_taken_to_move():
    """so-arm101-actuator 0.2.2: no motion_capabilities and no stop_capabilities."""
    response, monitor, _ = _arm_it(_Declares())
    assert response.status_code == 409
    assert ("actuator 'arm' declares no stop (stop_capabilities) and does not declare "
            "what it moves (motion_capabilities), so it may move anything"
            in response.json()["detail"]["reason"])
    assert monitor.state is GatewayState.SAFE_STOP


def test_an_actuator_that_declares_no_motion_does_not_hold_the_gateway():
    """castor-hal's read-only J1939 tap: no goals and no stop."""
    tap = _Declares(name="j1939", motion_capabilities=frozenset(),
                    stop_capabilities=frozenset())
    response, monitor, _ = _arm_it(tap)
    assert response.status_code == 200, response.text
    assert monitor.state is GatewayState.READY


def test_a_declaration_that_is_not_a_collection_does_not_exempt_an_actuator():
    response, _, _ = _arm_it(_Declares(motion_capabilities=None))
    assert response.status_code == 409


def test_the_built_in_no_op_declares_no_motion_and_can_be_cleared():
    assert NoOpActuator.motion_capabilities == frozenset()
    response, monitor, _ = _arm_it(NoOpActuator())
    assert response.status_code == 200, response.text
    assert monitor.state is GatewayState.READY


def test_one_unstoppable_actuator_among_several_holds_the_gateway_and_is_named():
    host = _Declares(name="host")                       # written before the declarations
    response, monitor, _ = _arm_it(actuators={"arm": _SimArm(), "host": host})
    assert response.status_code == 409
    reason = response.json()["detail"]["reason"]
    assert "actuator 'host' declares no stop" in reason
    assert "actuator 'arm'" not in reason
    assert monitor.state is GatewayState.SAFE_STOP

    host.motion_capabilities = frozenset()              # it says it moves nothing
    response, monitor, _ = _arm_it(actuators={"arm": _SimArm(), "host": host})
    assert response.status_code == 200, response.text


def test_an_actuator_with_a_stop_is_cleared_as_before():
    response, monitor, _ = _arm_it(_SimArm())
    assert response.status_code == 200, response.text
    assert monitor.state is GatewayState.READY


def test_startup_names_the_actuator_and_says_whether_it_holds_the_gateway(caplog):
    with caplog.at_level(logging.ERROR, logger="robot_md_gateway.receiver"):
        make_app(resolver=_Resolver(), actuators={
            "arm": _Declares(motion_capabilities=frozenset({"arm.move_to"})),
            "tap": _Declares(name="tap", motion_capabilities=frozenset()),
        }, actuator_configs={}, safety_monitor=SafetyMonitor())
    lines = [r.getMessage() for r in caplog.records]
    [arm] = [line for line in lines if "actuator 'arm'" in line]
    [tap] = [line for line in lines if "actuator 'tap'" in line]
    assert arm.startswith("no_declared_stop: actuator 'arm' declares no stop_capabilities")
    assert arm.endswith("it may move, so the gateway refuses to be cleared (armed) while it "
                        "is configured")
    assert tap.endswith("it declares no motion, so this does not hold the gateway")
