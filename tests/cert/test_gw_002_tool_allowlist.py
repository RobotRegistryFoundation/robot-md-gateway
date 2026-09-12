"""GW-002 — Unallowlisted motion tool denied before driver (Track 2)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from robot_md_gateway.cert import report as cert_report
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.receiver import make_app

FIXTURES = Path(__file__).parent.parent / "fixtures" / "manifests"


class _FakeResolver:
    def __init__(self, mapping):
        self._mapping = mapping

    def resolve_public_key_pem(self, kid):
        return self._mapping.get(kid)


@pytest.fixture(autouse=True)
def _reset_cert_report():
    cert_report.reset()
    yield


# Behavior change (T-003 anon fail-open fix): the tier gate now runs BEFORE the
# tool-allowlist gate, and anon (no/unknown bearer) is denied actuation. These
# tests exercise the GW-002 tool allowlist on the MANIPULATE scope, so they must
# present an actuate-tier bearer to reach the tool gate at all — otherwise they'd
# stop at tier_policy. The bearer is incidental to what they assert (the tool
# allowlist), so it is baked into the client helper.
ACTUATE_HEADERS = {"Authorization": "Bearer gw-002-actuate"}


def _client_with_allowlist(allowed: tuple[str, ...]):
    kid = (FIXTURES / "signing-key.kid").read_text().strip()
    pub = (FIXTURES / "signing-key.pub").read_bytes()
    app = make_app(
        resolver=_FakeResolver({kid: pub}),
        tool_allowlist=ToolAllowlist(allowed_tools=allowed),
        bearer_tiers={"gw-002-actuate": "actuate"},
    )
    return TestClient(app)


def test_gw_002_unallowlisted_tool_denied():
    client = _client_with_allowlist(allowed=("mcp__robot__render", "mcp__robot__validate"))
    response = client.post("/v1/invoke", headers=ACTUATE_HEADERS, json={
        "msg_id": "msg-gw-002-1",
        "type": "INVOKE",
        "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "MANIPULATE",
        "tool_name": "mcp__robot__execute_capability",
        "tool_args": {},
        "manifest_path": str(FIXTURES / "signed-good.md"),
    })
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["deny"] == "tool_allowlist"


def test_gw_002_allowlisted_tool_accepted():
    client = _client_with_allowlist(
        allowed=("mcp__robot__render", "mcp__robot__execute_capability"),
    )
    response = client.post("/v1/invoke", headers=ACTUATE_HEADERS, json={
        "msg_id": "msg-gw-002-2",
        "type": "INVOKE",
        "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "MANIPULATE",
        "tool_name": "mcp__robot__execute_capability",
        "tool_args": {},
        "manifest_path": str(FIXTURES / "signed-good.md"),
    })
    assert response.status_code == 200


def test_gw_002_pass_recorded():
    client = _client_with_allowlist(allowed=("mcp__robot__render",))
    client.post("/v1/invoke", headers=ACTUATE_HEADERS, json={
        "msg_id": "msg-gw-002-3", "type": "INVOKE",
        "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "MANIPULATE",
        "tool_name": "mcp__robot__execute_capability",
        "tool_args": {},
        "manifest_path": str(FIXTURES / "signed-good.md"),
    })
    serialized = cert_report.serialize(repo="robot-md-gateway", sha="HEAD")
    gw_002 = [p for p in serialized["properties"] if p["property_id"] == "GW-002"]
    assert len(gw_002) == 1 and gw_002[0]["outcome"] == "pass"


# --------------------------------------------------------------------------- #
# Startup invariant: allowlisted to move, not allowlisted to stop
#
# The live allowlist on the operator's arm carried twelve tools and no stop of
# any kind, for months, because nothing ever looked. This is what makes that
# omission announce itself on the next robot instead of being discovered by
# reading the file.
# --------------------------------------------------------------------------- #


class _MovingActuator:
    """A driver that declares what moves and what stops, as real drivers do."""

    name = "mover"
    description = "test double"
    config_schema: dict = {}
    motion_capabilities = frozenset({"arm.home", "arm.reach_point"})
    stop_capabilities = frozenset({"arm.estop"})

    def execute(self, **kwargs):  # pragma: no cover - never invoked here
        raise AssertionError("boot-time test; no invoke")


class _StillActuator:
    """Declares nothing that moves, so it needs no stop and must not be flagged."""

    name = "reader"
    description = "test double"
    config_schema: dict = {}

    def execute(self, **kwargs):  # pragma: no cover - never invoked here
        raise AssertionError("boot-time test; no invoke")


def _boot(allowed: tuple[str, ...], actuator):
    kid = (FIXTURES / "signing-key.kid").read_text().strip()
    pub = (FIXTURES / "signing-key.pub").read_bytes()
    return make_app(
        resolver=_FakeResolver({kid: pub}),
        tool_allowlist=ToolAllowlist(allowed_tools=allowed),
        actuator=actuator,
    )


def test_boot_refuses_motion_only_allowlist(caplog):
    """A motion-carrying allowlist with no stop is logged at ERROR under the
    named reason `allowlist_has_no_stop`.

    Logged, not refused: a gateway that will not start is a gateway an operator
    restarts with the check disabled, and a robot that will not answer
    `status.report` is not safer than one that will. The stop is what has to be
    reachable; the boot is not the thing to hold hostage.
    """
    import logging

    with caplog.at_level(logging.ERROR, logger="robot_md_gateway.receiver"):
        app = _boot(("arm.home", "arm.reach_point", "status.report"), _MovingActuator())

    assert "allowlist_has_no_stop" in caplog.text
    assert "arm.estop" in caplog.text, "the log must name the stop that is available"
    findings = app.state.allowlist_stop_findings
    assert [f["reason"] for f in findings] == ["allowlist_has_no_stop"]
    assert findings[0]["actuator"] == "mover"
    assert findings[0]["allowed_motion_tools"] == ["arm.home", "arm.reach_point"]


def test_boot_is_quiet_when_a_stop_is_allowlisted(caplog):
    import logging

    with caplog.at_level(logging.ERROR, logger="robot_md_gateway.receiver"):
        app = _boot(("arm.home", "arm.estop"), _MovingActuator())

    assert "allowlist_has_no_stop" not in caplog.text
    assert app.state.allowlist_stop_findings == []


def test_boot_is_quiet_for_an_actuator_that_moves_nothing(caplog):
    """`host.*` tools and the no-op driver move nothing, so demanding a stop
    from them would be noise - and noise is how a startup check gets ignored."""
    import logging

    with caplog.at_level(logging.ERROR, logger="robot_md_gateway.receiver"):
        app = _boot(("status.report", "host.shell"), _StillActuator())

    assert "allowlist_has_no_stop" not in caplog.text
    assert app.state.allowlist_stop_findings == []
