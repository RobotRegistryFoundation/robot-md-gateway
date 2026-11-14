"""`robot-md-gateway heartbeat` and `robot-md-gateway clear` (operator.py).

The tools are tested against the real gateway app, in memory: `post` is
routed into a FastAPI TestClient instead of the network, so every answer is the
one a served gateway would give. A few tests use the real `post` against a
local HTTP server, to check what goes on the wire.
"""

from __future__ import annotations

import base64
import http.server
import importlib
import json
import socket
import sys
import threading
import urllib.parse
from pathlib import Path
from typing import ClassVar

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from robot_md_gateway import operator
from robot_md_gateway.actuator import ActuatorOutcome
from robot_md_gateway.auth import _BearerEntry
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.cert.safety import GatewayState, SafetyMonitor
from robot_md_gateway.operator import (
    OperatorError,
    addresses_on_this_machine,
    build_clear,
    clear,
    heartbeat,
    load_signing_key,
    read_token,
)
from robot_md_gateway.receiver import make_app

SUPERVISOR_TOKEN = "supervisor-token-of-at-least-32-characters"
COMMISSION_TOKEN = "commission-token-of-at-least-32-characters"
ACTUATE_TOKEN = "actuate-token-of-at-least-32-characters"
BEARERS = {
    SUPERVISOR_TOKEN: _BearerEntry(token=SUPERVISOR_TOKEN, tier="read", caller_id="pendant",
                                   role="supervisor"),
    COMMISSION_TOKEN: _BearerEntry(token=COMMISSION_TOKEN, tier="commission",
                                   caller_id="operator"),
    ACTUATE_TOKEN: _BearerEntry(token=ACTUATE_TOKEN, tier="actuate", caller_id="agent"),
}
GATEWAY = "https://bob.example-tailnet.ts.net"
OPERATOR_KEY = Ed25519PrivateKey.generate()
OPERATOR_KID = "a1b2c3d4"


class _Arm:
    name, description = "arm", "test arm"
    config_schema: ClassVar[dict] = {}
    motion_capabilities = frozenset({"arm.move_to"})
    stop_capabilities = frozenset({"arm.estop"})

    def execute(self, *, envelope, manifest_path, tier, config):
        return ActuatorOutcome(success=True, outcome_kind="executed", telemetry={})


class _Resolver:
    """Knows the operator's key id, as RRF would."""

    def resolve_public_key_pem(self, kid):
        if kid != OPERATOR_KID:
            return None
        return OPERATOR_KEY.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def _held_gateway(*, signatures: bool = True):
    """A gateway as `serve` builds one: held, with no heartbeat yet."""
    chain = AuditChain()
    monitor = SafetyMonitor(state=GatewayState.SAFE_STOP, last_heartbeat_at=float("-inf"))
    app = make_app(
        resolver=_Resolver(), tool_allowlist=ToolAllowlist(allowed_tools=("arm.estop",)),
        bearers=BEARERS, safety_monitor=monitor, audit_chain=chain, actuator=_Arm(),
        actuator_config={}, require_envelope_signature=signatures,
    )
    return app, monitor, chain


def _in_memory(client):
    """operator.post, routed into the app instead of the network."""
    def post(url, token, body, timeout=None):
        kwargs = {"headers": {"Authorization": f"Bearer {token}"}}
        if body is not None:
            kwargs["json"] = body
        response = client.post(urllib.parse.urlsplit(url).path, **kwargs)
        try:
            return response.status_code, response.json()
        except ValueError:
            return response.status_code, response.text
    return post


def _times(n):
    """keep_going for exactly n rounds."""
    left = iter(range(n))
    return lambda: next(left, None) is not None


def _not_here(url):
    return []


def _keystore(tmp_path: Path, priv: Ed25519PrivateKey, pq_kid: str) -> Path:
    """A file in robot-md's keystore format (robot_md.signing.save_keypair)."""
    raw = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)
    path = tmp_path / "RRN-000000000011.signing.json"
    path.write_text(json.dumps({
        "rrn": "RRN-000000000011", "pq_kid": pq_kid,
        "ml_dsa": {"pub": "", "sec": ""},
        "ed25519": {"pub": base64.b64encode(pub).decode(),
                    "sec": base64.b64encode(raw).decode()},
    }))
    return path


# --------------------------------------------------------------------------- #
# The two acts, against the real gateway
# --------------------------------------------------------------------------- #


def test_heartbeats_then_a_signed_clear_arm_a_held_gateway(tmp_path):
    app, monitor, chain = _held_gateway()
    lines: list[str] = []
    with TestClient(app) as client:
        post = _in_memory(client)
        assert heartbeat(GATEWAY, SUPERVISOR_TOKEN, post=post, sleep=lambda s: None,
                         keep_going=_times(3), on_this_machine=_not_here,
                         out=lines.append) == 0
        priv, kid = load_signing_key(str(_keystore(tmp_path, OPERATOR_KEY, OPERATOR_KID)))
        envelope = build_clear(priv, kid, ruri="rcan://RRN-000000000011/arm")
        assert clear(GATEWAY, COMMISSION_TOKEN, envelope=envelope, post=post,
                     out=lines.append) == 0
    assert monitor.state is GatewayState.READY
    assert lines[0] == ("heartbeats accepted; the gateway is safe_stop. Only a clear arms it "
                        "(robot-md-gateway clear, with the commission token)")
    assert len(lines) == 3                       # printed once, not once a second
    assert lines[1] == "cleared: the gateway is ready (safety.clear: safe_stop -> ready)"
    [record] = [e for e in chain.entries if e.decision_reason.startswith("safety.clear:")
                and e.decision == "allow"]
    assert record.msg_id == envelope["msg_id"]
    assert record.envelope_kid == OPERATOR_KID
    assert record.caller == "operator"


def test_the_keystore_file_robot_md_invoke_signs_with_gives_its_pq_kid(tmp_path):
    priv, kid = load_signing_key(str(_keystore(tmp_path, OPERATOR_KEY, "deadbeef")))
    assert kid == "deadbeef"
    assert priv.public_key().public_bytes(serialization.Encoding.Raw,
                                          serialization.PublicFormat.Raw) == (
        OPERATOR_KEY.public_key().public_bytes(serialization.Encoding.Raw,
                                               serialization.PublicFormat.Raw))
    assert load_signing_key(str(_keystore(tmp_path, OPERATOR_KEY, "deadbeef")),
                            "override")[1] == "override"


def test_a_pem_key_signs_a_clear_and_needs_a_kid(tmp_path):
    pem = tmp_path / "operator.pem"
    pem.write_bytes(OPERATOR_KEY.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
    with pytest.raises(OperatorError, match="no key id: pass --kid"):
        load_signing_key(str(pem))
    priv, kid = load_signing_key(str(pem), OPERATOR_KID)
    app, monitor, _ = _held_gateway()
    with TestClient(app) as client:
        post = _in_memory(client)
        heartbeat(GATEWAY, SUPERVISOR_TOKEN, post=post, sleep=lambda s: None,
                  keep_going=_times(1), on_this_machine=_not_here, out=lambda line: None)
        assert clear(GATEWAY, COMMISSION_TOKEN, envelope=build_clear(priv, kid), post=post,
                     out=lambda line: None) == 0
    assert monitor.state is GatewayState.READY


def test_a_key_that_is_neither_format_is_refused(tmp_path):
    bad = tmp_path / "key"
    bad.write_text("{not json")
    with pytest.raises(OperatorError, match="is not a robot-md keystore file"):
        load_signing_key(str(bad))
    bad.write_text("-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n")
    with pytest.raises(OperatorError, match="is not an unencrypted PEM private key"):
        load_signing_key(str(bad))


def test_an_unsigned_clear_is_refused_where_signatures_are_required_and_says_what_to_do():
    app, monitor, _ = _held_gateway()
    lines: list[str] = []
    with TestClient(app) as client:
        post = _in_memory(client)
        heartbeat(GATEWAY, SUPERVISOR_TOKEN, post=post, sleep=lambda s: None,
                  keep_going=_times(1), on_this_machine=_not_here, out=lambda line: None)
        assert clear(GATEWAY, COMMISSION_TOKEN, post=post, out=lines.append) == 1
    assert monitor.state is GatewayState.SAFE_STOP
    assert lines[0].startswith("clear refused (403): safety.clear: refused, this gateway "
                               "requires signed envelopes")
    assert lines[1] == "This gateway requires a signed clear: pass --key, and --kid for a PEM key."


def test_an_unsigned_clear_arms_a_gateway_that_does_not_require_signatures():
    app, monitor, _ = _held_gateway(signatures=False)
    with TestClient(app) as client:
        post = _in_memory(client)
        heartbeat(GATEWAY, SUPERVISOR_TOKEN, post=post, sleep=lambda s: None,
                  keep_going=_times(1), on_this_machine=_not_here, out=lambda line: None)
        assert clear(GATEWAY, COMMISSION_TOKEN, post=post, out=lambda line: None) == 0
    assert monitor.state is GatewayState.READY


def test_a_refused_signed_clear_says_a_rerun_signs_a_new_msg_id():
    """The gateway spends a clear's msg_id even when it refuses it, so the same
    envelope is a replay the second time. Each run of the tool signs anew."""
    app, monitor, _ = _held_gateway()
    lines: list[str] = []
    envelope = build_clear(OPERATOR_KEY, OPERATOR_KID)
    with TestClient(app) as client:
        post = _in_memory(client)
        assert clear(GATEWAY, COMMISSION_TOKEN, envelope=envelope, post=post,
                     out=lines.append) == 1      # no heartbeat yet
        heartbeat(GATEWAY, SUPERVISOR_TOKEN, post=post, sleep=lambda s: None,
                  keep_going=_times(1), on_this_machine=_not_here, out=lambda line: None)
        assert clear(GATEWAY, COMMISSION_TOKEN, envelope=envelope, post=post,
                     out=lines.append) == 1      # the same msg_id again
        assert clear(GATEWAY, COMMISSION_TOKEN, envelope=build_clear(OPERATOR_KEY, OPERATOR_KID),
                     post=post, out=lines.append) == 0
    assert "no heartbeat has been received" in lines[0]
    assert lines[1] == ("The gateway has seen this envelope's msg_id now; running this "
                        "again signs a new one.")
    assert lines[2].startswith("clear refused (403): safety.clear: refused, replay:")
    assert monitor.state is GatewayState.READY
    assert build_clear(OPERATOR_KEY, OPERATOR_KID)["msg_id"] != envelope["msg_id"]


def test_the_clear_needs_the_commission_credential():
    app, monitor, _ = _held_gateway()
    lines: list[str] = []
    with TestClient(app) as client:
        post = _in_memory(client)
        heartbeat(GATEWAY, SUPERVISOR_TOKEN, post=post, sleep=lambda s: None,
                  keep_going=_times(1), on_this_machine=_not_here, out=lambda line: None)
        assert clear(GATEWAY, ACTUATE_TOKEN, envelope=build_clear(OPERATOR_KEY, OPERATOR_KID),
                     post=post, out=lines.append) == 1
    assert "requires the 'commission' tier" in lines[0]
    assert monitor.state is GatewayState.SAFE_STOP


# --------------------------------------------------------------------------- #
# The heartbeat's own rules
# --------------------------------------------------------------------------- #


def test_a_credential_that_is_not_a_supervisor_stops_the_heartbeat_at_once():
    app, _, _ = _held_gateway()
    lines: list[str] = []
    sent = []
    with TestClient(app) as client:
        inner = _in_memory(client)

        def post(url, token, body, **kwargs):
            sent.append(url)
            return inner(url, token, body)

        assert heartbeat(GATEWAY, ACTUATE_TOKEN, post=post, sleep=lambda s: None,
                         on_this_machine=_not_here, out=lines.append) == 2
    assert len(sent) == 1
    assert lines == ["heartbeat refused (403): heartbeats are accepted only from a supervisor "
                     "credential (role: supervisor in bearers.yaml), which cannot move the "
                     "robot; this credential holds the actuate tier. Stopping: sending again "
                     "with this credential cannot change that."]


def test_an_interval_the_gateway_would_trip_between_is_refused():
    app, _, _ = _held_gateway()
    lines: list[str] = []
    with TestClient(app) as client:
        assert heartbeat(GATEWAY, SUPERVISOR_TOKEN, interval=3.0, post=_in_memory(client),
                         sleep=lambda s: None, on_this_machine=_not_here,
                         out=lines.append) == 2
    assert lines == ["--interval 3 s is not shorter than the gateway's limit of 3 s, so it "
                     "would trip between heartbeats"]
    with pytest.raises(OperatorError, match="more than 0"):
        heartbeat(GATEWAY, SUPERVISOR_TOKEN, interval=0, on_this_machine=_not_here)


def test_the_heartbeat_retries_when_there_is_no_answer_and_prints_only_changes():
    answers = [OSError("connection refused"), OSError("connection refused"),
               (503, {"detail": {"reason": "the safety watchdog has not ticked"}}),
               (200, {"state": "safe_stop", "heartbeat_staleness_s": 3.0}),
               (200, {"state": "safe_stop", "heartbeat_staleness_s": 3.0}),
               (200, {"state": "ready", "heartbeat_staleness_s": 3.0})]
    slept: list[float] = []
    lines: list[str] = []
    now = [100.0]

    def post(url, token, body, timeout):
        assert url == GATEWAY + "/v1/safety/heartbeat" and body is None
        assert timeout == 1.0                    # given up after one interval
        now[0] += 0.25                           # each answer takes 0.25 s
        answer = answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    assert heartbeat(GATEWAY + "/", SUPERVISOR_TOKEN, post=post, sleep=slept.append,
                     clock=lambda: now[0], keep_going=_times(6), on_this_machine=_not_here,
                     out=lines.append) == 0
    # One a second from the start of the last one: a slow answer does not push
    # the next heartbeat late.
    assert slept == [0.75] * 6
    assert lines == [
        f"no answer from {GATEWAY}/v1/safety/heartbeat (connection refused); retrying",
        "heartbeat not accepted (503): the safety watchdog has not ticked; retrying",
        "heartbeats accepted; the gateway is safe_stop. Only a clear arms it "
        "(robot-md-gateway clear, with the commission token)",
        "heartbeats accepted; the gateway is ready",
    ]


@pytest.mark.parametrize("url", ["http://127.0.0.1:8080", "http://localhost:8080",
                                 "http://[::1]:8080", "http://127.0.0.2"])
def test_the_heartbeat_refuses_a_gateway_on_this_machine(url):
    sent = []
    with pytest.raises(OperatorError, match=r"is this machine \(.*\)\. Send heartbeats from "
                                            r"the supervising person's device"):
        heartbeat(url, SUPERVISOR_TOKEN, post=lambda *a, **k: sent.append(a) or (200, {}),
                  sleep=lambda s: None, keep_going=_times(1))
    assert sent == []                            # refused before anything was sent


def test_i_am_on_the_robot_sends_anyway_and_says_so():
    lines: list[str] = []
    assert heartbeat("http://127.0.0.1:8080", SUPERVISOR_TOKEN, i_am_on_the_robot=True,
                     post=lambda *a, **k: (200, {"state": "ready", "heartbeat_staleness_s": 3.0}),
                     sleep=lambda s: None, keep_going=_times(1), out=lines.append) == 0
    assert lines[0] == ("warning: sending heartbeats from the machine the gateway runs on "
                        "(127.0.0.1), as --i-am-on-the-robot says")


def test_addresses_on_this_machine():
    assert addresses_on_this_machine("http://127.0.0.1:8080") == ["127.0.0.1"]
    assert addresses_on_this_machine("https://localhost") != []
    assert addresses_on_this_machine("http://198.51.100.7:8080") == []   # TEST-NET-2
    assert addresses_on_this_machine("http://gateway.invalid") == []     # does not resolve
    assert addresses_on_this_machine("not a url") == []


def test_an_address_of_this_machine_that_is_not_loopback_counts_too():
    """On the robot, its own tailnet name resolves to an address of one of its
    interfaces, not to loopback."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("198.51.100.7", 9))       # picks a route; sends nothing
        mine = probe.getsockname()[0]
    except OSError:
        pytest.skip("no route off this machine")
    finally:
        probe.close()
    if mine.startswith("127."):
        pytest.skip("this machine has no address but loopback")
    assert addresses_on_this_machine(f"http://{mine}:8080") == [mine]


# --------------------------------------------------------------------------- #
# The token, the wire, the command line
# --------------------------------------------------------------------------- #


def test_the_token_comes_from_a_file_or_the_environment(tmp_path):
    path = tmp_path / "supervisor.token"
    path.write_text(SUPERVISOR_TOKEN + "\n")
    assert read_token(str(path), env={}) == SUPERVISOR_TOKEN
    assert read_token(None, env={operator.TOKEN_ENV: f" {COMMISSION_TOKEN} "}) == COMMISSION_TOKEN
    with pytest.raises(OperatorError, match="no bearer token: pass --token-file, or set "
                                            "ROBOT_MD_GATEWAY_TOKEN"):
        read_token(None, env={})
    path.write_text("one\ntwo\n")
    with pytest.raises(OperatorError, match="must hold one token and nothing else"):
        read_token(str(path), env={})


class _Recorder(http.server.BaseHTTPRequestHandler):
    seen: ClassVar[list] = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        type(self).seen.append({
            "path": self.path, "authorization": self.headers.get("Authorization"),
            "content_type": self.headers.get("Content-Type"),
            "body": self.rfile.read(length),
        })
        status = 403 if self.path.endswith("/refused") else 200
        payload = json.dumps({"detail": {"reason": "no"}} if status == 403
                             else {"state": "ready"}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def test_post_sends_the_bearer_and_json_and_returns_a_refusal_rather_than_raising():
    _Recorder.seen = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        answer = operator.post(base + "/v1/safety/heartbeat", "tok", None)
        assert answer == (200, {"state": "ready"})
        assert operator.post(base + "/refused", "tok", {"type": "ESTOP_CLEAR"}) == (
            403, {"detail": {"reason": "no"}})
    finally:
        server.shutdown()
        server.server_close()
    beat, refused = _Recorder.seen
    assert beat == {"path": "/v1/safety/heartbeat", "authorization": "Bearer tok",
                    "content_type": None, "body": b""}
    assert refused["content_type"] == "application/json"
    assert json.loads(refused["body"]) == {"type": "ESTOP_CLEAR"}
    with pytest.raises(OSError):
        operator.post(base + "/v1/safety/heartbeat", "tok", None, timeout=2)   # closed now


def _run(monkeypatch, *argv, token=SUPERVISOR_TOKEN):
    """Run the command line. main() and what it imports are taken from
    sys.modules now: test_backward_compat_shim purges robot_md_gateway.* from
    it, so a module imported at collection can be an older copy than the one
    main() imports, and a patch on it would not be seen."""
    monkeypatch.setattr(sys, "argv", ["robot-md-gateway", *argv])
    monkeypatch.setenv(operator.TOKEN_ENV, token)
    with pytest.raises(SystemExit) as exc:
        importlib.import_module("robot_md_gateway.__main__").main()
    return exc.value.code


def test_the_command_line_refuses_a_heartbeat_to_this_machine(monkeypatch, capsys):
    assert _run(monkeypatch, "heartbeat", "--gateway", "http://127.0.0.1:8080") == 2
    assert "pass --i-am-on-the-robot" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["heartbeat", "clear"])
def test_the_command_line_takes_no_token_and_never_echoes_one(monkeypatch, capsys, command):
    """argparse would read `--token X` as `--token-file X`, and the error for a
    missing file would print the token."""
    assert _run(monkeypatch, command, "--gateway", GATEWAY, "--token", "SECRET-VALUE") == 2
    err = capsys.readouterr().err
    assert "no --token: give it in --token-file, or in ROBOT_MD_GATEWAY_TOKEN" in err
    assert "SECRET-VALUE" not in err


def test_ctrl_c_stops_the_heartbeat_and_says_what_follows(monkeypatch, capsys):
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("robot_md_gateway.operator.heartbeat", interrupted)
    assert _run(monkeypatch, "heartbeat", "--gateway", GATEWAY) == 0
    assert capsys.readouterr().out == (
        "stopped: the gateway trips 3 s after the last heartbeat it accepted\n")


def test_the_command_line_clear_signs_with_the_key_it_is_given(monkeypatch, tmp_path):
    keystore = _keystore(tmp_path, OPERATOR_KEY, OPERATOR_KID)
    sent = []

    def fake_clear(gateway, token, *, envelope=None, **kwargs):
        sent.append((gateway, token, envelope))
        return 0

    monkeypatch.setattr("robot_md_gateway.operator.clear", fake_clear)
    assert _run(monkeypatch, "clear", "--gateway", GATEWAY, "--key", str(keystore),
                "--ruri", "rcan://RRN-000000000011/arm", token=COMMISSION_TOKEN) == 0
    [(gateway, token, envelope)] = sent
    assert (gateway, token) == (GATEWAY, COMMISSION_TOKEN)
    assert envelope["type"] == "ESTOP_CLEAR" and envelope["ruri"] == "rcan://RRN-000000000011/arm"
    assert envelope["envelope_signature"]["kid"] == OPERATOR_KID


def test_the_command_line_names_a_missing_key(monkeypatch, tmp_path, capsys):
    assert _run(monkeypatch, "clear", "--gateway", GATEWAY, "--key",
                str(tmp_path / "missing.json"), token=COMMISSION_TOKEN) == 2
    assert "robot-md-gateway clear:" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# The fourth review: a redirect, a near-miss flag, and what the guard says
# --------------------------------------------------------------------------- #


class _Elsewhere(http.server.BaseHTTPRequestHandler):
    """Another host. It records whatever reaches it."""

    seen: ClassVar[list] = []

    def do_GET(self):
        type(self).seen.append((self.command, self.headers.get("Authorization")))
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = do_GET

    def log_message(self, *args):
        pass


def _redirecting_to(location: str):
    class _Redirect(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    return _Redirect


@pytest.fixture
def redirect_elsewhere():
    """The review's R4-36-06: the gateway's URL answers 302 to a listener on
    another address. Yields the URL that redirects."""
    _Elsewhere.seen = []
    elsewhere = http.server.ThreadingHTTPServer(("127.0.0.2", 0), _Elsewhere)
    location = f"http://127.0.0.2:{elsewhere.server_port}/elsewhere"
    front = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _redirecting_to(location))
    for server in (elsewhere, front):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{front.server_port}", location
    finally:
        for server in (elsewhere, front):
            server.shutdown()
            server.server_close()


def test_a_redirect_is_a_refusal_and_the_token_goes_nowhere_else(redirect_elsewhere):
    """urllib followed a 302 to a POST with a GET to the new location, with the
    Authorization header, whatever the host."""
    front, location = redirect_elsewhere
    status, body = operator.post(front + "/v1/safety/heartbeat", SUPERVISOR_TOKEN, None)
    assert status == 302
    assert body["detail"]["deny"] == "redirect"
    assert f"a redirect to {location}; it was not followed" in body["detail"]["reason"]
    status, _ = operator.post(front + "/v1/safety/clear", COMMISSION_TOKEN, {"type": "x"})
    assert status == 302
    assert _Elsewhere.seen == []                   # nothing, and no token, reached it


def test_a_redirect_stops_the_heartbeat_and_refuses_the_clear(redirect_elsewhere):
    front, _location = redirect_elsewhere
    lines: list[str] = []
    assert heartbeat(front, SUPERVISOR_TOKEN, i_am_on_the_robot=True, sleep=lambda s: None,
                     keep_going=_times(5), out=lines.append) == 2
    assert lines[-1].startswith("heartbeat refused (302): ")
    assert lines[-1].endswith("Give --gateway the gateway's own address. Stopping.")
    lines.clear()
    envelope = build_clear(OPERATOR_KEY, OPERATOR_KID)
    assert clear(front, COMMISSION_TOKEN, envelope=envelope, out=lines.append) == 1
    [refused] = lines                              # no "the gateway has seen this msg_id"
    assert refused.startswith("clear refused (302): ")
    assert _Elsewhere.seen == []


@pytest.mark.parametrize("command, argv", [
    ("heartbeat", ["--tok", "SECRET-VALUE"]),
    ("heartbeat", ["--tok=SECRET-VALUE"]),
    ("clear", ["--token-fil", "SECRET-VALUE"]),
    ("heartbeat", ["SECRET-VALUE"]),
])
def test_an_unrecognized_argument_is_named_without_its_value(monkeypatch, capsys, command, argv):
    """The review's N2: argparse printed "unrecognized arguments: --tok
    SECRET-VALUE", and a near-miss flag is followed by the token itself."""
    assert _run(monkeypatch, command, "--gateway", GATEWAY, *argv) == 2
    err = capsys.readouterr().err
    assert "SECRET-VALUE" not in err
    assert "unrecognized arguments: " in err
    assert "what was typed with them is not shown" in err
    if argv[0].startswith("-"):
        assert f"unrecognized arguments: {argv[0].split('=')[0]};" in err


def test_a_value_argparse_cannot_use_is_not_repeated(monkeypatch, capsys):
    assert _run(monkeypatch, "heartbeat", "--gateway", GATEWAY, "--interval",
                "SECRET-VALUE") == 2
    err = capsys.readouterr().err
    assert "SECRET-VALUE" not in err
    assert "argument --interval: invalid float value: '(not shown)'" in err


def test_the_guard_says_that_an_ssh_tunnel_looks_like_the_robot():
    with pytest.raises(OperatorError, match=r"An SSH tunnel to the robot \(ssh -L\) looks the "
                                            r"same from here"):
        heartbeat("http://127.0.0.1:8080", SUPERVISOR_TOKEN, sleep=lambda s: None,
                  keep_going=_times(1))
