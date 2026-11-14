"""The operator's two acts: the supervisor's heartbeat, and the clear.

A served gateway starts held, and two acts arm it: heartbeats from the
supervisor credential (`role: supervisor`), then one clear from the commission
credential. These are the smallest tools that send them, so that nobody has to
write either by hand.

- `robot-md-gateway heartbeat` posts `/v1/safety/heartbeat` every second until
  it is stopped. Run it on the supervising person's device, never on the robot
  and never on the host that runs the agent: a heartbeat sent from the robot
  proves only that the gateway is running. So it refuses a gateway whose
  address is this machine's (a loopback address, or one bound to an interface
  here) unless `--i-am-on-the-robot` says that is meant. Stopping it stops the
  heartbeat, and the gateway trips 3 s later.
- `robot-md-gateway clear` posts `/v1/safety/clear` once. Where the gateway
  requires signed envelopes (`ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE=1`, as on
  bob), `--key` sends a signed `ESTOP_CLEAR` envelope with a new `msg_id` and
  the current `timestamp_ms`, so every run can be retried as it is.

Both read their bearer token from a file or from ROBOT_MD_GATEWAY_TOKEN, never
from the command line, where the process list and the shell history keep it.
Neither follows a redirect, so the token goes only to the address given.
Neither decides anything: the gateway does. They print what it answered.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import secrets
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .cert.envelope import sign_envelope

#: Where both tools look for the bearer token when no --token-file is given.
TOKEN_ENV = "ROBOT_MD_GATEWAY_TOKEN"

#: Seconds between heartbeats. The gateway trips after 3 s without one, so one
#: a second leaves room for two to be lost.
HEARTBEAT_INTERVAL_S = 1.0

#: post(url, bearer token, JSON body or None, timeout=seconds) -> (HTTP status,
#: parsed body). The tools take one as a parameter, so tests can route it into
#: the gateway app in memory.
Post = Callable[..., "tuple[int, object]"]


class OperatorError(Exception):
    """Something the operator has to fix before the tool can do anything."""


def read_token(token_file: str | None, *, env: Mapping[str, str] = os.environ) -> str:
    """The bearer token: the whole content of `token_file`, or TOKEN_ENV."""
    if token_file:
        token = Path(token_file).expanduser().read_text().strip()
        where = token_file
    else:
        token = env.get(TOKEN_ENV, "").strip()
        where = TOKEN_ENV
    if not token:
        raise OperatorError(f"no bearer token: pass --token-file, or set {TOKEN_ENV}")
    if any(c.isspace() for c in token):
        raise OperatorError(f"{where} must hold one token and nothing else")
    return token


def _parse(raw: bytes) -> object:
    try:
        return json.loads(raw)
    except ValueError:
        return raw.decode("utf-8", errors="replace")


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect. urllib follows a 301, 302 or 303 answer to a
    POST with a GET to the new location, and sends the Authorization header
    there, whatever the host (the fourth review's N1). The gateway never
    redirects, so a 3xx comes from something in front of it, and the token in
    that header is the supervisor's or the commission one."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None                     # urllib then raises HTTPError with the 3xx


_OPENER = urllib.request.build_opener(_NoRedirects)


def post(url: str, token: str, body: dict | None = None, *,
         timeout: float = 5.0) -> tuple[int, object]:
    """POST `body` as JSON (no body at all for None) with the bearer token.
    Returns (status, the parsed answer). An HTTP error status is returned, not
    raised, and a redirect is returned as a refusal (`deny: redirect`), never
    followed; no answer at all raises OSError."""
    headers = {"Authorization": f"Bearer {token}"}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return response.status, _parse(response.read())
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            where = exc.headers.get("Location") if exc.headers is not None else None
            return exc.code, {"detail": {"deny": "redirect", "reason": (
                f"{url} answered {exc.code}, a redirect"
                + (f" to {where}" if where else "")
                + "; it was not followed, so the token was sent nowhere else. Give "
                  "--gateway the gateway's own address")}}
        return exc.code, _parse(exc.read())


def _redirected(status: int) -> bool:
    return 300 <= status < 400


def _reason(body: object) -> str:
    """The gateway's own words for a refusal."""
    detail = body.get("detail", body) if isinstance(body, dict) else body
    if isinstance(detail, dict):
        return str(detail.get("reason") or detail.get("deny") or detail)
    return str(detail)


def addresses_on_this_machine(url: str) -> list[str]:
    """The addresses `url`'s host resolves to that are this machine's: loopback
    ones, and any that a socket here can bind, which only an address of one of
    this machine's own interfaces allows. On the robot that includes its tailnet
    name. Empty when the host does not resolve; the request will then fail and
    say so."""
    host = urllib.parse.urlsplit(url).hostname
    if not host:
        return []
    try:
        found = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return []
    mine = []
    for family, _type, _proto, _name, sockaddr in found:
        address = sockaddr[0]
        try:
            loopback = ipaddress.ip_address(address.split("%", 1)[0]).is_loopback
        except ValueError:
            loopback = False
        if loopback or _bindable(family, sockaddr):
            mine.append(address)
    return sorted(set(mine))


def _bindable(family: int, sockaddr: tuple) -> bool:
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as probe:
            probe.bind((sockaddr[0], 0, *sockaddr[2:]))
        return True
    except OSError:
        return False


def heartbeat(
    gateway: str,
    token: str,
    *,
    interval: float = HEARTBEAT_INTERVAL_S,
    i_am_on_the_robot: bool = False,
    post: Post = post,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    keep_going: Callable[[], bool] = lambda: True,
    on_this_machine: Callable[[str], list[str]] = addresses_on_this_machine,
    out: Callable[[str], None] = print,
) -> int:
    """Send heartbeats until `keep_going()` is false, and print each change in
    what the gateway answers. Returns 2 when the gateway refuses this
    credential (401 or 403), since sending again cannot change that, when its
    URL answers with a redirect, which is not followed, or when the interval
    is not shorter than the gateway's staleness limit; 0 otherwise. No answer,
    or a 503, is printed and retried.

    Heartbeats go out on a fixed cadence, one per `interval` from the start of
    the last one, so a slow answer does not push the next one late; and a
    request is given up after one interval (at least 1 s), so one that hangs
    does not hold back the next.

    Raises OperatorError before sending anything when the gateway's address is
    this machine's and `i_am_on_the_robot` is false."""
    if not interval > 0:
        raise OperatorError("--interval must be more than 0 seconds")
    url = gateway.rstrip("/") + "/v1/safety/heartbeat"
    mine = on_this_machine(url)
    if mine and not i_am_on_the_robot:
        raise OperatorError(
            f"{gateway} is this machine ({', '.join(mine)}). Send heartbeats from the "
            f"supervising person's device, never from the robot: a heartbeat sent "
            f"from the robot proves only that the gateway is running. An SSH tunnel "
            f"to the robot (ssh -L) looks the same from here, since it ends at a "
            f"loopback address; use the robot's tailnet address instead. If this is "
            f"meant, pass --i-am-on-the-robot."
        )
    if mine:
        out(f"warning: sending heartbeats from the machine the gateway runs on "
            f"({', '.join(mine)}), as --i-am-on-the-robot says")
    last = None
    while keep_going():
        due = clock() + interval
        try:
            status, body = post(url, token, None, timeout=max(interval, 1.0))
        except OSError as exc:
            now = f"no answer from {url} ({getattr(exc, 'reason', exc)}); retrying"
        else:
            if status in (401, 403):
                out(f"heartbeat refused ({status}): {_reason(body)}. Stopping: sending "
                    f"again with this credential cannot change that.")
                return 2
            if _redirected(status):
                out(f"heartbeat refused ({status}): {_reason(body)}. Stopping.")
                return 2
            if status != 200:
                now = f"heartbeat not accepted ({status}): {_reason(body)}; retrying"
            else:
                state = body.get("state") if isinstance(body, dict) else None
                limit = body.get("heartbeat_staleness_s") if isinstance(body, dict) else None
                if isinstance(limit, (int, float)) and interval >= limit:
                    out(f"--interval {interval:g} s is not shorter than the gateway's "
                        f"limit of {limit:g} s, so it would trip between heartbeats")
                    return 2
                now = f"heartbeats accepted; the gateway is {state}"
                if state != "ready":
                    now += (". Only a clear arms it (robot-md-gateway clear, with the "
                            "commission token)")
        if now != last:
            out(now)
            last = now
        sleep(max(0.0, due - clock()))
    return 0


def load_signing_key(path: str, kid: str | None = None) -> tuple[Ed25519PrivateKey, str]:
    """The key that signs a clear, and its key id.

    Either robot-md's keystore file (`~/.robot-md/keys/<rrn>.signing.json`,
    whose Ed25519 half signs and whose `pq_kid` is the key id `robot-md invoke`
    sends), or an Ed25519 PKCS8 PEM private key, which needs `kid`. The key id
    must be one the gateway's resolver knows (on bob: the registry, RRF)."""
    raw = Path(path).expanduser().read_bytes()
    if raw.lstrip().startswith(b"{"):
        try:
            data = json.loads(raw)
            priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(data["ed25519"]["sec"]))
        except (ValueError, KeyError, TypeError) as exc:
            raise OperatorError(f"{path} is not a robot-md keystore file "
                                f"({type(exc).__name__})") from None
        kid = kid or data.get("pq_kid")
    else:
        try:
            priv = serialization.load_pem_private_key(raw, password=None)
        except (ValueError, TypeError) as exc:
            raise OperatorError(f"{path} is not an unencrypted PEM private key "
                                f"({type(exc).__name__})") from None
        if not isinstance(priv, Ed25519PrivateKey):
            raise OperatorError(f"{path} is not an Ed25519 private key")
    if not kid:
        raise OperatorError("no key id: pass --kid, the id the gateway's resolver knows")
    return priv, kid


def build_clear(priv: Ed25519PrivateKey, kid: str, *, ruri: str | None = None,
                now_ms: int | None = None) -> dict:
    """A signed ESTOP_CLEAR envelope, as the gateway checks one where it
    requires signatures: a new msg_id, the current timestamp_ms, a nonce, and
    an Ed25519 signature by the gateway's own recipe."""
    body: dict = {
        "type": "ESTOP_CLEAR",
        "msg_id": uuid.uuid4().hex,
        "timestamp_ms": now_ms if now_ms is not None else int(time.time() * 1000),
        "nonce": secrets.token_hex(16),
    }
    if ruri:
        body["ruri"] = ruri
    return sign_envelope(priv, body, kid)


def clear(
    gateway: str,
    token: str,
    *,
    envelope: dict | None = None,
    post: Post = post,
    out: Callable[[str], None] = print,
) -> int:
    """POST /v1/safety/clear once, with `envelope` as its body when given.
    Prints what the gateway answered; returns 0 when it cleared, 1 otherwise."""
    url = gateway.rstrip("/") + "/v1/safety/clear"
    try:
        status, body = post(url, token, envelope)
    except OSError as exc:
        out(f"no answer from {url} ({getattr(exc, 'reason', exc)})")
        return 1
    if status == 200 and isinstance(body, dict):
        out(f"cleared: the gateway is {body.get('state')} ({body.get('reason')})")
        out("Each actuator keeps its own latch: for so-arm101-actuator, invoke "
            "arm.estop.clear at the commission tier.")
        return 0
    reason = _reason(body)
    out(f"clear refused ({status}): {reason}")
    if _redirected(status):
        return 1                        # it never reached the gateway: no hint applies
    if envelope is None and "ESTOP_CLEAR" in reason:
        out("This gateway requires a signed clear: pass --key, and --kid for a PEM key.")
    elif envelope is not None:
        out("The gateway has seen this envelope's msg_id now; running this again "
            "signs a new one.")
    return 1
