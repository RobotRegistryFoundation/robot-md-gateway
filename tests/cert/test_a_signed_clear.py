"""Where signed envelopes are required, so is a signed clear (review of #35,
finding 10).

On bob every invoke needs a signed, fresh, unreplayed envelope
(ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE=1 in robot-md's gateway.env), and the act
that makes the robot movable again needed only a bearer header. rcan-spec
replay-prevention: RESUME requires a fresh timestamp and a unique msg_id;
revocation: RESUME from a revoked key is rejected.
"""

from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from robot_md_gateway.attestation import SigningIdentity
from robot_md_gateway.auth import _BearerEntry
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.envelope import canonical_json
from robot_md_gateway.cert.safety import GatewayState, SafetyMonitor
from robot_md_gateway.receiver import make_app

KID = "operator-kid"
PRIV = Ed25519PrivateKey.generate()
PUB = PRIV.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
BEARERS = {"commission-token": "commission", "actuate-token": "actuate"}
SUPERVISOR = {"supervisor-token": _BearerEntry(token="supervisor-token", tier="read",
                                              caller_id="pendant", role="supervisor")}


class _Resolver:
    def __init__(self, *, offline=False):
        self.offline = offline

    def resolve_public_key_pem(self, kid):
        if self.offline:
            raise OSError("registry unreachable")
        return PUB if kid == KID else None


class _Clock:
    t = 1000.0

    def __call__(self):
        return self.t


def _app(*, require=True, resolver=None, export=None, **kw):
    clock, chain = _Clock(), AuditChain()
    monitor = SafetyMonitor(state=GatewayState.SAFE_STOP, last_heartbeat_at=float("-inf"))
    extra = {}
    if export is not None:
        extra = dict(attestation_export_file=export, signing_identity=SigningIdentity(
            priv=Ed25519PrivateKey.generate(), kid="gw", ran=None))
    app = make_app(resolver=resolver or _Resolver(), bearer_tiers=BEARERS, bearers=SUPERVISOR,
                   require_envelope_signature=require, safety_monitor=monitor,
                   audit_chain=chain, clock=clock, **extra, **kw)
    client = TestClient(app)
    assert client.post("/v1/safety/heartbeat",
                       headers={"Authorization": "Bearer supervisor-token"}).status_code == 200
    return client, monitor, chain


def _clear_envelope(*, msg_id=None, type_="ESTOP_CLEAR", timestamp_ms="now", kid=KID,
                    sign=True):
    body = {"msg_id": msg_id or f"clear-{time.monotonic_ns()}", "type": type_}
    if timestamp_ms == "now":
        body["timestamp_ms"] = int(time.time() * 1000)
    elif timestamp_ms is not None:
        body["timestamp_ms"] = timestamp_ms
    if sign:
        body["envelope_signature"] = {"kid": kid, "alg": "Ed25519", "sig": base64.b64encode(
            PRIV.sign(canonical_json(body))).decode()}
    return body


def _clear(client, body=None, token="commission-token"):
    kw = {"json": body} if body is not None else {}
    return client.post("/v1/safety/clear", headers={"Authorization": f"Bearer {token}"}, **kw)


def test_a_signed_fresh_clear_resumes_and_is_recorded_with_its_key(tmp_path):
    export = tmp_path / "trace.ndjsonl"
    client, monitor, chain = _app(export=export)
    body = _clear_envelope(msg_id="clear-1")
    response = _clear(client, body)
    assert response.status_code == 200, response.text
    assert monitor.state is GatewayState.READY
    [entry] = [e for e in chain.entries if e.decision_reason.startswith("safety.clear")]
    assert (entry.decision, entry.msg_id, entry.envelope_kid) == ("allow", "clear-1", KID)
    [line] = [json.loads(x) for x in export.read_text().splitlines()
              if json.loads(x)["invoke"].get("type") == "ESTOP_CLEAR"]
    assert line["invoke"] == body
    assert line["outcome"]["status"] == "ok"


@pytest.mark.parametrize(("body", "why"), [
    (None, "a clear must be one, of type ESTOP_CLEAR"),
    (_clear_envelope(sign=False), "envelope_signature: no envelope_signature field"),
    (_clear_envelope(type_="rcan/v1/invoke"), "not 'ESTOP_CLEAR'"),
    (_clear_envelope(kid="someone-else"), "envelope_signature: kid someone-else not registered"),
    (_clear_envelope(timestamp_ms=None), "envelope_freshness: missing_timestamp"),
    (_clear_envelope(timestamp_ms=int(time.time() * 1000) - 3_600_000),
     "envelope_freshness: stale_timestamp"),
])
def test_a_clear_that_is_not_signed_fresh_and_of_the_right_type_is_refused(body, why):
    client, monitor, chain = _app()
    response = _clear(client, body)
    assert response.status_code == 403, response.text
    assert why in response.json()["detail"]["reason"]
    assert monitor.state is GatewayState.SAFE_STOP
    [entry] = [e for e in chain.entries if e.decision_reason.startswith("safety.clear")]
    assert entry.decision == "deny"


def test_a_replayed_clear_is_refused():
    client, monitor, _ = _app()
    body = _clear_envelope(msg_id="clear-once")
    assert _clear(client, body).status_code == 200
    monitor.on_estop_wire(tripped=True)
    replayed = _clear(client, body)
    assert replayed.status_code == 403
    assert "replay" in replayed.json()["detail"]["reason"]
    assert monitor.state is GatewayState.ESTOP_ACTIVE


def test_a_clear_signed_by_a_revoked_key_is_refused():
    class _Revoked:
        def is_revoked(self, kid):
            return True

    client, monitor, _ = _app(revocation_resolver=_Revoked())
    response = _clear(client, _clear_envelope())
    assert response.status_code == 403
    assert f"revoked_key: kid={KID}" in response.json()["detail"]["reason"]
    assert monitor.state is GatewayState.SAFE_STOP


def test_a_key_lookup_that_fails_refuses_the_clear_without_a_500():
    client, monitor, _ = _app(resolver=_Resolver(offline=True))
    response = _clear(client, _clear_envelope())
    assert response.status_code == 403
    assert "could not be verified (OSError)" in response.json()["detail"]["reason"]
    assert monitor.state is GatewayState.SAFE_STOP


def test_the_signature_does_not_replace_the_commission_tier():
    client, monitor, _ = _app()
    response = _clear(client, _clear_envelope(), token="actuate-token")
    assert response.status_code == 403
    assert "'commission' tier" in response.json()["detail"]["reason"]
    assert monitor.state is GatewayState.SAFE_STOP


def test_where_signatures_are_not_required_the_bearer_is_enough():
    client, monitor, _ = _app(require=False)
    assert _clear(client).status_code == 200
    assert monitor.state is GatewayState.READY
