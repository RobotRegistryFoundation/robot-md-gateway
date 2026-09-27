"""Tests for scripts/rcan_conformance.py (the no-model, no-motion RCAN conformance run).

All offline. The end-to-end tests serve a real make_app() gateway on a loopback
port from a thread (uvicorn), configured like the rover's gateway: status.report
allowlisted at read|actuate|commission, sensor.battery not allowlisted, one READ
bearer, a signing identity and an export file. No robot and no network.
"""

from __future__ import annotations

import importlib.util
import json
import socket
import sys
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from robot_md_gateway.attestation import SigningIdentity
from robot_md_gateway.auth import _BearerEntry
from robot_md_gateway.cert.audit import AuditChain
from robot_md_gateway.cert.envelope import verify_envelope
from robot_md_gateway.cert.policy import ToolAllowlist
from robot_md_gateway.receiver import make_app

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "rcan_conformance.py"
_spec = importlib.util.spec_from_file_location("rcan_conformance", SCRIPT)
rc = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = rc  # dataclasses resolve annotations through sys.modules
_spec.loader.exec_module(rc)

FIX = Path(__file__).parent / "fixtures" / "manifests"
MANIFEST_KID = (FIX / "signing-key.kid").read_text().strip()
MANIFEST_PUB = (FIX / "signing-key.pub").read_bytes()
GOOD_MANIFEST = str(FIX / "signed-good.md")

TOKEN = "rmg_read_" + "0123456789abcdef" * 2
TEST_KID = "opencastor-conformance-test"


def _pem(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


class _Resolver:
    def __init__(self, mapping):
        self._m = mapping

    def resolve_public_key_pem(self, kid):
        return self._m.get(kid)


# --------------------------------------------------------------------------- #
# the case table                                                              #
# --------------------------------------------------------------------------- #
def test_case_table_names_only_the_two_read_tools():
    assert rc.ALLOWED_TOOLS == ("status.report", "sensor.battery")
    assert {c.tool for c in rc.CASES} <= set(rc.ALLOWED_TOOLS)
    rc.check_case_table()  # the shipped table passes its own guard
    assert [c.cid for c in rc.CASES] == ["C1", "C2", "C3", "C0", "C4", "C5"]
    assert {c.cid for c in rc.CASES if c.enforced_only} == {"C4", "C5"}


def test_case_table_guard_refuses_any_other_tool():
    bad = rc.Case("CX", "x", True, "not.a.real.tool", "OBSERVE", 200, None, "test")
    with pytest.raises(rc.Refused):
        rc.check_case_table((bad,))
    with pytest.raises(rc.Refused):
        rc.build_envelope(bad, run_id="r", rrn="RRN-1", manifest_path="/m")


def test_case_table_guard_refuses_replay_before_c0():
    c0 = next(c for c in rc.CASES if c.cid == "C0")
    c5 = next(c for c in rc.CASES if c.cid == "C5")
    with pytest.raises(rc.Refused):
        rc.check_case_table((c5, c0))


# --------------------------------------------------------------------------- #
# credentials and signing                                                     #
# --------------------------------------------------------------------------- #
def test_load_read_bearer_refuses_a_non_read_tier(tmp_path):
    f = tmp_path / "bearers.yaml"
    f.write_text("bearers:\n  - token: rmg_live_aaaaaaaaaaaaaaaaaaaaaaaa\n    tier: actuate\n"
                 "    caller: rcan-conformance\nactuator:\n  name: x\n")
    with pytest.raises(rc.Refused, match="READ bearer"):
        rc.load_read_bearer(f, "rcan-conformance")
    f.write_text(f"bearers:\n  - token: {TOKEN}\n    tier: read\n    caller: rcan-conformance\n")
    assert rc.load_read_bearer(f, "rcan-conformance") == TOKEN
    with pytest.raises(rc.Refused, match="exactly one"):
        rc.load_read_bearer(f, "someone-else")


def test_hand_written_envelope_verifies_and_a_tampered_one_does_not():
    key = Ed25519PrivateKey.generate()
    case = next(c for c in rc.CASES if c.cid == "C0")
    env = rc.build_envelope(case, run_id="r1", rrn="RRN-000000000012", manifest_path="/m")
    assert set(env) == {"msg_id", "type", "ruri", "scope", "tool_name", "tool_args",
                        "manifest_path", "nonce", "timestamp_ms"}
    rc.sign_envelope(key, env, TEST_KID)
    resolver = rc.OneKid(TEST_KID, _pem(key))
    assert verify_envelope(env, resolver=resolver).accepted
    env["scope"] = "MANIPULATE"
    assert not verify_envelope(env, resolver=resolver).accepted


# --------------------------------------------------------------------------- #
# end to end against a real gateway app                                       #
# --------------------------------------------------------------------------- #
class _Served:
    def __init__(self, app):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port,
                                                    log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started:
            assert time.monotonic() < deadline, "test gateway did not start"
            time.sleep(0.02)
        return f"http://127.0.0.1:{self.port}"

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(timeout=10)


def _setup(tmp_path, *, enforced: bool, allow_battery: bool = False):
    gw = Ed25519PrivateKey.generate()
    test = Ed25519PrivateKey.generate()
    (tmp_path / "gw.pem").write_bytes(_pem(gw))
    (tmp_path / "test-key.pem").write_bytes(test.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (tmp_path / "bearers.yaml").write_text(
        f"bearers:\n  - token: {TOKEN}\n    tier: read\n    caller: rcan-conformance\n")
    export = tmp_path / "export.ndjsonl"
    export.write_text("")
    tools = ("status.report", "sensor.battery") if allow_battery else ("status.report",)
    app = make_app(
        resolver=_Resolver({MANIFEST_KID: MANIFEST_PUB, TEST_KID: _pem(test)}),
        tool_allowlist=ToolAllowlist(allowed_tools=tools),
        tool_tier_requirements={"status.report": frozenset({"read", "actuate", "commission"})},
        bearers={TOKEN: _BearerEntry(token=TOKEN, tier="read", caller_id="rcan-conformance")},
        require_envelope_signature=enforced,
        audit_chain=AuditChain(),
        signing_identity=SigningIdentity(priv=gw, kid="gw-test", ran=None),
        attestation_export_file=export,
    )
    return app, export


def _argv(tmp_path, url, export, out, *extra):
    return ["--gateway", url, "--rrn", "RRN-000000000099", "--manifest-path", GOOD_MANIFEST,
            "--bearers", str(tmp_path / "bearers.yaml"), "--caller", "rcan-conformance",
            "--key-file", str(tmp_path / "test-key.pem"), "--kid", TEST_KID,
            "--gateway-pub", str(tmp_path / "gw.pem"), "--export", str(export),
            "--out", str(out), *extra]


def _no_token_anywhere(out: Path):
    for p in out.rglob("*"):
        if p.is_file():
            assert TOKEN.encode() not in p.read_bytes(), p


def test_unenforced_run_passes_c0_to_c3_and_skips_c4_c5(tmp_path):
    app, export = _setup(tmp_path, enforced=False)
    out = tmp_path / "bundle"
    with _Served(app) as url:
        code = rc.main(_argv(tmp_path, url, export, out))
    summary = json.loads((out / "summary.json").read_text())
    assert code == 0, summary
    assert summary["all_pass"] is True
    assert summary["cases_run"] == ["C1", "C2", "C3", "C0"]
    assert set(summary["cases_not_run"]) == {"C4", "C5"}
    got = {r["case"]: r["got"] for r in summary["results"]}
    assert got == {"C1": [403, "tool_tier"], "C2": [403, "tier_policy"],
                   "C3": [403, "tool_allowlist"], "C0": [200, None]}
    assert all(r["receipt_verified"] for r in summary["results"])
    assert summary["export"]["no_intent_for_refusals"] is True
    assert sorted(summary["export"]["found_by_corr_id"].values(),
                  key=lambda d: (d["intent"], d["outcome"])) == [
        {"intent": 0, "outcome": 1}] * 3 + [{"intent": 1, "outcome": 1}]
    _no_token_anywhere(out)
    records = json.loads((out / "requests-responses.json").read_text())
    assert all("stripped" in r["request"]["authorization"] or r["request"]["authorization"] == "none"
               for r in records)


def test_enforced_run_adds_unknown_signer_and_replay_refusals(tmp_path):
    app, export = _setup(tmp_path, enforced=True)
    out = tmp_path / "bundle"
    with _Served(app) as url:
        code = rc.main(_argv(tmp_path, url, export, out, "--enforced"))
    summary = json.loads((out / "summary.json").read_text())
    assert code == 0, summary
    got = {r["case"]: r["got"] for r in summary["results"]}
    assert got["C4"] == [403, "envelope_signature"]
    assert got["C5"] == [403, "replay"]
    # C5 reuses C0's id: one intent, two outcomes (the 200 and the replay refusal)
    c0_id = next(k for k in summary["export"]["expected_by_corr_id"] if k.endswith("-C0"))
    assert summary["export"]["found_by_corr_id"][c0_id] == {"intent": 1, "outcome": 2}
    # C4's envelope is checkable offline with the public key the bundle keeps
    assert any(p.name.startswith("opencastor-conformance-unknown-") for p in (out / "keys").iterdir())
    _no_token_anywhere(out)


def test_a_gate_that_decides_differently_fails_the_run(tmp_path):
    # sensor.battery allowlisted and with no tier requirement: C3 now gets a 200,
    # and the run must say so rather than pass.
    app, export = _setup(tmp_path, enforced=False, allow_battery=True)
    out = tmp_path / "bundle"
    with _Served(app) as url:
        code = rc.main(_argv(tmp_path, url, export, out))
    summary = json.loads((out / "summary.json").read_text())
    assert code == 1
    c3 = next(r for r in summary["results"] if r["case"] == "C3")
    assert c3["pass"] is False and c3["got"][0] == 200
    assert summary["export"]["no_intent_for_refusals"] is False


def test_refuses_to_reuse_an_output_folder(tmp_path):
    app, export = _setup(tmp_path, enforced=False)
    out = tmp_path / "bundle"
    out.mkdir()
    assert rc.main(_argv(tmp_path, "http://127.0.0.1:9", export, out)) == 2
