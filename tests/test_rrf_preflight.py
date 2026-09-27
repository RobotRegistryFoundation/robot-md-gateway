"""Tests for scripts/rrf_preflight.py (the RRF identity preflight).

Everything runs offline: the registry and the loopback stub are a dict of
canned answers (or, for the CLI test, a throwaway HTTP server on 127.0.0.1),
and the gateway's process facts are injected as a GatewayInfo instead of being
read from systemd and /proc. Keys are generated per test; nothing here reads
a real robot's files except the two optional bench-fixture parse tests, which
skip when the opencastor-ios checkout is absent.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import subprocess
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "rrf_preflight.py"
_spec = importlib.util.spec_from_file_location("rrf_preflight", SCRIPT)
pf = importlib.util.module_from_spec(_spec)
sys.modules["rrf_preflight"] = pf
_spec.loader.exec_module(pf)

REG = "https://registry.test"
STUB = "http://127.0.0.1:18090"
RRN = "RRN-000000000099"
RAN = "RAN-000000000999"
MK, GK, PHONE = "testbot-manifest", "testbot-gw", "opencastor-0123456789ab"
BEARER = "SECRET-BEARER-do-not-leak-0123456789"
NOW = 1_790_000_000  # 2026-09-21

BODY = """---
rcan_version: '3.0'
metadata:
  robot_name: testbot
  rrn: 'RRN-000000000099'
network:
  signing_alg: ml-dsa-65
drivers:
  - id: drive
    protocol: simulation
    backend: SimulatedDrive
    # nothing moves
    hardware_present: false
capabilities:
  - drive.set
  - status.report
  # a reading, not a tool
  - sensor.battery
---

# testbot
"""


def _pem(priv) -> str:
    return priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _spki_der(priv) -> bytes:
    return priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _spki(priv) -> str:
    return hashlib.sha256(_spki_der(priv)).hexdigest()


def _raw_b64(priv) -> str:
    return base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def signed_manifest(priv, kid: str, body: str = BODY, signed_body: str | None = None) -> bytes:
    sig = base64.b64encode(priv.sign((signed_body or body).encode())).decode()
    return (body + f"\n<!-- ROBOT-MD-SIG kid={kid} sig={sig} -->\n").encode()


def signed_outcome(priv, kid: str, ended: int) -> dict:
    """A v2 outcome signed the way the gateway signs (independent canonical form)."""
    oc = {"corr_id": "c-1", "rrn": RRN, "status": "ok", "receipt_version": 2,
          "caller": "rover-runtime", "tier": "read", "duration_ms": 12,
          "started_at": datetime.fromtimestamp(ended - 1, tz=timezone.utc).isoformat(),
          "ended_at": datetime.fromtimestamp(ended, tz=timezone.utc).isoformat()}
    msg = json.dumps(oc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    sig = base64.b64encode(priv.sign(msg)).decode()
    oc["envelope_signature"] = {"kid": kid, "alg": "Ed25519", "sig": sig}
    return oc


class World:
    """One robot's files, keys and canned HTTP answers."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.mkey = Ed25519PrivateKey.generate()
        self.gkey = Ed25519PrivateKey.generate()
        self.manifest = tmp / "ROBOT.md"
        self.manifest.write_bytes(signed_manifest(self.mkey, MK))
        self.fixture = tmp / "ROBOT-fixture.md"
        self.fixture.write_bytes(self.manifest.read_bytes())
        self.keyfile = tmp / "gw-private.pem"  # never created: the preflight must not open it
        (tmp / "gw-private.pem.pub").write_text(_pem(self.gkey))
        self.pins = {
            MK: {"spki_sha256": _spki(self.mkey), "role": "manifest", "rrn": RRN, "ran": ""},
            GK: {"spki_sha256": _spki(self.gkey), "role": "gateway-attestation", "rrn": RRN,
                 "ran": ""},
        }
        self.pairing = tmp / "pair.json"
        self.write_pairing(_spki_der(self.gkey), GK)
        self.export = tmp / "export.ndjsonl"
        self.write_export(self.gkey, NOW - 60)
        self.env_file = tmp / "gateway-policy.env"
        self.env_file.write_text(
            'ROBOT_MD_TOOL_ALLOWLIST="drive.set,status.report"\nSOME_TOKEN=abc\n')
        self.answers: dict[str, tuple[int, object]] = {
            f"{STUB}/v2/keys/{MK}": (200, {"kid": MK, "public_key_pem": _pem(self.mkey)}),
            f"{STUB}/v2/keys/{GK}": (200, {"kid": GK, "public_key_pem": _pem(self.gkey)}),
            f"{REG}/v2/robots/_next": (200, {"next_rrn": "RRN-000000000100"}),
        }

    def write_pairing(self, spki_der: bytes, kid: str) -> None:
        self.pairing.write_text(json.dumps({
            "v": 1, "gateway_url": "http://192.0.2.10:8081", "bearer": BEARER,
            "console_token": BEARER + "-console", "manifest_path": str(self.manifest), "rrn": RRN,
            "attest_kid": kid, "attest_pub": base64.b64encode(spki_der).decode(),
        }))

    def write_export(self, signer, ended: int) -> None:
        lines = [
            {"v": "1", "rrn": RRN, "corr_id": "c-0",
             "invoke": {"msg_id": "c-0", "tool_name": "status.report", "type": "INVOKE"},
             "outcome": signed_outcome(signer, GK, ended - 5)},
            {"v": "1", "rrn": RRN, "corr_id": "c-1",
             "invoke": {"msg_id": "c-1", "tool_name": "sensor.battery",
                        "envelope_signature": {"kid": PHONE, "sig": "AAAA"}},
             "outcome": signed_outcome(signer, GK, ended)},
        ]
        self.export.write_text("".join(json.dumps(x) + "\n" for x in lines))

    def registry_serves_everything(self) -> None:
        for kid, key in ((MK, self.mkey), (GK, self.gkey)):
            self.answers[f"{REG}/v2/keys/{kid}"] = (200, {
                "kid": kid, "alg": "Ed25519", "public_key_pem": _pem(key), "ran": RAN,
                "pq_kid": "abcd1234", "valid_from": "2026-01-01T00:00:00Z", "valid_until": None,
                "status": "active"})
        self.answers[f"{REG}/v2/robots/{RRN}"] = (200, {
            "rrn": RRN, "name": "testbot", "model": "rc-car", "verification_status": "verified",
            "pq_kid": "abcd1234", "registered_at": "2026-09-27T00:00:00Z"})
        self.answers[f"{REG}/v2/authorities/{RAN}"] = (200, {
            "ran": RAN, "organization": "Test", "display_name": "testbot gateway",
            "purpose": "attestation",
            "signing_pub": _raw_b64(self.gkey), "pq_kid": "abcd1234", "status": "active"})

    def fetch(self, url: str):
        status, body = self.answers.get(url, (404, {"error": "not found"}))
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        return pf.Http(url, status, raw if status else b"", "" if status else "URLError: refused")

    def gateway(self, **env_over) -> "pf.GatewayInfo":
        env = {
            "ROBOT_MD_ATTESTATION_KID": GK,
            "ROBOT_MD_ATTESTATION_KEY_FILE": str(self.keyfile),
            "ROBOT_MD_ATTESTATION_RAN": RAN,
            "ROBOT_MD_ATTESTATION_EXPORT_FILE": str(self.export),
            "OPENCASTOR_OPS_RRF_URL": STUB,
            "ROBOT_MANIFEST": str(self.manifest),
            "ROBOT_MD_TOOL_ALLOWLIST": "drive.set,status.report",
        }
        env.update({k: v for k, v in env_over.items() if v is not None})
        for k, v in env_over.items():
            if v is None:
                env.pop(k, None)
        return pf.GatewayInfo(
            unit="testbot-gateway.service", active="active", pid=4242, started_epoch=NOW - 3600,
            env=env, disk_env=dict(env), env_files={str(self.env_file): NOW - 7200},
            robot_md_arg=str(self.manifest))

    def run(self, mode: str = "live", gateway=None, pins=None, **over) -> dict:
        inp = pf.Inputs(
            robot="testbot", manifest_path=str(self.manifest), fixture_path=str(self.fixture),
            pins=self.pins if pins is None else pins, pins_path="pins.json", pins_sha256="0" * 64,
            registry_base=REG, resolver_base=STUB, resolver_source="test", mode=mode,
            gateway=(gateway or self.gateway()) if mode == "live" else None,
            pairing_path=str(self.pairing) if mode == "live" else "",
            host_addrs=["192.0.2.10"], now_epoch=NOW, tool={"name": "t"}, host="testhost")
        for k, v in over.items():
            setattr(inp, k, v)
        return pf.Preflight(inp, self.fetch).run()


def ids(out: dict, severity: str | None = None) -> set[str]:
    return {f["id"] for f in out["findings"] if severity is None or f["severity"] == severity}


def by_mode(out: dict, mode: str) -> str:
    return out["verdicts_by_mode"][mode]["verdict"]


@pytest.fixture
def w(tmp_path: Path) -> World:
    return World(tmp_path)


# -- the three verdicts ------------------------------------------------------


def test_registry_404_everywhere_is_local_keys_only(w: World) -> None:
    out = w.run()
    assert out["verdict"] == "local-keys-only"
    assert by_mode(out, "bench") == "local-keys-only"
    assert out["manifest_signature"] == {"local": "verified", "registry": "not-registered",
                                         "pin": "verified-under-pinned-key"}
    assert {f"kid-not-registered:{MK}", f"kid-not-registered:{GK}", "rrn-not-registered",
            "ran-not-found"} <= ids(out)
    assert out["stop_reasons"] == []


def test_registry_serving_the_pinned_keys_resolves(w: World) -> None:
    w.registry_serves_everything()
    out = w.run()
    assert out["verdict"] == "registry-resolves", out["findings"]
    assert by_mode(out, "bench") == "registry-resolves"
    assert all(out["registry_checks"]["live"].values())
    assert out["manifest_signature"]["registry"] == "verified"
    assert out["gateway"]["ran"]["holds_gateway_key"] is True


def test_bench_mode_reads_no_gateway_and_no_pairing(w: World) -> None:
    w.registry_serves_everything()
    out = w.run(mode="bench")
    assert out["verdict"] == "registry-resolves"
    assert list(out["verdicts_by_mode"]) == ["bench"]
    assert "gateway" not in out and "pairing" not in out
    assert not any("/authorities/" in h["url"] for h in out["http"])


def test_unreachable_registry_is_local_keys_only(w: World) -> None:
    for url in (f"{REG}/v2/keys/{MK}", f"{REG}/v2/keys/{GK}", f"{REG}/v2/robots/{RRN}",
                f"{REG}/v2/robots/_next", f"{REG}/v2/authorities/{RAN}"):
        w.answers[url] = (0, b"")
    out = w.run()
    assert out["verdict"] == "local-keys-only"
    assert f"registry-unreachable:{MK}" in ids(out, "warn")
    assert any(h["status"] == 0 and h["error"] for h in out["http"])


# -- the mismatch table ------------------------------------------------------


def test_fixture_differing_from_live_manifest_stops(w: World) -> None:
    w.fixture.write_bytes(w.manifest.read_bytes() + b" ")
    out = w.run()
    assert out["verdict"] == "STOP:fixture-differs-from-live-manifest"
    assert by_mode(out, "bench").startswith("STOP:fixture-differs")


def test_manifest_signature_failing_against_local_key_stops(w: World) -> None:
    w.manifest.write_bytes(signed_manifest(w.mkey, MK, body=BODY, signed_body=BODY + "tampered"))
    w.fixture.write_bytes(w.manifest.read_bytes())
    out = w.run(mode="bench")
    assert out["verdict"] == "STOP:manifest-signature-fails-local-key"
    assert out["manifest_signature"]["local"] == "failed"


def test_manifest_kid_unknown_to_local_resolver_stops(w: World) -> None:
    del w.answers[f"{STUB}/v2/keys/{MK}"]
    out = w.run(mode="bench")
    assert out["verdict"] == "STOP:manifest-kid-not-resolvable-locally"


def test_squatted_kid_at_registry_stops(w: World) -> None:
    w.registry_serves_everything()
    other = Ed25519PrivateKey.generate()
    w.answers[f"{REG}/v2/keys/{MK}"] = (
        200, {"kid": MK, "public_key_pem": _pem(other), "ran": "RAN-000000000001"})
    out = w.run()
    assert out["verdict"] == f"STOP:registry-key-differs-from-local:{MK}"
    assert out["manifest_signature"]["registry"] == "failed"
    assert by_mode(out, "bench") == out["verdict"]


def test_revoked_kid_stops(w: World) -> None:
    w.answers[f"{REG}/v2/keys/{GK}"] = (410, {"error": "kid revoked", "kid": GK, "ran": RAN})
    out = w.run()
    assert out["verdict"] == f"STOP:kid-revoked:{GK}"
    # The gateway kid is only in use for a live test.
    assert by_mode(out, "bench") == "local-keys-only"


def test_revoked_robot_stops(w: World) -> None:
    w.registry_serves_everything()
    w.answers[f"{REG}/v2/robots/{RRN}"] = (200, {"rrn": RRN, "name": "testbot", "revoked": True,
                                                 "verification_status": "verified"})
    out = w.run(mode="bench")
    assert out["verdict"] == "STOP:robot-revoked"


def test_local_key_differing_from_pin_stops(w: World) -> None:
    w.pins[MK] = dict(w.pins[MK], spki_sha256="0" * 64)
    out = w.run(mode="bench")
    assert out["verdict"] == f"STOP:local-key-differs-from-pin:{MK}"
    assert out["manifest_signature"]["pin"] == "local-key-differs-from-pin"


def test_missing_pin_blocks_registry_resolves_but_does_not_stop(w: World) -> None:
    w.registry_serves_everything()
    out = w.run(mode="bench", pins={})
    assert out["verdict"] == "local-keys-only"
    assert f"no-pin:{MK}" in ids(out, "warn")


def test_pairing_attest_pub_differing_stops_live_only(w: World) -> None:
    w.write_pairing(_spki_der(Ed25519PrivateKey.generate()), GK)
    out = w.run()
    assert out["verdict"] == "STOP:pairing-attest-pub-differs"
    assert by_mode(out, "bench") == "local-keys-only"
    assert out["pairing"]["attest_pub_matches_local"] is False


def test_pairing_attest_kid_differing_stops(w: World) -> None:
    w.write_pairing(_spki_der(w.gkey), "some-other-kid")
    out = w.run()
    assert "pairing-attest-kid-differs" in out["stop_reasons"]


def test_drive_backend_mismatch_stops_live_and_is_recorded_for_bench(w: World) -> None:
    out = w.run(gateway=w.gateway(OPENCASTOR_DRIVE="pca9685"))
    assert out["verdict"] == "STOP:drive-backend-differs-from-manifest"
    assert by_mode(out, "bench") == "local-keys-only"
    assert out["gateway"]["drive"]["state"] == "differs"
    assert out["gateway"]["drive"]["gateway_backends"] == ["PCA9685Drive"]
    f = next(f for f in out["findings"] if f["id"] == "drive-backend-differs-from-manifest")
    assert f["stop_in"] == ["live"]


def test_unset_drive_env_matches_a_simulated_manifest(w: World) -> None:
    out = w.run()
    assert out["gateway"]["drive"]["state"] == "matches"
    assert out["gateway"]["drive"]["gateway_env"] == ""


def test_next_rrn_equal_to_ours_warns_without_stopping(w: World) -> None:
    w.answers[f"{REG}/v2/robots/_next"] = (200, {"next_rrn": RRN})
    out = w.run()
    assert "next-rrn-is-ours" in ids(out, "warn")
    assert out["verdict"] == "local-keys-only"
    assert out["rrn"]["next"]["equals_ours"] is True


# -- the gateway side (live only) --------------------------------------------


def test_ran_holding_a_different_key_is_a_named_warning_not_a_stop(w: World) -> None:
    w.registry_serves_everything()
    other = Ed25519PrivateKey.generate()
    w.answers[f"{REG}/v2/authorities/{RAN}"] = (200, {
        "ran": RAN, "display_name": "old signer", "signing_pub": _raw_b64(other),
        "status": "active"})
    out = w.run()
    assert "ran-holds-different-key" in ids(out, "warn")
    assert out["verdict"] == "local-keys-only"  # no longer registry-resolves, not a stop
    assert out["registry_checks"]["live"]["declared_ran_holds_gateway_key"] is False
    assert by_mode(out, "bench") == "registry-resolves"


def test_retired_pinned_kid_registry_mismatch_is_reported_never_stops(w: World) -> None:
    old_local, old_registry = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    w.pins["testbot-gw-old"] = {"spki_sha256": _spki(old_local),
                                "role": "gateway-attestation-retired", "rrn": RRN, "ran": ""}
    w.answers[f"{STUB}/v2/keys/testbot-gw-old"] = (200, {"public_key_pem": _pem(old_local)})
    w.answers[f"{REG}/v2/keys/testbot-gw-old"] = (
        200, {"public_key_pem": _pem(old_registry), "ran": RAN})
    w.answers[f"{REG}/v2/authorities/{RAN}"] = (
        200, {"ran": RAN, "signing_pub": _raw_b64(old_registry)})
    out = w.run()
    assert "registry-key-differs-from-local:testbot-gw-old" in ids(out, "warn")
    assert out["verdict"] == "local-keys-only"
    assert out["gateway"]["ran"]["registry_kids_with_this_key"] == ["testbot-gw-old"]
    detail = next(f["detail"] for f in out["findings"] if f["id"] == "ran-holds-different-key")
    assert "testbot-gw-old" in detail


def test_rotated_key_file_sidecar_stops(w: World) -> None:
    (w.tmp / "gw-private.pem.pub").write_text(_pem(Ed25519PrivateKey.generate()))
    out = w.run()
    assert "gateway-key-file-differs-from-local-key" in out["stop_reasons"]


def test_receipt_that_fails_the_local_key_stops(w: World) -> None:
    w.write_export(Ed25519PrivateKey.generate(), NOW - 60)
    out = w.run()
    assert "gateway-receipt-fails-local-key" in out["stop_reasons"]
    assert out["export"]["latest_receipt"]["verifies_under_local_key"] is False


def test_newest_receipt_is_checked_and_its_age_reported(w: World) -> None:
    out = w.run()
    lr = out["export"]["latest_receipt"]
    assert lr["verifies_under_local_key"] is True and lr["after_process_start"] is True
    assert lr["corr_id"] == "c-1" and lr["receipt_version"] == 2
    w.write_export(w.gkey, NOW - 99_999)
    out = w.run()
    assert "latest-receipt-predates-process-start" in ids(out, "info")


def test_signer_kids_and_unsigned_invokes_are_counted(w: World) -> None:
    out = w.run()
    assert out["export"]["signed_invokes_by_kid"] == {PHONE: 1}
    assert out["export"]["unsigned_invokes"] == 1
    assert out["signers"][PHONE] == {"seen_in_export_tail": 1, "local": "not-found",
                                     "registry": "not-registered"}
    assert f"signer-kid-not-resolvable-locally:{PHONE}" in ids(out, "warn")
    assert out["verdict"] == "local-keys-only"


def test_enforcement_on_turns_an_unknown_signer_into_a_stop(w: World) -> None:
    out = w.run(gateway=w.gateway(ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE="1"))
    assert out["gateway"]["flags_on"] == ["ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE"]
    assert f"signer-kid-not-resolvable-locally:{PHONE}" in out["stop_reasons"]
    assert "envelope-signature-not-enforced" not in ids(out)


def test_gateway_not_running_stops_live(w: World) -> None:
    gw = w.gateway()
    gw.active, gw.pid = "inactive", 0
    out = w.run(gateway=gw)
    assert out["verdict"] == "STOP:gateway-not-running"
    assert by_mode(out, "bench") == "local-keys-only"


def test_gateway_without_signing_identity_stops(w: World) -> None:
    out = w.run(gateway=w.gateway(ROBOT_MD_ATTESTATION_KID=None))
    assert "gateway-not-signing" in out["stop_reasons"]


def test_env_drift_and_late_env_file_edits_are_warnings(w: World) -> None:
    gw = w.gateway()
    gw.disk_env["OPENCASTOR_DRIVE"] = "pca9685"
    gw.env_files[str(w.env_file)] = NOW  # edited after the process started
    out = w.run(gateway=gw)
    assert {"gateway-env-differs-from-unit-files",
            "gateway-env-file-changed-after-start"} <= ids(out, "warn")
    assert out["gateway"]["env_differs_from_unit_files"] == ["OPENCASTOR_DRIVE"]


def test_allowlist_is_compared_with_manifest_capabilities(w: World) -> None:
    out = w.run()
    assert out["gateway"]["allowlist_vs_manifest"] == {"manifest_only": ["sensor.battery"],
                                                       "gateway_only": []}


def test_pairing_pointing_at_another_host_warns(w: World) -> None:
    out = w.run(host_addrs=["192.0.2.99"])
    assert "pairing-gateway-url-not-this-host" in ids(out, "warn")


# -- output contract ---------------------------------------------------------


def test_output_is_canonical_strings_ints_bools_only_and_never_carries_a_bearer(w: World) -> None:
    w.registry_serves_everything()
    out = w.run()
    pf.check_output_types(out)
    blob = pf.canonical_json(out)
    assert pf.canonical_json(json.loads(blob)) == blob
    assert BEARER.encode() not in blob
    assert b"console_token" not in blob and b"bearer\"" not in blob
    assert b"null" not in blob
    urls = [h["url"] for h in out["http"]]
    assert len(urls) == len(set(urls))  # one GET per URL, cached
    assert all(len(h["body_sha256"]) == 64 for h in out["http"])


def test_check_output_types_rejects_floats_none_and_big_ints() -> None:
    for bad in ({"a": 1.5}, {"a": None}, {"a": 2**53}, {1: "x"}):
        with pytest.raises(TypeError):
            pf.check_output_types(bad)


def test_manifest_facts_match_the_gateway_cut(w: World) -> None:
    out = w.run(mode="bench")
    m = out["manifest"]
    assert m["kid"] == MK and m["rrn"] == RRN and m["sig_bytes"] == 64
    assert m["signed_body_sha256"] == hashlib.sha256(BODY.encode()).hexdigest()
    assert m["capabilities"] == ["drive.set", "status.report", "sensor.battery"]
    assert m["drive"]["backend"] == "SimulatedDrive" and m["drive"]["hardware_present"] == "false"
    assert "manifest-signing-alg-declared-differs" in ids(out, "info")


def test_env_file_reader_keeps_only_listed_names_and_strips_quotes() -> None:
    env = pf.parse_env_file('ROBOT_MD_TOOL_ALLOWLIST="a,b"\nexport ROBOT_MD_REQUIRE_X=1\n'
                            "# c\nSOME_TOKEN=secret\nOPENCASTOR_DRIVE='pca9685'\n")
    assert env == {"ROBOT_MD_TOOL_ALLOWLIST": "a,b", "ROBOT_MD_REQUIRE_X": "1",
                   "OPENCASTOR_DRIVE": "pca9685"}


def test_http_get_sends_a_bodyless_get_with_its_own_user_agent(monkeypatch) -> None:
    seen = []

    class Resp:
        status = 200

        def read(self, n):
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout):
        seen.append(req)
        return Resp()

    monkeypatch.setattr(pf.urllib.request, "urlopen", fake_urlopen)
    r = pf.http_get("https://registry.test/v2/keys/x")
    assert r.status == 200
    req = seen[0]
    assert req.get_method() == "GET" and req.data is None
    assert "Python-urllib" not in req.get_header("User-agent")


def test_the_script_has_exactly_one_network_call_site_and_it_is_a_get() -> None:
    src = SCRIPT.read_text()
    assert src.count("urlopen(") == 1
    assert src.count("method=") == 1 and 'method="GET"' in src
    for verb in ('"POST"', '"PUT"', '"PATCH"', '"DELETE"'):
        assert verb not in src


# -- the real bench fixtures (skipped without the opencastor-ios checkout) ---

FIXTURES = Path.home() / "projects/opencastor-ios/CastorKit/Tests/CastorKitTests/Fixtures"


@pytest.mark.parametrize("name,rrn,kid,backend", [
    ("ROBOT-rover-live.md", "RRN-000000000012", "rover-manifest-2026", "PCA9685Drive"),
    ("ROBOT-bob-live.md", "RRN-000000000011", "bob-manifest-2026", ""),
])
def test_real_bench_fixtures_parse(name, rrn, kid, backend) -> None:
    path = FIXTURES / name
    if not path.is_file():
        pytest.skip("opencastor-ios fixtures not present")
    m = pf.parse_manifest(str(path), path.read_bytes())
    assert (m.rrn, m.kid, len(m.sig)) == (rrn, kid, 64)
    assert m.drive.get("backend", "") == backend
    assert "status.report" in m.capabilities


# -- the CLI, end to end, against a throwaway local HTTP server ---------------


class _Server:
    def __init__(self, answers: dict[str, tuple[int, object]]) -> None:
        outer = answers

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                status, body = outer.get(self.path, (404, {"error": "not found"}))
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()


def test_cli_bench_run_writes_canonical_bytes_and_exits_by_verdict(
    w: World, tmp_path: Path
) -> None:
    pins = tmp_path / "pins.json"
    pins.write_text(json.dumps({"_meta": {"note": "x"}, **w.pins}))
    answers = {
        f"/stub/v2/keys/{MK}": (200, {"kid": MK, "public_key_pem": _pem(w.mkey)}),
        "/reg/v2/robots/_next": (200, {"next_rrn": RRN}),
    }
    srv = _Server(answers)
    try:
        args = [sys.executable, str(SCRIPT), "--robot", "testbot", "--manifest", str(w.manifest),
                "--fixture", str(w.fixture), "--mode", "bench", "--pins", str(pins),
                "--registry-base", srv.base + "/reg", "--resolver-base", srv.base + "/stub"]
        out_file = tmp_path / "pf.json"
        p = subprocess.run(args + ["--out", str(out_file)], capture_output=True, timeout=60)
        assert p.returncode == 3, p.stderr.decode()
        blob = out_file.read_bytes()
        assert p.stdout == blob + b"\n"
        doc = json.loads(blob)
        assert doc["verdict"] == "local-keys-only"
        assert doc["pins_file"]["kids"] == sorted([MK, GK])
        assert doc["pins_file"]["sha256"] == hashlib.sha256(pins.read_bytes()).hexdigest()
        assert doc["tool"]["sha256"] == hashlib.sha256(SCRIPT.read_bytes()).hexdigest()
        assert b"next-rrn-is-ours" in p.stderr

        # the registry now answers for the manifest kid and the robot: bench resolves, exit 0
        answers[f"/reg/v2/keys/{MK}"] = (
            200, {"kid": MK, "public_key_pem": _pem(w.mkey), "ran": RAN})
        answers[f"/reg/v2/robots/{RRN}"] = (
            200, {"rrn": RRN, "name": "testbot", "verification_status": "verified"})
        p = subprocess.run(args + ["--quiet"], capture_output=True, timeout=60)
        assert p.returncode == 0, p.stdout.decode()
        assert json.loads(p.stdout)["verdict"] == "registry-resolves"
        assert p.stderr == b""
    finally:
        srv.close()


def test_cli_usage_errors_exit_2(tmp_path: Path) -> None:
    bad = tmp_path / "pins.json"
    bad.write_text(json.dumps({"k": {"spki_sha256": "nothex"}}))
    p = subprocess.run([sys.executable, str(SCRIPT), "--robot", "x", "--manifest", "/nonexistent",
                        "--mode", "bench", "--pins", str(bad)], capture_output=True, timeout=60)
    assert p.returncode == 2
    p = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, timeout=60)
    assert p.returncode == 2
