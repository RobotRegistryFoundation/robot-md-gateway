#!/usr/bin/env python3
"""RRF identity preflight: which keys a robot's evidence can be checked with, today.

Run before every bench run and every live RCAN test. It answers one question
per robot: can the manifest (and, for a live test, the gateway's receipts) be
checked against keys the public Robot Registry Foundation serves, or only
against the local copies this host holds, or is something inconsistent enough
that the run must not go ahead at all?

It only LOOKS. Every network call is an HTTP GET (one call site, `http_get`),
it never registers, re-signs, restarts, pairs or fixes anything, and it never
talks to a gateway's /v1/invoke. It reads local files (the manifest, the bench
fixture, the pins file, the pairing payload's public fields, the tail of the
gateway's attestation export) and, for a live test, the running gateway's
environment through /proc (a fixed list of non-secret names only).

Like verify_receipt.py it imports only the standard library and
``cryptography``, so a third party can run it without the gateway package.

WHAT IT CHECKS, PER ROBOT (design: rcan-rrf-design.md section A)

 1. Manifest: sha256 of the file, the footer kid, sha256 of the signed body
    (the bytes before the ROBOT-MD-SIG footer, exactly as the gateway's
    manifest_provenance.py cuts them), and whether the bench fixture is the
    same file.
 2. Manifest signature, three ways, recorded separately: (a) against the local
    copy the gateway resolves (the loopback stub, 127.0.0.1:8090 on this Pi),
    (b) against GET <registry>/v2/keys/<kid>, (c) against the pinned SPKI
    fingerprint.
 3. RRN: GET /v2/robots/{rrn} and GET /v2/robots/_next.
 4. Live only, the gateway: signing kid from the running process's env, its
    local copy, registry answer and pin; its RAN (GET /v2/authorities/{ran});
    whether the pairing payload's attest_pub is the gateway's key (the
    `castor pair --force` rotation trap); the non-secret flags (REQUIRE_*,
    OPENCASTOR_DRIVE against the manifest's drive backend, the tool
    allowlist, process start time); the newest receipt in the export tail,
    verified against the local key.
 5. Live only, signer kids seen in the export tail (the phone, a test key):
    the registry's answer and whether the local resolver knows them.

VERDICT (one per mode; the requested mode decides the exit code)

    registry-resolves  every in-use kid resolves publicly to its pinned key,
                       the manifest verifies under the registry's key, the RRN
                       record exists and is not revoked (live: and a declared
                       RAN holds the gateway's key).
    local-keys-only    signatures check out against the local copies, but the
                       registry answers 404, or cannot be reached, or does not
                       back every link above.
    STOP:<reason>      the first stop condition found; `stop_reasons` lists all.

STOP CONDITIONS (section A's mismatch table, plus four key-identity checks
added in the same spirit, marked +):

    fixture differs from the live manifest ............ bench + live
    manifest signature fails against the local key .... bench + live
    registry key differs from the local copy or pin ... wherever the kid is used
    kid answers 410, or the robot record is revoked ... wherever the kid is used
    pairing attest_pub/attest_kid differs from gateway  live
    gateway drive backend differs from the manifest ... live (bench: recorded)
  + local key differs from its pin .................... wherever the kid is used
  + manifest or gateway kid not resolvable locally .... wherever the kid is used
  + gateway key file's .pub sidecar differs from local  live
  + newest receipt fails against the local key ........ live

A kid or RRN answering 404, or an unreachable registry, is never a stop: the
run goes ahead labelled local-keys-only. `next_rrn` equal to our RRN is a
warning. Kids that are pinned for this RRN but not in use (a retired key) are
checked and reported, and never stop anything.

The registry is a directory of identities and keys. It enforces nothing, and
nothing here may be read as the registry refusing, allowing or approving an
action. A verdict says which keys the evidence can be checked with; it says
nothing about whether any action is safe or correct.

OUTPUT is canonical JSON (sorted keys, compact, UTF-8, no ASCII escaping) whose
values are strings, integers and booleans only, so it can be embedded in a
bench `run` line and sealed. Every GET is listed with its HTTP status and the
sha256 of its body, so anyone can repeat it and compare. No bearer, token or
private key byte is ever read into the output: the pairing payload is read for
v, gateway_url, rrn, manifest_path, attest_kid and attest_pub only, and the
output is refused if a secret value from that file appears in it anyway.

Usage:
    python scripts/rrf_preflight.py --robot rover --pins pins.json --out pf.json
    python scripts/rrf_preflight.py --robot bob --pins pins.json --mode bench
    python scripts/rrf_preflight.py --manifest ROBOT.md --fixture fix.md \\
        --mode bench --pins pins.json

Exit codes:
    0  registry-resolves (for --mode)
    3  local-keys-only   (for --mode): run, labelled; no registry claim anywhere
    1  STOP:<reason>     (for --mode): do not run
    2  usage or input error
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PREFLIGHT_VERSION = 1
DEFAULT_REGISTRY = "https://robotregistryfoundation.org"
DEFAULT_RESOLVER = "http://127.0.0.1:8090"
# Cloudflare in front of the registry answers 403 to the default
# Python-urllib User-Agent (see auth.py RRFResolverFromEnv).
USER_AGENT = "robot-md-gateway-rrf-preflight/1 (+GET-only identity check)"
HTTP_TIMEOUT_S = 10
MAX_BODY = 1 << 20
EXPORT_TAIL_BYTES = 512 * 1024
MAX_SAFE_INT = 2**53

VERDICT_REGISTRY = "registry-resolves"
VERDICT_LOCAL = "local-keys-only"
BENCH, LIVE = "bench", "live"
BOTH = (BENCH, LIVE)
TRUTHY = {"1", "true", "yes", "on"}

EXIT_REGISTRY, EXIT_STOP, EXIT_USAGE, EXIT_LOCAL = 0, 1, 2, 3

# This Pi's layout. Every path can be overridden on the command line.
_FIXTURES = "~/projects/opencastor-ios/CastorKit/Tests/CastorKitTests/Fixtures"
PROFILES: dict[str, dict[str, str]] = {
    "rover": {
        "manifest": "~/rover/ROBOT.md",
        "fixture": f"{_FIXTURES}/ROBOT-rover-live.md",
        "unit": "rover-gateway.service",
        "pairing": "~/rover/pair-payload.json",
    },
    "bob": {
        "manifest": "~/bob/ROBOT.md",
        "fixture": f"{_FIXTURES}/ROBOT-bob-live.md",
        "unit": "bob-gateway.service",
        "pairing": "~/bob/pair-payload.json",
    },
}

# The only environment names ever read from a gateway process or its unit
# files. Paths and flags, never a credential. ROBOT_MD_REQUIRE_* is matched by
# prefix so a flag added later is reported rather than silently missed.
GATEWAY_ENV_NAMES = (
    "ROBOT_MD_ATTESTATION_KID",
    "ROBOT_MD_ATTESTATION_RAN",
    "ROBOT_MD_ATTESTATION_KEY_FILE",
    "ROBOT_MD_ATTESTATION_EXPORT_FILE",
    "OPENCASTOR_OPS_RRF_URL",
    "ROBOT_MANIFEST",
    "ROBOT_MD_PATH",
    "ROBOT_MD_BEARERS_FILE",
    "ROBOT_MD_HITL_FROM_MANIFEST",
    "ROBOT_MD_ENVELOPE_MAX_SKEW_S",
    "ROBOT_MD_TOOL_ALLOWLIST",
    "ROBOT_MD_TOOL_MIN_TIER",
    "OPENCASTOR_DRIVE",
)
GATEWAY_ENV_PREFIXES = ("ROBOT_MD_REQUIRE_",)
PAIRING_PUBLIC_FIELDS = ("v", "gateway_url", "rrn", "manifest_path", "attest_kid", "attest_pub")
PAIRING_SECRET_FIELDS = ("bearer", "console_token", "commission_bearer", "token")

# OPENCASTOR_DRIVE value -> the drive class names a manifest may declare for it
# (rc_car_actuator.backend.drive_from_env). Unset means SimulatedDrive.
DRIVE_BACKENDS: dict[str, tuple[str, ...]] = {
    "simulated": ("SimulatedDrive",),
    "sim": ("SimulatedDrive",),
    "none": ("SimulatedDrive",),
    "pca9685": ("PCA9685Drive",),
    "pca9685-tank": ("PCA9685Drive", "DifferentialMixer"),
    "maestro": ("MaestroDrive",),
    "pigpio": ("PWMDrive",),
}

# Same footer grammar as robot_md_gateway/manifest_provenance.py.
_SIG_RE = re.compile(
    r"\n<!--\s*ROBOT-MD-SIG\s+kid=(?P<kid>\S+)\s+sig=(?P<sig>[A-Za-z0-9+/=]+)\s*-->\s*\Z",
)


class UsageError(Exception):
    """Bad arguments or unreadable required input: exit 2."""


# --------------------------------------------------------------------------
# canonical JSON (same recipe as verify_receipt.py) and hashing
# --------------------------------------------------------------------------


def canonical_json(body: Any) -> bytes:
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _normalize(v: Any) -> Any:
    """rcan canonical normalization (whole-number floats -> int); receipts only."""
    if isinstance(v, bool):
        return v
    if isinstance(v, float) and v.is_integer():
        return int(v)
    if isinstance(v, dict):
        return {k: _normalize(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_normalize(x) for x in v]
    return v


def receipt_signed_bytes(outcome: dict) -> bytes:
    body = {k: v for k, v in outcome.items() if k != "envelope_signature"}
    return canonical_json(_normalize(body))


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def check_output_types(x: Any, path: str = "$") -> None:
    """Strings, integers (|n| < 2^53) and booleans only, in lists and objects."""
    if isinstance(x, (bool, str)):
        return
    if isinstance(x, int):
        if abs(x) >= MAX_SAFE_INT:
            raise TypeError(f"{path}: integer {x} is not below 2^53")
        return
    if isinstance(x, list):
        for i, v in enumerate(x):
            check_output_types(v, f"{path}[{i}]")
        return
    if isinstance(x, dict):
        for k, v in x.items():
            if not isinstance(k, str) or not k.isascii():
                raise TypeError(f"{path}: key {k!r} is not an ASCII string")
            check_output_types(v, f"{path}.{k}")
        return
    raise TypeError(f"{path}: {type(x).__name__} is not allowed in a preflight")


def _s(v: Any) -> str:
    """A registry string field, or "" when absent/null/not a string."""
    return v if isinstance(v, str) else ""


def utc_iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(ts: str) -> int:
    """ISO-8601 -> epoch seconds, or -1 when it cannot be read."""
    try:
        return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())
    except (ValueError, AttributeError):
        return -1


# --------------------------------------------------------------------------
# keys
# --------------------------------------------------------------------------


def _spki_der(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def pub_from_pem(pem: bytes) -> Ed25519PublicKey | None:
    try:
        pub = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError):
        return None
    return pub if isinstance(pub, Ed25519PublicKey) else None


def pub_from_raw_b64(b64: str) -> Ed25519PublicKey | None:
    try:
        raw = base64.b64decode(b64, validate=True)
        return Ed25519PublicKey.from_public_bytes(raw) if len(raw) == 32 else None
    except (ValueError, TypeError):
        return None


def pub_from_spki_b64(b64: str) -> Ed25519PublicKey | None:
    try:
        pub = serialization.load_der_public_key(base64.b64decode(b64, validate=True))
    except (ValueError, TypeError):
        return None
    return pub if isinstance(pub, Ed25519PublicKey) else None


def spki_sha256(pub: Ed25519PublicKey | None) -> str:
    return sha256_hex(_spki_der(pub)) if pub is not None else ""


def ed25519_verifies(pub: Ed25519PublicKey | None, sig: bytes, msg: bytes) -> bool:
    if pub is None:
        return False
    try:
        pub.verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


# --------------------------------------------------------------------------
# HTTP: GET only, one call site, every answer recorded
# --------------------------------------------------------------------------


@dataclass
class Http:
    url: str
    status: int  # 0 = no HTTP answer at all (DNS, refused, timeout, TLS)
    body: bytes = b""
    error: str = ""

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except (ValueError, UnicodeDecodeError):
            return None

    def record(self) -> dict:
        return {
            "url": self.url,
            "status": self.status,
            "body_sha256": sha256_hex(self.body),
            "bytes": len(self.body),
            "error": self.error,
        }


def http_get(url: str) -> Http:
    """The one network call in this file. GET, no body, bounded read."""
    req = urllib.request.Request(
        url, method="GET",
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:  # noqa: S310
            return Http(url, int(resp.status), resp.read(MAX_BODY))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(MAX_BODY) or b""
        except Exception:  # noqa: BLE001
            body = b""
        return Http(url, int(exc.code), body)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        return Http(url, 0, b"", f"{type(exc).__name__}: {reason}"[:200])


class Recorder:
    """Wraps a GET function: caches per URL and keeps every answer, in order."""

    def __init__(self, fetch: Callable[[str], Http]) -> None:
        self._fetch = fetch
        self._cache: dict[str, Http] = {}
        self.log: list[dict] = []

    def get(self, url: str) -> Http:
        if url not in self._cache:
            r = self._fetch(url)
            self._cache[url] = r
            self.log.append(r.record())
        return self._cache[url]


def _url(base: str, *parts: str) -> str:
    return base.rstrip("/") + "/" + "/".join(urllib.parse.quote(p, safe="") for p in parts)


# --------------------------------------------------------------------------
# manifest
# --------------------------------------------------------------------------


def _scalar(raw: str) -> str:
    v = raw.strip()
    if v[:1] in ("'", '"'):
        end = v.find(v[0], 1)
        return v[1:end] if end > 0 else v[1:]
    return v.split(" #", 1)[0].strip()


def _frontmatter(text: str) -> list[str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return []
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return lines[1:i]
    return []


def _top_blocks(fm: list[str]) -> dict[str, list[str]]:
    blocks: dict[str, list[str]] = {}
    cur = None
    for ln in fm:
        m = re.match(r"^([A-Za-z_][\w-]*):(.*)$", ln)
        if m:
            cur = m.group(1)
            blocks[cur] = []
        elif cur is not None:
            blocks[cur].append(ln)
    return blocks


def _block_scalars(lines: list[str], indent: int = 2) -> dict[str, str]:
    out: dict[str, str] = {}
    pat = re.compile(r"^ {%d}([A-Za-z_][\w-]*):(.*)$" % indent)
    for ln in lines:
        m = pat.match(ln)
        if m and m.group(2).strip():
            out.setdefault(m.group(1), _scalar(m.group(2)))
    return out


def _block_list(lines: list[str]) -> list[str]:
    out = []
    for ln in lines:
        m = re.match(r"^ {0,2}-\s+([^\s#:]+)\s*(#.*)?$", ln)
        if m:
            out.append(m.group(1))
    return out


def _block_items(lines: list[str]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for ln in lines:
        m = re.match(r"^  - ([A-Za-z_][\w-]*):(.*)$", ln)
        if m:
            items.append({m.group(1): _scalar(m.group(2))})
            continue
        m = re.match(r"^    ([A-Za-z_][\w-]*):(.*)$", ln)
        if m and items and m.group(2).strip():
            items[-1].setdefault(m.group(1), _scalar(m.group(2)))
    return items


@dataclass
class Manifest:
    path: str
    raw: bytes
    kid: str = ""
    sig: bytes = b""
    sig_b64_ok: bool = False
    body: bytes = b""
    footer: bool = False
    rrn: str = ""
    robot_name: str = ""
    signing_alg: str = ""
    capabilities: list[str] = field(default_factory=list)
    drive: dict[str, str] = field(default_factory=dict)


def parse_manifest(path: str, raw: bytes) -> Manifest:
    m = Manifest(path=path, raw=raw)
    text = raw.decode("utf-8", errors="replace")
    match = _SIG_RE.search(text)
    if match is not None:
        m.footer = True
        m.kid = match.group("kid")
        m.body = text[: match.start()].encode("utf-8")
        try:
            m.sig = base64.b64decode(match.group("sig"), validate=True)
            m.sig_b64_ok = True
        except ValueError:
            m.sig = b""
    blocks = _top_blocks(_frontmatter(text))
    meta = _block_scalars(blocks.get("metadata", []))
    m.rrn = meta.get("rrn", "")
    m.robot_name = meta.get("robot_name", "")
    m.signing_alg = _block_scalars(blocks.get("network", [])).get("signing_alg", "")
    m.capabilities = _block_list(blocks.get("capabilities", []))
    for item in _block_items(blocks.get("drivers", [])):
        if item.get("id") == "drive" or item.get("backend", "").endswith("Drive"):
            keys = ("id", "protocol", "backend", "hardware_present")
            m.drive = {k: item.get(k, "") for k in keys}
            break
    return m


# --------------------------------------------------------------------------
# gateway facts (live only) — gathered by collect_gateway(), injected in tests
# --------------------------------------------------------------------------


@dataclass
class GatewayInfo:
    unit: str
    active: str = ""
    pid: int = 0
    started_epoch: int = -1
    env: dict[str, str] = field(default_factory=dict)       # running process
    disk_env: dict[str, str] = field(default_factory=dict)  # unit + env files
    env_files: dict[str, int] = field(default_factory=dict)  # path -> mtime
    robot_md_arg: str = ""
    error: str = ""


def _wanted_env(name: str) -> bool:
    return name in GATEWAY_ENV_NAMES or name.startswith(GATEWAY_ENV_PREFIXES)


def parse_env_file(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#") or "=" not in ln:
            continue
        name, _, val = ln.partition("=")
        name = name.strip()
        if name.startswith("export "):
            name = name[7:].strip()
        if not _wanted_env(name):
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        out[name] = val
    return out


def _process_start_epoch(pid: int) -> int:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        fields = stat[stat.rindex(")") + 2:].split()
        start_ticks = int(fields[19])  # field 22 overall
        btime = next(
            int(ln.split()[1]) for ln in Path("/proc/stat").read_text().splitlines()
            if ln.startswith("btime ")
        )
        return btime + start_ticks // os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, StopIteration, IndexError):
        return -1


def collect_gateway(unit: str) -> GatewayInfo:
    """Read-only: `systemctl --user show`, /proc/<pid>/{environ,cmdline,stat}."""
    info = GatewayInfo(unit=unit)
    unit_env: dict[str, str] = {}
    file_env: dict[str, str] = {}
    try:
        out = subprocess.run(
            ["systemctl", "--user", "show", unit, "-p", "ActiveState", "-p", "MainPID",
             "-p", "EnvironmentFiles", "-p", "Environment"],
            capture_output=True, text=True, timeout=10, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        info.error = f"systemctl failed: {type(exc).__name__}"
        return info
    for ln in out.splitlines():
        key, _, val = ln.partition("=")
        if key == "ActiveState":
            info.active = val
        elif key == "MainPID":
            info.pid = int(val) if val.isdigit() else 0
        elif key == "EnvironmentFiles" and val:
            path = val.split(" (", 1)[0]
            try:
                info.env_files[path] = int(os.stat(path).st_mtime)
                file_env.update(parse_env_file(Path(path).read_text()))
            except OSError:
                info.env_files[path] = -1
        elif key == "Environment" and val:
            try:
                for tok in shlex.split(val):
                    name, _, v = tok.partition("=")
                    if _wanted_env(name):
                        unit_env[name] = v
            except ValueError:
                pass
    # systemd: a value from EnvironmentFile= overrides the same name in Environment=.
    info.disk_env = {**unit_env, **file_env}
    if info.pid <= 0:
        info.error = info.error or "unit has no main process"
        return info
    try:
        environ = Path(f"/proc/{info.pid}/environ").read_bytes().split(b"\0")
        for item in environ:
            name, _, val = item.decode("utf-8", "replace").partition("=")
            if _wanted_env(name):
                info.env[name] = val
        argv = Path(f"/proc/{info.pid}/cmdline").read_bytes().split(b"\0")
        args = [a.decode("utf-8", "replace") for a in argv]
        if "--robot-md" in args and args.index("--robot-md") + 1 < len(args):
            info.robot_md_arg = args[args.index("--robot-md") + 1]
    except OSError as exc:
        info.error = f"cannot read /proc/{info.pid}: {type(exc).__name__}"
    info.started_epoch = _process_start_epoch(info.pid)
    return info


def host_addresses() -> list[str]:
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True, text=True,
                             timeout=5, check=False).stdout
        return sorted(set(out.split()))
    except (OSError, subprocess.SubprocessError):
        return []


# --------------------------------------------------------------------------
# findings and verdicts
# --------------------------------------------------------------------------


@dataclass
class Finding:
    id: str
    detail: str
    stop_in: tuple[str, ...] = ()
    level: str = "info"  # severity outside stop_in: "warn" or "info"

    def to_json(self, mode: str) -> dict:
        return {
            "id": self.id,
            "detail": self.detail,
            "severity": "stop" if mode in self.stop_in else self.level,
            "stop_in": list(self.stop_in),
        }


def verdict_for(
    mode: str, findings: list[Finding], registry_checks: dict[str, bool]
) -> tuple[str, list[str]]:
    stops = [f.id for f in findings if mode in f.stop_in]
    if stops:
        return "STOP:" + stops[0], stops
    if registry_checks and all(registry_checks.values()):
        return VERDICT_REGISTRY, []
    return VERDICT_LOCAL, []


# --------------------------------------------------------------------------
# the preflight
# --------------------------------------------------------------------------


@dataclass
class Inputs:
    robot: str
    manifest_path: str
    fixture_path: str
    pins: dict[str, dict]
    pins_path: str
    pins_sha256: str
    registry_base: str
    resolver_base: str
    resolver_source: str
    mode: str
    gateway: GatewayInfo | None = None
    pairing_path: str = ""
    export_path: str = ""
    host_addrs: list[str] = field(default_factory=list)
    now_epoch: int = 0
    tool: dict = field(default_factory=dict)
    host: str = ""


class Preflight:
    def __init__(self, inp: Inputs, fetch: Callable[[str], Http]) -> None:
        self.inp = inp
        self.http = Recorder(fetch)
        self.findings: list[Finding] = []
        self.kids: dict[str, dict] = {}
        self._pubs: dict[tuple[str, str], Ed25519PublicKey | None] = {}
        self.secrets: list[str] = []
        self.inp_rrn = ""

    # -- helpers -----------------------------------------------------------

    def find(
        self, fid: str, detail: str, stop_in: tuple[str, ...] = (), level: str = "info"
    ) -> None:
        self.findings.append(Finding(fid, detail, stop_in, level))

    def lookup_local(self, kid: str) -> dict:
        r = self.http.get(_url(self.inp.resolver_base, "v2", "keys", kid))
        rec = {"url": r.url, "status": r.status, "body_sha256": sha256_hex(r.body),
               "result": "", "spki_sha256": ""}
        pub = None
        if r.status == 200:
            body = r.json()
            pem = body.get("public_key_pem") if isinstance(body, dict) else None
            pub = pub_from_pem(pem.encode()) if isinstance(pem, str) else None
            rec["result"] = "found" if pub else "bad-response"
        elif r.status == 404:
            rec["result"] = "not-found"
        else:
            rec["result"] = "unreachable" if r.status == 0 else f"http-{r.status}"
        rec["spki_sha256"] = spki_sha256(pub)
        self._pubs[("local", kid)] = pub
        return rec

    def lookup_registry(self, kid: str) -> dict:
        r = self.http.get(_url(self.inp.registry_base, "v2", "keys", kid))
        rec = {"url": r.url, "status": r.status, "body_sha256": sha256_hex(r.body),
               "result": "", "spki_sha256": "", "ran": "", "key_status": "",
               "pq_kid": "", "valid_from": "", "valid_until": ""}
        body = r.json() if r.body else None
        pub = None
        if r.status == 200:
            pem = body.get("public_key_pem") if isinstance(body, dict) else None
            pub = pub_from_pem(pem.encode()) if isinstance(pem, str) else None
            rec["result"] = "found" if pub else "bad-response"
            if isinstance(body, dict):
                for k in ("ran", "pq_kid", "valid_from", "valid_until"):
                    rec[k] = _s(body.get(k))
                rec["key_status"] = _s(body.get("status"))
        elif r.status == 404:
            rec["result"] = "not-registered"
        elif r.status == 410:
            rec["result"] = "revoked"
            if isinstance(body, dict):
                rec["ran"] = _s(body.get("ran"))
        elif r.status == 0:
            rec["result"] = "unreachable"
        elif r.status >= 500:
            rec["result"] = "server-error"
        else:
            rec["result"] = f"http-{r.status}"
        rec["spki_sha256"] = spki_sha256(pub)
        self._pubs[("registry", kid)] = pub
        return rec

    def check_kid(self, kid: str, role: str, in_use: tuple[str, ...]) -> dict:
        """Local copy, registry answer and pin for one kid; findings by name."""
        if kid in self.kids:
            entry = self.kids[kid]
            entry["roles_here"] = sorted(set(entry["roles_here"]) | {role})
            entry["in_use_in"] = sorted(set(entry["in_use_in"]) | set(in_use))
            return entry
        local = self.lookup_local(kid)
        reg = self.lookup_registry(kid)
        pin = self.inp.pins.get(kid)
        pin_rec = {"present": pin is not None, "spki_sha256": "", "role": "", "rrn": "", "ran": ""}
        if pin is not None:
            for k in ("spki_sha256", "role", "rrn", "ran"):
                pin_rec[k] = _s(pin.get(k)).lower() if k == "spki_sha256" else _s(pin.get(k))
        lspki, rspki, pspki = local["spki_sha256"], reg["spki_sha256"], pin_rec["spki_sha256"]
        entry = {
            "kid": kid, "roles_here": [role], "in_use_in": list(in_use),
            "local": local, "registry": reg, "pin": pin_rec,
            "local_matches_pin": bool(pin and lspki and lspki == pspki),
            "registry_matches_local": bool(rspki and rspki == lspki),
            "registry_matches_pin": bool(pin and rspki and rspki == pspki),
        }
        self.kids[kid] = entry
        lvl = "warn"
        # pin
        if pin is None:
            self.find(f"no-pin:{kid}",
                      f"{kid} has no pin, so no registry answer for it can be accepted",
                      level="warn" if role in ("manifest", "gateway-attestation") else "info")
        elif local["result"] == "found" and not entry["local_matches_pin"]:
            self.find(f"local-key-differs-from-pin:{kid}",
                      f"the local copy of {kid} (spki {lspki[:16]}) is not the pinned key "
                      f"(spki {pspki[:16]}): rotated or replaced since it was pinned",
                      stop_in=in_use, level=lvl)
        # registry
        res = reg["result"]
        if res == "found":
            if local["result"] == "found" and not entry["registry_matches_local"]:
                self.find(f"registry-key-differs-from-local:{kid}",
                          f"the registry serves a different key under {kid} "
                          f"(spki {rspki[:16]}, {reg['ran'] or 'no RAN'}) than the local "
                          f"copy (spki {lspki[:16]}): the name is squatted, or one side rotated",
                          stop_in=in_use, level=lvl)
            elif pin is not None and not entry["registry_matches_pin"]:
                self.find(f"registry-key-differs-from-pin:{kid}",
                          f"the registry serves a key under {kid} that is not the pinned key",
                          stop_in=in_use, level=lvl)
            if pin is not None and pin_rec["ran"] and reg["ran"] != pin_rec["ran"]:
                self.find(f"registry-ran-differs-from-pin:{kid}",
                          f"the registry maps {kid} to {reg['ran'] or 'no RAN'}, "
                          f"the pin says {pin_rec['ran']}", level="warn")
        elif res == "revoked":
            self.find(f"kid-revoked:{kid}", f"the registry answers 410 (revoked) for {kid}",
                      stop_in=in_use, level=lvl)
        elif res == "not-registered":
            self.find(f"kid-not-registered:{kid}",
                      f"the registry answers 404 for {kid}; it can only be checked against "
                      "local copies")
        else:
            self.find(f"registry-unreachable:{kid}",
                      f"no usable registry answer for {kid} ({res}); it can only be checked "
                      "against local copies", level="warn")
        if pin is not None:
            if pin_rec["role"] and pin_rec["role"] != role:
                self.find(f"pin-role-differs:{kid}",
                          f"{kid} is used here as {role}, pinned as {pin_rec['role']}",
                          level="warn")
            if pin_rec["rrn"] and self.inp_rrn and pin_rec["rrn"] != self.inp_rrn:
                self.find(f"pin-rrn-differs:{kid}",
                          f"{kid} is pinned to {pin_rec['rrn']}, this robot is {self.inp_rrn}",
                          level="warn")
        return entry

    # -- the run -----------------------------------------------------------

    def run(self) -> dict:
        inp = self.inp
        out: dict[str, Any] = {
            "preflight_version": PREFLIGHT_VERSION,
            "robot": inp.robot,
            "mode": inp.mode,
            "checked_at": utc_iso(inp.now_epoch),
            "host": inp.host,
            "tool": inp.tool,
            "registry_base": inp.registry_base,
            "resolver_base": inp.resolver_base,
            "resolver_source": inp.resolver_source,
            "pins_file": {"path": inp.pins_path, "sha256": inp.pins_sha256,
                          "kids": sorted(k for k in inp.pins)},
            "not_claimed": [
                "the registry enforces nothing; a verdict says which keys the evidence can be "
                "checked with",
                "nothing here says an action is safe or correct",
            ],
        }
        mf = self._manifest(out)
        modes = (BENCH, LIVE) if inp.mode == LIVE else (BENCH,)
        registry_checks: dict[str, dict[str, bool]] = {m: {} for m in modes}
        if mf is not None:
            self._manifest_keys(out, mf, registry_checks)
            self._rrn(out, mf, registry_checks)
            if inp.mode == LIVE:
                self._gateway(out, mf, registry_checks)
            self._other_pins(mf)
        self._name_ran_key(out)
        out["kids"] = self.kids
        out["registry_checks"] = registry_checks
        out["findings"] = [f.to_json(inp.mode) for f in self.findings]
        verdicts = {}
        for m in modes:
            v, stops = verdict_for(m, self.findings, registry_checks[m])
            verdicts[m] = {"verdict": v, "stop_reasons": stops}
        out["verdicts_by_mode"] = verdicts
        out["verdict"] = verdicts[inp.mode]["verdict"]
        out["stop_reasons"] = verdicts[inp.mode]["stop_reasons"]
        out["http"] = self.http.log
        check_output_types(out)
        return out

    def _manifest(self, out: dict) -> Manifest | None:
        inp = self.inp
        rec: dict[str, Any] = {"path": inp.manifest_path}
        out["manifest"] = rec
        try:
            raw = Path(inp.manifest_path).read_bytes()
        except OSError as exc:
            rec["error"] = type(exc).__name__
            self.find("manifest-unreadable", f"cannot read {inp.manifest_path}", stop_in=BOTH)
            return None
        mf = parse_manifest(inp.manifest_path, raw)
        self.inp_rrn = mf.rrn
        rec.update({
            "sha256": sha256_hex(raw), "bytes": len(raw), "footer": mf.footer, "kid": mf.kid,
            "signed_body_sha256": sha256_hex(mf.body) if mf.footer else "",
            "signed_body_bytes": len(mf.body), "sig_bytes": len(mf.sig),
            "rrn": mf.rrn, "robot_name": mf.robot_name,
            "signing_alg_declared": mf.signing_alg,
            "capabilities": mf.capabilities,
            "drive": mf.drive,
        })
        fx: dict[str, Any] = {"path": inp.fixture_path, "checked": bool(inp.fixture_path)}
        rec["fixture"] = fx
        if inp.fixture_path:
            try:
                fraw = Path(inp.fixture_path).read_bytes()
                fx["sha256"] = sha256_hex(fraw)
                fx["matches_live"] = fraw == raw
                if not fx["matches_live"]:
                    self.find("fixture-differs-from-live-manifest",
                              f"the fixture {inp.fixture_path} (sha256 {fx['sha256'][:16]}) is not "
                              f"the live manifest (sha256 {rec['sha256'][:16]})", stop_in=BOTH)
            except OSError as exc:
                fx["error"] = type(exc).__name__
                self.find("fixture-unreadable", f"cannot read the fixture {inp.fixture_path}",
                          stop_in=BOTH)
        else:
            self.find("no-fixture-compared",
                      "no bench fixture was given, so fixture-vs-live equality was not checked")
        if not mf.footer:
            self.find("manifest-unsigned", "the manifest has no ROBOT-MD-SIG footer", stop_in=BOTH)
            return None
        if not mf.sig_b64_ok:
            self.find("manifest-signature-malformed", "the footer's sig is not valid base64",
                      stop_in=BOTH)
            return None
        if not mf.rrn:
            self.find("manifest-has-no-rrn",
                      "metadata.rrn is missing, so there is no registry record to look up",
                      level="warn")
        if mf.signing_alg and mf.signing_alg.lower() not in ("ed25519",) and len(mf.sig) == 64:
            self.find("manifest-signing-alg-declared-differs",
                      f"network.signing_alg says {mf.signing_alg}; the footer is a 64-byte "
                      "Ed25519 signature")
        return mf

    def _manifest_keys(self, out: dict, mf: Manifest, registry_checks: dict) -> None:
        entry = self.check_kid(mf.kid, "manifest", BOTH)
        local_pub = self._pubs.get(("local", mf.kid))
        reg_pub = self._pubs.get(("registry", mf.kid))
        sig_rec: dict[str, str] = {}
        if entry["local"]["result"] != "found":
            sig_rec["local"] = "unresolved"
            self.find("manifest-kid-not-resolvable-locally",
                      f"the local resolver cannot serve {mf.kid} ({entry['local']['result']}); "
                      "the gateway would refuse every invoke at manifest_provenance",
                      stop_in=BOTH)
        elif ed25519_verifies(local_pub, mf.sig, mf.body):
            sig_rec["local"] = "verified"
        else:
            sig_rec["local"] = "failed"
            self.find("manifest-signature-fails-local-key",
                      f"the manifest signature does not verify under the local copy of {mf.kid}",
                      stop_in=BOTH)
        rres = entry["registry"]["result"]
        if rres == "found":
            ok = ed25519_verifies(reg_pub, mf.sig, mf.body)
            sig_rec["registry"] = "verified" if ok else "failed"
        else:
            sig_rec["registry"] = rres
        if not entry["pin"]["present"]:
            sig_rec["pin"] = "no-pin"
        elif sig_rec["local"] == "verified" and entry["local_matches_pin"]:
            sig_rec["pin"] = "verified-under-pinned-key"
        elif sig_rec["registry"] == "verified" and entry["registry_matches_pin"]:
            sig_rec["pin"] = "verified-under-pinned-key"
        elif entry["local"]["result"] == "found" and not entry["local_matches_pin"]:
            sig_rec["pin"] = "local-key-differs-from-pin"
        else:
            sig_rec["pin"] = "not-verified"
        out["manifest_signature"] = sig_rec
        backed = bool(entry["registry"]["result"] == "found" and entry["registry_matches_local"]
                      and entry["registry_matches_pin"])
        for m in registry_checks:
            registry_checks[m]["manifest_kid_registry_is_pinned_and_local_key"] = backed
            registry_checks[m]["manifest_verifies_under_registry_key"] = (
                sig_rec["registry"] == "verified")

    def _rrn(self, out: dict, mf: Manifest, registry_checks: dict) -> None:
        rec: dict[str, Any] = {"rrn": mf.rrn}
        out["rrn"] = rec
        ok = False
        if mf.rrn:
            r = self.http.get(_url(self.inp.registry_base, "v2", "robots", mf.rrn))
            body = r.json() if r.body else None
            rec.update({"url": r.url, "status": r.status, "body_sha256": sha256_hex(r.body)})
            if r.status == 200 and isinstance(body, dict):
                revoked = body.get("revoked") is True
                rec["record"] = {
                    "name": _s(body.get("name")), "model": _s(body.get("model")),
                    "manufacturer": _s(body.get("manufacturer")),
                    "verification_status": _s(body.get("verification_status")),
                    "revoked": revoked, "revoked_at": _s(body.get("revoked_at")),
                    "pq_kid": _s(body.get("pq_kid")),
                    "registered_at": _s(body.get("registered_at")),
                    "ruri": _s(body.get("ruri")),
                    "has_ed25519_key": "signing_pub" in body or "public_key_pem" in body,
                }
                if revoked:
                    self.find("robot-revoked", f"the registry marks {mf.rrn} revoked", stop_in=BOTH)
                else:
                    ok = True
                rr = rec["record"]
                vs = rr["verification_status"]
                if vs != "verified":
                    detail = (f"{mf.rrn} exists with verification_status '{vs}', pq_kid "
                              f"{rr['pq_kid'] or 'none'}, registered {rr['registered_at']}")
                    if not rr["has_ed25519_key"]:
                        detail += "; the record holds no Ed25519 key and names no manifest kid"
                    self.find("rrn-record-unverified", detail)
                if mf.robot_name and rr["name"] and rr["name"] != mf.robot_name:
                    self.find("rrn-record-name-differs",
                              f"the registry names {mf.rrn} '{rr['name']}', the manifest says "
                              f"'{mf.robot_name}'", level="warn")
            elif r.status == 404:
                self.find("rrn-not-registered", f"the registry answers 404 for {mf.rrn}")
            else:
                self.find("rrn-registry-unreachable",
                          f"no usable registry answer for {mf.rrn} (HTTP {r.status})", level="warn")
        nx = self.http.get(_url(self.inp.registry_base, "v2", "robots", "_next"))
        nbody = nx.json() if nx.body else None
        next_rrn = _s(nbody.get("next_rrn")) if isinstance(nbody, dict) else ""
        rec["next"] = {"url": nx.url, "status": nx.status, "body_sha256": sha256_hex(nx.body),
                       "next_rrn": next_rrn, "equals_ours": bool(mf.rrn and next_rrn == mf.rrn)}
        if rec["next"]["equals_ours"]:
            self.find("next-rrn-is-ours",
                      f"the registry's next number to issue is {mf.rrn}, this robot's own "
                      "unregistered RRN: whoever registers next is given it", level="warn")
        for m in registry_checks:
            registry_checks[m]["rrn_record_exists_not_revoked"] = ok

    def _gateway(self, out: dict, mf: Manifest, registry_checks: dict) -> None:
        inp = self.inp
        gw = inp.gateway
        rec: dict[str, Any] = {"unit": gw.unit if gw else ""}
        out["gateway"] = rec
        if gw is None or gw.error or gw.pid <= 0 or gw.active != "active":
            if gw is None:
                rec["error"] = "no gateway unit given"
            else:
                rec["error"] = gw.error or f"unit is {gw.active or 'unknown'}, pid {gw.pid}"
            self.find("gateway-not-running", f"cannot read the running gateway: {rec['error']}",
                      stop_in=(LIVE,))
            return
        env = gw.env
        rec.update({
            "active": gw.active, "main_pid": gw.pid,
            "process_started_at": utc_iso(gw.started_epoch) if gw.started_epoch >= 0 else "",
            "env": {k: env[k] for k in sorted(env)},
            "robot_md_arg": gw.robot_md_arg,
        })
        # flags
        flags = {k: env[k] for k in sorted(env)
                 if k.startswith(GATEWAY_ENV_PREFIXES) or k == "ROBOT_MD_HITL_FROM_MANIFEST"}
        for k in ("ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE", "ROBOT_MD_REQUIRE_ENVELOPE_TIMESTAMP",
                  "ROBOT_MD_REQUIRE_RRN_BINDING", "ROBOT_MD_HITL_FROM_MANIFEST"):
            flags.setdefault(k, "")
        rec["flags"] = flags
        rec["flags_on"] = sorted(k for k, v in flags.items() if v.strip().lower() in TRUTHY)
        enforce_sig = "ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE" in rec["flags_on"]
        if not enforce_sig:
            self.find("envelope-signature-not-enforced",
                      "ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE is off: the gateway records a "
                      "caller's envelope signature but its decision does not depend on it")
        # env drift against the unit's files
        drift = sorted(k for k in set(env) | set(gw.disk_env)
                       if env.get(k, "") != gw.disk_env.get(k, ""))
        rec["env_differs_from_unit_files"] = drift
        if drift:
            self.find("gateway-env-differs-from-unit-files",
                      "the running process and its unit files disagree on: " + ", ".join(drift),
                      level="warn")
        changed = sorted(p for p, mt in gw.env_files.items()
                         if gw.started_epoch >= 0 and mt > gw.started_epoch)
        rec["env_files"] = {p: (utc_iso(mt) if mt >= 0 else "unreadable")
                            for p, mt in gw.env_files.items()}
        if changed:
            self.find("gateway-env-file-changed-after-start",
                      "edited after the process started (not loaded until a restart): "
                      + ", ".join(changed), level="warn")
        # manifest the gateway was started with
        live_mf = gw.robot_md_arg or env.get("ROBOT_MANIFEST", "")
        rec["manifest_path_matches"] = bool(live_mf) and (
            os.path.realpath(live_mf) == os.path.realpath(inp.manifest_path))
        if live_mf and not rec["manifest_path_matches"]:
            self.find("gateway-manifest-path-differs",
                      f"the gateway runs with {live_mf}, this preflight checked "
                      f"{inp.manifest_path}", stop_in=(LIVE,))
        # drive backend
        rec["drive"] = self._drive(env, mf)
        # allowlist
        allow = [t for t in re.split(r"[,\s]+", env.get("ROBOT_MD_TOOL_ALLOWLIST", "")) if t]
        rec["allowlist"] = allow
        rec["min_tier"] = env.get("ROBOT_MD_TOOL_MIN_TIER", "")
        manifest_only = sorted(set(mf.capabilities) - set(allow))
        gateway_only = sorted(set(allow) - set(mf.capabilities))
        rec["allowlist_vs_manifest"] = {"manifest_only": manifest_only,
                                        "gateway_only": gateway_only}
        if manifest_only:
            self.find("manifest-capabilities-not-allowlisted",
                      "declared in the manifest, refused at tool_allowlist: "
                      + ", ".join(manifest_only))
        if gateway_only:
            self.find("allowlisted-tools-not-in-manifest",
                      "allowlisted by the gateway, not declared in the manifest: "
                      + ", ".join(gateway_only))
        # signing identity
        kid = env.get("ROBOT_MD_ATTESTATION_KID", "")
        rec["signing_kid"] = kid
        if not kid or not env.get("ROBOT_MD_ATTESTATION_KEY_FILE"):
            self.find("gateway-not-signing",
                      "the gateway env has no ROBOT_MD_ATTESTATION_KID/KEY_FILE: it runs "
                      "verifier-only and signs nothing",
                      stop_in=(LIVE,))
            return
        entry = self.check_kid(kid, "gateway-attestation", (LIVE,))
        local_pub = self._pubs.get(("local", kid))
        if entry["local"]["result"] != "found":
            self.find("gateway-kid-not-resolvable-locally",
                      f"the local resolver cannot serve {kid} ({entry['local']['result']}), so "
                      "no receipt can be checked against a local copy", stop_in=(LIVE,))
        sidecar = env["ROBOT_MD_ATTESTATION_KEY_FILE"] + ".pub"
        side_rec: dict[str, Any] = {"path": sidecar}
        try:
            side_pub = pub_from_pem(Path(sidecar).read_bytes())
            side_rec["spki_sha256"] = spki_sha256(side_pub)
            side_rec["matches_local"] = bool(
                side_pub and side_rec["spki_sha256"] == entry["local"]["spki_sha256"])
            if entry["local"]["result"] == "found" and not side_rec["matches_local"]:
                self.find("gateway-key-file-differs-from-local-key",
                          f"the public half next to the gateway's key file is not the local copy "
                          f"of {kid}: the key was rotated (castor pair --force?) and the next "
                          "restart signs with a key nothing else knows", stop_in=(LIVE,))
        except OSError:
            side_rec["spki_sha256"] = ""
            side_rec["matches_local"] = False
            self.find("gateway-key-sidecar-missing",
                      f"no public sidecar at {sidecar}; the key file itself is never opened")
        rec["key_file_public_sidecar"] = side_rec
        # RAN
        ran = env.get("ROBOT_MD_ATTESTATION_RAN", "")
        ran_rec: dict[str, Any] = {"ran": ran}
        rec["ran"] = ran_rec
        ran_ok = True
        if ran:
            r = self.http.get(_url(inp.registry_base, "v2", "authorities", ran))
            body = r.json() if r.body else None
            ran_rec.update({"url": r.url, "status": r.status, "body_sha256": sha256_hex(r.body)})
            if r.status == 200 and isinstance(body, dict):
                apub = pub_from_raw_b64(_s(body.get("signing_pub")))
                aspki = spki_sha256(apub)
                matches = sorted(k for k, p in inp.pins.items()
                                 if aspki and _s(p.get("spki_sha256")).lower() == aspki)
                ran_rec.update({
                    "organization": _s(body.get("organization")),
                    "display_name": _s(body.get("display_name")),
                    "purpose": _s(body.get("purpose")), "status": _s(body.get("status")),
                    "pq_kid": _s(body.get("pq_kid")),
                    "registered_at": _s(body.get("registered_at")),
                    "signing_pub_spki_sha256": aspki,
                    "holds_gateway_key": bool(aspki and aspki == entry["local"]["spki_sha256"]),
                    "matches_pinned_kids": matches,
                })
                if not ran_rec["holds_gateway_key"]:
                    ran_ok = False
                    self.find("ran-holds-different-key",
                              f"{ran} (the gateway's declared RAN, '{ran_rec['display_name']}') "
                              f"holds Ed25519 spki {aspki[:16]}, not the key the gateway signs "
                              f"with ({kid}, spki {entry['local']['spki_sha256'][:16]}); it "
                              "matches " + (", ".join(matches) if matches else "no pinned kid"),
                              level="warn")
                if ran_rec["status"] == "revoked":
                    self.find("ran-revoked", f"the registry marks {ran} revoked", stop_in=(LIVE,))
            elif r.status == 404:
                ran_ok = False
                self.find("ran-not-found",
                          f"the gateway declares {ran}, which the registry does not have (404)",
                          level="warn")
            else:
                ran_ok = False
                self.find("ran-registry-unreachable",
                          f"no usable registry answer for {ran} (HTTP {r.status})", level="warn")
            reg_ran = entry["registry"]["ran"]
            if reg_ran and reg_ran != ran:
                ran_ok = False
                self.find("gateway-kid-registry-ran-differs",
                          f"the registry maps {kid} to {reg_ran}, the gateway declares {ran}",
                          level="warn")
        else:
            self.find("ran-not-declared", "the gateway env sets no ROBOT_MD_ATTESTATION_RAN")
        registry_checks[LIVE]["gateway_kid_registry_is_pinned_and_local_key"] = bool(
            entry["registry"]["result"] == "found" and entry["registry_matches_local"]
            and entry["registry_matches_pin"])
        registry_checks[LIVE]["declared_ran_holds_gateway_key"] = ran_ok
        # pairing payload and export
        self._pairing(out, mf, kid, entry)
        self._export(out, gw, kid, local_pub, enforce_sig)

    def _drive(self, env: dict, mf: Manifest) -> dict:
        env_name = env.get("OPENCASTOR_DRIVE", "").strip().lower()
        m_backend = mf.drive.get("backend", "")
        rec: dict[str, Any] = {
            "gateway_env": env_name,
            "gateway_backends": list(DRIVE_BACKENDS.get(env_name or "simulated", ())),
            "manifest_backend": m_backend, "manifest_protocol": mf.drive.get("protocol", ""),
            "manifest_hardware_present": mf.drive.get("hardware_present", ""),
        }
        if not env_name and not mf.drive:
            rec["state"] = "not-applicable"
            return rec
        expected = DRIVE_BACKENDS.get(env_name or "simulated")
        if expected is None:
            rec["state"] = "unknown-gateway-backend"
            matches = False
        else:
            matches = m_backend in expected
            hw_env = (env_name or "simulated") not in ("simulated", "sim", "none")
            hw_mf = mf.drive.get("hardware_present", "").lower() == "true"
            if mf.drive.get("hardware_present") and hw_env != hw_mf:
                matches = False
            rec["state"] = "matches" if matches else "differs"
        rec["matches"] = matches
        if not matches:
            self.find("drive-backend-differs-from-manifest",
                      f"the gateway drives with OPENCASTOR_DRIVE={env_name or '(unset: simulated)'}"
                      f", the signed manifest declares backend {m_backend or 'none'} "
                      f"(hardware_present: {mf.drive.get('hardware_present') or 'unset'})",
                      stop_in=(LIVE,), level="warn")
        return rec

    def _pairing(self, out: dict, mf: Manifest, kid: str, entry: dict) -> None:
        inp = self.inp
        rec: dict[str, Any] = {"path": inp.pairing_path}
        out["pairing"] = rec
        if not inp.pairing_path:
            self.find("pairing-payload-not-given",
                      "no pairing payload was given; attest_pub was not compared", level="warn")
            return
        try:
            data = json.loads(Path(inp.pairing_path).read_bytes())
            if not isinstance(data, dict):
                raise ValueError("not an object")
        except (OSError, ValueError) as exc:
            rec["error"] = type(exc).__name__
            self.find("pairing-payload-unreadable", f"cannot read {inp.pairing_path}",
                      stop_in=(LIVE,))
            return
        self.secrets = [v for k, v in data.items()
                        if k in PAIRING_SECRET_FIELDS and isinstance(v, str) and len(v) >= 8]
        pub = {k: data.get(k) for k in PAIRING_PUBLIC_FIELDS}
        apub = pub_from_spki_b64(_s(pub["attest_pub"]))
        url = _s(pub["gateway_url"])
        host = urllib.parse.urlsplit(url).hostname or ""
        rec.update({
            "v": pub["v"] if isinstance(pub["v"], int) and not isinstance(pub["v"], bool) else 0,
            "gateway_url": url, "gateway_host": host,
            "gateway_host_is_this_host": host in inp.host_addrs,
            "rrn": _s(pub["rrn"]), "manifest_path": _s(pub["manifest_path"]),
            "attest_kid": _s(pub["attest_kid"]),
            "attest_pub_spki_sha256": spki_sha256(apub),
        })
        rec["attest_kid_matches_gateway"] = rec["attest_kid"] == kid
        aspki = rec["attest_pub_spki_sha256"]
        rec["attest_pub_matches_local"] = bool(apub and aspki == entry["local"]["spki_sha256"])
        rec["attest_pub_matches_pin"] = bool(apub and aspki == entry["pin"]["spki_sha256"])
        if not rec["attest_kid_matches_gateway"]:
            self.find("pairing-attest-kid-differs",
                      f"the pairing payload names {rec['attest_kid'] or 'no kid'}, the gateway "
                      f"signs as {kid}", stop_in=(LIVE,))
        if not rec["attest_pub_matches_local"]:
            self.find("pairing-attest-pub-differs",
                      f"the pairing payload's attest_pub (spki {aspki[:16] or 'unreadable'}) is "
                      f"not the local copy of {kid}: the phone would reject every receipt",
                      stop_in=(LIVE,))
        if rec["rrn"] != mf.rrn:
            self.find("pairing-rrn-differs",
                      f"the pairing payload says {rec['rrn'] or 'no RRN'}, the manifest {mf.rrn}",
                      level="warn")
        mp = rec["manifest_path"]
        if mp and os.path.realpath(mp) != os.path.realpath(inp.manifest_path):
            self.find("pairing-manifest-path-differs",
                      f"the phone will send manifest_path {mp}, this preflight checked "
                      f"{inp.manifest_path}", level="warn")
        if not rec["gateway_host_is_this_host"]:
            self.find("pairing-gateway-url-not-this-host",
                      f"the pairing QR points at {host or 'no host'}, which is not an address of "
                      f"this host ({', '.join(inp.host_addrs) or 'none found'}); regenerate it "
                      "without --force", level="warn")

    def _export(self, out: dict, gw: GatewayInfo, kid: str,
                local_pub: Ed25519PublicKey | None, enforce_sig: bool) -> None:
        inp = self.inp
        path = inp.export_path or gw.env.get("ROBOT_MD_ATTESTATION_EXPORT_FILE", "")
        rec: dict[str, Any] = {"path": path}
        out["export"] = rec
        signers: dict[str, int] = {}
        unsigned = 0
        latest = None
        lines: list[bytes] = []
        if path:
            try:
                with open(path, "rb") as fh:
                    size = fh.seek(0, os.SEEK_END)
                    fh.seek(max(0, size - EXPORT_TAIL_BYTES))
                    chunk = fh.read()
                lines = chunk.split(b"\n")
                if size > EXPORT_TAIL_BYTES:
                    lines = lines[1:]  # first line of the window is partial
                rec["bytes"] = size
            except OSError as exc:
                rec["error"] = type(exc).__name__
        rec["tail_lines"] = sum(1 for ln in lines if ln.strip())
        for ln in lines:
            if not ln.strip():
                continue
            try:
                d = json.loads(ln)
            except ValueError:
                continue
            if not isinstance(d, dict):
                continue
            inv = d.get("invoke")
            if isinstance(inv, dict) and d.get("record_kind") != "intent":
                es = inv.get("envelope_signature")
                if isinstance(es, dict) and isinstance(es.get("kid"), str):
                    signers[es["kid"]] = signers.get(es["kid"], 0) + 1
                else:
                    unsigned += 1
            oc = d.get("outcome")
            if isinstance(oc, dict):
                es = oc.get("envelope_signature")
                if isinstance(es, dict) and es.get("kid") == kid:
                    latest = oc
        rec["signed_invokes_by_kid"] = signers
        rec["unsigned_invokes"] = unsigned
        if latest is not None:
            try:
                sig = base64.b64decode(latest["envelope_signature"].get("sig", ""), validate=True)
            except (ValueError, TypeError):
                sig = b""
            ok = ed25519_verifies(local_pub, sig, receipt_signed_bytes(latest))
            ended = _s(latest.get("ended_at"))
            ended_epoch = _parse_iso(ended) if ended else -1
            rv = latest.get("receipt_version")
            rec["latest_receipt"] = {
                "corr_id": _s(latest.get("corr_id")), "status": _s(latest.get("status")),
                "ended_at": ended,
                "receipt_version": rv if isinstance(rv, int) and not isinstance(rv, bool) else 1,
                "caller": _s(latest.get("caller")), "tier": _s(latest.get("tier")),
                "verifies_under_local_key": ok,
                "after_process_start": bool(ended_epoch >= 0 and gw.started_epoch >= 0
                                            and ended_epoch >= gw.started_epoch),
            }
            if not ok:
                self.find("gateway-receipt-fails-local-key",
                          f"the newest receipt signed as {kid} does not verify under the local "
                          f"copy of {kid}", stop_in=(LIVE,))
            elif not rec["latest_receipt"]["after_process_start"]:
                self.find("latest-receipt-predates-process-start",
                          f"the newest receipt ({ended or 'no time'}) is older than the running "
                          "process; nothing signed since the start shows which key the process "
                          "holds")
        else:
            self.find("no-receipt-in-export-tail",
                      f"no receipt signed as {kid} in the tail of {path or 'the export'}")
        if unsigned:
            self.find("unsigned-invokes-in-export-tail",
                      f"{unsigned} invoke(s) in the export tail carry no envelope signature; "
                      "with ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE on, each would get a signed 403",
                      level="warn" if enforce_sig else "info")
        srec: dict[str, Any] = {}
        out["signers"] = srec
        for skid in sorted(signers):
            # Revoked (410) or a registry key that differs from the local copy
            # stops a live test through check_kid, because in_use is (LIVE,).
            e = self.check_kid(skid, "envelope-signer", (LIVE,))
            srec[skid] = {"seen_in_export_tail": signers[skid], "local": e["local"]["result"],
                          "registry": e["registry"]["result"]}
            if e["local"]["result"] != "found":
                self.find(f"signer-kid-not-resolvable-locally:{skid}",
                          f"the gateway's resolver cannot serve signer {skid}; with "
                          "ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE on, its envelopes would be refused",
                          stop_in=(LIVE,) if enforce_sig else (), level="warn")

    def _name_ran_key(self, out: dict) -> None:
        """Say which registry kid (looked up in this run) holds a RAN's key."""
        ran = out.get("gateway", {}).get("ran", {})
        aspki = ran.get("signing_pub_spki_sha256", "")
        if not aspki:
            return
        kids = sorted(k for k, e in self.kids.items() if e["registry"]["spki_sha256"] == aspki)
        ran["registry_kids_with_this_key"] = kids
        if kids:
            for f in self.findings:
                if f.id == "ran-holds-different-key":
                    f.detail += "; the registry serves this key under " + ", ".join(kids)

    def _other_pins(self, mf: Manifest) -> None:
        """Pinned kids for this RRN that nothing here uses (retired keys)."""
        for kid in sorted(self.inp.pins):
            pin = self.inp.pins[kid]
            if kid in self.kids or not mf.rrn or _s(pin.get("rrn")) != mf.rrn:
                continue
            self.check_kid(kid, _s(pin.get("role")) or "pinned", ())


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def load_pins(path: str) -> tuple[dict[str, dict], str]:
    if not path:
        return {}, ""
    try:
        raw = Path(path).expanduser().read_bytes()
        data = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise UsageError(f"cannot read pins {path}: {type(exc).__name__}") from exc
    if not isinstance(data, dict):
        raise UsageError(f"pins {path} is not a JSON object")
    pins = {k: v for k, v in data.items() if not k.startswith("_") and isinstance(v, dict)}
    for kid, p in pins.items():
        if not re.fullmatch(r"[0-9a-f]{64}", _s(p.get("spki_sha256")).lower()):
            raise UsageError(f"pin {kid}: spki_sha256 is not 64 lowercase hex characters")
    return pins, sha256_hex(raw)


def tool_info() -> dict:
    me = Path(__file__).resolve()
    info = {"name": "scripts/rrf_preflight.py", "sha256": sha256_hex(me.read_bytes()),
            "git_commit": "", "git_dirty": False}
    try:
        top = subprocess.run(["git", "-C", str(me.parent), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=5, check=False)
        if top.returncode == 0:
            info["git_commit"] = top.stdout.strip()
            st = subprocess.run(
                ["git", "-C", str(me.parent), "status", "--porcelain", "--", me.name],
                capture_output=True, text=True, timeout=5, check=False)
            info["git_dirty"] = bool(st.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return info


def _summary(out: dict) -> str:
    lines = [f"rrf_preflight {out['robot']} ({out['mode']}) at {out['checked_at']}"]
    for m, v in out["verdicts_by_mode"].items():
        extra = ""
        if len(v["stop_reasons"]) > 1:
            extra = f"  (all stops: {', '.join(v['stop_reasons'])})"
        lines.append(f"  verdict[{m}] = {v['verdict']}{extra}")
    for f in out["findings"]:
        lines.append(f"  [{f['severity']:<4}] {f['id']}: {f['detail']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None, fetch: Callable[[str], Http] = http_get) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--robot", default="", help=f"profile name ({', '.join(PROFILES)}) or a label")
    ap.add_argument("--mode", choices=(BENCH, LIVE), default=None,
                    help="live (default when a gateway unit is known) also checks the gateway, "
                         "pairing and export")
    ap.add_argument("--manifest", default="")
    ap.add_argument("--fixture", default="",
                    help="bench fixture that must equal the live manifest; 'none' to skip")
    ap.add_argument("--unit", default="", help="gateway systemd --user unit (live mode)")
    ap.add_argument("--pairing", default="",
                    help="pairing payload JSON (live mode); only public fields are read")
    ap.add_argument("--export", default="",
                    help="attestation export NDJSON (default: from the gateway env)")
    ap.add_argument("--pins", default=os.environ.get("RRF_PREFLIGHT_PINS", ""))
    ap.add_argument("--registry-base", default=DEFAULT_REGISTRY)
    ap.add_argument("--resolver-base", default="",
                    help="local key resolver (default: the gateway's OPENCASTOR_OPS_RRF_URL, "
                         "else 127.0.0.1:8090)")
    ap.add_argument("--out", default="",
                    help="write the canonical JSON bytes here (no trailing newline)")
    ap.add_argument("--quiet", action="store_true", help="no summary on stderr")
    a = ap.parse_args(argv)

    prof = PROFILES.get(a.robot, {})
    if not a.robot or (not prof and not a.manifest):
        ap.error("give --robot <profile> or --robot <label> --manifest PATH")

    def pick(flag: str, key: str) -> str:
        v = flag or prof.get(key, "")
        return "" if v == "none" else os.path.expanduser(v)

    manifest = pick(a.manifest, "manifest")
    fixture = pick(a.fixture, "fixture")
    unit = a.unit or prof.get("unit", "")
    mode = a.mode or (LIVE if unit else BENCH)
    if mode == LIVE and not unit:
        ap.error("--mode live needs a gateway --unit")
    try:
        pins, pins_sha = load_pins(a.pins)
    except UsageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE

    gw = collect_gateway(unit) if mode == LIVE else None
    if a.resolver_base:
        resolver, source = a.resolver_base, "flag"
    elif gw is not None and "OPENCASTOR_OPS_RRF_URL" in gw.env:
        resolver, source = gw.env["OPENCASTOR_OPS_RRF_URL"], "gateway-process-env"
    elif gw is not None and not gw.error and gw.pid > 0:
        resolver, source = DEFAULT_REGISTRY, "gateway-default-public-registry"
    else:
        resolver, source = DEFAULT_RESOLVER, "default-loopback-stub"

    inp = Inputs(
        robot=a.robot, manifest_path=manifest, fixture_path=fixture,
        pins=pins, pins_path=os.path.expanduser(a.pins) if a.pins else "", pins_sha256=pins_sha,
        registry_base=a.registry_base.rstrip("/"), resolver_base=resolver.rstrip("/"),
        resolver_source=source, mode=mode, gateway=gw,
        pairing_path=pick(a.pairing, "pairing") if mode == LIVE else "",
        export_path=os.path.expanduser(a.export) if a.export else "",
        host_addrs=host_addresses() if mode == LIVE else [],
        now_epoch=int(datetime.now(timezone.utc).timestamp()),
        tool=tool_info(), host=socket.gethostname(),
    )
    pf = Preflight(inp, fetch)
    out = pf.run()
    blob = canonical_json(out)
    for secret in pf.secrets:
        if secret.encode() in blob:
            print("ERROR: a pairing secret reached the output; nothing written", file=sys.stderr)
            return EXIT_USAGE
    if a.out:
        Path(a.out).expanduser().write_bytes(blob)
    sys.stdout.buffer.write(blob + b"\n")
    sys.stdout.flush()
    if not a.quiet:
        print(_summary(out), file=sys.stderr)
    v = out["verdict"]
    if v.startswith("STOP:"):
        return EXIT_STOP
    return EXIT_REGISTRY if v == VERDICT_REGISTRY else EXIT_LOCAL


if __name__ == "__main__":
    sys.exit(main())
