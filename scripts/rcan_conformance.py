#!/usr/bin/env python3
"""RCAN conformance run against a live robot-md-gateway: no model, no motion.

Sends a handful of HAND-WRITTEN RCAN INVOKE envelopes to one gateway and checks
that each is decided the way the gateway's own gates say it must be, that every
answer (yes or no) comes back as a receipt signed by the gateway's key, and that
no refusal left an intent record in the gateway's export. It is design section
B2 of the RCAN/RRF plan (2026-09-27).

THE CASES (the tool and scope of each are fixed here, not taken from input):

    C1  no bearer,   status.report, OBSERVE     -> 403 tool_tier
    C2  read bearer, status.report, MANIPULATE  -> 403 tier_policy
    C3  read bearer, sensor.battery, OBSERVE    -> 403 tool_allowlist
    C0  read bearer, status.report, OBSERVE     -> 200
  only with --enforced (ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE=1 on the gateway):
    C4  an envelope signed by a key the gateway cannot resolve -> 403 envelope_signature
    C5  C0's request body sent again byte for byte              -> 403 replay

WHAT IT WILL NEVER DO. Every envelope names one of the two tools in
ALLOWED_TOOLS, both of which read state; a case naming any other tool is refused
before a request is built, so this script cannot be pointed at a tool that moves
anything. It never reads a model reply, a bench result or a draft: these
envelopes are written here, by hand, and signed with an operator TEST key.
Signing a model's draft with an operator key would be "a script signs", not "a
person signs", which is exactly what this tool must not be able to do.

CREDENTIALS. The bearer is looked up by its caller name in the gateway's
bearers.yaml and must be READ tier (refused otherwise): at read tier the
gateway's per-tool tier table refuses any motion tool before a driver runs, and
every v2 receipt signs the caller and tier it was issued to. The bearer is
never printed or written: every saved request says only which credential was
used, and the whole output folder is scanned for the token before exit (a hit
deletes the file and fails the run). The test key signs the envelopes
(robot_md_gateway.cert.envelope.sign_envelope, the gateway's own recipe); its
public PEM is written into the bundle so every envelope can be checked later.
C4's key is generated in memory for this run and never stored; its public PEM
goes into the bundle too, so C4's signature is checkable even though the
gateway could not check it.

WHAT A PASS MEANS. The gateway decided these hand-written requests the way its
configured gates say it should, and signed every decision with the key given as
--gateway-pub. It says nothing about whether any action is correct, and nothing
about requests this script did not send. The receipts do not bind tool_args or
the manifest (receipt v2); the export line keeps the raw envelope next to the
signed outcome, and that link is not signed.

Offline checks run on the saved bundle: scripts/verify_receipt.py on every
response body and every export outcome line (exit 0 expected), verify_envelope
on every export line's invoke with a one-kid resolver holding the test (or C4)
public key, and the export's intent/outcome counts per correlation id.

Exit 0 = every case met its expectation and every check passed; 1 = something
did not (the summary says what); 2 = refused to run (bad input).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS.parent / "src"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from robot_md_gateway.cert.envelope import sign_envelope, verify_envelope  # noqa: E402

#: The only tool names this script will ever put in an envelope. Both read
#: state: status.report reports the robot's state, and sensor.battery is a
#: reading the rover's manifest declares but its gateway does not allowlist.
ALLOWED_TOOLS = ("status.report", "sensor.battery")

#: Scopes a case may declare. MANIPULATE appears only as C2's CLAIM, sent with a
#: read bearer and a read-only tool, to show the tier gate refusing it.
ALLOWED_SCOPES = ("OBSERVE", "MANIPULATE")

TEST_KID_DEFAULT = "opencastor-conformance-2026"


class Refused(Exception):
    """Bad input: the run does not start (exit 2)."""


@dataclass(frozen=True)
class Case:
    cid: str
    title: str
    send_bearer: bool
    tool: str
    scope: str
    expect_status: int
    #: The gate named in the 403 body (`detail.deny`), None for a 200.
    expect_deny: str | None
    #: "test" = signed with the operator test key; "unknown" = signed with a
    #: key made in memory for this run; "replay" = C0's exact bytes again.
    signer: str
    enforced_only: bool = False


CASES: tuple[Case, ...] = (
    Case("C1", "no bearer, status.report, OBSERVE", False,
         "status.report", "OBSERVE", 403, "tool_tier", "test"),
    Case("C2", "read bearer, status.report, scope MANIPULATE", True,
         "status.report", "MANIPULATE", 403, "tier_policy", "test"),
    Case("C3", "read bearer, sensor.battery, OBSERVE", True,
         "sensor.battery", "OBSERVE", 403, "tool_allowlist", "test"),
    Case("C0", "read bearer, status.report, OBSERVE", True,
         "status.report", "OBSERVE", 200, None, "test"),
    Case("C4", "read bearer, status.report, signed by a key the gateway cannot resolve", True,
         "status.report", "OBSERVE", 403, "envelope_signature", "unknown", enforced_only=True),
    Case("C5", "C0's request body sent again byte for byte", True,
         "status.report", "OBSERVE", 403, "replay", "replay", enforced_only=True),
)


def check_case_table(cases: tuple[Case, ...] = CASES) -> None:
    """Refuse any case that names a tool or scope outside the allowlists."""
    for c in cases:
        if c.tool not in ALLOWED_TOOLS:
            raise Refused(f"case {c.cid} names tool {c.tool!r}; only {ALLOWED_TOOLS} may be sent")
        if c.scope not in ALLOWED_SCOPES:
            raise Refused(f"case {c.cid} declares scope {c.scope!r}; only {ALLOWED_SCOPES}")
        if c.signer not in ("test", "unknown", "replay"):
            raise Refused(f"case {c.cid} has signer {c.signer!r}")
    ids = [c.cid for c in cases]
    if len(set(ids)) != len(ids):
        raise Refused("duplicate case ids")
    if "C5" in ids and ids.index("C5") < ids.index("C0"):
        raise Refused("C5 replays C0, so it must come after it")


def load_read_bearer(bearers_file: Path, caller: str) -> str:
    """The token of the bearer named `caller`, which must be read tier."""
    import yaml

    data = yaml.safe_load(bearers_file.read_text())
    rows = data.get("bearers", []) if isinstance(data, dict) else (data or [])
    hits = [r for r in rows if isinstance(r, dict) and r.get("caller") == caller]
    if len(hits) != 1:
        raise Refused(f"{bearers_file}: expected exactly one bearer with caller {caller!r}, found {len(hits)}")
    if hits[0].get("tier") != "read":
        raise Refused(f"bearer {caller!r} is tier {hits[0].get('tier')!r}; conformance runs only with a READ bearer")
    token = hits[0].get("token")
    if not isinstance(token, str) or len(token) < 16:
        raise Refused(f"bearer {caller!r} has no usable token")
    return token


def load_ed25519_private(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise Refused(f"{path} is not an Ed25519 private key")
    return key


def public_pem(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def spki_sha256(pem: bytes) -> str:
    pub = serialization.load_pem_public_key(pem)
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def build_envelope(case: Case, *, run_id: str, rrn: str, manifest_path: str,
                   now_ms: int | None = None) -> dict:
    """A hand-written INVOKE envelope for one case (unsigned)."""
    if case.tool not in ALLOWED_TOOLS:  # belt and braces: check_case_table ran first
        raise Refused(f"refusing to build an envelope for {case.tool!r}")
    return {
        "msg_id": f"rcan-conformance-{run_id}-{case.cid}",
        "type": "rcan/v1/invoke",
        "ruri": f"rcan://{rrn}/{case.tool}",
        "scope": case.scope,
        "tool_name": case.tool,
        "tool_args": {},
        "manifest_path": manifest_path,
        "nonce": uuid.uuid4().hex,
        "timestamp_ms": int(time.time() * 1000) if now_ms is None else now_ms,
    }


class OneKid:
    """A resolver that knows exactly one kid (for offline envelope checks)."""

    def __init__(self, kid: str, pem: bytes) -> None:
        self.kid, self.pem = kid, pem

    def resolve_public_key_pem(self, kid: str) -> bytes | None:
        return self.pem if kid == self.kid else None


def post(url: str, body: bytes, token: str | None, timeout: float) -> tuple[int, dict, bytes]:
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, _json_or_empty(raw), raw
    except urllib.error.HTTPError as exc:
        raw = exc.read() or b""
        return exc.code, _json_or_empty(raw), raw


def _json_or_empty(raw: bytes) -> dict:
    try:
        v = json.loads(raw or b"{}")
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {"_non_object_body": v}


def signed_outcome_of(body: dict) -> dict | None:
    """The gateway's signed outcome inside an ALLOW body or a 403 DENY body."""
    out = body.get("outcome")
    if isinstance(out, dict) and "envelope_signature" in out:
        return out
    detail = body.get("detail")
    if isinstance(detail, dict) and isinstance(detail.get("outcome"), dict):
        return detail["outcome"]
    return None


def deny_of(body: dict) -> str | None:
    detail = body.get("detail")
    return detail.get("deny") if isinstance(detail, dict) else None


def judge_response(case: Case, *, status: int, body: dict, msg_id: str,
                   caller: str | None, tier: str) -> list[str]:
    """What is wrong with this answer, as sentences (empty = as expected)."""
    problems: list[str] = []
    if status != case.expect_status:
        problems.append(f"HTTP {status}, expected {case.expect_status}")
    if case.expect_deny is not None and deny_of(body) != case.expect_deny:
        problems.append(f"deny {deny_of(body)!r}, expected {case.expect_deny!r}")
    out = signed_outcome_of(body)
    if out is None:
        problems.append("no signed outcome in the response")
        return problems
    want_status = "ok" if case.expect_status == 200 else "denied"
    if out.get("status") != want_status:
        problems.append(f"outcome status {out.get('status')!r}, expected {want_status!r}")
    if out.get("corr_id") != msg_id:
        problems.append(f"outcome corr_id {out.get('corr_id')!r} != msg_id {msg_id!r}")
    if out.get("receipt_version") != 2:
        problems.append(f"receipt_version {out.get('receipt_version')!r}, expected 2")
    if out.get("caller") != caller:
        problems.append(f"outcome caller {out.get('caller')!r}, expected {caller!r}")
    if out.get("tier") != tier:
        problems.append(f"outcome tier {out.get('tier')!r}, expected {tier!r}")
    if case.expect_deny is not None:
        # The signed outcome names the refusing gate as error.kind (and repeats
        # it at the start of error.message), inside the signed bytes.
        err = out.get("error")
        kind = err.get("kind") if isinstance(err, dict) else None
        if kind != case.expect_deny:
            problems.append(f"signed error.kind {kind!r}, expected {case.expect_deny!r}")
    elif out.get("error") is not None:
        problems.append(f"an allowed call carries a signed error {out.get('error')!r}")
    return problems


def run_verify_receipt(path: Path, pubkey: Path) -> tuple[int, str]:
    r = subprocess.run(
        [sys.executable, str(SCRIPTS / "verify_receipt.py"), "--receipt", str(path),
         "--pubkey", str(pubkey)],
        capture_output=True, text=True, timeout=60,
    )
    return r.returncode, (r.stdout + r.stderr).strip()


def export_lines_for(export: Path, corr_ids: set[str], start_line: int) -> list[tuple[int, dict, str]]:
    """(line number, parsed, raw) for every export line from start_line on whose corr_id is ours."""
    found = []
    with export.open("rb") as f:
        for n, raw in enumerate(f, start=1):
            if n < start_line:
                continue
            try:
                d = json.loads(raw)
            except ValueError:
                continue
            if isinstance(d, dict) and d.get("corr_id") in corr_ids:
                found.append((n, d, raw.decode("utf-8").rstrip("\n")))
    return found


def expected_export_counts(cases: list[Case], msg_ids: dict[str, str]) -> dict[str, dict[str, int]]:
    """Per correlation id: how many intent and outcome lines the export must hold.

    An intent is written only for a request that passed every gate (it is the
    record that a dispatch is about to happen). C5 reuses C0's msg_id, so its
    refusal is a second OUTCOME line under C0's id and no second intent.
    """
    want: dict[str, dict[str, int]] = {}
    for c in cases:
        mid = msg_ids[c.cid]
        slot = want.setdefault(mid, {"intent": 0, "outcome": 0})
        slot["outcome"] += 1
        if c.expect_status == 200:
            slot["intent"] += 1
    return want


def count_bytes_line(path: Path) -> int:
    with path.open("rb") as f:
        return sum(1 for _ in f)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def scrub_check(out_dir: Path, secret: str) -> list[str]:
    """Delete any written file that contains the bearer; return their names."""
    hits = []
    needle = secret.encode()
    for p in sorted(out_dir.rglob("*")):
        if p.is_file() and needle in p.read_bytes():
            hits.append(str(p))
            p.unlink()
    return hits


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--gateway", required=True, help="gateway base URL, e.g. http://127.0.0.1:8081")
    ap.add_argument("--rrn", required=True)
    ap.add_argument("--manifest-path", required=True, help="the manifest path the gateway will verify")
    ap.add_argument("--bearers", required=True, type=Path, help="the gateway's bearers.yaml")
    ap.add_argument("--caller", default="rcan-conformance", help="caller name of the READ bearer to use")
    ap.add_argument("--key-file", required=True, type=Path, help="test key (Ed25519 PKCS8 PEM)")
    ap.add_argument("--kid", default=TEST_KID_DEFAULT)
    ap.add_argument("--gateway-pub", required=True, type=Path, help="the gateway's signing public key PEM")
    ap.add_argument("--export", required=True, type=Path, help="the gateway's attestation export NDJSON")
    ap.add_argument("--out", required=True, type=Path, help="bundle directory (must not exist)")
    ap.add_argument("--enforced", action="store_true",
                    help="the gateway enforces envelope signatures: also run C4 and C5")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args(argv)

    try:
        check_case_table()
        if args.out.exists():
            raise Refused(f"{args.out} exists; every run gets a new folder")
        token = load_read_bearer(args.bearers, args.caller)
        test_key = load_ed25519_private(args.key_file)
        gw_pem = args.gateway_pub.read_bytes()
        serialization.load_pem_public_key(gw_pem)
        if not args.export.is_file():
            raise Refused(f"no export at {args.export}")
        manifest_bytes = Path(args.manifest_path).read_bytes()
    except (Refused, OSError, ValueError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2

    cases = [c for c in CASES if args.enforced or not c.enforced_only]
    skipped = [c for c in CASES if c not in cases]
    started = datetime.now(tz=timezone.utc)
    run_id = started.strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]
    out = args.out
    (out / "responses").mkdir(parents=True)
    (out / "export").mkdir()
    (out / "keys").mkdir()

    test_pub = public_pem(test_key)
    (out / "keys" / f"{args.kid}.pem").write_bytes(test_pub)
    (out / "keys" / "gateway.pem").write_bytes(gw_pem)
    unknown_key = Ed25519PrivateKey.generate()  # C4 only; never stored
    unknown_kid = f"opencastor-conformance-unknown-{run_id[-6:]}"
    if any(c.signer == "unknown" for c in cases):
        (out / "keys" / f"{unknown_kid}.pem").write_bytes(public_pem(unknown_key))

    export_before_lines = count_bytes_line(args.export)
    head = args.export.with_name(args.export.name + ".head")
    before = {
        "export_lines": export_before_lines,
        "export_sha256": sha256_file(args.export),
        "head": head.read_text() if head.is_file() else None,
    }

    url = args.gateway.rstrip("/") + "/v1/invoke"
    msg_ids: dict[str, str] = {}
    sent_bytes: dict[str, bytes] = {}
    records = []
    for c in cases:
        if c.signer == "replay":
            body_bytes = sent_bytes["C0"]
            envelope = json.loads(body_bytes)
            signer_kid = envelope["envelope_signature"]["kid"]
        else:
            envelope = build_envelope(c, run_id=run_id, rrn=args.rrn, manifest_path=args.manifest_path)
            key, signer_kid = (test_key, args.kid) if c.signer == "test" else (unknown_key, unknown_kid)
            sign_envelope(key, envelope, signer_kid)
            body_bytes = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode()
        msg_ids[c.cid] = envelope["msg_id"]
        sent_bytes[c.cid] = body_bytes
        t0 = time.monotonic()
        status, body, raw = post(url, body_bytes, token if c.send_bearer else None, args.timeout)
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        resp_path = out / "responses" / f"{c.cid}.json"
        resp_path.write_bytes(raw)
        caller = args.caller if c.send_bearer else None
        tier = "read" if c.send_bearer else "anon"
        problems = judge_response(c, status=status, body=body, msg_id=envelope["msg_id"],
                                  caller=caller, tier=tier)
        v_rc, v_out = run_verify_receipt(resp_path, args.gateway_pub)
        if v_rc != 0:
            problems.append(f"verify_receipt.py exit {v_rc} on the response")
        records.append({
            "case": asdict(c),
            "request": {
                "method": "POST", "url": url,
                "authorization": (f"Bearer <stripped: caller {args.caller}, tier read>"
                                  if c.send_bearer else "none"),
                "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
                "body": body_bytes.decode("utf-8"),
                "signer_kid": signer_kid,
            },
            "response": {"http_status": status, "deny": deny_of(body), "elapsed_ms": elapsed_ms,
                         "file": f"responses/{c.cid}.json",
                         "sha256": hashlib.sha256(raw).hexdigest()},
            "verify_receipt": {"exit": v_rc, "output": v_out},
            "problems": problems,
        })

    # The export is written before the response returns; a short settle keeps
    # a slow SD card from turning into a false "missing line".
    time.sleep(0.5)
    lines = export_lines_for(args.export, set(msg_ids.values()), export_before_lines + 1)
    (out / "export" / "slice.ndjson").write_text("".join(raw + "\n" for _, _, raw in lines))
    want = expected_export_counts(cases, msg_ids)
    got: dict[str, dict[str, int]] = {mid: {"intent": 0, "outcome": 0} for mid in want}
    export_checks = []
    pems = {args.kid: test_pub, unknown_kid: public_pem(unknown_key)}
    for n, d, raw in lines:
        kind = d.get("record_kind")
        mid = d.get("corr_id")
        if kind in ("intent", "outcome"):
            got[mid][kind] += 1
        row = {"line": n, "seq": d.get("seq"), "record_kind": kind, "corr_id": mid}
        inv = d.get("invoke") or {}
        sig_kid = (inv.get("envelope_signature") or {}).get("kid")
        if sig_kid in pems:
            r = verify_envelope(inv, resolver=OneKid(sig_kid, pems[sig_kid]))
            row["invoke_signature"] = {"kid": sig_kid, "accepted": r.accepted, "reason": r.reason}
        else:
            row["invoke_signature"] = {"kid": sig_kid, "accepted": False,
                                       "reason": "not signed by a key from this run"}
        if kind == "outcome":
            p = out / "export" / f"line-{n}-outcome.json"
            p.write_text(raw)
            rc, text = run_verify_receipt(p, args.gateway_pub)
            row["verify_receipt"] = {"exit": rc, "output": text}
        export_checks.append(row)

    export_problems = []
    for mid, w in want.items():
        if got[mid] != w:
            export_problems.append(f"{mid}: export holds {got[mid]}, expected {w}")
    for row in export_checks:
        if not row["invoke_signature"]["accepted"]:
            export_problems.append(f"line {row['line']}: invoke signature not verified ({row['invoke_signature']['reason']})")
        if row["record_kind"] == "outcome" and row["verify_receipt"]["exit"] != 0:
            export_problems.append(f"line {row['line']}: verify_receipt.py exit {row['verify_receipt']['exit']}")
    refusal_ids = {msg_ids[c.cid] for c in cases if c.expect_status != 200 and c.signer != "replay"}
    intents_for_refusals = sorted(mid for mid in refusal_ids if got[mid]["intent"])
    if intents_for_refusals:
        export_problems.append(f"intent line(s) exist for refused ids: {intents_for_refusals}")

    after = {
        "export_lines": count_bytes_line(args.export),
        "export_sha256": sha256_file(args.export),
        "head": head.read_text() if head.is_file() else None,
    }
    all_pass = not export_problems and all(not r["problems"] for r in records)
    summary = {
        "tool": "robot-md-gateway scripts/rcan_conformance.py",
        "run_id": run_id,
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "finished_at": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "gateway": args.gateway,
        "rrn": args.rrn,
        "manifest_path": args.manifest_path,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "credential": {"caller": args.caller, "tier": "read", "token": "<never written>"},
        "test_key": {"kid": args.kid, "spki_sha256": spki_sha256(test_pub),
                     "public_pem": f"keys/{args.kid}.pem"},
        "gateway_key": {"spki_sha256": spki_sha256(gw_pem), "public_pem": "keys/gateway.pem"},
        "enforced_flag_given": args.enforced,
        "cases_run": [c.cid for c in cases],
        "cases_not_run": {c.cid: "needs --enforced (the gateway must enforce envelope signatures)"
                          for c in skipped},
        "export": {"path": str(args.export), "before": before, "after": after,
                   "slice": "export/slice.ndjson",
                   "expected_by_corr_id": want, "found_by_corr_id": got,
                   "no_intent_for_refusals": not intents_for_refusals,
                   "lines": export_checks, "problems": export_problems},
        "results": [{"case": r["case"]["cid"], "expect": [r["case"]["expect_status"], r["case"]["expect_deny"]],
                     "got": [r["response"]["http_status"], r["response"]["deny"]],
                     "receipt_verified": r["verify_receipt"]["exit"] == 0,
                     "pass": not r["problems"], "problems": r["problems"]} for r in records],
        "all_pass": all_pass,
        "not_claimed": [
            "a pass says the gateway decided these hand-written requests as its configured gates say and signed each decision; it says nothing about requests this script did not send",
            "no model output was read, drafted or signed by this run",
            "receipt v2 does not bind tool_args or the manifest; the export keeps the raw envelope beside the signed outcome, and that link is not signed",
            "caller names a credential, not a person",
        ],
    }
    (out / "requests-responses.json").write_text(json.dumps(records, indent=1, sort_keys=True) + "\n")
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")

    leaked = scrub_check(out, token)
    if leaked:
        print(f"BEARER FOUND in {leaked}; those files were deleted", file=sys.stderr)
        return 1

    for r in summary["results"]:
        mark = "PASS" if r["pass"] else "FAIL"
        print(f"{mark} {r['case']}: expected {r['expect']}, got {r['got']}, receipt verified {r['receipt_verified']}"
              + ("" if r["pass"] else f"  {r['problems']}"))
    for cid, why in summary["cases_not_run"].items():
        print(f"not run {cid}: {why}")
    print(f"export: {len(lines)} line(s) for this run; expected {want}; found {got}; "
          f"no intent for refusals: {not intents_for_refusals}")
    for p in export_problems:
        print(f"export problem: {p}")
    print(f"=> {'all cases passed' if all_pass else 'NOT all cases passed'}; bundle {out}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
