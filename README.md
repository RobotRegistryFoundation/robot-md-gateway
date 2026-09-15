# robot-md-gateway

> **The mandatory enforcement gateway for the OpenCastor stack.**
> Receives signed RCAN action envelopes, verifies manifest provenance, applies tier policy + tool allowlist, dispatches to drivers. Exclusive path between agent intent and any actuator. Open, neutral, becomes OpenCastor's safety kernel via open-core extraction.

[![PyPI](https://img.shields.io/pypi/v/robot-md-gateway.svg)](https://pypi.org/project/robot-md-gateway/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-green)](https://www.python.org)
[![RCAN](https://img.shields.io/badge/RCAN-live%20matrix-blue)](https://rcan.dev/compatibility)

> **Renamed in 2026-05.** This package was previously published as `robot-md-dispatcher`. The old name is now a tombstone on PyPI; `pip install robot-md-dispatcher` continues to work and pulls this package as a dependency. Imports and the `robot-md-dispatcher` CLI keep working through v0.4.x via a backward-compat shim. See [CHANGELOG.md](CHANGELOG.md) for migration notes.

## Where this fits in the stack

`robot-md-gateway` is **Layer 3** of the OpenCastor stack — the
enforcement gateway. Every action that crosses from agent intent to
any actuator passes through this gateway. There is no second path.

| Layer | Piece | What it is |
|---|---|---|
| **1 — Declaration** | [robot-md](https://github.com/RobotRegistryFoundation/robot-md) | The ROBOT.md file + Python CLI. Declares identity, capabilities, safety gates. |
| **2 — Agent runtime** | (any MCP host) | Claude Code, Codex, Gemini — plans actions, calls tools, never reaches actuators directly. |
| **3 — Gateway / Enforcement** ← *this* | [robot-md-gateway](https://github.com/RobotRegistryFoundation/robot-md-gateway) | Mandatory exclusive path. Verifies signatures, applies policy, signs audit bundles. |
| **4 — Robot-facing runtime** | [OpenCastor](https://github.com/craigm26/OpenCastor) | Productized open-core runtime. Embeds the gateway as its safety kernel. |
| **5 — Protocol** | [rcan-spec](https://github.com/continuonai/rcan-spec) | Wire format, envelopes, conformance suite. |
| **6 — Registry** | [Robot Registry Foundation](https://robotregistryfoundation.org) | Identity (RRN/RCN/RMN/RHN), public keys, evidence. |

[See the live compatibility matrix →](https://rcan.dev/compatibility)

## What it does

The gateway accepts incoming **signed RCAN INVOKE envelopes** — never
plaintext goals, never SDK sessions. Every envelope is checked for:

1. **Manifest provenance** — the ROBOT.md being actuated against has a verified signature from a key registered to this robot's RRN at RRF.
2. **Tier + RBAC** — the caller's bearer token resolves to a tier authorized for this scope.
3. **Tool allowlist** — the requested tool is in the operator's policy (default-deny on unknown).
4. **Confidence + HiTL gates** *(Phase 4 — Plan 6)* — model-asserted confidence above threshold; human-in-the-loop approval if scope demands it.
5. **Replay protection + freshness** *(Plan 6; freshness v0.5.0a7)*: the envelope's `msg_id` is checked against a bounded FIFO window of ids already seen (oldest evicted first), and when the envelope carries a `timestamp_ms` it must fall inside a configurable window, by default 300 seconds either side of the gateway's clock. An envelope that carries no `timestamp_ms` is not freshness-checked unless `ROBOT_MD_REQUIRE_ENVELOPE_TIMESTAMP` is on: the iOS client signs the field into its pre-image, older CLI signers do not send it at all, and refusing them all would be a silent break. The window is bounded, so this limits how long a captured envelope stays useful; it is not a permanent ledger of every id ever seen.
6. **ESTOP precedence** *(Plan 6)* — physical or operator stop signal preempts any pending action.

**Which of those run depends on one setting, so read this before quoting the
list.** Checks 1, 2, 3, 4 and 6 run on every request. The envelope signature
check itself, and check 5 (replay and freshness) which sits behind it, run
**only when `ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE` is on, and it is off by
default**. With it off the gateway still reads the envelope and still applies
the other five checks, but it does not require the envelope to be signed and
therefore does not check the id against the replay window or the timestamp
against the freshness window. Turning it on is one environment variable, and a
deployment that wants any of what check 5 describes has to turn it on. The
defaults are permissive on purpose, for bring-up; they are not the
configuration this section describes unless you set them that way.

If all checks pass, the gateway dispatches to a local actuation tool
(typically a robot-md-mcp tool call or a direct driver invocation) and
emits a **signed audit bundle** entry per action. If any check fails,
the action is denied and the failure is logged + signed.

## What it does not do

- ❌ **Spawn LLM planners.** That was the v0.2.x mode; it now ships as `--legacy-byok-launcher` for backward compat (deprecation-warned), removed in v0.4.0. Planners run in agent runtimes (Layer 2), separately, and produce signed envelopes that come *to* the gateway.
- ❌ **Be optional.** If you can move the robot without going through the gateway, you don't have an enforcement gateway — you have a hint.
- ❌ **Cover Layer 4.** Drivers, fleet UI, cloud bridge belong to OpenCastor (or any future Layer-4 runtime); not here.

<!-- BEGIN: ecosystem authority disclaimer (canonical, verbatim per spec §10) -->
> **Where safety is actually enforced.**
>
> Physical safety is enforced at Layer 3 (`robot-md-gateway`) or Layer 4 (a runtime that embeds it, e.g., OpenCastor). Declaration alone (Layer 1) does not enforce safety. Agent host alone (Layer 2) is not the safety boundary. If a deployment lacks Layer 3, no safety claim attaches to it.
<!-- END: ecosystem authority disclaimer -->

## Status (v0.3.0a1)

This release lands the rename + scope-shift skeleton. The receive-only
RCAN handler, manifest provenance verification (cert MF-001 / MF-002),
and direct-device-bypass denial (cert GW-001) ship in upcoming patch
releases under Plan 6. The legacy planner-launcher mode is preserved
behind `--legacy-byok-launcher` for one minor release.

## Installation

```bash
pip install robot-md-gateway
```

## Quick start (legacy mode, until receive-only ships)

```bash
python3 -m venv .venv
.venv/bin/pip install robot-md-gateway robot-md   # robot-md-mcp ships with robot-md
.venv/bin/robot-md-gateway init --yes
.venv/bin/robot-md-gateway --legacy-byok-launcher serve \
  --bearers ./bearers.yaml --robot-md ./ROBOT.md
```

`init --yes` writes `bearers.yaml`, `.env`, and `dispatch-test.sh` next to your
ROBOT.md and prints a generated actuate-tier token once. Save the token — it's
not stored anywhere else. Run `robot-md-gateway init` (no `--yes`) for a
guided walk that explains each knob.

## Production install

`systemd/install.sh` handles the full setup: dedicated `robot` system user, `/opt/robot-md-gateway/.venv` with hardened unit, `DeviceAllow=/dev/ttyACM0 rw`, `MemoryMax=1G`, `CPUQuota=80%`, journal logging.

Run `robot-md-gateway init --yes` first (next to your `ROBOT.md`) to generate
`bearers.yaml`, `.env`, and `dispatch-test.sh`. Then:

```bash
sudo ./systemd/install.sh
sudo cp ./bearers.yaml ./.env /etc/robot-md-gateway/
sudo cp ./ROBOT.md /etc/robot-md-gateway/ROBOT.md
sudo systemctl daemon-reload && sudo systemctl enable --now robot-md-gateway
```

### Ingress — do not port-forward

The gateway binds to `127.0.0.1` by design. Expose it via Tailscale Funnel (named, revocable, TLS-terminated):

```bash
tailscale serve --bg --https=443 http://127.0.0.1:8080
tailscale funnel 443 on
```

## Configuration

Environment variables (also settable via CLI flags — flags win):

| Variable | Purpose | Default |
|---|---|---|
| `ROBOT_MD_PATH` | Path to the `ROBOT.md` loaded as the manifest under verification | unset |
| `ROBOT_MD_BEARERS_FILE` | Path to `bearers.yaml` | **required** |
| `ROBOT_MD_MCP_COMMAND` | Stdio MCP command the gateway dispatches to | `robot-md-mcp` |
| `ROBOT_MD_MCP_ARGS` | Space-separated args for the MCP command | (none) |
| `ROBOT_MD_LOG_LEVEL` | Python log level | `INFO` |
| `ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE` | Require every envelope to carry a signature this gateway can check. **The replay window and the freshness window below only run when this is on.** | off |
| `ROBOT_MD_ENVELOPE_MAX_SKEW_S` | Half-width of the envelope freshness window, in seconds, both directions. Unparseable, zero or negative values log a warning and fall back to the default, because a zero window would deny every envelope that carries a timestamp | `300` |
| `ROBOT_MD_REQUIRE_ENVELOPE_TIMESTAMP` | Deny an envelope that carries no `timestamp_ms` instead of letting it through unchecked | off |

## What a client gets back

`/v1/invoke` answers with exactly three shapes. A client that handles these
three handles every tool on every actuator.

**Allowed and executed — `200`:**

```json
{
  "ok": true,
  "manifest_kid": "bob-manifest-2026",
  "scope": "MANIPULATE",
  "tool_name": "arm.move_to",
  "actuator_name": "so-arm101",
  "outcome_kind": "executed",
  "telemetry": {"...": "whatever the driver measured"},
  "attestation": "attested",
  "outcome": {"...": "the signed receipt"},
  "envelope_signature": {"kid": "...", "alg": "Ed25519", "sig": "..."}
}
```

**Denied — `403`.** By a gateway gate, or by the driver's own policy. Either
way it is signed, audited, and safe to keep as evidence:

```json
{
  "detail": {
    "deny": "actuator_policy",
    "reason": "out_of_workspace: x=500mm is outside the declared workspace (-200 to 340mm)",
    "actuator_name": "so-arm101",
    "telemetry": {"deny": "out_of_workspace", "reason": "x=500mm is outside ..."},
    "attestation": "attested",
    "envelope_signature": {"kid": "...", "alg": "Ed25519", "sig": "..."}
  }
}
```

`detail.deny` names which gate refused (`tier_policy`, `tool_allowlist`,
`manifest_provenance`, `safety_state`, `actuator_policy`, …). For
`actuator_policy` — the driver's own refusal — `detail.telemetry` carries the
driver's machine-readable code when it produced one; branch on that, not on the
wording of `reason`. The key is absent when the driver had nothing structured to
say.

**Broken — `500`.** The driver raised. A fault is never dressed up as a
decision, so it does not arrive as a deny and carries no receipt.

### What is inside the signed receipt

The `outcome` object is the receipt. Its bytes are what the Ed25519 signature
covers, so every field listed here is bound to the signature and cannot be
edited without breaking it.

```json
{
  "receipt_version": 2,
  "corr_id": "the envelope's msg_id",
  "rrn": "RRN-... (the robot, from its signed manifest)",
  "status": "ok | denied | failure | error",
  "started_at": "2026-09-14T...", "ended_at": "2026-09-14T...",
  "caller": "craig-iphone",
  "tier": "actuate",
  "envelope_signature": {"kid": "...", "alg": "Ed25519", "sig": "..."}
}
```

**`caller` names a CREDENTIAL, never a person.** It is the `caller` field of
the bearer entry in `bearers.yaml` that authorised the request, the name the
operator wrote beside a token (`craig-iphone`, `host-config`,
`readonly-probe`). It says which token was presented. It does not say who was
holding the device, and no field in this receipt does. A bearer entry with no
`caller` declared produces `"caller": null`, which is the honest answer rather
than a guess.

`receipt_version` tells a reader which shape they have. Receipts signed before
v0.5.0a7 carry no `receipt_version` key at all, no `caller` and no `tier`;
those are version 1 and they stay valid forever. `scripts/verify_receipt.py`
accepts both, and prints which one it read:

```bash
python scripts/verify_receipt.py --receipt receipt.json --pubkey gateway.pub
```

Exit 0 means the bytes carry a signature from the key you supplied AND a
one-byte-flipped copy was rejected. On a version 2 receipt the flipped field is
`caller`, so a hand-edited caller exits non-zero. That is all a pass means: the
record has not changed since it was signed. It is not a statement that the
action was safe, correct, or authorised by any particular person. A signed
receipt is an accountability artifact, and reading it is the check.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
.venv/bin/ruff check src tests
```

The test suite mocks external SDK boundaries via Protocol shims, so `pytest` runs offline. The tier gate, auth, and HTTP surface are exercised end-to-end with a `TestClient`. Real tool names from `robot-md-mcp`'s server are pinned in `tests/test_gating.py`; if the upstream tool surface shifts in a way that inverts a read/actuate classification, the test fails loudly.

## License

Apache-2.0. See [LICENSE](LICENSE).
