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
5. **Replay protection** *(Plan 6)* — envelope's nonce + timestamp not previously seen.
6. **ESTOP precedence** *(Plan 6)* — physical or operator stop signal preempts any pending action.

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

### Onboarding checklist for the operator

The systemd service runs as the unprivileged `robot` user, which the install
script adds to `dialout` so it can open `/dev/ttyACM*`. The interactive human
who installs the gateway usually *also* wants to run `robot-md`,
`robot-md-mcp`, or `robot-md-gateway` from their own shell — and that
requires the same group membership for their UID. Without it,
`backend.open` fails with `EACCES` and the MCP server silently falls through
to "no backend" mode (see issue #21).

`systemd/install.sh` handles this by default: it adds `$SUDO_USER` to
`dialout` alongside the service user. To opt out (strictly service-only
install), pass `--no-interactive-user`:

```bash
sudo ./systemd/install.sh --no-interactive-user
```

**You must log out and back in** for the new group membership to attach to
your login session. After re-login, verify with:

```bash
groups | grep -E 'dialout|robot-md-gateway' && ls -l /dev/ttyACM0 && echo OK
```

If `/dev/ttyACM0` is owned by a custom group (e.g. a site-local udev rule
that hands the device to `robot-md-gateway:robot-md-gateway` rather than
`dialout`), add yourself to that group too. Pass the username explicitly —
under `sudo`, `$USER` is `root` and would add the wrong account:

```bash
sudo usermod -aG <group> <your-login-username>
# or, programmatically: sudo usermod -aG <group> "$(logname)"
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

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
.venv/bin/ruff check src tests
```

The test suite mocks external SDK boundaries via Protocol shims, so `pytest` runs offline. The tier gate, auth, and HTTP surface are exercised end-to-end with a `TestClient`. Real tool names from `robot-md-mcp`'s server are pinned in `tests/test_gating.py`; if the upstream tool surface shifts in a way that inverts a read/actuate classification, the test fails loudly.

## License

Apache-2.0. See [LICENSE](LICENSE).
