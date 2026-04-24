# robot-md-dispatcher

> **BYOK Claude Agent SDK dispatcher for a `ROBOT.md`-described robot.**
> Accepts natural-language tasks over HTTP and runs them through a local Claude agent on the robot host. Reasoning, tool-calling, and audit stay local — only the goal and final result cross the network. Each caller brings their own Anthropic API key.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-green)](https://www.python.org)

## Where this fits in the stack

`robot-md-mcp` is the right answer when a human operator drives a robot from an interactive MCP client (Claude Code, Claude Desktop, Cursor, Zed). `robot-md-dispatcher` is the right answer when an **external system** — a cron job, a Slack bot, a phone app, another agent — needs to hand a robot a task and wait for the result. You keep the ROBOT.md safety gates; you get tier-gated auth; you don't open remote MCP to the internet.

| Layer | Piece | What it is |
|---|---|---|
| **Declaration** | [ROBOT.md](https://github.com/RobotRegistryFoundation/robot-md) | The file a robot ships at its root. YAML frontmatter + markdown prose. |
| **Agent bridge** | [robot-md-mcp](https://github.com/RobotRegistryFoundation/robot-md-mcp) | MCP server that exposes a `ROBOT.md` to any MCP-aware agent over stdio. |
| **Remote dispatch** ← *this* | [robot-md-dispatcher](https://github.com/RobotRegistryFoundation/robot-md-dispatcher) | **BYOK Claude Agent SDK dispatcher** — accepts tasks over HTTP, runs them through a local Claude agent, consumes `robot-md-mcp` unchanged. |
| **Wire protocol** | [RCAN](https://rcan.dev/spec/) | How robots, gateways, and planners talk. |
| **Registry** | [Robot Registry Foundation](https://robotregistryfoundation.org) | Permanent RRN identities. |
| **Reference runtime** | [OpenCastor](https://github.com/craigm26/OpenCastor) | Open-source robot runtime. |

## Why not remote MCP?

Three shapes were considered; this repo is shape (c):

| | (a) `--http` on robot-md-mcp | (b) Python shim around robot-md-mcp | (c) **Agent SDK dispatcher** |
|---|---|---|---|
| Reasoning runs at | Remote Claude surface | Remote Claude surface | **Robot host** |
| Unit crossing the network | Every tool call + every result | Every tool call + every result | **Goal + final result** |
| Upstream change required | Yes | None (shim) | **None (consumer)** |
| Sensor data leaves the LAN | Yes | Yes | **No** |
| Fits "fix upstream first" | Yes | No | **Yes** |

`robot-md-mcp` remains a clean stdio server. The dispatcher *consumes* it; it does not wrap or mirror it.

## How it works

1. Caller POSTs to `/dispatch` with:
   - `Authorization: Bearer <tier-token>` — determines **actuate** vs **read** tier
   - `X-Anthropic-Api-Key: sk-ant-...` — the caller's own Anthropic key; inference bills to them
   - Body `{"goal": "<natural language task>"}`
2. The dispatcher spins up a **fresh** [`ClaudeSDKClient`](https://github.com/anthropics/claude-agent-sdk-python) for this request with `env={"ANTHROPIC_API_KEY": <caller_key>}`, `mcp_servers={"robot": {"type":"stdio","command":"robot-md-mcp"}}`, and a `system_prompt` that includes the full `ROBOT.md`.
3. The agent loop runs on the robot host. Every tool invocation passes through two gates:
   - `can_use_tool` — denies actuation tools (`estop`, `execute_task`, `record_skill`, ...) for read-tier callers. **Default-deny**: new tools added upstream are gated until you allowlist them.
   - `PreToolUse` audit hook — writes `(caller, tier, key-fingerprint, tool, args)` to the journal.
4. Agent messages stream back to the caller as NDJSON.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install robot-md-dispatcher robot-md   # robot-md-mcp ships with robot-md

cat > bearers.yaml <<'EOF'
- token: replace-me-read
  tier: read
  caller: example-read
- token: replace-me-actuate
  tier: actuate
  caller: example-actuate
EOF

# Generate real tokens: python3 -c "import secrets;print(secrets.token_urlsafe(32))"

.venv/bin/robot-md-dispatcher serve \
  --robot-md ./ROBOT.md \
  --bearers ./bearers.yaml \
  --host 127.0.0.1 --port 8080
```

Dispatch a task:

```bash
curl -N http://127.0.0.1:8080/dispatch \
  -H "Authorization: Bearer replace-me-actuate" \
  -H "X-Anthropic-Api-Key: sk-ant-..." \
  -H "Content-Type: application/json" \
  -d '{"goal": "validate the manifest and describe what the robot can do"}'
```

The response is NDJSON — one JSON object per agent message. Tail it.

## Production install

`systemd/install.sh` handles the full setup: dedicated `robot` system user, `/opt/robot-md-dispatcher/.venv` with hardened unit, `DeviceAllow=/dev/ttyACM0 rw`, `MemoryMax=1G`, `CPUQuota=80%`, journal logging.

```bash
sudo ./systemd/install.sh
sudoedit /etc/robot-md-dispatcher/bearers.yaml
cp ROBOT.md /etc/robot-md-dispatcher/ROBOT.md
sudo systemctl daemon-reload && sudo systemctl enable --now robot-md-dispatcher
```

### Ingress — do not port-forward

The dispatcher binds to `127.0.0.1` by design. Expose it via Tailscale Funnel (named, revocable, TLS-terminated):

```bash
tailscale serve --bg --https=443 http://127.0.0.1:8080
tailscale funnel 443 on
```

## Safety model

- **Default-deny tier gate.** Read-tier callers can only invoke allowlisted observation tools (`render`, `validate`, `get_*`, `list_*`, `describe_*`, `vision_find`, `discover`, `status`). Every other tool — including `estop` and `estop_clear`, which are safety-critical but still disruptive — requires actuate-tier. Operators who want read-tier estop must install a custom policy.
- **ROBOT.md is in the system prompt.** Claude sees every safety gate in the manifest on every dispatch. Gate violations are refused with an explanation.
- **Resource rails.** `max_turns` and `max_budget_usd` are Pydantic-bounded; the systemd unit adds `MemoryMax`, `CPUQuota`, and `TasksMax` at the process level.
- **Audit log.** Every tool call lands in the journal with the caller ID, tier, API-key fingerprint (sha256[:12], never the key itself), tool name, and args.
- **No key persistence.** The caller's API key lives only in the per-request subprocess env and the in-memory `AuthContext`. It is never logged, stored, or forwarded.

## BYOK and billing

v0.1 is Bring Your Own Key: every caller supplies their own `sk-ant-...` and Anthropic bills them directly. This keeps the dispatcher out of the billing path entirely — you host the control plane, your users pay for the inference they request.

A managed billing layer (shared keys, per-caller quotas, Stripe metering) is out of scope for this repo and belongs in downstream infrastructure; see [opencastor-ops](https://github.com/craigm26/opencastor-ops) for that shape.

## Configuration

Environment variables (also settable via CLI flags — flags win):

| Variable | Purpose | Default |
|---|---|---|
| `ROBOT_MD_PATH` | Path to the `ROBOT.md` loaded into the system prompt | unset |
| `ROBOT_MD_BEARERS_FILE` | Path to `bearers.yaml` | **required** |
| `ROBOT_MD_MCP_COMMAND` | Stdio MCP command the agent connects to | `robot-md-mcp` |
| `ROBOT_MD_MCP_ARGS` | Space-separated args for the MCP command | (none) |
| `ROBOT_MD_LOG_LEVEL` | Python log level | `INFO` |

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
.venv/bin/ruff check src tests
```

The test suite mocks the Claude Agent SDK boundary via a `ClientFactory` protocol, so `pytest` runs offline and does not require `claude` CLI, an API key, or the `claude-agent-sdk` package to actually function — only to import. The tier gate, auth, and HTTP surface are exercised end-to-end with a `TestClient`.

Real tool names from `robot-md-mcp`'s server are pinned in `tests/test_gating.py`; if the upstream tool surface shifts in a way that inverts a read/actuate classification, the test fails loudly.

## License

Apache-2.0. See [LICENSE](LICENSE).
