# robot-md-dispatcher: `init` wizard design

**Status:** Draft — 2026-04-24
**Scope:** v0.2.0 of `robot-md-dispatcher` + one slash command added to `robot-md-mcp`'s existing Claude Code plugin

---

## Problem

A user has a robot with `ROBOT.md` already in place (set up via `castor init`, `robot-md`, or by hand). They now want to enable remote dispatch so external systems can hand this robot tasks over HTTP. Today that means: generate bearer tokens with a `python3 -c "import secrets; ..."` one-liner, write `bearers.yaml` by hand, author a `.env`, read the README, and maybe shell out to `install.sh` and `tailscale`. It's a dozen small steps.

Target experience: one command, all defaults taken, done. Or the same command in guided mode, explaining each knob as it asks.

**Non-goals:**
- First-time robot onboarding / scaffolding `ROBOT.md` (belongs in `castor init` / `robot-md`).
- Running `sudo` from the wizard itself (the production-install step prints commands for the user to run).
- Starting the dispatcher service (`init` writes config; `serve` runs it).
- Registering with RRF (RRN is read from `ROBOT.md` if present; not mutated).

---

## Architecture

### Canonical implementation

A new module `src/robot_md_dispatcher/init_wizard.py` in the dispatcher package. Single entry point:

```python
def run(*, interactive: bool, cwd: Path, force: bool, no_token_stdout: bool) -> int: ...
```

One code path; `interactive` toggles prompts vs. defaults; `no_token_stdout` toggles the "print the token to stdout" step; `force` toggles overwrite behavior. Returns a process exit code.

### CLI entry points

Both are subcommands on the existing `robot-md-dispatcher` command (`src/robot_md_dispatcher/__main__.py`):

- **`robot-md-dispatcher init`** — guided mode. Each prompt is preceded by a one-sentence explanation of what the knob does, *then* asks with a default in brackets.
- **`robot-md-dispatcher init --yes`** — one-shot mode. No prompts. Uses defaults, writes files, prints the generated actuate token and next-step commands.
- **`robot-md-dispatcher init --yes --force`** — one-shot, overwrite existing `bearers.yaml` / `.env`. Invalidates old tokens.
- **`robot-md-dispatcher init --yes --no-token-stdout`** — one-shot, never prints the token to stdout. Used by the plugin slash command so freshly-generated secrets don't enter the agent's context window. The user opens `bearers.yaml` to read the token.

### Claude Code plugin surface

A **slash command** (not a skill) added to the existing `robot-md-mcp` plugin:

```
robot-md-mcp/
├── .claude-plugin/
│   └── plugin.json
├── skills/
│   └── using-robot-md/          # existing
└── commands/                    # new directory
    └── enable-dispatch.md       # new slash command
```

`/enable-dispatch` instructs Claude to:
1. Verify `ROBOT.md` exists in the workspace root; bail with a clear message if not.
2. Verify `robot-md-dispatcher` is importable/on PATH; if not, tell the user to `pip install robot-md-dispatcher`.
3. Run `robot-md-dispatcher init --yes --no-token-stdout` via Bash, streaming output.
4. Tell the user: *"bearer token written to `./bearers.yaml` — open the file to read it. Not printed here to keep it out of this conversation."*
5. Print the `serve` command for them to run next.

**Why a slash command, not a skill:** generating and writing secrets is an explicit user action, not something an LLM should activate on trigger-match. The user types `/enable-dispatch` when they want it, full stop.

### Precondition check

Before any prompts or writes:

1. `./ROBOT.md` exists.
2. `from robot_md.validate import validate; validate(Path('./ROBOT.md'))` returns clean.

If either fails, the wizard exits 1 with a fix-directing message (see Error handling). The wizard never scaffolds `ROBOT.md`.

---

## Prompt flow (guided mode)

Each prompt is preceded by a boxed explanation. Mashing Enter accepts the default.

```
$ robot-md-dispatcher init

Found ROBOT.md for 'my-so-arm' (RRN: RRN-000000000042).

╭─ What this does ────────────────────────────────────────────╮
│ Writes a bearers.yaml (access tokens) and a .env (paths +   │
│ MCP command) next to your ROBOT.md. Does not start the      │
│ service or open network ports.                              │
╰──────────────────────────────────────────────────────────────╯
Enable remote dispatch for 'my-so-arm'? [Y/n]

╭─ Bind address ──────────────────────────────────────────────╮
│ Local address the dispatcher listens on. Use 127.0.0.1 if   │
│ you'll front this with Tailscale Funnel or a reverse proxy. │
│ Use 0.0.0.0 only if your network boundary is hardened.      │
╰──────────────────────────────────────────────────────────────╯
Bind address [127.0.0.1]:

╭─ Port ──────────────────────────────────────────────────────╮
│ TCP port the HTTP server binds to. 8080 is the default.     │
╰──────────────────────────────────────────────────────────────╯
Port [8080]:

╭─ Bearer tokens ─────────────────────────────────────────────╮
│ Callers authenticate with a bearer token. Each token has a  │
│ tier: 'actuate' can drive the robot; 'read' can only call   │
│ observation tools (render, validate, get_*, list_*, ...).   │
╰──────────────────────────────────────────────────────────────╯
Generate an actuate-tier token? [Y/n]
Also generate a read-tier token? [y/N]

╭─ Production install (systemd) ──────────────────────────────╮
│ For long-running hosts, install as a systemd service under  │
│ a dedicated 'robot' user with MemoryMax/CPUQuota limits.    │
│ Requires sudo. This wizard prints the commands; it does NOT │
│ run sudo on your behalf.                                    │
╰──────────────────────────────────────────────────────────────╯
Install as systemd service? [y/N]

╭─ Tailscale Funnel ──────────────────────────────────────────╮
│ Named, revocable, TLS-terminated public URL via your        │
│ tailnet. We'll print the two setup commands; we won't run   │
│ them (they need your interactive auth).                     │
╰──────────────────────────────────────────────────────────────╯
Print Tailscale Funnel setup commands? [y/N]

─── Writing files ────────────────────────────────────────────
  ./bearers.yaml       (0600, 1 token)
  ./.env               (0644, 4 vars)
  ./dispatch-test.sh   (0700)

─── Next steps ───────────────────────────────────────────────
Actuate-tier bearer token (save it now — not stored elsewhere):

  HJk3l9...XYZ

Start the dispatcher:
  robot-md-dispatcher serve --bearers ./bearers.yaml --robot-md ./ROBOT.md

Send a test dispatch (exports ANTHROPIC_API_KEY first):
  export ANTHROPIC_API_KEY=sk-ant-...
  ./dispatch-test.sh

Tip: add these files to .gitignore —
  bearers.yaml
  .env
  dispatch-test.sh
```

## Prompt flow (one-shot mode)

```
$ robot-md-dispatcher init --yes
Found ROBOT.md for 'my-so-arm'.
Writing: bind 127.0.0.1:8080, 1 actuate token, dev-mode (./ files).
  ./bearers.yaml
  ./.env
  ./dispatch-test.sh

Actuate token (save now — not persisted anywhere else):
  HJk3l9...XYZ

Next:
  robot-md-dispatcher serve --bearers ./bearers.yaml --robot-md ./ROBOT.md

Tip: add bearers.yaml, .env, dispatch-test.sh to .gitignore
```

With `--no-token-stdout` (plugin path), the "Actuate token" block is replaced by:

```
Actuate token written to ./bearers.yaml (0600). Open the file to read it.
```

---

## File outputs & data shape

### Always written

**`./bearers.yaml`** — matches `BearerStore.from_yaml`'s expected shape exactly (`src/robot_md_dispatcher/auth.py`):

```yaml
# robot-md-dispatcher bearers — generated by `init` on 2026-04-24
# Rotate by replacing tokens and restarting the service.
- token: <secrets.token_urlsafe(32)>
  tier: actuate
  caller: actuate-default
# If the user opted in to a read token:
# - token: <...>
#   tier: read
#   caller: read-default
```

Permissions `0600`. Caller IDs default to `<tier>-default`; user renames after the fact. The wizard does not prompt for caller IDs (one caller per tier is the zero-friction case).

**`./.env`** — consumed by `create_app_from_env()`:

```
ROBOT_MD_PATH=./ROBOT.md
ROBOT_MD_BEARERS_FILE=./bearers.yaml
ROBOT_MD_MCP_COMMAND=robot-md-mcp
ROBOT_MD_LOG_LEVEL=INFO
```

Permissions `0644`. `ROBOT_MD_MCP_COMMAND` is not prompted — `robot-md-mcp` is the ecosystem default; override via `serve --mcp-command` when needed.

### Conditionally written

**`./dispatch-test.sh`** — only if the actuate token is generated (i.e., always, at current defaults). Permissions `0700` — the bearer token is baked into the script in plaintext, so group/other must not read it. Template:

```bash
#!/usr/bin/env bash
# robot-md-dispatcher smoke test — generated 2026-04-24 by `init`
set -euo pipefail

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    echo "error: export ANTHROPIC_API_KEY=sk-ant-... before running this script" >&2
    exit 1
fi

curl -N http://127.0.0.1:8080/dispatch \
    -H "Authorization: Bearer <ACTUATE_TOKEN>" \
    -H "X-Anthropic-Api-Key: ${ANTHROPIC_API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{"goal": "call render and describe the robot"}'
```

The bearer token is baked into the script (it's already secret-scoped to the user's dev machine); the Anthropic key is read from env to avoid persisting a second secret in a second file. The script refuses to run without `ANTHROPIC_API_KEY` set.

### Never written by `init`

- `/etc/robot-md-dispatcher/*` — even when systemd=yes. User runs `sudo ./systemd/install.sh && sudo cp ./bearers.yaml ./.env /etc/robot-md-dispatcher/` per printed instructions. Keeps `init` sudo-free.
- `ROBOT.md` — precondition.
- `.gitignore` — wizard prints a tip; does not mutate the repo's metadata files.

### Idempotence

- If `./bearers.yaml` or `./.env` exist without `--force`: refuse with `./bearers.yaml already exists. Use 'init --force' to regenerate tokens (this invalidates the old ones).`
- `init --force` overwrites both files and generates new tokens atomically (both-or-neither). Old tokens are gone — that's the v0.2 rotation story.
- `init --yes` without `--force` still refuses on existing files; silent overwrite is the wrong default.
- `rotate` and `add-caller` are named in docs as future subcommands but not shipped in v0.2.

---

## Error handling & atomicity

### Hard failures (exit 1 with specific message, no traceback)

| Condition | Message |
|---|---|
| `./ROBOT.md` missing | `No ROBOT.md in <cwd>. Run 'robot-md init' or 'castor init' first.` |
| `ROBOT.md` fails `robot_md.validate.validate(...)` | Prints validation errors verbatim, then `Fix ROBOT.md and re-run 'robot-md-dispatcher init'.` |
| `robot-md` Python package not importable | `robot-md package not installed. Install with 'pip install robot-md'.` (declared as a pip dep in v0.2; this fires only if someone unpins it) |
| `robot-md-mcp` binary not on PATH | `robot-md-mcp not found on PATH. Install with 'npm install -g robot-md-mcp' (Node) or 'pip install robot-md' (Python wrapper).` |
| `./bearers.yaml` or `./.env` exists, no `--force` | `./bearers.yaml already exists. Use 'init --force' to regenerate tokens (this invalidates the old ones).` |
| Bare `init` (no `--yes`), stdin is not a TTY | `Interactive mode requires a TTY. Use 'init --yes' for defaults, or run from a terminal.` |

### Soft warnings (printed, do not block)

*(None as of v0.2 — `robot-md-mcp` missing is now a hard fail per design decision.)*

### Atomicity

- Files are written via `tempfile.NamedTemporaryFile` in the target dir, then `os.replace()` to the final name — either committed or not; no half-files.
- If any write fails after a prior write succeeded, the wizard `os.unlink`s the earlier successes before exiting non-zero.
- The token is printed to stdout (or suppressed, per `--no-token-stdout`) **only after** both `bearers.yaml` and `.env` are committed. A crash mid-write can never leave a token in scrollback that isn't also in the file.

### Keyboard interrupt

Caught at the top of `run()`, prints `Aborted. No files written.`, exits 130. No traceback.

### Token-in-LLM-context threat model

The plugin slash command runs `init --yes --no-token-stdout` precisely so freshly-generated secrets don't enter the agent's conversation context (which may be retained in session transcripts, forwarded to sub-agents, etc.). The CLI path (run in the user's terminal, where stdout is under their control) echoes the token once with a "save it now" admonition; the plugin path suppresses this and directs the user to open `bearers.yaml` themselves.

This is documented in the spec and in the plugin command's help text; users who want to pipe the plugin's output somewhere are explicitly told the token isn't in it.

---

## Dependencies

Adds one pip dep to `pyproject.toml`:

```toml
dependencies = [
    "claude-agent-sdk>=0.1",
    "fastapi>=0.110",
    "uvicorn[standard]>=0.27",
    "python-frontmatter>=1.0",
    "pydantic>=2.6",
    "robot-md>=1.1",        # new — for validate + parser used by init
]
```

`robot-md` is already in the ecosystem and exports `robot_md.validate` and `robot_md.parser` as public Python modules. Importing directly (vs. subprocessing `robot-md` CLI) avoids the binary-on-PATH check, runs faster, and gives the wizard direct access to parsed frontmatter (we need the robot name for the confirm prompt regardless).

No new dev-deps. `pytest`, `monkeypatch`, `capsys`, and `tmp_path` cover the test surface.

---

## Testing strategy

All offline, deterministic. No real robot, no real API key, no network.

| Test | Validates |
|---|---|
| `test_init_yes_golden_path` | `init --yes` in tmp cwd with valid `ROBOT.md` writes `bearers.yaml` (0600, one actuate entry, token ≥ 32 chars, loadable via `BearerStore.from_yaml`), `.env` (0644, 4 expected vars, correct paths), `dispatch-test.sh` (0700, executable, baked token matches yaml) |
| `test_init_yes_prints_token_once` | Captured stdout contains the token string exactly once, equal to the token in `bearers.yaml` |
| `test_init_yes_no_token_stdout` | With `--no-token-stdout`, stdout does *not* contain the token; file contains it; stdout contains the "open the file" message |
| `test_init_refuses_without_robot_md` | Empty cwd → exit 1, stderr matches `No ROBOT.md` |
| `test_init_refuses_on_invalid_robot_md` | Bad frontmatter → exit 1, stderr includes validate errors |
| `test_init_refuses_on_existing_files` | Pre-existing `bearers.yaml` → exit 1, stderr mentions `--force` |
| `test_init_force_overwrites` | `--force` regenerates; old token no longer resolves via `BearerStore` |
| `test_init_non_tty_refuses_without_yes` | Piped stdin + bare `init` → exit 1 with TTY message |
| `test_init_guided_accepts_all_defaults` | Pipe `"\n" * N` to `init`, assert same outputs as `--yes` |
| `test_init_guided_custom_port` | Pipe answers with port `9090`; assert `.env` has `9090` and `dispatch-test.sh` uses `9090` |
| `test_init_missing_robot_md_mcp` | Mock `shutil.which('robot-md-mcp')` to None → exit 1 |
| `test_init_atomicity_on_write_failure` | Patch `os.replace` to raise on second file; assert no partial files remain, non-zero exit |
| `test_init_ctrl_c_clean_abort` | Inject `KeyboardInterrupt` into a prompt; assert exit 130, no files, "Aborted" message |
| `test_init_read_token_optional` | Guided run answering `y` to read-tier prompt; `bearers.yaml` has both entries; both load via `BearerStore` |
| `test_init_extracts_robot_name_from_frontmatter` | `ROBOT.md` with `name: my-so-arm` → confirm prompt renders `'my-so-arm'` |

Framework: existing `pytest` suite; `pathlib.Path`, `tmp_path`, `capsys`, `monkeypatch`. No new dev-deps.

---

## Plugin slash command

**File:** `robot-md-mcp/commands/enable-dispatch.md` (new directory in the plugin repo).

**Body** (skeleton):

```markdown
---
name: enable-dispatch
description: Enable remote HTTP dispatch for this ROBOT.md robot. Generates bearer tokens and writes dispatcher config. Does not print secrets to this conversation.
---

Run `robot-md-dispatcher init --yes --no-token-stdout` in the workspace root.

Precondition: `ROBOT.md` must exist at the workspace root and `robot-md-dispatcher`
must be importable / installed (`pip install robot-md-dispatcher`). If either is
missing, stop and tell the user.

After the command succeeds, tell the user:
1. `bearers.yaml` and `.env` have been written to the workspace root
2. Their actuate-tier bearer token is in `bearers.yaml` (not shown here by design —
   open the file directly)
3. They can start the dispatcher with:
   `robot-md-dispatcher serve --bearers ./bearers.yaml --robot-md ./ROBOT.md`

Do not echo, print, or repeat the contents of `bearers.yaml` in the conversation.
```

The slash command intentionally declines to read/echo the token — that's what the `--no-token-stdout` flag is for at the CLI level, and the command's instructions reinforce it at the agent level.

---

## Release plan

v0.2.0 release sequencing — important to avoid shipping a plugin command that invokes a not-yet-published binary:

1. **First**: `robot-md-dispatcher` 0.2.0
   - Add `init_wizard.py` + tests.
   - Wire `init` subcommand in `__main__.py`.
   - Add `robot-md>=1.1` dep.
   - Tag, publish to PyPI.
2. **Then**: `robot-md-mcp` plugin release
   - Add `commands/enable-dispatch.md`.
   - Bump plugin version in `.claude-plugin/plugin.json`.
   - Tag, republish plugin.
3. **README updates** — after both are out, update the "Remote dispatch" row in `robot-md/README.md` and `robot-md-mcp/README.md` to mention `init` / `/enable-dispatch` as the zero-friction path.

A user on an old plugin version doesn't see the slash command but can still run `robot-md-dispatcher init --yes` from their terminal — no broken state, just a missing convenience.

---

## Open questions

None as of this draft. All advisor concerns addressed:
- Slash command (not skill) — explicit user action, matches Q3 pick.
- Plugin file lives at `commands/enable-dispatch.md` (new dir in plugin, matches Claude Code plugin convention).
- Plugin path uses `--no-token-stdout` to keep secrets out of agent context.
- `robot-md` validation via Python import, not CLI subprocess.
- `.gitignore` tip explicitly lists `dispatch-test.sh`.
- `dispatch-test.sh` refuses to run without `ANTHROPIC_API_KEY`.
- Release order named: dispatcher 0.2.0 first, plugin second.
