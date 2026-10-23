# robot-md-gateway

> **The enforcement gateway for the OpenCastor stack.**
> Receives signed RCAN action envelopes, verifies manifest provenance, applies tier policy + tool allowlist, dispatches to drivers. Designed to be the only path between agent intent and any actuator; that holds only when the deployment makes it so (see [Where this fits in the stack](#where-this-fits-in-the-stack)). Open source; intended to become OpenCastor's safety kernel via open-core extraction.

[![PyPI](https://img.shields.io/pypi/v/robot-md-gateway.svg)](https://pypi.org/project/robot-md-gateway/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-green)](https://www.python.org)
[![RCAN](https://img.shields.io/badge/RCAN-live%20matrix-blue)](https://rcan.dev/compatibility)

> **Renamed in 2026-05.** This package was previously published as `robot-md-dispatcher`. The old name is now a tombstone on PyPI; `pip install robot-md-dispatcher` continues to work and pulls this package as a dependency. Imports and the `robot-md-dispatcher` CLI keep working through v0.4.x via a backward-compat shim. See [CHANGELOG.md](CHANGELOG.md) for migration notes.

## Where this fits in the stack

`robot-md-gateway` is **Layer 3** of the OpenCastor stack — the
enforcement gateway. It is designed to be the only path from agent
intent to any actuator. That holds only when the deployment makes it
so: the gateway runs as its own service account, and the GW-001 udev
rule makes that account the owner and group of the robot's device nodes
(mode 0660), so other non-root users get `EACCES` when they open them
([procedure](docs/hil/gw-001-procedure.md)). The default
`systemd/install.sh` does not set this up: it gives the device to the
`dialout` group and adds the installing user to that group, so another
local process can still reach the servos. Adding users to the device's
group, as the [onboarding checklist](#onboarding-checklist-for-the-operator)
describes for interactive use, has the same effect.

| Layer | Piece | What it is |
|---|---|---|
| **1 — Declaration** | [robot-md](https://github.com/RobotRegistryFoundation/robot-md) | The ROBOT.md file + Python CLI. Declares identity, capabilities, safety gates. |
| **2 — Agent runtime** | (any MCP host) | Claude Code, Codex, Gemini — plans actions, calls tools, and is not meant to reach actuators directly. |
| **3 — Gateway / Enforcement** ← *this* | [robot-md-gateway](https://github.com/RobotRegistryFoundation/robot-md-gateway) | Designed to be the only path to the actuators, when the deployment enforces it (see above). Verifies signatures, applies policy, signs audit bundles. |
| **4 — Robot-facing runtime** | [OpenCastor](https://github.com/craigm26/OpenCastor) | Productized open-core runtime. Embeds the gateway as its safety kernel. |
| **5 — Protocol** | [rcan-spec](https://github.com/RobotRegistryFoundation/rcan-spec) | Wire format, envelopes, conformance suite. |
| **6 — Registry** | [Robot Registry Foundation](https://robotregistryfoundation.org) | Identity (RRN/RCN/RMN/RHN), public keys, evidence. |

[See the live compatibility matrix →](https://rcan.dev/compatibility)

## What it does

The gateway accepts incoming **signed RCAN INVOKE envelopes** — never
plaintext goals, never SDK sessions. Every envelope is checked for:

1. **Manifest provenance** — the ROBOT.md being actuated against has a verified signature from a key registered to this robot's RRN at RRF.
2. **Tier + RBAC** — the caller's bearer token resolves to a tier authorized for this scope.
3. **Tool allowlist** — the requested tool is in the operator's policy (default-deny on unknown). A tool the actuator declares as motion (`motion_capabilities`) must also be invoked under an actuation scope (`MANIPULATE`, `NAVIGATE`, `ACTUATE`, `EXECUTE`, `COMMISSION`, in any case): the same motion relabelled `OBSERVE` is refused, because the tier, confidence and HiTL gates key off that caller-written field. For a motion tool those gates also apply the strictest motion scope's rule (HiTL on any of MANIPULATE, NAVIGATE, ACTUATE, EXECUTE covers all four), so relabelling among them buys nothing.
4. **Confidence + HiTL gates** *(Phase 4 — Plan 6)* — model-asserted confidence above threshold; human-in-the-loop approval if scope demands it.
5. **Replay protection + freshness** *(Plan 6; freshness v0.5.0a7)*: the envelope's `msg_id` is checked against a bounded FIFO window of ids already seen (oldest evicted first), and when the envelope carries a `timestamp_ms` it must fall inside a configurable window, by default 300 seconds either side of the gateway's clock. An envelope that carries no `timestamp_ms` is not freshness-checked unless `ROBOT_MD_REQUIRE_ENVELOPE_TIMESTAMP` is on: the iOS client signs the field into its pre-image, older CLI signers do not send it at all, and refusing them all would be a silent break. The window is bounded, so this limits how long a captured envelope stays useful; it is not a permanent ledger of every id ever seen.
6. **ESTOP precedence** *(Plan 6)* — physical or operator stop signal preempts any pending action. A stop tool sent through `/v1/invoke` (one an actuator declares in `stop_capabilities`) runs on worker threads of its own (`STOP_LANES`), so it does not wait behind other requests for a thread; whether it then preempts a motion in progress is up to the actuator (so-arm101-actuator latches first and ends a paced move at its next setpoint). A flood of requests that saturates the gateway's CPU still delays it, because CPU and the GIL are shared by every thread (the stop latched 4.7 s after it was sent under 200 looping clients on two cores, in simulation; 0.05 s with no other traffic): the software stop is not the physical e-stop. A declared stop (a tool the actuator that receives it declares in `stop_capabilities`) takes a path of its own. It passes in every gateway state, `safe_stop` and `estop_active` included, which refuse everything else. It is judged as `SAFETY` whatever scope the envelope carries. It is never refused for its signature, freshness, revocation or replay (a replayed stop is processed and recorded as `REPLAY_DETECTED`), and the key registry is never consulted for it. The actuator gets the pinned manifest, or none, never the one the request names, and confidence and HiTL do not apply. A stop still needs a bearer the gateway knows (any tier), the operator's allowlist and the operator's per-tool tiers (see [Heartbeat and safe-stop](#heartbeat-and-safe-stop-sf-002)).

**Which of those run depends on one setting, so read this before quoting the
list.** Checks 1, 2, 3, 4 and 6 run on every request but a declared stop, which
skips 1, 4 and 5 as item 6 says. The envelope signature
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

### Record before dispatch, and record again after

The gateway writes its record before dispatch. **This is implemented, not spec
text.** Since v0.5.0a8 the allow path writes **two** entries per invoke, in this
order:

1. an **intent** entry, written after every check above has passed and
   **before** `target_actuator.execute()` is called. It carries the tool, the
   envelope id and msg id, the caller and tier, the nonce and the name of the
   actuator about to be driven, signed with the same Ed25519 recipe the outcome
   uses. It says the gateway was about to dispatch. **It says nothing about
   whether the dispatch happened.**
2. an **outcome** entry, written after the actuator returned or raised. This is
   the entry that says what happened, and it carries the intent entry's chain
   hash so the pair is one hop apart.

Read the pair through that hash and the shared `corr_id`, **never off the chain
by position**. Two invokes at once are two threads, and A-intent, B-intent,
A-outcome, B-outcome is an ordinary interleaving: the entries stay correctly
linked and correctly ordered, but a pair need not be adjacent.

The record used to be written only after the dispatch, on purpose, so that it
could say what actually happened. That reason is still true, which is why the
late record stayed. What the late record could never cover is the case where
nothing comes back at all: a driver that hangs, a process killed mid-motion, a
robot unplugged between the gate and the wire. Those used to leave no trace that
anything had been attempted. RCAN §6.3 makes the write before driver dispatch
normative, and the pair is how both halves are true at once.

An intent with no outcome beside it is **a dispatch that never reported**. It is
not an action that happened, and `scripts/verify_receipt.py --walk` names it in
exactly those words rather than counting it either way.

**Both writes are on the request path**, before and after the dispatch, and on a
Pi 5 with the export on the SD card they add about 16.6 ms of blocking IO per
invoke, of which about 8.3 ms falls before the actuator is called. That is one
`fsync` per line and it is the floor for a record that is on disk before the
robot moves. An `fsync` has no timeout, so a failing card can make an invoke
slow; it cannot make it wrong, and unsetting
`ROBOT_MD_ATTESTATION_EXPORT_FILE` takes the export off the path entirely.

Both writes are **best effort**, unchanged from the contract the outcome record
has always had: a signing failure, a full disk or an unwritable export is logged
and swallowed. It never crashes the request and it never changes whether the
robot moves. A record is evidence, not enforcement.

### Is anything missing? `--walk`

Every NDJSON trace line written from v0.5.0a8 carries a `seq` (monotonic within
one export file) and a `chain_prev` (sha256 of the previous line's bytes), with
the head persisted in a sibling `<export>.head` file written **before** the line
it describes. Deleting or truncating a line now leaves a hole:

```bash
python scripts/verify_receipt.py --walk attestation-export.ndjsonl
```

No key and no network needed, so a third party handed the file can run it.
Walking Bob's real 4437-line, 4.1 MB export takes 0.15 s on a Pi 5.
Exit 0 is a clean walk, 1 is a gap or a chain break, 3 is named findings a
person has to read. A clean walk means the numbering and the links agree with
each other; it does **not** mean the file is complete. A line cut from the end,
with the head file taken too, leaves nothing local to notice, which is the whole
reason there is an off-box copy.

### The file grows, and it is meant to

The export is append-only and **there is no cap and no rotation**. Two lines per
invoke since v0.5.0a8, roughly a kilobyte each: Bob's export was 4437 lines and
4.1 MB before any of this, from one robot and no shipper. Plan for it the way
you would plan for a journal, and watch the disk.

Rotation is deliberately not built in, and **a rotated export reads as
tampering**, which is the correct reading and not a bug. The shipper's offset
would land past the end of the shorter file and it stops with a named
`TAMPER/TRUNCATED` line rather than re-delivering, because from the outside a
rotation and somebody cutting the file are the same event. `--walk` on the new
file sees a `seq` that does not start where the old one stopped. If you must
move the file, do it deliberately: stop the gateway, move the export, the head
and the offset together, and keep the old file, because the off-box copy is the
only thing that shows what the local one no longer holds.

Lines written before v0.5.0a8 carry no `seq` and **bind nothing**; the walk says
how many there are and refuses to imply otherwise. The first numbered line after
them binds the last unnumbered line's bytes and is marked `unnumbered_history`.
A missing head file beside a numbered export is reported the same way, on the
line, as `head_recovered_from_file`: the gateway continues from what the file
itself still proves rather than refusing to append (which would destroy evidence
to protect the appearance of an unbroken chain) or silently restarting at 1
(which is the failure this whole format exists to end).

## What it does not do

- ❌ **Spawn LLM planners.** That was the v0.2.x mode; it now ships as `--legacy-byok-launcher` for backward compat (deprecation-warned), removed in v0.4.0. Planners run in agent runtimes (Layer 2), separately, and produce signed envelopes that come *to* the gateway.
- ❌ **Be optional.** If you can move the robot without going through the gateway, you don't have an enforcement gateway — you have a hint.
- ❌ **Cover Layer 4.** Drivers, fleet UI, cloud bridge belong to OpenCastor (or any future Layer-4 runtime); not here.

<!-- BEGIN: ecosystem authority disclaimer (canonical; revised 2026-10-08 from spec §10 after EV-03; keep identical in robot-md, robot-md-gateway and OpenCastor) -->
> **Where safety is meant to be enforced.**
>
> Physical limits are meant to be enforced at Layer 3 (`robot-md-gateway` and the actuator driver it calls), and only for commands that pass through it. OpenCastor (Layer 4) does not embed the gateway yet, so actuators it drives directly are not covered. Declaration alone (Layer 1) does not enforce safety. Agent host alone (Layer 2) is not the safety boundary. If a deployment lacks Layer 3, no safety claim attaches to it. Layer 3 is not a certified safety function, and hostile-input testing in simulation (October 2026) found motions it does not yet bound.
<!-- END: ecosystem authority disclaimer -->

## Status (v0.3.0a1)

This release lands the rename + scope-shift skeleton. The receive-only
RCAN handler, manifest provenance verification (test properties MF-001 /
MF-002), and direct-device-bypass denial (test property GW-001) ship in upcoming patch
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

`systemd/install.sh` handles the full setup: dedicated `robot` system user, `/opt/robot-md-dispatcher/.venv` with hardened unit, `DeviceAllow=/dev/ttyACM0 rw`, `MemoryMax=1G`, `CPUQuota=80%`, journal logging.

The on-disk names still carry the package's old name: the install goes to
`/opt/robot-md-dispatcher`, config to `/etc/robot-md-dispatcher`, and the unit
is `robot-md-dispatcher.service`. The installer writes
`/etc/robot-md-dispatcher/dispatcher.env` with absolute paths; the unit reads
that file, not a `.env`.

Run `robot-md-gateway init --yes` first (next to your `ROBOT.md`) to generate
`bearers.yaml`, `.env`, and `dispatch-test.sh`. Then:

```bash
sudo ./systemd/install.sh
sudo cp ./bearers.yaml ./ROBOT.md /etc/robot-md-dispatcher/
sudo systemctl daemon-reload && sudo systemctl enable --now robot-md-dispatcher
```

Run `install.sh` before the copy. It creates `bearers.yaml` `root:robot` with
mode 0640, and copying onto an existing file keeps that owner and mode. The file
`init` writes has an actuate entry (and a read one) but no supervisor and no
commission entry: add both (see [Bearer tokens](#bearer-tokens)), or the gateway
stays held.

### Bearer tokens

The unit runs `serve --bearers /etc/robot-md-dispatcher/bearers.yaml`. Without
that file systemd refuses to start it (`AssertPathExists=`). A file with no
entries, an empty token or a placeholder token (`REPLACE-WITH-...`) stops the
gateway at startup; a token shorter than 32 characters loads with a
`weak_bearer_token` warning. If there is no file, `install.sh` creates one with
two generated tokens, an `actuate`-tier one for the agent's client and a
supervisor one for the heartbeat, and no commission token. It is `root:robot`
0640, so the service reads it through its group and cannot rewrite it. No token
is printed, and the installer never overwrites an existing file. Neither file is
ever committed: `bearers.yaml` and `dispatch-test.sh` are in `.gitignore`.

How a client gets its token:

1. On the robot, read it with `sudo cat /etc/robot-md-dispatcher/bearers.yaml`.
2. Prefer one entry per client, so each receipt names the credential that
   acted (`caller`). Edit with `sudoedit`, which keeps the owner and mode, then
   `sudo systemctl restart robot-md-dispatcher`:

   ```yaml
   bearers:
     - token: "..."          # python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
       tier: actuate         # read | actuate | commission
       caller: craig-iphone  # names the credential, never a person
     - token: "..."          # a token of its own, never one used above
       role: supervisor      # the heartbeat credential: read tier, nothing more
       caller: craig-laptop
   ```

3. Give the token to the client out of band, for example in the app's settings
   or in an environment variable on the agent host. The client sends it as
   `Authorization: Bearer <token>`.

The credentials, and who holds them:

- `actuate`: the agent's client. It can move the robot; it cannot clear a stop.
- `role: supervisor`: the device of the person supervising the robot, never the
  agent's host and never the robot. It is the only credential the heartbeat
  accepts. It holds the read tier, so on `/v1/invoke` it can stop the robot and
  read, and nothing else. The gateway refuses to start if a supervisor entry
  has any other tier, or if one token is listed twice.
- `commission`: the operator, and nobody else. The gateway starts held, and only
  a commission clear arms it (`POST /v1/safety/clear`); clearing so-arm101's
  latch (`arm.estop.clear`) needs it too. Add this entry by hand; the installer
  does not create one. Keep it out of every agent's config.
- A stop (`arm.estop`) needs any of these. A request with no bearer, or one the
  gateway does not know, is refused even for a stop.

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

## Heartbeat and safe-stop (SF-002)

`robot-md-gateway serve` always runs a safety monitor, and there is no switch to
turn it off.

**It starts held.** A gateway that starts, or restarts, is in `safe_stop`: it
refuses every request with `deny: safety_state`, except a declared stop, until
an operator arms it. A restart is never a resume. To arm it, in this order:

1. From the supervisor's device, send heartbeats at least every 3 seconds (send
   one every second):

   ```bash
   curl -fsS -X POST -H "Authorization: Bearer $SUPERVISOR_TOKEN" \
     http://127.0.0.1:8080/v1/safety/heartbeat
   ```

2. As the operator, `POST /v1/safety/clear` with the `commission` bearer.

**Who may send the heartbeat.** Only a credential with `role: supervisor` in
`bearers.yaml` (see [Bearer tokens](#bearer-tokens)). Every other credential is
refused (403 `not_a_supervisor`), the agent's included: the heartbeat says that
the person supervising the robot can still reach it, so the thing being
supervised must never be able to keep it alive. A request with no bearer is
refused (401), and so is an unknown one (403).

Keep the supervisor token on the supervising person's device, such as the
operator's app or laptop. Never put it on the host that runs the agent, and
never on the robot. Where the agent runs on the robot itself, as on bob, either
would put the heartbeat beside the thing it supervises, and a heartbeat sent
from the robot only proves that the gateway is running.

**When the heartbeat stops.** After 3 seconds without one, the gateway enters
`safe_stop`. A watchdog thread checks every 0.1 s, whether or not requests are
arriving. Every move into `safe_stop` or `estop_active` (the in-process ESTOP
wire, `app.state.safety_monitor.on_estop_wire`), `safe_stop` to `estop_active`
included, is a trip:

- The gateway sends each actuator that declares a stop (`stop_capabilities`)
  that stop, as itself: no bearer and no gate, at tier `read`, with the pinned
  manifest or none. For so-arm101-actuator that is `arm.estop`: it latches, ends
  a paced move at its next setpoint and holds the pose. The hold is done in
  software; it is not a hardware e-stop.
- Each stop runs on a thread of its own, so a stop that hangs on its bus delays
  no other actuator's stop and does not stop the watchdog. After 10 s without an
  answer the gateway records it as failed and stops waiting for it. A stop
  whose thread could not start is tried again on the next tick.
- Nothing on this path reads ROBOT.md: what to stop, and the robot's RRN, were
  resolved when the gateway started.
- An actuator that refuses this stop cannot be stopped by the gateway, so every
  motion through it is refused from then until the gateway restarts
  (`deny: stop_unreachable`). The same holds from startup for one whose declared
  tiers (`required_tiers`, or a module-level `REQUIRED_TIERS`) leave out `read`.
  A tool declared both as a stop and as a motion stops the gateway at startup.
- The trip, each stop and each timeout are recorded in the audit chain and the
  export (`safety_trip: ...`, `safety_stop: ...`, `safety_stop_timeout: ...`).
  The trip record names the caller of the last accepted heartbeat. An actuator
  that declares no stop cannot be stopped this way: the gateway logs
  `no_declared_stop` for it at startup, and the trip record says
  `nothing was told to stop`.

From then on every request is refused with `deny: safety_state`, except a
declared stop (item 6 under [What it does](#what-it-does)).

**If the watchdog itself stops ticking** for 1 s, the gateway fails closed: it
enters `safe_stop` and sends the stops, and the heartbeat and the clear answer
503 `safety_watchdog`, never 200.

**Resuming takes two explicit steps.** A heartbeat alone never resumes.

1. `POST /v1/safety/clear`, which is refused:
   - with 409 while a stop of the last trip has neither answered nor timed out
     (the clear first sends any stop not yet sent);
   - with 503 while the watchdog is not ticking;
   - with 403 while the heartbeat is stale, or before any has arrived since the
     gateway started;
   - with 403 below the commission tier;
   - with 403, where `ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE` is on, unless the
     body is a signed envelope of type `ESTOP_CLEAR`, with a fresh
     `timestamp_ms`, a `msg_id` never seen before, and a key that is not
     revoked.

   Allowed or refused, the clear is recorded like any decision: the audit
   chain, a signed receipt on the response, and a line in the export.
2. Clear the actuator's own latch. For so-arm101-actuator, invoke
   `arm.estop.clear` at the commission tier. It must be on
   `ROBOT_MD_TOOL_ALLOWLIST`. Until then the arm refuses motion itself
   (`deny: actuator_policy`, `estop_latched`).

**A restart and the arm's latch.** so-arm101-actuator keeps its latch in
memory, inside the gateway's process, so a restart forgets it. The gateway's own
hold stands in for it: a restarted gateway starts held and dispatches nothing
but stops until a commission clear. After that clear the arm is not latched,
so the clear alone resumes it. A restart also discards the in-memory audit
chain; a clear keeps it.

**What is not built yet.** The design names the
[robot-md-pendant](https://github.com/RobotRegistryFoundation/robot-md-pendant)
as the heartbeat's source (`docs/gateway-integration-spec.md`: a signed
heartbeat every second, 3 s staleness, an explicit resume). Nothing delivers a
pendant heartbeat yet, so the supervisor credential is a bearer token for now;
later the gateway should accept only the pendant's verified, signed heartbeat.
A second lease, renewed by the agent harness only when it has heard from the
model, would also stop the robot when the connection to the model is lost.

## Configuration

Environment variables (also settable via CLI flags — flags win):

| Variable | Purpose | Default |
|---|---|---|
| `ROBOT_MD_PATH` | Path to the `ROBOT.md` this gateway enforces. When set, `/v1/invoke` denies (403 `manifest_pin`, audited) any envelope whose `manifest_path` resolves to a different file. Unset = no pin; bench only | unset |
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
say. A driver's refusal is recorded as a refusal: `status: "denied"` in the
signed receipt and `decision: "deny"`, reason `actuator_policy: ...`, in the
audit chain.

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
