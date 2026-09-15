# Changelog

## [Unreleased] (0.5.0a8)

### Added

- **The gateway records before it dispatches (OC-M-04).** The allow path now
  writes two entries per invoke instead of one: an **intent** entry after every
  gate has passed and before `target_actuator.execute()` is called, and the
  **outcome** entry after the actuator answered. `AuditEntry` grew
  `entry_kind` (`"intent"` | `"outcome"`, defaulting to `"outcome"` so every
  entry written before this release keeps exactly the meaning it already had),
  plus `tool_name`, `envelope_id`, `nonce` and `intent_chain_hash`. The outcome
  entry's `intent_chain_hash` is the intent entry's chain hash, so the pair is
  one hop apart.

  **Nothing that already exists stops verifying.** `verify_audit_bundle`
  recomputes each entry's hash from the dict in the bundle rather than from an
  `AuditEntry` rebuilt out of it, so a bundle signed before these fields existed
  is hashed over exactly the bytes it was signed over. `GET /v1/audit/last`
  returns the entry's `__dict__` and the iOS client decodes it into a
  schema-free `CanonicalValue`, so the five new keys ride along with nothing to
  fall out of date. Both are pinned by tests now, because the obvious
  alternative implementation of either would have silently invalidated every
  bundle ever exported.

  The late record stayed, because the reason it existed is still true: only a
  record written after the dispatch can say what happened. What it could never
  cover is the case where nothing comes back at all, and that case is now on the
  record.

  **An intent is not an action that happened.** The signed intent payload's
  status is `"dispatching"` and is never anything else; the intent NDJSON line
  carries no `outcome` key at all. `scripts/verify_receipt.py --walk` reports an
  intent with no outcome as `dispatch never reported`, which is a named finding
  and not a gap, and `--receipt` refuses an intent record by name rather than
  printing a PASS beside `status=dispatching`.

  **Best effort, unchanged.** Every write in the new path is wrapped the way the
  outcome path already was: a signing failure, a full disk or an unwritable
  export is logged and swallowed. It never crashes the request and never alters
  actuation. A record is evidence, not enforcement.

  Volume note for busy robots: this roughly doubles the durable trace. Bob's
  export was already growing without a shipper; see the shipper unit below.

- **The durable trace is ordered, and a removed line leaves a hole (OC-10).**
  Every `rcan-action-trace/1` line now carries `seq` (monotonic within one export
  file) and `chain_prev` (sha256 of the previous line's bytes, as written, with
  no trailing newline), plus `record_kind`. The head is persisted in a sibling
  `<export>.head` file written **before** the line it describes, so the only
  crash window leaves the head one AHEAD of the file (a line that never landed,
  which a walk reports) and never one behind (a reused seq, which would be a
  silent restart inside the sequence).

  **Lines written before this release bind nothing**, and nothing here pretends
  otherwise. They carry no `seq` and no links, and this release cannot
  retroactively give them any. The first numbered line after such history starts
  at `seq: 1`, sets `chain_prev` to the sha256 of the last unnumbered line's
  bytes, and is marked `chain_note: "unnumbered_history"`.

  **A missing head file beside a numbered export is reported, not silently
  restarted.** The gateway appends, continues from what the file itself still
  proves (last line's `seq` + 1, `chain_prev` over its bytes), and marks that one
  line `chain_note: "head_recovered_from_file"`. Refusing to append was
  considered and rejected: the record path is best effort by contract, and
  refusing would destroy evidence to protect the appearance of an unbroken
  chain. If the head and the tail were removed together, the rebuilt number is
  the truncated file's, and only an off-box copy shows it. The marker is what
  tells a reader to go and compare.

- **`scripts/verify_receipt.py --walk <file>`.** Walks a whole NDJSON export and
  reports the first gap by seq and any chain break. No key, no network, no
  import of this package, so a third party handed the file can run it and check
  the operator's arithmetic. Exit 0 clean, 1 for a gap or a chain break, 3 for
  named findings a person has to read. A clean walk is consistency, not
  completeness, and the output says so.

### Changed

- **The shipper reports tampering instead of re-delivering from zero (OC-10).**
  A persisted offset past the end of the export file means bytes this shipper
  already delivered are gone from the local copy. That now logs
  `TAMPER/TRUNCATED` with the offset, the path and the size, raises
  `ShipperTamperStop`, and exits 3 (which the generated unit lists in
  `RestartPreventExitStatus`, so the journal keeps the line). The offset file is
  left untouched and nothing is re-sent.

  The old behaviour reset to 0 and re-delivered, and it had the failure exactly
  backwards: truncation is the one event the off-box copy exists to survive, and
  quietly starting over turned it into a silent re-upload that made the local
  file authoritative again. This is a report, not a defence. Nothing here
  prevents tampering and nothing here can.

### Fixed

- **Two invokes at once no longer fork the chain or lose a line.** `/v1/invoke`
  is a sync FastAPI path operation, so Starlette runs it in a worker thread and
  two invokes with different msg_ids are genuinely concurrent. Three things were
  not safe under that, and record-before-dispatch made all three twice as likely
  by writing twice per invoke:

  - `AuditChain.append` read `entries[-1].chain_hash`, hashed, then appended.
    Two threads read the same predecessor and both linked to it. Measured on a
    Pi 5 with 8 threads appending 25 entries each and the interpreter switch
    interval turned down: 257 to 302 of 400 entries ended up with a `chain_prev`
    that was not the previous entry's `chain_hash`. The entries were all still
    there; their ORDER stopped being provable, which is what a hash chain is
    for. `append` now holds a `threading.Lock` and RETURNS the stored entry.
  - the intent path read the hash back off `audit_chain.entries[-1]`, which
    under two invokes can be the other request's intent. It reads the returned
    entry now. An evidence link that points at the wrong dispatch is worse than
    one that is absent.
  - `append_trace_line` read the head, wrote the head and appended the line as
    three separate steps, and `write_trace_head` staged through one shared
    `<export>.head.tmp`. Two threads both got seq N, and the second's
    `os.replace` raised `FileNotFoundError` because the first had already
    renamed the temp file away, which the best-effort wrapper swallows: the
    request succeeded and THE TRACE LINE WAS SILENTLY GONE. 8 threads writing 6
    lines each left 6 of 48 lines in the file. Appends are now serialised by a
    per-export-file lock and each writer stages through its own temp name.

- **Three fsyncs before every dispatch was too many; there is now one.** The
  intent line is written before `target_actuator.execute()`, so every fsync on
  that path is time a `drive.stop` or an `arm.estop` spends waiting on an SD
  card before the robot is told anything. Measured on a Pi 5, ext4 on the card,
  per trace line: head `fsync` + directory `fsync` + export-line `fsync` was
  16.3 ms mean / 21.8 ms p95; the head `fsync` alone is 8.3 ms mean / 12.2 ms
  p95. An invoke writes two lines, so the added blocking IO per invoke went from
  32.7 ms to 16.6 ms, of which 8.3 ms is before the dispatch.

  The directory `fsync` and the export-line `fsync` were the two that bought the
  least. Losing the head's rename loses the head, and a missing head is already a
  handled and REPORTED condition (`head_recovered_from_file` on the next line).
  Losing the line lands in the crash window the head file already names and
  `--walk` already reports, and durability of that line is a promise this export
  never made before v0.5.0a8 anyway: it was a plain buffered write.

  **This does not make the record less true, only less likely to survive a power
  cut**, and every way it can be lost is named on the next line written or
  reported by `--walk`. The honest remaining limit: an `fsync` on a stalling SD
  card has no timeout, so a failing card can still make an invoke slow. It
  cannot make it wrong, and unsetting `ROBOT_MD_ATTESTATION_EXPORT_FILE` takes
  the export off the path entirely.

- **A partial last line no longer restarts the sequence or eats the next
  record.** A crash between the first byte of a trace line and its newline
  leaves a torn tail, and dropping the per-line `fsync` above makes that shape
  likelier. Two things went wrong on such a file and both are fixed:

  - `next_trace_link` could not read a seq off the torn line, concluded the file
    had never been numbered, and returned `seq: 1` with
    `chain_note: "unnumbered_history"`. A numbered file restarted at 1 AND said
    on the record that it had never been numbered, which is precisely the silent
    restart this format exists to end. It now looks further back for the last
    line whose number can be read, continues from there, and marks the line
    `chain_note: "previous_line_partial"`. The torn line's own number is
    unreadable and is not guessed.
  - `append_trace_line` wrote straight onto a file that did not end in a
    newline, welding the torn record and the whole new record into one
    unparseable line, so a crash cost two records instead of one. It writes a
    separating newline and leaves the torn line exactly as it is, broken and
    reportable.

  `--walk` names a partial last line as `PARTIAL LINE` and exits 3 rather than
  1: nothing the file claims is missing. The message says that cutting the tail
  off a file looks the same from here and that only an off-box copy separates
  the two.

### Deliberately not in this release

- **`ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE` is still off, and the flip is
  deliberately last.** The Python client has to sign first. `castor`'s
  `bench/sacpaint/gateway.py` `build_envelope` attaches no `envelope_signature`,
  so turning the gate on today returns 403 to `castor bench`, the console and
  the paint rail while the iOS app keeps working. The order is: generate a
  caller identity in `castor up` and publish its kid to the RRF stub, make the
  Python client sign the invoke, and only then render
  `ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE=1` into the generated policy. Nobody flip
  the flag early.

- **The shipper sends outcomes, not intents, and says so.** PlatAtlas's rcan
  ingest reads `rec.outcome ?? {}` and verifies it. An intent line has no
  `outcome` key on purpose, so an intent would land over there with
  `exec_verdict: "verify_failed"` and `binding_ok: false`. Confirmed by reading
  the rail: the ingest never 4xxs, never throws, never fails the batch, and both
  actor population and action-context indexing are gated on
  `binding_ok && authz_verdict === 'verified'`, so an intent could never be
  counted as an execution. Shipping them would be safe.

  It would not be honest yet, which is the reason it is not done.
  Record-before-dispatch writes one intent per invoke, so shipping them would
  fill the remote store with records marked as failed signature verification
  when not one signature failed: the intent IS signed, correctly, and the field
  says `verify_failed` only because the thing it verifies is not in the record.
  Any recompute over the pack would then report a large and growing population
  of failed signatures that are not failures, which ruins the first number an
  outside party looks at.

  So `ship_once` skips `record_kind: "intent"` lines, counts them, and logs the
  count with the reason. The offset still advances past them, so nothing is
  re-read. Lines with no `record_kind` at all (everything written before
  v0.5.0a8) mean outcome and are shipped. Lines that do not parse are shipped:
  deciding that a malformed line is not evidence is not the shipper's call.

  **The honest cost, stated rather than buried:** the local export stays
  complete and is the copy `--walk` reads, but until this changes the off-box
  copy does NOT hold the record that a dispatch was attempted. A dispatch that
  never reported is visible only in the file the operator controls. Teaching the
  ingest to read `record_kind` is a rail follow-up; when it lands, set
  `PLATATLAS_SHIP_INTENTS=1` and the remote copy becomes complete too.

## [Unreleased] (0.5.0a7)

### Changed

- **Receipts are version 2 and carry the caller.** The signed outcome now
  includes `receipt_version: 2`, `caller` and `tier`, all three inside the
  signed bytes. Until now the serve path collapsed the bearer store to
  `{token: tier}` one step before the only record in this ecosystem that gets
  signed outside the agent's process, so every receipt said an actuate-tier
  principal acted and none said which of the robot's credentials did.

  **`caller` names a CREDENTIAL, never a person.** It is the `caller` field of
  the bearer entry in `bearers.yaml` that authorised the request, the name the
  operator wrote beside a token (`craig-iphone`, `host-config`,
  `readonly-probe`). It says which token was presented. It does not say who was
  holding the device, and no field in the receipt does. A bearer entry with no
  `caller` yields `"caller": null`.

  **Wire change, both versions accepted.** The iOS app, the PlatAtlas console
  and the shipper all read receipts, and receipts already on disk are version 1
  forever. Version 1 is a receipt with no `receipt_version` key; it carries no
  caller and no tier. `scripts/verify_receipt.py` accepts both, says which it
  read, and on a version 2 receipt flips `caller` for its tamper check, so a
  hand-edited caller exits non-zero. `AuditEntry` and `GET /v1/audit/last` grew
  the same two fields; entries exported before this release verify unchanged.

- **A refusal is recorded as a fail, not a pass.** Five cert modules called
  `record_property_pass` on the branch where they REFUSED something, so the
  gateway's own report could not tell a refusal from a success: a gateway that
  denied everything produced the same evidence as one that allowed everything
  correctly, and a tripped ESTOP filed SF-001 evidence in the gateway's favour.
  Every deny branch in `cert/gates.py`, `cert/policy.py`, `cert/rrn_binding.py`,
  `cert/safety.py` and `cert/envelope.py` now records a fail, through a single
  `cert/report.py::record_property` entry point that takes the outcome as an
  argument so a branch cannot inherit a pass from the function name.
  `cert/revocation.py` and `receiver.py` already did this correctly and are
  unchanged. Genuine allow branches still record passes.

  This changes what a released `gateway-authority-*.json` looks like: reports
  that drive deny paths (the emitter does) now show fails against RC-002,
  RC-003, RC-004, GW-002, GW-003, MF-003, SF-001 and SF-002 where they showed
  passes before. Nothing about the gate behaviour changed; only the outcome
  written down did.

- **The replay cache evicts the oldest id, not an arbitrary one.** It was a
  `set` whose overflow branch called `set.pop()`, which removes an arbitrary
  member, so the id it dropped could be the one seen a millisecond earlier and
  dropping an id is exactly what re-enables its replay. It is an
  insertion-ordered queue now: oldest out, everything inside the window stays
  rejected, and re-recording an id does not refresh its place in the queue.

### Added

- **Envelope freshness, the check README has claimed since Plan 6.** An
  envelope's `timestamp_ms` must fall inside a configurable window, by default
  300 seconds either side of the gateway's clock; outside it the envelope is
  denied with `deny: envelope_freshness`, reason `stale_timestamp`, recorded as
  an RC-002 fail and signed like any other decision. The check runs BEFORE the
  replay cache, so a flood of stale envelopes cannot push live ids out of the
  window.

  The honest limit: an envelope that carries no `timestamp_ms` is not
  freshness-checked unless `ROBOT_MD_REQUIRE_ENVELOPE_TIMESTAMP` is on. The iOS
  client signs the field into its pre-image; the bring-up harness and older CLI
  signers do not send it at all, and refusing them all would be a silent break
  for a check they never had. `ROBOT_MD_ENVELOPE_MAX_SKEW_S` sets the width.

- **A `bearers.yaml` with no `caller` field loads.** It used to read
  `row["caller"]` and take the whole gateway down at boot on a file that was
  valid the day it was written. `castor up` generates the field, so this
  affects only hand-written and pre-0.5 files.

- **A driver's structured refusal now reaches the client.** An actuator that
  declines on policy (`outcome_kind="denied"`) already returned a signed 403
  with `deny: actuator_policy` and a `reason` sentence. When the driver also
  produced telemetry — a machine-readable account of *why* — that account is now
  returned under `detail.telemetry`.

  `reason` is prose for a person, and prose gets reworded. A client deciding
  what to do next needs a code it can branch on; without one, every client ends
  up regexing the sentence and the message becomes an accidental API that can
  never change. This is not new information on the wire: telemetry is already
  hashed into the signed outcome (`telemetry_sha256`), so the structure returned
  here is bound to the same signature the sentence is, and the ALLOW path has
  always returned it verbatim.

  The key is **absent**, not empty, when the driver had nothing structured to
  say — `telemetry: {}` would read as a claim that the driver considered the
  question and said nothing about it.

  The first consumer is `so-arm101-actuator` ≥ 0.3.0, whose `arm.move_to`
  refuses an unholdable Cartesian target with codes such as `unreachable`,
  `joint_limits` and `unsafe_pose`:

  ```json
  {
    "detail": {
      "deny": "actuator_policy",
      "reason": "out_of_workspace: x=500mm is outside the declared workspace (-200 to 340mm)",
      "actuator_name": "so-arm101",
      "telemetry": {
        "deny": "out_of_workspace",
        "reason": "x=500mm is outside the declared workspace (-200 to 340mm)"
      },
      "attestation": "attested",
      "envelope_signature": {"kid": "...", "alg": "Ed25519", "sig": "..."}
    }
  }
  ```

  An actuator that CRASHES still returns 500 — unchanged, and still the line
  that keeps a fault from being dressed up as a decision.

## [0.5.0a6] — 2026-07-16

### Security
- **Tools are now bound to caller tiers** (`ROBOT_MD_TOOL_MIN_TIER`). The tier
  gate keys off the envelope's self-declared `scope`, which the caller controls,
  while the allowlist gate never sees the tier — so an envelope naming an
  actuating tool under `scope: "OBSERVE"` cleared both. Binding tiers to the
  TOOL closes that. Unset preserves prior behaviour.
- **An unreadable `manifest_path` now fails closed** as a signed, audited
  `manifest_provenance` denial. Previously a missing file, a directory, or an
  empty string raised through as a bare HTTP 500 with no receipt and no audit
  entry — and clients that accept only 200/403 could not consume it at all.
- Adds the `commission` tier and includes `COMMISSION` in the actuation scopes.
- **An actuator's own policy refusal is now a signed 403**, not a bare 500.
  A driver that declines on policy (`outcome_kind="denied"` — e.g. an RC car
  asked to move with no drive approval open) was falling into the generic
  actuator-failure path: unsigned, and unreadable to clients that accept only
  200/403. It now returns `deny: actuator_policy` with the signed outcome
  attached, like every other gate. An actuator that CRASHES still returns 500 —
  a fault must never be dressed up as a decision.

### Added

- **Signed receipts on the wire.** `/v1/invoke` now embeds the Ed25519-signed
  outcome in the HTTP response so a client can verify the receipt without the
  NDJSON attestation file. ALLOW (200) responses carry a top-level
  `envelope_signature: {kid, alg, sig}`, the full signed `outcome`, and
  `attestation: "attested"`; 403 DENY responses carry the same signed record
  inside `detail`. The signature reuses the exact `build_outcome` +
  `sign_envelope` recipe as the file trace — the wire receipt is byte-identical
  to the file's `outcome` (no new crypto).
- **Explicit unattested marker.** When `ROBOT_MD_ATTESTATION_KEY_FILE`/`KID`
  are unset the gateway still returns 200/403 (never crashes) with
  `attestation: "unattested"` and `envelope_signature: null`, so a client can
  render honestly.
- **`scripts/verify_receipt.py`.** Standalone third-party verifier (stdlib +
  `cryptography` only, no gateway import) that verifies a receipt's signature
  against the kid's public key and proves a one-byte flip fails. Exits 0 only
  when authentic AND tamper-evident.
- **Tests.** `test_receiver_signed_wire.py` (signed-allow / signed-deny /
  unattested-fallback / tamper / wrong-key) and `test_verify_receipt_script.py`
  (subprocess end-to-end).

## [0.5.0a3] — 2026-05-11

### Added

- **Multi-actuator dispatch.** `make_app(actuators={name: Actuator},
  actuator_configs={name: dict})` registers multiple actuators behind one
  gateway. The receiver routes `/v1/invoke` by `envelope.actuator_name`;
  missing name → 422, unknown name → 404. Single-actuator mode
  (`make_app(actuator=...)`) is unchanged and remains the default. Closes
  the robot-md trial → gateway invoke gap for rigs with both a perception
  actuator and a motion actuator (Spec B Phase E).
- **`actuators:` list section in bearers.yaml.** New `load_actuators_section()`
  reads `actuators: [{name, config}, ...]`. The serve path uses the list
  shape when present and falls back to the singular `actuator:` section
  otherwise.
- **`InvokeEnvelope.actuator_name`.** Now a real optional field rather than
  silently dropped via Pydantic's `extra='ignore'`. Required when the
  gateway is configured for multiple actuators; ignored otherwise.

## [0.5.0a2] — 2026-05-10

### Added

- **`telemetry` in `/v1/invoke` 200 response.** Receiver now returns the
  full `outcome.telemetry` dict alongside `outcome_kind`, so callers can
  verify actuator-level success (e.g., `move().reached`) without a second
  round-trip. Required for `bob.local/MOTION-FIDELITY-100` cert-intake
  evidence (Phase 2 of the foundation rebuild roadmap).

## [0.5.0a1] — 2026-05-08

### Added

- **Actuator extension surface.** New `Actuator` Protocol in
  `robot_md_gateway.actuator` discovered via Python entry-points
  (`robot_md_gateway.actuators` group). Built-in `NoOpActuator`. Operators
  publish their own actuator package; gateway picks it up at serve time.
- **Audit-chain outcome fields.** `AuditEntry` gains `actuator_name`,
  `actuator_outcome_kind`, `actuator_telemetry_sha256`, `actuator_telemetry_path`,
  `actuator_error_kind` (all optional, default `None`). Audit entries from v0.4.x
  verify cleanly under the v0.5.0a1 verifier.
- **Per-actuator config.** `bearers.yaml` accepts a new top-level dict shape
  (`bearers:` + `actuator:` keys); the legacy top-level list shape continues to
  work. Actuator config is validated against the actuator's `config_schema`
  using `jsonschema` at serve startup; mismatch fails serve loudly.
- **`list-actuators` subcommand.** Walks the entry-point group; prints each
  discovered actuator's name, description, and config schema. With `--bearers`,
  marks the currently-configured choice with an asterisk.
- **`/v1/audit/last` endpoint.** Read-only; returns the last audit entry as JSON
  for downstream tooling (used by `robot-md invoke --print-bundle-entry` in Plan 2).
- **Telemetry persistence.** Actuators that set `ActuatorOutcome.telemetry_path`
  to a file get the file's bytes hashed into the audit entry alongside the path —
  so the bundle's cryptographic receipt covers what the actuator did, not just
  the gate decision.

### Changed

- `make_app(...)` gains `actuator: Actuator | None = None` and
  `actuator_config: dict | None = None` keyword-only parameters. Existing call
  sites work unchanged (defaults route to `NoOpActuator()` + `{}`).
- `/v1/invoke` response shape gains `actuator_name` and `outcome_kind` fields
  on success. Clients ignoring them are unaffected.
- `BearerStore.from_yaml` accepts both legacy list and new dict shape; legacy
  files require no change.

### Compatibility

- v0.4.x audit chains verify cleanly under v0.5.0a1's verifier (forward-compat
  test in suite). Cross-version verification in the OTHER direction
  (v0.5.0a1 chains under v0.4.x verifier) is NOT supported — chain hash includes
  the new fields.
- Legacy `--legacy-byok-launcher` mode is unchanged.

### Dependencies

- New runtime dep: `jsonschema>=4.0` (used to validate per-actuator config).

## v0.3.0a1 — 2026-05-03

### Renamed

- **Package + GitHub repo: `robot-md-dispatcher` → `robot-md-gateway`.** Old PyPI name republished as a tombstone (v0.2.1) that depends on this package. Old GitHub URL redirects.
- **Module: `robot_md_dispatcher` → `robot_md_gateway`.** Backward-compat shim ships at the old import path with a `DeprecationWarning`. Shim removed in v0.5.0.
- **CLI: `robot-md-gateway`** is the new command. The old `robot-md-dispatcher` command keeps working with a deprecation banner; removed in v0.5.0.

### Scope-shifted

- **Default mode is now receive-only RCAN envelope enforcement.** The gateway accepts signed INVOKE envelopes, verifies them, and dispatches to drivers. The previous v0.2.x planner-launcher mode is preserved behind `--legacy-byok-launcher` for backward compat — deprecation-warned, removed in v0.4.0.
- **Manifest provenance verification added.** Every action's target ROBOT.md is checked for a valid signature against an RRF-registered key (cert property MF-001 / MF-002).
- **Direct device-node bypass denial added.** udev policy generator + service-account isolation enforce the gateway as the exclusive `/dev/tty*` owner (cert property GW-001).

### Forbidden-phrase lint

- The previous v0.2.x framing is now blocked by the ecosystem-wide forbidden-phrase lint (Plan 2). The new README ships into already-honest copy.

## 0.2.0 — 2026-04-24

### Added
- New `robot-md-dispatcher init` subcommand that scaffolds `bearers.yaml`, `.env`, and a `dispatch-test.sh` smoke-test script for a robot whose `ROBOT.md` is already in place. Has a guided mode (explains each knob) and a `--yes` one-shot mode (all defaults).
- `--force` flag to regenerate files (invalidates old tokens).
- `--no-token-stdout` flag that suppresses the "print token once" step — used by the `/enable-dispatch` Claude Code slash command in `robot-md-mcp` so fresh secrets never enter agent context.
- Hard-fail preconditions: `ROBOT.md` must exist and pass `robot_md.validate`; `robot-md-mcp` must be on PATH.

### Changed
- `robot-md>=1.1` is now a runtime dependency (used for ROBOT.md parse + validate via Python API instead of subprocessing the CLI). This pulls in `robot-md`'s transitive deps (numpy, jinja2, jsonschema, mcp, rich, ruamel-yaml, typer, websockets, rcan[pq,crypto]) — install footprint grows accordingly; users on minimal images should be aware.

## 0.1.0 — 2026-04-24

Initial scaffold. FastAPI `/dispatch` endpoint, tier-based gating, bearer auth, systemd install script, BYOK billing pattern.
