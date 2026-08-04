# Changelog

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
