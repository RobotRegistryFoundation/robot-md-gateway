# Changelog

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
