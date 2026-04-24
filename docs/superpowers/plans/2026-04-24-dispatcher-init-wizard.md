# Dispatcher `init` Wizard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `robot-md-dispatcher init` (guided + `--yes` one-shot) and an `/enable-dispatch` slash command in `robot-md-mcp`'s Claude Code plugin, so a user with `ROBOT.md` already in place can enable remote dispatch with one command.

**Architecture:** New module `src/robot_md_dispatcher/init_wizard.py` implements a single `run(*, interactive, cwd, force, no_token_stdout) -> int`. CLI wraps it via `init` subcommand in `__main__.py`. Plugin adds `commands/enable-dispatch.md` that shells out with `--no-token-stdout` so secrets never enter agent context. ROBOT.md validation imports `robot_md.{parser,validate}` directly — no subprocess.

**Tech Stack:** Python 3.10+, stdlib `secrets` for tokens, stdlib `tempfile`+`os.replace` for atomic writes, `pyyaml` (already a transitive dep via `python-frontmatter`), `robot-md>=1.1` (new pip dep), existing `pytest` suite.

**Spec:** `docs/superpowers/specs/2026-04-24-dispatcher-init-wizard-design.md`

---

## File Structure

**New files in `robot-md-dispatcher`:**
- `src/robot_md_dispatcher/init_wizard.py` — the wizard (one module, ~300 lines)
- `tests/test_init_wizard.py` — all wizard tests
- `tests/fixtures/valid_robot.md` — fixture ROBOT.md used by many tests

**Modified files in `robot-md-dispatcher`:**
- `pyproject.toml` — add `robot-md>=1.1` dep, bump version `0.1.0` → `0.2.0`
- `src/robot_md_dispatcher/__main__.py` — add `init` subcommand
- `tests/conftest.py` — add `valid_robot_md` fixture
- `README.md` — add `init` to the quick-start section
- `CHANGELOG.md` — create + add 0.2.0 entry

**New files in `robot-md-mcp` (separate repo, separate commit):**
- `commands/enable-dispatch.md` — slash command

**Modified files in `robot-md-mcp`:**
- `.claude-plugin/plugin.json` — version bump only (optional; plugin doesn't auto-pin)

---

## Task 1: Bump version and add `robot-md` dep

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Update `pyproject.toml`**

Edit the `[project]` and `dependencies` blocks. Current state has `version = "0.1.0"` and a 5-item dependencies list. Change both:

```toml
[project]
name = "robot-md-dispatcher"
version = "0.2.0"
# ... (keep other fields unchanged)

dependencies = [
    "claude-agent-sdk>=0.1",
    "fastapi>=0.110",
    "uvicorn[standard]>=0.27",
    "python-frontmatter>=1.0",
    "pydantic>=2.6",
    "robot-md>=1.1",
]
```

- [ ] **Step 2: Verify `robot-md` installs into the dev venv**

Run:
```bash
cd /home/craigm26/robot-md-dispatcher
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -c "from robot_md.parser import parse_file; from robot_md.validate import validate, VALID; print('ok')"
```
Expected stdout: `ok`

If that fails with `ModuleNotFoundError: No module named 'robot_md'`, install the local sibling explicitly:
```bash
.venv/bin/pip install -e /home/craigm26/robot-md/cli
```

- [ ] **Step 3: Run existing test suite — must still be green**

Run:
```bash
.venv/bin/pytest -q
```
Expected: all 15 existing tests pass, no new failures.

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml
git commit -m "$(cat <<'EOF'
chore: bump to 0.2.0 and add robot-md dep

Version bump for the upcoming 'init' wizard. robot-md is now a
runtime dep because the wizard validates ROBOT.md via the Python
API rather than subprocessing the CLI.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Valid `ROBOT.md` fixture + module skeleton

**Files:**
- Create: `tests/fixtures/valid_robot.md`
- Create: `src/robot_md_dispatcher/init_wizard.py`
- Modify: `tests/conftest.py`
- Create: `tests/test_init_wizard.py`

- [ ] **Step 1: Create the fixture**

Write `tests/fixtures/valid_robot.md` — a minimal ROBOT.md that passes `robot_md.validate`. Use an existing valid example as the template:

```bash
cp /home/craigm26/robot-md/examples/arm_manipulator/ROBOT.md /home/craigm26/robot-md-dispatcher/tests/fixtures/valid_robot.md
```

If that example doesn't exist or the validator rejects it, copy from `/home/craigm26/robot-md/examples/so_arm101/ROBOT.md` instead, or whichever example `robot_md validate` returns exit 0 on. Verify:

```bash
cd /home/craigm26/robot-md-dispatcher
.venv/bin/python -c "
from pathlib import Path
from robot_md.parser import parse_file
from robot_md.validate import validate, VALID
r = validate(parse_file(Path('tests/fixtures/valid_robot.md')))
assert r.code == VALID, r.errors
print('fixture valid, robot name:', parse_file(Path('tests/fixtures/valid_robot.md')).frontmatter.get('name'))
"
```
Expected: `fixture valid, robot name: <some-name>` (no assertion error).

- [ ] **Step 2: Add a fixture to `conftest.py`**

Append to `tests/conftest.py`:

```python
import shutil as _shutil


@pytest.fixture
def valid_robot_md(tmp_path: Path) -> Path:
    """Copy the packaged fixture ROBOT.md into a tmp_path and return the path."""
    src = Path(__file__).parent / "fixtures" / "valid_robot.md"
    dst = tmp_path / "ROBOT.md"
    _shutil.copy(src, dst)
    return dst
```

- [ ] **Step 3: Create the wizard module skeleton**

Write `src/robot_md_dispatcher/init_wizard.py`:

```python
"""Interactive and one-shot wizard that enables remote dispatch for a ROBOT.md robot."""

from __future__ import annotations

from pathlib import Path


def run(
    *,
    interactive: bool,
    cwd: Path,
    force: bool = False,
    no_token_stdout: bool = False,
) -> int:
    """Run the init wizard. Returns a process exit code."""
    raise NotImplementedError("init_wizard.run is not yet implemented")
```

- [ ] **Step 4: Write the first (smoke) test**

Create `tests/test_init_wizard.py`:

```python
from __future__ import annotations

from pathlib import Path

from robot_md_dispatcher import init_wizard


def test_wizard_module_imports_and_run_exists():
    assert callable(init_wizard.run)
```

- [ ] **Step 5: Run tests**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: 1 passed.

- [ ] **Step 6: Commit**

```bash
git add src/robot_md_dispatcher/init_wizard.py tests/test_init_wizard.py tests/conftest.py tests/fixtures/valid_robot.md
git commit -m "$(cat <<'EOF'
feat(init): scaffold init_wizard module and test fixture

Empty run() signature, smoke test, and a valid ROBOT.md fixture
copied from robot-md's examples for use by the wizard tests.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Precondition — refuse when `ROBOT.md` is missing

**Files:**
- Modify: `src/robot_md_dispatcher/init_wizard.py`
- Modify: `tests/test_init_wizard.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_init_wizard.py`:

```python
def test_refuses_without_robot_md(tmp_path: Path, capsys):
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "No ROBOT.md" in err
    assert "robot-md init" in err or "castor init" in err
```

- [ ] **Step 2: Run test — verify fail**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py::test_refuses_without_robot_md -v
```
Expected: FAIL with `NotImplementedError`.

- [ ] **Step 3: Implement precondition check**

Replace the body of `src/robot_md_dispatcher/init_wizard.py`:

```python
"""Interactive and one-shot wizard that enables remote dispatch for a ROBOT.md robot."""

from __future__ import annotations

import sys
from pathlib import Path


class _Precondition(Exception):
    """Precondition failure with a user-facing message."""


def _check_robot_md_exists(cwd: Path) -> Path:
    robot_md = cwd / "ROBOT.md"
    if not robot_md.exists():
        raise _Precondition(
            f"No ROBOT.md in {cwd}. Run 'robot-md init' or 'castor init' first."
        )
    return robot_md


def run(
    *,
    interactive: bool,
    cwd: Path,
    force: bool = False,
    no_token_stdout: bool = False,
) -> int:
    try:
        _check_robot_md_exists(cwd)
    except _Precondition as e:
        print(str(e), file=sys.stderr)
        return 1
    return 0
```

- [ ] **Step 4: Run test — verify pass**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/robot_md_dispatcher/init_wizard.py tests/test_init_wizard.py
git commit -m "feat(init): refuse when ROBOT.md is missing

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Precondition — validate ROBOT.md via `robot_md.validate`

**Files:**
- Modify: `src/robot_md_dispatcher/init_wizard.py`
- Modify: `tests/test_init_wizard.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_init_wizard.py`:

```python
def test_refuses_on_invalid_robot_md(tmp_path: Path, capsys):
    (tmp_path / "ROBOT.md").write_text("no frontmatter here\n")
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "ROBOT.md" in err
    assert "re-run" in err.lower() or "fix" in err.lower()


def test_accepts_valid_robot_md(tmp_path: Path, valid_robot_md: Path):
    # valid_robot_md fixture already copies ROBOT.md into tmp_path
    # At this point in the plan, the wizard only does precondition checks,
    # so it should return 0 (no files yet — that comes in later tasks).
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0
```

Note: `valid_robot_md` uses its own `tmp_path`, so pass that same `tmp_path` as `cwd`. The fixture signature `(tmp_path: Path) -> Path` means pytest injects the same `tmp_path` into both the fixture and the test, so this works.

- [ ] **Step 2: Run tests — verify fail**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: `test_refuses_on_invalid_robot_md` and `test_accepts_valid_robot_md` both FAIL.

- [ ] **Step 3: Implement validation**

Add to `src/robot_md_dispatcher/init_wizard.py` below `_check_robot_md_exists`:

```python
def _validate_robot_md(robot_md: Path) -> str:
    """Validate ROBOT.md and return the robot name. Raises _Precondition on failure."""
    try:
        from robot_md.parser import ParseError, parse_file
        from robot_md.validate import VALID, validate
    except ImportError as e:
        raise _Precondition(
            "robot-md package not installed. Install with 'pip install robot-md'."
        ) from e

    try:
        parsed = parse_file(robot_md)
    except ParseError as e:
        raise _Precondition(
            f"ROBOT.md parse error: {e}\n"
            "Fix ROBOT.md and re-run 'robot-md-dispatcher init'."
        ) from e

    result = validate(parsed)
    if result.code != VALID:
        msg_lines = ["ROBOT.md validation failed:"]
        for err in result.errors:
            msg_lines.append(f"  - {err}")
        msg_lines.append("Fix ROBOT.md and re-run 'robot-md-dispatcher init'.")
        raise _Precondition("\n".join(msg_lines))

    return str(parsed.frontmatter.get("name", "unknown"))
```

Update `run()` to call it:

```python
def run(
    *,
    interactive: bool,
    cwd: Path,
    force: bool = False,
    no_token_stdout: bool = False,
) -> int:
    try:
        robot_md = _check_robot_md_exists(cwd)
        robot_name = _validate_robot_md(robot_md)  # noqa: F841 — used in later tasks
    except _Precondition as e:
        print(str(e), file=sys.stderr)
        return 1
    return 0
```

- [ ] **Step 4: Run tests — verify pass**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: all 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/robot_md_dispatcher/init_wizard.py tests/test_init_wizard.py
git commit -m "feat(init): validate ROBOT.md via robot_md.validate

Uses the robot_md Python API directly (parser + validate modules)
rather than subprocessing the CLI. Surfaces validation errors to
stderr with a pointer back to the user action.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Precondition — `robot-md-mcp` binary on PATH

**Files:**
- Modify: `src/robot_md_dispatcher/init_wizard.py`
- Modify: `tests/test_init_wizard.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_init_wizard.py`:

```python
def test_refuses_if_mcp_missing(tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys):
    monkeypatch.setattr("shutil.which", lambda cmd: None if cmd == "robot-md-mcp" else "/bin/true")
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "robot-md-mcp" in err
    assert "not found on PATH" in err


def test_passes_when_mcp_present(tmp_path: Path, valid_robot_md: Path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0
```

- [ ] **Step 2: Run tests — verify fail**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py::test_refuses_if_mcp_missing -v
```
Expected: FAIL (wizard returns 0 because it never checks).

- [ ] **Step 3: Implement the check**

In `src/robot_md_dispatcher/init_wizard.py`, add `import shutil` at the top, and add a new helper below `_validate_robot_md`:

```python
import shutil


def _check_mcp_on_path() -> None:
    if shutil.which("robot-md-mcp") is None:
        raise _Precondition(
            "robot-md-mcp not found on PATH. Install with "
            "'npm install -g robot-md-mcp' (Node) or 'pip install robot-md' "
            "(Python wrapper)."
        )
```

Update `run()` body:

```python
    try:
        robot_md = _check_robot_md_exists(cwd)
        robot_name = _validate_robot_md(robot_md)  # noqa: F841
        _check_mcp_on_path()
    except _Precondition as e:
        print(str(e), file=sys.stderr)
        return 1
    return 0
```

- [ ] **Step 4: Run tests — verify pass**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: all 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/robot_md_dispatcher/init_wizard.py tests/test_init_wizard.py
git commit -m "feat(init): hard-fail when robot-md-mcp is missing

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: `WizardConfig` dataclass + token generation

**Files:**
- Modify: `src/robot_md_dispatcher/init_wizard.py`
- Modify: `tests/test_init_wizard.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_init_wizard.py`:

```python
def test_default_config_has_sensible_values():
    cfg = init_wizard.WizardConfig()
    assert cfg.bind == "127.0.0.1"
    assert cfg.port == 8080
    assert cfg.generate_actuate is True
    assert cfg.generate_read is False
    assert cfg.systemd_print is False
    assert cfg.tailscale_print is False


def test_generate_tokens_actuate_only_by_default():
    cfg = init_wizard.WizardConfig()
    actuate, read = init_wizard._generate_tokens(cfg)
    assert len(actuate) >= 32
    assert read is None


def test_generate_tokens_both_when_opted_in():
    cfg = init_wizard.WizardConfig(generate_read=True)
    actuate, read = init_wizard._generate_tokens(cfg)
    assert len(actuate) >= 32
    assert read is not None and len(read) >= 32
    assert actuate != read
```

- [ ] **Step 2: Run tests — verify fail**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: 3 new tests FAIL (AttributeError).

- [ ] **Step 3: Implement**

In `src/robot_md_dispatcher/init_wizard.py` at the top, add imports:

```python
import secrets
from dataclasses import dataclass
```

Add the dataclass and helper near the top, after the imports:

```python
@dataclass
class WizardConfig:
    bind: str = "127.0.0.1"
    port: int = 8080
    generate_actuate: bool = True
    generate_read: bool = False
    systemd_print: bool = False
    tailscale_print: bool = False


def _generate_tokens(cfg: WizardConfig) -> tuple[str, str | None]:
    actuate = secrets.token_urlsafe(32) if cfg.generate_actuate else ""
    read = secrets.token_urlsafe(32) if cfg.generate_read else None
    return actuate, read
```

- [ ] **Step 4: Run tests — verify pass**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: all 9 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/robot_md_dispatcher/init_wizard.py tests/test_init_wizard.py
git commit -m "feat(init): WizardConfig dataclass and token generator

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Atomic write helper

**Files:**
- Modify: `src/robot_md_dispatcher/init_wizard.py`
- Modify: `tests/test_init_wizard.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_init_wizard.py`:

```python
import os


def test_atomic_write_commits_content_and_perms(tmp_path: Path):
    target = tmp_path / "out.txt"
    init_wizard._atomic_write(target, "hello\n", mode=0o600)
    assert target.read_text() == "hello\n"
    assert oct(target.stat().st_mode & 0o777) == "0o600"


def test_atomic_write_overwrites_existing(tmp_path: Path):
    target = tmp_path / "out.txt"
    target.write_text("old")
    init_wizard._atomic_write(target, "new", mode=0o600)
    assert target.read_text() == "new"


def test_atomic_write_removes_temp_on_failure(tmp_path: Path, monkeypatch):
    target = tmp_path / "out.txt"

    def boom(src: str, dst: str) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)

    try:
        init_wizard._atomic_write(target, "x", mode=0o600)
    except OSError:
        pass

    assert not target.exists()
    # No leftover dotfile in target_dir
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith(".out.txt.")]
    assert leftovers == []
```

- [ ] **Step 2: Run tests — verify fail**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: 3 new tests FAIL (AttributeError).

- [ ] **Step 3: Implement the helper**

At the top of `src/robot_md_dispatcher/init_wizard.py` add:

```python
import os
import tempfile
```

Add below `_generate_tokens`:

```python
def _atomic_write(path: Path, content: str, mode: int) -> None:
    """Write `content` to `path` atomically. On failure, leaves no partial files."""
    target_dir = path.parent
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(target_dir))
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise
```

- [ ] **Step 4: Run tests — verify pass**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: all 12 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/robot_md_dispatcher/init_wizard.py tests/test_init_wizard.py
git commit -m "feat(init): atomic write helper with rollback

Uses tempfile.mkstemp + os.replace; cleans up temp on failure so
a crash mid-write leaves no partial files.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Write `bearers.yaml`

**Files:**
- Modify: `src/robot_md_dispatcher/init_wizard.py`
- Modify: `tests/test_init_wizard.py`

- [ ] **Step 1: Write failing test**

Append to `tests/test_init_wizard.py`:

```python
from robot_md_dispatcher.auth import BearerStore


def test_write_bearers_yaml_actuate_only(tmp_path: Path):
    path = tmp_path / "bearers.yaml"
    init_wizard._write_bearers_yaml(
        path, actuate_token="AAAA", read_token=None
    )
    # Format is loadable by the real consumer
    store = BearerStore.from_yaml(path)
    assert store.resolve("AAAA") is not None
    assert store.resolve("AAAA").tier == "actuate"
    assert store.resolve("AAAA").caller_id == "actuate-default"
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_write_bearers_yaml_both_tiers(tmp_path: Path):
    path = tmp_path / "bearers.yaml"
    init_wizard._write_bearers_yaml(path, actuate_token="A", read_token="R")
    store = BearerStore.from_yaml(path)
    assert store.resolve("A").tier == "actuate"
    assert store.resolve("R").tier == "read"
    assert store.resolve("R").caller_id == "read-default"
```

- [ ] **Step 2: Run tests — verify fail**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py::test_write_bearers_yaml_actuate_only tests/test_init_wizard.py::test_write_bearers_yaml_both_tiers -v
```
Expected: FAIL (AttributeError).

- [ ] **Step 3: Implement**

Add to `src/robot_md_dispatcher/init_wizard.py` (we use plain string formatting rather than `yaml.safe_dump` to keep the comment header):

```python
def _write_bearers_yaml(path: Path, *, actuate_token: str, read_token: str | None) -> None:
    lines = [
        "# robot-md-dispatcher bearers — generated by `init`.",
        "# Rotate by replacing tokens and restarting the service.",
    ]
    if actuate_token:
        lines.extend([
            f"- token: {actuate_token}",
            "  tier: actuate",
            "  caller: actuate-default",
        ])
    if read_token:
        lines.extend([
            f"- token: {read_token}",
            "  tier: read",
            "  caller: read-default",
        ])
    content = "\n".join(lines) + "\n"
    _atomic_write(path, content, mode=0o600)
```

- [ ] **Step 4: Run tests — verify pass**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: all 14 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/robot_md_dispatcher/init_wizard.py tests/test_init_wizard.py
git commit -m "feat(init): emit bearers.yaml loadable by BearerStore

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Write `.env`

**Files:**
- Modify: `src/robot_md_dispatcher/init_wizard.py`
- Modify: `tests/test_init_wizard.py`

- [ ] **Step 1: Write failing test**

Append to `tests/test_init_wizard.py`:

```python
def test_write_env_contains_four_expected_vars(tmp_path: Path):
    path = tmp_path / ".env"
    init_wizard._write_env(path)
    content = path.read_text()
    assert "ROBOT_MD_PATH=./ROBOT.md" in content
    assert "ROBOT_MD_BEARERS_FILE=./bearers.yaml" in content
    assert "ROBOT_MD_MCP_COMMAND=robot-md-mcp" in content
    assert "ROBOT_MD_LOG_LEVEL=INFO" in content
    assert oct(path.stat().st_mode & 0o777) == "0o644"
```

- [ ] **Step 2: Run test — verify fail**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py::test_write_env_contains_four_expected_vars -v
```
Expected: FAIL (AttributeError).

- [ ] **Step 3: Implement**

Add to `src/robot_md_dispatcher/init_wizard.py`:

```python
def _write_env(path: Path) -> None:
    content = (
        "ROBOT_MD_PATH=./ROBOT.md\n"
        "ROBOT_MD_BEARERS_FILE=./bearers.yaml\n"
        "ROBOT_MD_MCP_COMMAND=robot-md-mcp\n"
        "ROBOT_MD_LOG_LEVEL=INFO\n"
    )
    _atomic_write(path, content, mode=0o644)
```

- [ ] **Step 4: Run tests — verify pass**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: all 15 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/robot_md_dispatcher/init_wizard.py tests/test_init_wizard.py
git commit -m "feat(init): emit .env with the four consumed vars

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Write `dispatch-test.sh` (0700, ANTHROPIC_API_KEY gated)

**Files:**
- Modify: `src/robot_md_dispatcher/init_wizard.py`
- Modify: `tests/test_init_wizard.py`

- [ ] **Step 1: Write failing test**

Append to `tests/test_init_wizard.py`:

```python
def test_write_dispatch_test_sh_bakes_token_and_is_0700(tmp_path: Path):
    path = tmp_path / "dispatch-test.sh"
    init_wizard._write_dispatch_test_sh(
        path, actuate_token="ABCDE", bind="127.0.0.1", port=8080
    )
    content = path.read_text()
    assert "Authorization: Bearer ABCDE" in content
    assert "127.0.0.1:8080" in content
    assert "ANTHROPIC_API_KEY" in content  # gated on env var
    assert content.startswith("#!/usr/bin/env bash")
    assert oct(path.stat().st_mode & 0o777) == "0o700"  # token in plaintext -> user-only


def test_write_dispatch_test_sh_uses_custom_port(tmp_path: Path):
    path = tmp_path / "dispatch-test.sh"
    init_wizard._write_dispatch_test_sh(
        path, actuate_token="X", bind="127.0.0.1", port=9090
    )
    assert "127.0.0.1:9090" in path.read_text()
```

- [ ] **Step 2: Run tests — verify fail**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v -k dispatch_test_sh
```
Expected: both FAIL (AttributeError).

- [ ] **Step 3: Implement**

Add to `src/robot_md_dispatcher/init_wizard.py`:

```python
def _write_dispatch_test_sh(
    path: Path, *, actuate_token: str, bind: str, port: int
) -> None:
    content = f"""#!/usr/bin/env bash
# robot-md-dispatcher smoke test — generated by `init`.
set -euo pipefail

if [[ -z "${{ANTHROPIC_API_KEY:-}}" ]]; then
    echo "error: export ANTHROPIC_API_KEY=sk-ant-... before running this script" >&2
    exit 1
fi

curl -N http://{bind}:{port}/dispatch \\
    -H "Authorization: Bearer {actuate_token}" \\
    -H "X-Anthropic-Api-Key: ${{ANTHROPIC_API_KEY}}" \\
    -H "Content-Type: application/json" \\
    -d '{{"goal": "call render and describe the robot"}}'
"""
    _atomic_write(path, content, mode=0o700)
```

- [ ] **Step 4: Run tests — verify pass**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: all 17 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/robot_md_dispatcher/init_wizard.py tests/test_init_wizard.py
git commit -m "feat(init): generate 0700 dispatch-test.sh with ANTHROPIC_API_KEY gate

Permissions are 0700 because the bearer token is baked in plaintext
— group and other must not read it. The script refuses to run
without ANTHROPIC_API_KEY set so the BYOK key isn't persisted.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: Orchestrate `init --yes` golden path (writes all three files, prints token once)

**Files:**
- Modify: `src/robot_md_dispatcher/init_wizard.py`
- Modify: `tests/test_init_wizard.py`

- [ ] **Step 1: Write failing test**

Append to `tests/test_init_wizard.py`:

```python
def test_init_yes_golden_path(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0

    bearers = tmp_path / "bearers.yaml"
    env = tmp_path / ".env"
    test_sh = tmp_path / "dispatch-test.sh"

    assert bearers.exists() and oct(bearers.stat().st_mode & 0o777) == "0o600"
    assert env.exists() and oct(env.stat().st_mode & 0o777) == "0o644"
    assert test_sh.exists() and oct(test_sh.stat().st_mode & 0o777) == "0o700"

    # Token is in bearers.yaml, printed exactly once to stdout, and baked into dispatch-test.sh
    store = BearerStore.from_yaml(bearers)
    actuate_entries = [e for e in store._by_token.values() if e.tier == "actuate"]
    assert len(actuate_entries) == 1
    token = actuate_entries[0].token
    out = capsys.readouterr().out
    assert out.count(token) == 1
    assert token in test_sh.read_text()
```

- [ ] **Step 2: Run test — verify fail**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py::test_init_yes_golden_path -v
```
Expected: FAIL (bearers.yaml does not exist — `run()` still returns 0 without writing).

- [ ] **Step 3: Implement orchestration**

Replace `run()` in `src/robot_md_dispatcher/init_wizard.py`:

```python
def run(
    *,
    interactive: bool,
    cwd: Path,
    force: bool = False,
    no_token_stdout: bool = False,
) -> int:
    try:
        robot_md = _check_robot_md_exists(cwd)
        robot_name = _validate_robot_md(robot_md)
        _check_mcp_on_path()
    except _Precondition as e:
        print(str(e), file=sys.stderr)
        return 1

    cfg = WizardConfig()  # interactive-mode prompts come in later tasks
    actuate_token, read_token = _generate_tokens(cfg)

    _write_bearers_yaml(
        cwd / "bearers.yaml",
        actuate_token=actuate_token,
        read_token=read_token,
    )
    _write_env(cwd / ".env")
    if actuate_token:
        _write_dispatch_test_sh(
            cwd / "dispatch-test.sh",
            actuate_token=actuate_token,
            bind=cfg.bind,
            port=cfg.port,
        )

    _print_next_steps(
        cfg=cfg,
        robot_name=robot_name,
        actuate_token=actuate_token,
        no_token_stdout=no_token_stdout,
    )
    return 0


def _print_next_steps(
    *,
    cfg: WizardConfig,
    robot_name: str,
    actuate_token: str,
    no_token_stdout: bool,
) -> None:
    print(f"Found ROBOT.md for {robot_name!r}.")
    print(
        f"Writing: bind {cfg.bind}:{cfg.port}, 1 actuate token, dev-mode (./ files)."
    )
    print("  ./bearers.yaml")
    print("  ./.env")
    if actuate_token:
        print("  ./dispatch-test.sh")

    if no_token_stdout:
        print()
        print("Actuate token written to ./bearers.yaml (0600). Open the file to read it.")
    else:
        print()
        print("Actuate token (save now — not persisted anywhere else):")
        print(f"  {actuate_token}")

    print()
    print("Next:")
    print(
        f"  robot-md-dispatcher serve --bearers ./bearers.yaml "
        f"--robot-md ./ROBOT.md"
    )
    print()
    print("Tip: add bearers.yaml, .env, dispatch-test.sh to .gitignore")
```

- [ ] **Step 4: Run tests — verify pass**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: all 18 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/robot_md_dispatcher/init_wizard.py tests/test_init_wizard.py
git commit -m "feat(init): orchestrate init --yes golden path

run() writes bearers.yaml, .env, and dispatch-test.sh, then prints
the actuate token exactly once with 'save now' admonition.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: `--no-token-stdout` suppresses token echo

**Files:**
- Modify: `tests/test_init_wizard.py` (already implemented — just add the test)

- [ ] **Step 1: Write test**

Append to `tests/test_init_wizard.py`:

```python
def test_no_token_stdout_suppresses_token(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=True)
    assert rc == 0

    bearers = tmp_path / "bearers.yaml"
    store = BearerStore.from_yaml(bearers)
    token = [e for e in store._by_token.values() if e.tier == "actuate"][0].token

    out = capsys.readouterr().out
    assert token not in out
    assert "Open the file" in out
```

- [ ] **Step 2: Run test — verify pass**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py::test_no_token_stdout_suppresses_token -v
```
Expected: PASS (logic was implemented in Task 11's `_print_next_steps`).

- [ ] **Step 3: Commit**

```bash
git add tests/test_init_wizard.py
git commit -m "test(init): verify --no-token-stdout suppresses echo

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 13: Existing-file refusal + `--force` overwrite

**Files:**
- Modify: `src/robot_md_dispatcher/init_wizard.py`
- Modify: `tests/test_init_wizard.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_init_wizard.py`:

```python
def test_refuses_on_existing_bearers_yaml(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    (tmp_path / "bearers.yaml").write_text("- token: old\n  tier: actuate\n  caller: c\n")
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "bearers.yaml already exists" in err
    assert "--force" in err


def test_refuses_on_existing_env(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    (tmp_path / ".env").write_text("X=1\n")
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert ".env already exists" in err


def test_force_overwrites_and_invalidates_old_token(
    tmp_path: Path, valid_robot_md: Path, monkeypatch
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    (tmp_path / "bearers.yaml").write_text("- token: OLD\n  tier: actuate\n  caller: c\n")

    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=True, no_token_stdout=False)
    assert rc == 0

    store = BearerStore.from_yaml(tmp_path / "bearers.yaml")
    assert store.resolve("OLD") is None  # old token no longer valid
```

- [ ] **Step 2: Run tests — verify fail**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v -k "existing or force"
```
Expected: first two FAIL (wizard overwrites silently); third PASSES (overwrite was already happening).

- [ ] **Step 3: Implement refusal**

Add to `src/robot_md_dispatcher/init_wizard.py`:

```python
def _check_no_existing_files(cwd: Path) -> None:
    for name in ("bearers.yaml", ".env"):
        if (cwd / name).exists():
            raise _Precondition(
                f"./{name} already exists. Use 'init --force' to regenerate tokens "
                "(this invalidates the old ones)."
            )
```

Update the precondition block in `run()`:

```python
    try:
        robot_md = _check_robot_md_exists(cwd)
        robot_name = _validate_robot_md(robot_md)
        _check_mcp_on_path()
        if not force:
            _check_no_existing_files(cwd)
    except _Precondition as e:
        print(str(e), file=sys.stderr)
        return 1
```

- [ ] **Step 4: Run tests — verify pass**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: all 21 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/robot_md_dispatcher/init_wizard.py tests/test_init_wizard.py
git commit -m "feat(init): refuse on existing files; --force overwrites

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 14: TTY check — bare `init` without `--yes` refuses when stdin isn't a TTY

**Files:**
- Modify: `src/robot_md_dispatcher/init_wizard.py`
- Modify: `tests/test_init_wizard.py`

- [ ] **Step 1: Write failing test**

Append to `tests/test_init_wizard.py`:

```python
def test_bare_init_refuses_on_non_tty(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    # pytest's capsys replaces stdin with a non-tty already; assert explicitly:
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    rc = init_wizard.run(interactive=True, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "TTY" in err
    assert "--yes" in err
```

- [ ] **Step 2: Run test — verify fail**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py::test_bare_init_refuses_on_non_tty -v
```
Expected: FAIL.

- [ ] **Step 3: Implement**

In `run()`, after the precondition block and before `cfg = WizardConfig()`, insert:

```python
    if interactive and not sys.stdin.isatty():
        print(
            "Interactive mode requires a TTY. Use 'init --yes' for defaults, "
            "or run from a terminal.",
            file=sys.stderr,
        )
        return 1
```

- [ ] **Step 4: Run tests — verify pass**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: all 22 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/robot_md_dispatcher/init_wizard.py tests/test_init_wizard.py
git commit -m "feat(init): refuse bare 'init' when stdin is not a TTY

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 15: Guided mode — prompts with explanation boxes, all defaults

**Files:**
- Modify: `src/robot_md_dispatcher/init_wizard.py`
- Modify: `tests/test_init_wizard.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_init_wizard.py`:

```python
import io


def test_guided_mode_accepts_all_defaults(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    # Pipe enough newlines to default every prompt.
    monkeypatch.setattr("sys.stdin", io.StringIO("\n" * 20))

    rc = init_wizard.run(interactive=True, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0

    # Same outputs as --yes golden path
    bearers = BearerStore.from_yaml(tmp_path / "bearers.yaml")
    actuate = [e for e in bearers._by_token.values() if e.tier == "actuate"]
    assert len(actuate) == 1
    # .env defaults
    env_text = (tmp_path / ".env").read_text()
    assert "ROBOT_MD_PATH=./ROBOT.md" in env_text
    # dispatch-test.sh uses default port
    assert "127.0.0.1:8080" in (tmp_path / "dispatch-test.sh").read_text()


def test_guided_mode_declining_initial_confirm_aborts(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdin", io.StringIO("n\n"))

    rc = init_wizard.run(interactive=True, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0
    assert not (tmp_path / "bearers.yaml").exists()
    out = capsys.readouterr().out
    assert "aborted" in out.lower() or "cancelled" in out.lower() or "no changes" in out.lower()
```

- [ ] **Step 2: Run tests — verify fail**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v -k guided_mode_accepts_all_defaults
```
Expected: FAIL (current `run()` ignores interactive flag).

- [ ] **Step 3: Implement prompt helpers**

Add to `src/robot_md_dispatcher/init_wizard.py`:

```python
def _box(title: str, lines: list[str]) -> str:
    width = 64
    top = f"╭─ {title} " + "─" * (width - len(title) - 4) + "╮"
    bot = "╰" + "─" * (width - 1) + "╯"
    body = "\n".join(f"│ {line.ljust(width - 3)}│" for line in lines)
    return f"{top}\n{body}\n{bot}"


def _ask_yes_no(question: str, default: bool) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    raw = input(f"{question} {suffix}: ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")


def _ask_text(question: str, default: str) -> str:
    raw = input(f"{question} [{default}]: ").strip()
    return raw or default


def _ask_int(question: str, default: int) -> int:
    while True:
        raw = input(f"{question} [{default}]: ").strip()
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            print(f"  not an integer: {raw!r}", file=sys.stderr)


def _prompt_config(robot_name: str) -> WizardConfig | None:
    """Interactive prompts. Returns None if user declined the initial confirm."""
    print(_box(
        "What this does",
        [
            "Writes a bearers.yaml (access tokens) and a .env (paths +",
            "MCP command) next to your ROBOT.md. Does not start the",
            "service or open network ports.",
        ],
    ))
    if not _ask_yes_no(f"Enable remote dispatch for {robot_name!r}?", default=True):
        print("No changes made.")
        return None

    print(_box(
        "Bind address",
        [
            "Local address the dispatcher listens on. Use 127.0.0.1 if",
            "you'll front this with Tailscale Funnel or a reverse proxy.",
            "Use 0.0.0.0 only if your network boundary is hardened.",
        ],
    ))
    bind = _ask_text("Bind address", default="127.0.0.1")

    print(_box(
        "Port",
        ["TCP port the HTTP server binds to. 8080 is the default."],
    ))
    port = _ask_int("Port", default=8080)

    print(_box(
        "Bearer tokens",
        [
            "Callers authenticate with a bearer token. Each token has a",
            "tier: 'actuate' can drive the robot; 'read' can only call",
            "observation tools (render, validate, get_*, list_*, ...).",
        ],
    ))
    gen_actuate = _ask_yes_no("Generate an actuate-tier token?", default=True)
    gen_read = _ask_yes_no("Also generate a read-tier token?", default=False)

    print(_box(
        "Production install (systemd)",
        [
            "For long-running hosts, install as a systemd service under",
            "a dedicated 'robot' user with MemoryMax/CPUQuota limits.",
            "Requires sudo. This wizard PRINTS the commands; it does NOT",
            "run sudo on your behalf.",
        ],
    ))
    systemd = _ask_yes_no("Install as systemd service?", default=False)

    print(_box(
        "Tailscale Funnel",
        [
            "Named, revocable, TLS-terminated public URL via your",
            "tailnet. We'll print the two setup commands; we won't run",
            "them (they need your interactive auth).",
        ],
    ))
    tailscale = _ask_yes_no("Print Tailscale Funnel setup commands?", default=False)

    return WizardConfig(
        bind=bind,
        port=port,
        generate_actuate=gen_actuate,
        generate_read=gen_read,
        systemd_print=systemd,
        tailscale_print=tailscale,
    )
```

Update `run()` to use it (replace `cfg = WizardConfig()`):

```python
    if interactive:
        cfg = _prompt_config(robot_name)
        if cfg is None:
            return 0  # user declined the initial confirm; no changes made
    else:
        cfg = WizardConfig()

    actuate_token, read_token = _generate_tokens(cfg)
    ...
```

- [ ] **Step 4: Run tests — verify pass**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: all 24 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/robot_md_dispatcher/init_wizard.py tests/test_init_wizard.py
git commit -m "feat(init): guided mode with explanation-boxed prompts

Each prompt is preceded by a boxed paragraph explaining what the
knob does; pressing Enter accepts the default. Declining the
initial confirm exits cleanly with no files written.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 16: Guided mode — custom port and read-tier opt-in

**Files:**
- Modify: `tests/test_init_wizard.py`

- [ ] **Step 1: Write tests**

Append to `tests/test_init_wizard.py`:

```python
def test_guided_mode_custom_port(
    tmp_path: Path, valid_robot_md: Path, monkeypatch
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    # Confirm=Y, bind=default, port=9090, actuate=default, read=default, systemd=default, tailscale=default
    monkeypatch.setattr("sys.stdin", io.StringIO("\n\n9090\n\n\n\n\n"))

    rc = init_wizard.run(interactive=True, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0
    assert "127.0.0.1:9090" in (tmp_path / "dispatch-test.sh").read_text()


def test_guided_mode_read_tier_opt_in(
    tmp_path: Path, valid_robot_md: Path, monkeypatch
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    # Walk to the read-tier prompt and answer "y"; defaults for everything else
    monkeypatch.setattr("sys.stdin", io.StringIO("\n\n\n\ny\n\n\n"))

    rc = init_wizard.run(interactive=True, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0
    store = BearerStore.from_yaml(tmp_path / "bearers.yaml")
    tiers = {e.tier for e in store._by_token.values()}
    assert tiers == {"read", "actuate"}
```

- [ ] **Step 2: Run tests — verify pass**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v -k "custom_port or read_tier"
```
Expected: both PASS (already implemented in Task 15).

- [ ] **Step 3: Commit**

```bash
git add tests/test_init_wizard.py
git commit -m "test(init): cover custom port and read-tier opt-in in guided mode

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 17: Systemd + Tailscale next-step print branches

**Files:**
- Modify: `src/robot_md_dispatcher/init_wizard.py`
- Modify: `tests/test_init_wizard.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_init_wizard.py`:

```python
def test_systemd_opt_in_prints_install_commands(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    # Walk to the systemd prompt and answer "y"; tailscale=default
    monkeypatch.setattr("sys.stdin", io.StringIO("\n\n\n\n\ny\n\n"))

    rc = init_wizard.run(interactive=True, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0
    out = capsys.readouterr().out
    assert "sudo" in out
    assert "install.sh" in out
    assert "/etc/robot-md-dispatcher" in out


def test_tailscale_opt_in_prints_funnel_commands(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdin", io.StringIO("\n\n\n\n\n\ny\n"))

    rc = init_wizard.run(interactive=True, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0
    out = capsys.readouterr().out
    assert "tailscale serve" in out
    assert "tailscale funnel" in out
    assert "8080" in out  # default port substituted in
```

- [ ] **Step 2: Run tests — verify fail**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v -k "systemd_opt_in or tailscale_opt_in"
```
Expected: both FAIL.

- [ ] **Step 3: Implement print branches**

Append to `_print_next_steps` in `src/robot_md_dispatcher/init_wizard.py`, just before the `.gitignore` tip:

```python
    if cfg.systemd_print:
        print()
        print("Production install (run these):")
        print("  sudo ./systemd/install.sh")
        print("  sudo cp ./bearers.yaml ./.env /etc/robot-md-dispatcher/")
        print("  sudo cp ./ROBOT.md /etc/robot-md-dispatcher/ROBOT.md")
        print("  sudo systemctl daemon-reload && sudo systemctl enable --now robot-md-dispatcher")

    if cfg.tailscale_print:
        print()
        print("Tailscale Funnel exposure (run these):")
        print(f"  tailscale serve --bg --https=443 http://{cfg.bind}:{cfg.port}")
        print("  tailscale funnel 443 on")
```

- [ ] **Step 4: Run tests — verify pass**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: all 28 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/robot_md_dispatcher/init_wizard.py tests/test_init_wizard.py
git commit -m "feat(init): print systemd/Tailscale next-step commands when opted in

Wizard never executes sudo or tailscale — it prints the commands
with the user's bind/port substituted in.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 18: Ctrl-C during prompts — clean abort with exit 130

**Files:**
- Modify: `src/robot_md_dispatcher/init_wizard.py`
- Modify: `tests/test_init_wizard.py`

- [ ] **Step 1: Write failing test**

Append to `tests/test_init_wizard.py`:

```python
def test_ctrl_c_during_prompt_returns_130_no_files(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    def boom(prompt: str) -> str:
        raise KeyboardInterrupt()

    monkeypatch.setattr("builtins.input", boom)

    rc = init_wizard.run(interactive=True, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 130
    err = capsys.readouterr().err
    assert "Aborted" in err
    assert not (tmp_path / "bearers.yaml").exists()
    assert not (tmp_path / ".env").exists()
    assert not (tmp_path / "dispatch-test.sh").exists()
```

- [ ] **Step 2: Run test — verify fail**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py::test_ctrl_c_during_prompt_returns_130_no_files -v
```
Expected: FAIL (KeyboardInterrupt propagates as an unhandled exception).

- [ ] **Step 3: Implement handler**

Wrap the `_prompt_config` call in `run()`:

```python
    if interactive:
        try:
            cfg = _prompt_config(robot_name)
        except KeyboardInterrupt:
            print("\nAborted. No files written.", file=sys.stderr)
            return 130
        if cfg is None:
            return 0
    else:
        cfg = WizardConfig()
```

- [ ] **Step 4: Run tests — verify pass**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: all 29 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/robot_md_dispatcher/init_wizard.py tests/test_init_wizard.py
git commit -m "feat(init): Ctrl-C aborts cleanly with exit 130 and no files

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 19: Atomicity — mid-write failure rolls back prior files

**Files:**
- Modify: `src/robot_md_dispatcher/init_wizard.py`
- Modify: `tests/test_init_wizard.py`

- [ ] **Step 1: Write failing test**

Append to `tests/test_init_wizard.py`:

```python
def test_atomicity_rollback_on_second_write_failure(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)

    original_replace = os.replace
    calls: list[str] = []

    def flaky_replace(src, dst):
        calls.append(str(dst))
        if len(calls) == 2:  # fail on the second atomic write (.env)
            raise OSError("simulated disk full")
        return original_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)

    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 1

    # Both user-facing files absent (bearers.yaml was rolled back)
    assert not (tmp_path / "bearers.yaml").exists()
    assert not (tmp_path / ".env").exists()
    assert not (tmp_path / "dispatch-test.sh").exists()

    err = capsys.readouterr().err
    assert "Write failed" in err
```

- [ ] **Step 2: Run test — verify fail**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py::test_atomicity_rollback_on_second_write_failure -v
```
Expected: FAIL (bearers.yaml left behind, or unhandled OSError).

- [ ] **Step 3: Implement rollback**

Add to `src/robot_md_dispatcher/init_wizard.py`:

```python
def _rollback(cwd: Path) -> None:
    for name in ("bearers.yaml", ".env", "dispatch-test.sh"):
        try:
            (cwd / name).unlink()
        except FileNotFoundError:
            pass
```

Wrap the write block in `run()`:

```python
    actuate_token, read_token = _generate_tokens(cfg)

    try:
        _write_bearers_yaml(
            cwd / "bearers.yaml",
            actuate_token=actuate_token,
            read_token=read_token,
        )
        _write_env(cwd / ".env")
        if actuate_token:
            _write_dispatch_test_sh(
                cwd / "dispatch-test.sh",
                actuate_token=actuate_token,
                bind=cfg.bind,
                port=cfg.port,
            )
    except OSError as e:
        _rollback(cwd)
        print(f"Write failed: {e}", file=sys.stderr)
        return 1
```

- [ ] **Step 4: Run tests — verify pass**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: all 30 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/robot_md_dispatcher/init_wizard.py tests/test_init_wizard.py
git commit -m "feat(init): roll back partial writes on mid-stream failure

If .env fails to write after bearers.yaml succeeded, the wizard
unlinks bearers.yaml (and any dispatch-test.sh) before exiting
non-zero, so the user never has a token in a file that isn't
paired with a working .env.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 20: Wire `init` subcommand into `__main__.py`

**Files:**
- Modify: `src/robot_md_dispatcher/__main__.py`
- Modify: `tests/test_init_wizard.py`

- [ ] **Step 1: Write failing tests (invoke the CLI via argparse, no subprocess needed)**

Append to `tests/test_init_wizard.py`:

```python
import subprocess


def test_cli_init_help_mentions_yes_and_force():
    out = subprocess.run(
        ["robot-md-dispatcher", "init", "--help"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "--yes" in out
    assert "--force" in out
    assert "--no-token-stdout" in out


def test_cli_init_yes_runs_wizard(tmp_path: Path, valid_robot_md: Path):
    # Stub robot-md-mcp on PATH via a dummy binary in a tmp dir
    stub_dir = tmp_path / "stubs"
    stub_dir.mkdir()
    stub = stub_dir / "robot-md-mcp"
    stub.write_text("#!/usr/bin/env bash\ntrue\n")
    stub.chmod(0o755)

    env = dict(os.environ)
    env["PATH"] = f"{stub_dir}:{env['PATH']}"

    result = subprocess.run(
        ["robot-md-dispatcher", "init", "--yes"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "bearers.yaml").exists()
    assert (tmp_path / ".env").exists()
    assert (tmp_path / "dispatch-test.sh").exists()
```

- [ ] **Step 2: Run tests — verify fail**

Run:
```bash
.venv/bin/pytest tests/test_init_wizard.py -v -k cli_init
```
Expected: FAIL — `argparse` complains that `init` isn't a valid subcommand.

- [ ] **Step 3: Wire the subcommand**

Replace `src/robot_md_dispatcher/__main__.py`:

```python
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(prog="robot-md-dispatcher")
    sub = parser.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", help="Run the dispatcher HTTP server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument(
        "--robot-md", default=None, help="Path to ROBOT.md (sets ROBOT_MD_PATH)"
    )
    serve.add_argument(
        "--bearers",
        default=None,
        help="Path to bearers YAML (sets ROBOT_MD_BEARERS_FILE)",
    )
    serve.add_argument(
        "--mcp-command",
        default=None,
        help="Stdio MCP command to spawn (default: robot-md-mcp)",
    )

    init = sub.add_parser(
        "init",
        help="Generate bearers.yaml and .env for a ROBOT.md robot",
    )
    init.add_argument(
        "--yes",
        action="store_true",
        help="Non-interactive: take all defaults, no prompts",
    )
    init.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing bearers.yaml and .env (invalidates old tokens)",
    )
    init.add_argument(
        "--no-token-stdout",
        action="store_true",
        help="Do not echo the generated token to stdout "
        "(used by the Claude Code plugin slash command)",
    )

    args = parser.parse_args()

    if args.cmd == "serve":
        if args.robot_md:
            os.environ["ROBOT_MD_PATH"] = args.robot_md
        if args.bearers:
            os.environ["ROBOT_MD_BEARERS_FILE"] = args.bearers
        if args.mcp_command:
            os.environ["ROBOT_MD_MCP_COMMAND"] = args.mcp_command

        logging.basicConfig(
            level=os.environ.get("ROBOT_MD_LOG_LEVEL", "INFO"),
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )

        import uvicorn

        from .app import create_app_from_env

        uvicorn.run(create_app_from_env(), host=args.host, port=args.port)
        return

    if args.cmd == "init":
        from .init_wizard import run as wizard_run

        rc = wizard_run(
            interactive=not args.yes,
            cwd=Path.cwd(),
            force=args.force,
            no_token_stdout=args.no_token_stdout,
        )
        sys.exit(rc)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Reinstall so the console script picks up the new subcommand, then run the tests**

Run:
```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest tests/test_init_wizard.py -v
```
Expected: all 32 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/robot_md_dispatcher/__main__.py tests/test_init_wizard.py
git commit -m "feat(cli): add 'init' subcommand with --yes/--force/--no-token-stdout

Wires the wizard into the existing argparse dispatcher. CLI tests
exec the installed console script to cover end-to-end argument
parsing and process exit codes.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 21: Slash command in `robot-md-mcp`

**Files (in a different repo — `/home/craigm26/robot-md-mcp`):**
- Create: `commands/enable-dispatch.md`

- [ ] **Step 1: Create the commands directory and file**

```bash
cd /home/craigm26/robot-md-mcp
mkdir -p commands
```

Write `commands/enable-dispatch.md`:

```markdown
---
name: enable-dispatch
description: Enable remote HTTP dispatch for this ROBOT.md robot. Generates bearer tokens and writes dispatcher config files. Does NOT print the generated token into this conversation.
---

Run `robot-md-dispatcher init --yes --no-token-stdout` in the workspace root.

Preconditions:

1. `ROBOT.md` must exist at the workspace root. If it's missing, stop and tell the user to run `robot-md init` or `castor init` first.
2. `robot-md-dispatcher` must be installed. If `which robot-md-dispatcher` fails, stop and tell the user to run `pip install robot-md-dispatcher`.

After the command completes successfully:

1. Tell the user that `bearers.yaml`, `.env`, and `dispatch-test.sh` have been written to the workspace root.
2. Tell the user that their actuate-tier bearer token is in `bearers.yaml` (mode 0600) — and that they should open the file directly to read it. Explain that the token was intentionally not printed here to keep it out of this conversation's context.
3. Print this exact next step:
   ```
   robot-md-dispatcher serve --bearers ./bearers.yaml --robot-md ./ROBOT.md
   ```
4. Remind the user to add `bearers.yaml`, `.env`, and `dispatch-test.sh` to `.gitignore`.

Do not read, echo, or repeat the contents of `bearers.yaml` in this conversation under any circumstances.
```

- [ ] **Step 2: Verify Claude Code picks up the slash command**

The plugin is loaded when `robot-md-mcp` is installed as a Claude Code plugin. Manual check: in a fresh Claude Code session with the plugin active, type `/` — `enable-dispatch` should appear in the slash-command menu. (This cannot be automated from pytest; record the result in the commit message.)

- [ ] **Step 3: Commit in the `robot-md-mcp` repo**

```bash
cd /home/craigm26/robot-md-mcp
git add commands/enable-dispatch.md
git commit -m "$(cat <<'EOF'
feat(plugin): add /enable-dispatch slash command

Runs 'robot-md-dispatcher init --yes --no-token-stdout' in the
workspace root so a ROBOT.md-backed robot can flip on remote
dispatch with one slash command. Uses --no-token-stdout so fresh
bearer tokens never enter the agent's conversation context.

Requires robot-md-dispatcher >= 0.2.0 on the user's PATH.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 22: README + CHANGELOG + final validation

**Files:**
- Modify: `/home/craigm26/robot-md-dispatcher/README.md`
- Create: `/home/craigm26/robot-md-dispatcher/CHANGELOG.md` (if absent) or modify

- [ ] **Step 1: Update the README Quick start**

In `README.md`, change the Quick start section. Current form walks the user through writing `bearers.yaml` by hand; replace with:

```markdown
## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install robot-md-dispatcher robot-md
.venv/bin/robot-md-dispatcher init --yes
.venv/bin/robot-md-dispatcher serve --bearers ./bearers.yaml --robot-md ./ROBOT.md
```

`init --yes` writes `bearers.yaml`, `.env`, and `dispatch-test.sh` next to your
ROBOT.md and prints a generated actuate-tier token once. Save the token — it's
not stored anywhere else. Run `robot-md-dispatcher init` (no `--yes`) for a
guided walk that explains each knob.

From a Claude Code session with the `robot-md-mcp` plugin enabled, you can
alternatively run the slash command `/enable-dispatch` — it runs `init --yes`
for you but does not print the generated token into the conversation.
```

Also update the "Production install" section to reference `init` as the prerequisite rather than hand-writing `bearers.yaml`.

- [ ] **Step 2: Create/update CHANGELOG.md**

Check:
```bash
ls /home/craigm26/robot-md-dispatcher/CHANGELOG.md 2>/dev/null
```

If it exists, prepend a new 0.2.0 section. If not, create it:

```markdown
# Changelog

## 0.2.0 — 2026-04-24

### Added
- New `robot-md-dispatcher init` subcommand that scaffolds `bearers.yaml`, `.env`, and a `dispatch-test.sh` smoke-test script for a robot whose `ROBOT.md` is already in place. Has a guided mode (explains each knob) and a `--yes` one-shot mode (all defaults).
- `--force` flag to regenerate files (invalidates old tokens).
- `--no-token-stdout` flag that suppresses the "print token once" step — used by the `/enable-dispatch` Claude Code slash command in `robot-md-mcp` so fresh secrets never enter agent context.
- Hard-fail preconditions: `ROBOT.md` must exist and pass `robot_md.validate`; `robot-md-mcp` must be on PATH.

### Changed
- `robot-md>=1.1` is now a runtime dependency (used for ROBOT.md parse + validate via Python API instead of subprocessing the CLI).

## 0.1.0 — 2026-04-24

Initial scaffold. FastAPI `/dispatch` endpoint, tier-based gating, bearer auth, systemd install script, BYOK billing pattern.
```

- [ ] **Step 3: Run the full validation suite**

Run all four:
```bash
cd /home/craigm26/robot-md-dispatcher
.venv/bin/pytest -q
.venv/bin/ruff check src tests
.venv/bin/python -c "from robot_md_dispatcher.init_wizard import run; print('import ok')"
```

Then a real end-to-end dry run with the fixture ROBOT.md:
```bash
tmp=$(mktemp -d)
cp tests/fixtures/valid_robot.md "$tmp/ROBOT.md"
(cd "$tmp" && /home/craigm26/robot-md-dispatcher/.venv/bin/robot-md-dispatcher init --yes)
ls -la "$tmp"
cat "$tmp/bearers.yaml"
rm -rf "$tmp"
```
Expected: `bearers.yaml` (0600), `.env` (0644), `dispatch-test.sh` (0700) all present; one actuate entry in `bearers.yaml`.

All four must return clean (pytest 0 fails, ruff 0 issues, import ok, end-to-end shows the three files with correct perms).

- [ ] **Step 4: Commit**

```bash
cd /home/craigm26/robot-md-dispatcher
git add README.md CHANGELOG.md
git commit -m "$(cat <<'EOF'
docs: document 'init' wizard in README and CHANGELOG for 0.2.0

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5: Push (optional — only if the user asks)**

Do NOT push without the user's explicit go-ahead. When asked:
```bash
cd /home/craigm26/robot-md-dispatcher && git push
cd /home/craigm26/robot-md-mcp && git push
```

Release cut (PyPI + plugin registry) is a separate step beyond this plan.

---

## Self-Review

**1. Spec coverage** — every spec section maps to at least one task:

| Spec section | Task(s) |
|---|---|
| Module layout (`init_wizard.py`, `run()` signature) | 2 |
| `WizardConfig` dataclass + token gen | 6 |
| Atomic write helper | 7 |
| Bearers/env/test-sh outputs with exact perms | 8, 9, 10 |
| Golden path `init --yes` | 11 |
| `--no-token-stdout` flag | 12 |
| Existing-file refusal + `--force` | 13 |
| TTY requirement for bare `init` | 14 |
| Guided mode with explanation boxes | 15, 16 |
| Systemd + Tailscale print branches | 17 |
| Ctrl-C clean abort | 18 |
| Atomicity rollback on write failure | 19 |
| CLI subcommand wiring | 20 |
| Plugin `/enable-dispatch` slash command | 21 |
| README + CHANGELOG updates | 22 |
| `robot-md>=1.1` dep + version bump | 1 |
| `robot-md-mcp` PATH precondition | 5 |
| ROBOT.md validate via Python import (not subprocess) | 4 |

**2. Placeholder scan** — grep-style read of the plan for `TBD`, `TODO`, "similar to", "fill in": none present. All code blocks contain actual code.

**3. Type consistency** — shared symbols cross-referenced:

- `WizardConfig` fields defined in Task 6 (`bind`, `port`, `generate_actuate`, `generate_read`, `systemd_print`, `tailscale_print`) — all used in Task 15 prompt flow and Task 17 print branches with the same names.
- `_generate_tokens` returns `tuple[str, str | None]` (Task 6) — consumed by `run()` in Task 11 as `actuate_token, read_token`.
- `_atomic_write(path, content, mode)` signature (Task 7) — called from Tasks 8, 9, 10 with that keyword shape.
- `_write_bearers_yaml(path, *, actuate_token, read_token)` (Task 8) — called from `run()` in Task 11 with those keyword names.
- `BearerStore.from_yaml` shape (existing code) — matches test assertions in Tasks 8 and 11.
- `--no-token-stdout` CLI flag (Task 20) → `no_token_stdout=args.no_token_stdout` in `run()` signature (Task 2) — matches.

**4. External API references** — `robot_md.parser.parse_file`, `robot_md.parser.ParseError`, `robot_md.validate.validate`, `robot_md.validate.VALID` — all verified against `/home/craigm26/robot-md/cli/src/robot_md/validate.py` and `parser.py` during plan writing.
