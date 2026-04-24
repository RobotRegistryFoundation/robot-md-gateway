from __future__ import annotations

import os
from pathlib import Path

from robot_md_dispatcher import init_wizard
from robot_md_dispatcher.auth import BearerStore


def test_wizard_module_imports_and_run_exists():
    assert callable(init_wizard.run)


def test_refuses_without_robot_md(tmp_path: Path, capsys):
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "No ROBOT.md" in err
    assert "robot-md init" in err or "castor init" in err


def test_refuses_on_invalid_robot_md(tmp_path: Path, capsys):
    (tmp_path / "ROBOT.md").write_text("no frontmatter here\n")
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "ROBOT.md" in err
    assert "re-run" in err.lower() or "fix" in err.lower()


def test_accepts_valid_robot_md(tmp_path: Path, valid_robot_md: Path, monkeypatch):
    # valid_robot_md fixture already copies ROBOT.md into tmp_path
    # At this point in the plan, the wizard only does precondition checks,
    # so it should return 0 (no files yet — that comes in later tasks).
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0


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


def test_refuses_on_schema_invalid_robot_md(tmp_path: Path, capsys):
    # Well-formed frontmatter but schema-invalid (missing required fields).
    # Exercises the result.code != VALID branch of _validate_robot_md, which
    # is distinct from the ParseError branch tested by
    # test_refuses_on_invalid_robot_md.
    (tmp_path / "ROBOT.md").write_text("---\nfoo: bar\n---\n# body\n")
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "validation failed" in err


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


def test_write_env_contains_four_expected_vars(tmp_path: Path):
    path = tmp_path / ".env"
    init_wizard._write_env(path)
    content = path.read_text()
    assert "ROBOT_MD_PATH=./ROBOT.md" in content
    assert "ROBOT_MD_BEARERS_FILE=./bearers.yaml" in content
    assert "ROBOT_MD_MCP_COMMAND=robot-md-mcp" in content
    assert "ROBOT_MD_LOG_LEVEL=INFO" in content
    assert oct(path.stat().st_mode & 0o777) == "0o644"
