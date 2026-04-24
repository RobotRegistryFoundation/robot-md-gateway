from __future__ import annotations

from pathlib import Path

from robot_md_dispatcher import init_wizard


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


def test_accepts_valid_robot_md(tmp_path: Path, valid_robot_md: Path):
    # valid_robot_md fixture already copies ROBOT.md into tmp_path
    # At this point in the plan, the wizard only does precondition checks,
    # so it should return 0 (no files yet — that comes in later tasks).
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
