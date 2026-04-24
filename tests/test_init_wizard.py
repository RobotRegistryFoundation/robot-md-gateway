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
