from __future__ import annotations

from pathlib import Path

from robot_md_dispatcher import init_wizard


def test_wizard_module_imports_and_run_exists():
    assert callable(init_wizard.run)
