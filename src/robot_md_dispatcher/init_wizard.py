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
