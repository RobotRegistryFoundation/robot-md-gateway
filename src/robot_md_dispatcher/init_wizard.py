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
