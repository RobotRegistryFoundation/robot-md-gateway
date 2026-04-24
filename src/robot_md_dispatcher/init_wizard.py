"""Interactive and one-shot wizard that enables remote dispatch for a ROBOT.md robot."""

from __future__ import annotations

import sys
from pathlib import Path


class _Precondition(Exception):
    """Precondition failure with a user-facing message."""


def _check_robot_md_exists(cwd: Path) -> Path:
    robot_md = cwd / "ROBOT.md"
    if not robot_md.is_file():
        raise _Precondition(
            f"No ROBOT.md in {cwd}. Run 'robot-md init' or 'castor init' first."
        )
    return robot_md


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

    # RCAN v3 schema: robot name lives at metadata.robot_name, not top-level name.
    metadata = parsed.frontmatter.get("metadata") or {}
    return str(metadata.get("robot_name", "unknown"))


def run(
    *,
    interactive: bool,
    cwd: Path,
    force: bool = False,
    no_token_stdout: bool = False,
) -> int:
    """Run the init wizard. Returns a process exit code."""
    try:
        robot_md = _check_robot_md_exists(cwd)
        robot_name = _validate_robot_md(robot_md)  # noqa: F841 — used in later tasks
    except _Precondition as e:
        print(str(e), file=sys.stderr)
        return 1
    return 0
