"""Test that `robot-md-dispatcher` CLI delegates to gateway main with a deprecation warning."""

from __future__ import annotations

import subprocess
import sys


def test_legacy_cli_module_invocable_with_deprecation_message():
    """`python -m robot_md_gateway._legacy_cli --help` runs + warns on stderr."""
    result = subprocess.run(
        [sys.executable, "-m", "robot_md_gateway._legacy_cli", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "deprecated" in result.stderr.lower()
    assert "robot-md-gateway" in result.stderr.lower()
    assert "usage" in result.stdout.lower() or "options" in result.stdout.lower()
