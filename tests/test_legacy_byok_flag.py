"""Test that --legacy-byok-launcher selects the legacy app and warns."""

from __future__ import annotations

import subprocess
import sys


def test_legacy_byok_launcher_flag_warns_and_runs():
    """Invoking with --legacy-byok-launcher --help warns on stderr and exits 0."""
    result = subprocess.run(
        [sys.executable, "-m", "robot_md_gateway", "--legacy-byok-launcher", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "legacy" in result.stderr.lower() or "deprecated" in result.stderr.lower()


def test_default_mode_does_not_warn_about_byok():
    """Default mode (no flag) should NOT print the BYOK deprecation message."""
    result = subprocess.run(
        [sys.executable, "-m", "robot_md_gateway", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    stderr = result.stderr.lower()
    assert "legacy-byok" not in stderr or "removed in v0.4.0" in stderr


def test_help_documents_legacy_flag():
    """The --legacy-byok-launcher flag must appear in --help output."""
    result = subprocess.run(
        [sys.executable, "-m", "robot_md_gateway", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert "--legacy-byok-launcher" in result.stdout
