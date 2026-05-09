"""Tests for the list-actuators CLI subcommand."""
from __future__ import annotations

import json
import subprocess
import sys

import pytest


def _run_cli(*args: str, expect_zero: bool = True) -> subprocess.CompletedProcess:
    cmd = [sys.executable, "-m", "robot_md_gateway", *args]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if expect_zero and proc.returncode != 0:
        pytest.fail(f"CLI exited {proc.returncode}; stderr:\n{proc.stderr}\nstdout:\n{proc.stdout}")
    return proc


class TestListActuatorsCLI:
    def test_lists_built_in_noop(self):
        proc = _run_cli("list-actuators")
        assert "noop" in proc.stdout.lower()
        # Description text should appear as well.
        assert "default" in proc.stdout.lower() or "log" in proc.stdout.lower()

    def test_marks_active_actuator_when_bearers_path_provided(self, tmp_path):
        bearers = tmp_path / "bearers.yaml"
        bearers.write_text("""\
bearers:
  - token: actuate-token
    tier: actuate
    caller: actuate-default
actuator:
  name: noop
  config: {}
""")
        proc = _run_cli("list-actuators", "--bearers", str(bearers))
        # Active actuator marked with asterisk
        assert "*" in proc.stdout
        # Specifically, the line with "noop" should have the asterisk.
        noop_lines = [line for line in proc.stdout.splitlines() if "noop" in line.lower()]
        assert any("*" in line for line in noop_lines)
