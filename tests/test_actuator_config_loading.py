"""Tests for bearers.yaml legacy/new-shape parsing + actuator config extraction."""
from __future__ import annotations

from pathlib import Path

import pytest

from robot_md_gateway.auth import BearerStore, load_actuator_section


def _write(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "bearers.yaml"
    p.write_text(content)
    return p


class TestBearersLegacyListShape:
    def test_legacy_list_shape_still_parses(self, tmp_path):
        path = _write(tmp_path, """\
- token: actuate-token
  tier: actuate
  caller: actuate-default
""")
        store = BearerStore.from_yaml(path)
        assert store.resolve("actuate-token") is not None

    def test_legacy_list_shape_has_no_actuator_section(self, tmp_path):
        path = _write(tmp_path, """\
- token: actuate-token
  tier: actuate
  caller: actuate-default
""")
        section = load_actuator_section(path)
        assert section == {"name": "noop", "config": {}}


class TestBearersNewDictShape:
    def test_new_shape_parses_bearers_under_key(self, tmp_path):
        path = _write(tmp_path, """\
bearers:
  - token: actuate-token
    tier: actuate
    caller: actuate-default
actuator:
  name: my-driver
  config:
    log_level: INFO
    output_dir: ./telemetry
""")
        store = BearerStore.from_yaml(path)
        assert store.resolve("actuate-token") is not None

    def test_new_shape_actuator_section(self, tmp_path):
        path = _write(tmp_path, """\
bearers:
  - token: actuate-token
    tier: actuate
    caller: actuate-default
actuator:
  name: my-driver
  config:
    log_level: INFO
""")
        section = load_actuator_section(path)
        assert section == {
            "name": "my-driver",
            "config": {"log_level": "INFO"},
        }

    def test_new_shape_actuator_section_omitted_defaults_to_noop(self, tmp_path):
        path = _write(tmp_path, """\
bearers:
  - token: actuate-token
    tier: actuate
    caller: actuate-default
""")
        section = load_actuator_section(path)
        assert section == {"name": "noop", "config": {}}
