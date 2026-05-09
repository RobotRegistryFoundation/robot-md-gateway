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


import jsonschema


class _SchemaValidatedActuator:
    name = "schema-checked"
    description = "test schema validation"
    config_schema = {
        "type": "object",
        "properties": {
            "log_level": {"type": "string", "enum": ["INFO", "DEBUG", "WARNING"]},
        },
        "required": ["log_level"],
    }
    def execute(self, *, envelope, manifest_path, tier, config):
        from robot_md_gateway.actuator import ActuatorOutcome
        return ActuatorOutcome(success=True, outcome_kind="executed")


class TestServeWiresActuator:
    def test_validate_actuator_config_against_schema_passes(self):
        from robot_md_gateway.__main__ import _validate_actuator_config

        # Should NOT raise.
        _validate_actuator_config(
            actuator_instance=_SchemaValidatedActuator(),
            config={"log_level": "INFO"},
        )

    def test_validate_actuator_config_against_schema_rejects(self):
        from robot_md_gateway.__main__ import _validate_actuator_config

        with pytest.raises(jsonschema.ValidationError):
            _validate_actuator_config(
                actuator_instance=_SchemaValidatedActuator(),
                config={"log_level": "VERBOSE"},  # not in enum
            )

    def test_validate_actuator_config_with_empty_schema_skips(self):
        from robot_md_gateway.__main__ import _validate_actuator_config

        class _EmptySchema:
            config_schema: dict = {}
            def __init__(self): pass

        # Should NOT raise even with arbitrary config.
        _validate_actuator_config(
            actuator_instance=_EmptySchema(),
            config={"anything": "goes"},
        )


class TestServeBearerTiers:
    def test_bearer_tiers_extracted_from_bearers_yaml(self, tmp_path):
        # Smoke: build a bearer-tiers dict from a bearers.yaml the same way
        # the serve path does. This documents the contract; the actual serve
        # invocation isn't started in unit tests.
        from robot_md_gateway.auth import BearerStore
        bearers_path = tmp_path / "bearers.yaml"
        bearers_path.write_text("""\
- token: actuate-token
  tier: actuate
  caller: actuate-default
""")
        store = BearerStore.from_yaml(bearers_path)
        bearer_tiers = {token: entry.tier for token, entry in store._by_token.items()}
        assert bearer_tiers == {"actuate-token": "actuate"}
