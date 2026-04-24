from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from robot_md_dispatcher.auth import AuthContext, BearerStore
from robot_md_dispatcher.gating import TierPolicy


@pytest.fixture
def bearers_yaml(tmp_path: Path) -> Path:
    path = tmp_path / "bearers.yaml"
    path.write_text(
        yaml.safe_dump(
            [
                {"token": "read-token", "tier": "read", "caller": "alice"},
                {"token": "actuate-token", "tier": "actuate", "caller": "bob"},
            ]
        )
    )
    return path


@pytest.fixture
def bearer_store(bearers_yaml: Path) -> BearerStore:
    return BearerStore.from_yaml(bearers_yaml)


@pytest.fixture
def policy() -> TierPolicy:
    return TierPolicy.default()


@pytest.fixture
def read_auth() -> AuthContext:
    return AuthContext(caller_id="alice", tier="read", api_key="sk-ant-test-read")


@pytest.fixture
def actuate_auth() -> AuthContext:
    return AuthContext(caller_id="bob", tier="actuate", api_key="sk-ant-test-actuate")
