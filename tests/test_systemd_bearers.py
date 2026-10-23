"""The deployed unit runs with bearer auth, and fails closed without it.

Regression: systemd/robot-md-dispatcher.service ran `serve` without --bearers,
so a deployed gateway loaded no bearers at all and every request was anon (and
the actuator section of bearers.yaml was never read, so it ran the no-op
actuator). install.sh wrote a bearers.yaml of comments only, mode 0640.

What these tests pin:
- the unit passes --bearers and refuses to start when the file is missing;
- the unit's service can actually read its config directory;
- install.sh creates the bearer file with a generated actuate token and a
  generated supervisor token, root:robot 0640, never printed and never
  overwritten, not even by a run racing another;
- the gateway itself refuses to serve when --bearers names a missing or empty
  file;
- a bearers.yaml never gets committed from a checkout.
"""

from __future__ import annotations

import grp
import os
import pwd
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from robot_md_gateway.auth import BearerStore

REPO = Path(__file__).resolve().parents[1]
UNIT = REPO / "systemd" / "robot-md-dispatcher.service"
INSTALL = REPO / "systemd" / "install.sh"
CREATE = REPO / "systemd" / "create-bearers.sh"
BEARERS = "/etc/robot-md-dispatcher/bearers.yaml"


def _unit_lines() -> list[str]:
    """The unit's directives, with backslash continuations joined."""
    lines, cur = [], ""
    for raw in UNIT.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            cur += line[:-1] + " "
            continue
        lines.append(" ".join((cur + line).split()))
        cur = ""
    return lines


def _directive(name: str) -> list[str]:
    return [line.split("=", 1)[1] for line in _unit_lines() if line.startswith(f"{name}=")]


# --- the unit ----------------------------------------------------------------


def test_the_unit_serves_with_the_bearer_file():
    [exec_start] = _directive("ExecStart")
    assert re.search(r"\bserve\b", exec_start)
    assert f"--bearers {BEARERS}" in exec_start


def test_the_unit_refuses_to_start_without_the_bearer_file():
    assert BEARERS in _directive("AssertPathExists")


def test_the_unit_can_read_its_config_directory():
    """Group=dialout replaces the service user's primary group, and install.sh
    makes the config dir root:robot 0750. Without `robot` as a supplementary
    group the service cannot open anything in it: bearers.yaml, ROBOT.md."""
    assert _directive("User") == ["robot"]
    assert "robot" in " ".join(_directive("SupplementaryGroups")).split()
    assert 'install -d -o root -g robot -m 0750 "$CONFIG_DIR"' in INSTALL.read_text()


def test_the_unit_and_the_installer_agree_on_the_path():
    assert 'CONFIG_DIR="/etc/robot-md-dispatcher"' in INSTALL.read_text()
    assert os.path.dirname(BEARERS) == "/etc/robot-md-dispatcher"


# --- install.sh and the bearer file --------------------------------------------


def test_install_sh_creates_the_bearer_file_through_the_helper():
    text = INSTALL.read_text()
    assert '"$REPO_DIR/systemd/create-bearers.sh" "$CONFIG_DIR/bearers.yaml" root robot' in text
    # The old comment-only file, readable by the group, is gone.
    assert "chmod 0640 \"$CONFIG_DIR/bearers.yaml\"" not in text


def _me() -> tuple[str, str]:
    return pwd.getpwuid(os.getuid()).pw_name, grp.getgrgid(os.getgid()).gr_name


def _create(path: Path) -> subprocess.CompletedProcess:
    owner, group = _me()
    return subprocess.run(["bash", str(CREATE), str(path), owner, group],
                          capture_output=True, text=True, check=False)


def test_the_helper_writes_an_actuate_and_a_supervisor_token_0640(tmp_path):
    path = tmp_path / "bearers.yaml"
    result = _create(path)

    assert result.returncode == 0, result.stderr
    st = path.stat()
    assert stat.S_IMODE(st.st_mode) == 0o640
    assert (st.st_uid, st.st_gid) == (os.getuid(), os.getgid())
    store = BearerStore.from_yaml(path)            # the gateway can load it
    entries = sorted(store._by_token.values(), key=lambda e: e.caller_id)
    assert [(e.caller_id, e.tier, e.role) for e in entries] == [
        ("actuate-default", "actuate", None), ("supervisor-default", "read", "supervisor")]
    assert all(len(e.token) >= 40 for e in entries)
    assert entries[0].token != entries[1].token
    # No commission entry: clearing a stop is added by hand, deliberately.
    assert "commission" not in {e.tier for e in entries}
    # Never printed: not on stdout, not on stderr.
    assert not any(e.token in result.stdout + result.stderr for e in entries)


def test_runs_racing_each_other_leave_exactly_one_file(tmp_path):
    """The name is taken with link(2): of runs racing for it, one wins, the
    others leave it unchanged, and no temporary file is left behind."""
    owner, group = _me()
    path = tmp_path / "bearers.yaml"
    runs = [subprocess.Popen(["bash", str(CREATE), str(path), owner, group],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for _ in range(8)]
    results = [(r.wait(), r.stdout.read()) for r in runs]
    for r in runs:
        r.stdout.close()
        r.stderr.close()
    assert all(code == 0 for code, _ in results)
    assert sum(out.startswith("created") for _, out in results) == 1
    assert [p.name for p in tmp_path.iterdir()] == ["bearers.yaml"]
    BearerStore.from_yaml(path)


def test_the_helper_never_overwrites_an_existing_file(tmp_path):
    path = tmp_path / "bearers.yaml"
    assert _create(path).returncode == 0
    before = path.read_bytes()
    again = _create(path)
    assert again.returncode == 0
    assert path.read_bytes() == before
    assert "left unchanged" in again.stdout


def test_every_install_gets_its_own_tokens(tmp_path):
    a, b = tmp_path / "a.yaml", tmp_path / "b.yaml"
    assert _create(a).returncode == 0 and _create(b).returncode == 0
    tokens = [set(BearerStore.from_yaml(p)._by_token) for p in (a, b)]
    assert not tokens[0] & tokens[1]


def test_the_helper_leaves_nothing_behind_when_it_cannot_finish(tmp_path):
    path = tmp_path / "bearers.yaml"
    result = subprocess.run(
        ["bash", str(CREATE), str(path), "no-such-user-xyz", "no-such-group-xyz"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode != 0
    assert list(tmp_path.iterdir()) == []


# --- the gateway itself fails closed -------------------------------------------


@pytest.mark.parametrize("content", [None, "", "# comments only, like the old install.sh\n"])
def test_serve_refuses_to_start_on_a_missing_or_empty_bearer_file(monkeypatch, tmp_path, content):
    import uvicorn

    from robot_md_gateway import __main__ as gw_main

    path = tmp_path / "bearers.yaml"
    if content is not None:
        path.write_text(content)
    served = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: served.append(app))
    monkeypatch.setattr(sys, "argv", ["robot-md-gateway", "serve", "--bearers", str(path)])
    with pytest.raises((FileNotFoundError, ValueError)):
        gw_main.main()
    assert served == []


# --- never committed ---------------------------------------------------------------


def test_bearer_files_are_gitignored():
    ignored = {line.strip() for line in (REPO / ".gitignore").read_text().splitlines()}
    assert {"bearers.yaml", "dispatch-test.sh"} <= ignored


def test_no_bearer_file_is_tracked():
    try:
        tracked = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True,
                                 text=True, check=True).stdout.split()
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    assert [p for p in tracked if Path(p).name == "bearers.yaml"] == []


def test_the_yaml_the_helper_writes_is_the_documented_shape(tmp_path):
    path = tmp_path / "bearers.yaml"
    assert _create(path).returncode == 0
    data = yaml.safe_load(path.read_text())
    assert set(data) == {"bearers"}
    assert [set(row) for row in data["bearers"]] == [
        {"token", "tier", "caller"}, {"token", "role", "caller"}]
