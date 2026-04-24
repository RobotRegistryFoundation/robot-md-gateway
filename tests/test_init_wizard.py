from __future__ import annotations

import io
import os
from pathlib import Path

from robot_md_dispatcher import init_wizard
from robot_md_dispatcher.auth import BearerStore


def test_wizard_module_imports_and_run_exists():
    assert callable(init_wizard.run)


def test_refuses_without_robot_md(tmp_path: Path, capsys):
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "No ROBOT.md" in err
    assert "robot-md init" in err or "castor init" in err


def test_refuses_on_invalid_robot_md(tmp_path: Path, capsys):
    (tmp_path / "ROBOT.md").write_text("no frontmatter here\n")
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "ROBOT.md" in err
    assert "re-run" in err.lower() or "fix" in err.lower()


def test_accepts_valid_robot_md(tmp_path: Path, valid_robot_md: Path, monkeypatch):
    # valid_robot_md fixture already copies ROBOT.md into tmp_path
    # At this point in the plan, the wizard only does precondition checks,
    # so it should return 0 (no files yet — that comes in later tasks).
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0


def test_refuses_if_mcp_missing(tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys):
    monkeypatch.setattr("shutil.which", lambda cmd: None if cmd == "robot-md-mcp" else "/bin/true")
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "robot-md-mcp" in err
    assert "not found on PATH" in err


def test_passes_when_mcp_present(tmp_path: Path, valid_robot_md: Path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0


def test_refuses_on_schema_invalid_robot_md(tmp_path: Path, capsys):
    # Well-formed frontmatter but schema-invalid (missing required fields).
    # Exercises the result.code != VALID branch of _validate_robot_md, which
    # is distinct from the ParseError branch tested by
    # test_refuses_on_invalid_robot_md.
    (tmp_path / "ROBOT.md").write_text("---\nfoo: bar\n---\n# body\n")
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "validation failed" in err


def test_default_config_has_sensible_values():
    cfg = init_wizard.WizardConfig()
    assert cfg.bind == "127.0.0.1"
    assert cfg.port == 8080
    assert cfg.generate_actuate is True
    assert cfg.generate_read is False
    assert cfg.systemd_print is False
    assert cfg.tailscale_print is False


def test_generate_tokens_actuate_only_by_default():
    cfg = init_wizard.WizardConfig()
    actuate, read = init_wizard._generate_tokens(cfg)
    assert len(actuate) >= 32
    assert read is None


def test_generate_tokens_both_when_opted_in():
    cfg = init_wizard.WizardConfig(generate_read=True)
    actuate, read = init_wizard._generate_tokens(cfg)
    assert len(actuate) >= 32
    assert read is not None and len(read) >= 32
    assert actuate != read


def test_atomic_write_commits_content_and_perms(tmp_path: Path):
    target = tmp_path / "out.txt"
    init_wizard._atomic_write(target, "hello\n", mode=0o600)
    assert target.read_text() == "hello\n"
    assert oct(target.stat().st_mode & 0o777) == "0o600"


def test_atomic_write_overwrites_existing(tmp_path: Path):
    target = tmp_path / "out.txt"
    target.write_text("old")
    init_wizard._atomic_write(target, "new", mode=0o600)
    assert target.read_text() == "new"


def test_atomic_write_removes_temp_on_failure(tmp_path: Path, monkeypatch):
    target = tmp_path / "out.txt"

    def boom(src: str, dst: str) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)

    try:
        init_wizard._atomic_write(target, "x", mode=0o600)
    except OSError:
        pass

    assert not target.exists()
    # No leftover dotfile in target_dir
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith(".out.txt.")]
    assert leftovers == []


def test_write_bearers_yaml_actuate_only(tmp_path: Path):
    path = tmp_path / "bearers.yaml"
    init_wizard._write_bearers_yaml(
        path, actuate_token="AAAA", read_token=None
    )
    # Format is loadable by the real consumer
    store = BearerStore.from_yaml(path)
    assert store.resolve("AAAA") is not None
    assert store.resolve("AAAA").tier == "actuate"
    assert store.resolve("AAAA").caller_id == "actuate-default"
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_write_bearers_yaml_both_tiers(tmp_path: Path):
    path = tmp_path / "bearers.yaml"
    init_wizard._write_bearers_yaml(path, actuate_token="A", read_token="R")
    store = BearerStore.from_yaml(path)
    assert store.resolve("A").tier == "actuate"
    assert store.resolve("R").tier == "read"
    assert store.resolve("R").caller_id == "read-default"


def test_write_env_contains_four_expected_vars(tmp_path: Path):
    path = tmp_path / ".env"
    init_wizard._write_env(path)
    content = path.read_text()
    assert "ROBOT_MD_PATH=./ROBOT.md" in content
    assert "ROBOT_MD_BEARERS_FILE=./bearers.yaml" in content
    assert "ROBOT_MD_MCP_COMMAND=robot-md-mcp" in content
    assert "ROBOT_MD_LOG_LEVEL=INFO" in content
    assert oct(path.stat().st_mode & 0o777) == "0o644"


def test_write_dispatch_test_sh_bakes_token_and_is_0700(tmp_path: Path):
    path = tmp_path / "dispatch-test.sh"
    init_wizard._write_dispatch_test_sh(
        path, actuate_token="ABCDE", bind="127.0.0.1", port=8080
    )
    content = path.read_text()
    assert "Authorization: Bearer ABCDE" in content
    assert "127.0.0.1:8080" in content
    assert "ANTHROPIC_API_KEY" in content  # gated on env var
    assert content.startswith("#!/usr/bin/env bash")
    assert oct(path.stat().st_mode & 0o777) == "0o700"  # token in plaintext -> user-only


def test_write_dispatch_test_sh_uses_custom_port(tmp_path: Path):
    path = tmp_path / "dispatch-test.sh"
    init_wizard._write_dispatch_test_sh(
        path, actuate_token="X", bind="127.0.0.1", port=9090
    )
    assert "127.0.0.1:9090" in path.read_text()


def test_init_yes_golden_path(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0

    bearers = tmp_path / "bearers.yaml"
    env = tmp_path / ".env"
    test_sh = tmp_path / "dispatch-test.sh"

    assert bearers.exists() and oct(bearers.stat().st_mode & 0o777) == "0o600"
    assert env.exists() and oct(env.stat().st_mode & 0o777) == "0o644"
    assert test_sh.exists() and oct(test_sh.stat().st_mode & 0o777) == "0o700"

    # Token is in bearers.yaml, printed exactly once to stdout, and baked into dispatch-test.sh
    store = BearerStore.from_yaml(bearers)
    actuate_entries = [e for e in store._by_token.values() if e.tier == "actuate"]
    assert len(actuate_entries) == 1
    token = actuate_entries[0].token
    out = capsys.readouterr().out
    assert out.count(token) == 1
    assert token in test_sh.read_text()


def test_no_token_stdout_suppresses_token(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=True)
    assert rc == 0

    bearers = tmp_path / "bearers.yaml"
    store = BearerStore.from_yaml(bearers)
    token = [e for e in store._by_token.values() if e.tier == "actuate"][0].token

    out = capsys.readouterr().out
    assert token not in out
    assert "Open the file" in out


def test_refuses_on_existing_bearers_yaml(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    (tmp_path / "bearers.yaml").write_text("- token: old\n  tier: actuate\n  caller: c\n")
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "bearers.yaml already exists" in err
    assert "--force" in err


def test_refuses_on_existing_env(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    (tmp_path / ".env").write_text("X=1\n")
    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert ".env already exists" in err


def test_force_overwrites_and_invalidates_old_token(
    tmp_path: Path, valid_robot_md: Path, monkeypatch
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    (tmp_path / "bearers.yaml").write_text("- token: OLD\n  tier: actuate\n  caller: c\n")

    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=True, no_token_stdout=False)
    assert rc == 0

    store = BearerStore.from_yaml(tmp_path / "bearers.yaml")
    assert store.resolve("OLD") is None  # old token no longer valid


def test_bare_init_refuses_on_non_tty(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    # pytest's capsys replaces stdin with a non-tty already; assert explicitly:
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    rc = init_wizard.run(interactive=True, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "TTY" in err
    assert "--yes" in err


def test_guided_mode_accepts_all_defaults(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    # Pipe enough newlines to default every prompt.
    monkeypatch.setattr("sys.stdin", io.StringIO("\n" * 20))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    rc = init_wizard.run(interactive=True, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0

    # Same outputs as --yes golden path
    bearers = BearerStore.from_yaml(tmp_path / "bearers.yaml")
    actuate = [e for e in bearers._by_token.values() if e.tier == "actuate"]
    assert len(actuate) == 1
    # .env defaults
    env_text = (tmp_path / ".env").read_text()
    assert "ROBOT_MD_PATH=./ROBOT.md" in env_text
    # dispatch-test.sh uses default port
    assert "127.0.0.1:8080" in (tmp_path / "dispatch-test.sh").read_text()


def test_guided_mode_declining_initial_confirm_aborts(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    monkeypatch.setattr("sys.stdin", io.StringIO("n\n"))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    rc = init_wizard.run(interactive=True, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0
    assert not (tmp_path / "bearers.yaml").exists()
    out = capsys.readouterr().out
    assert "aborted" in out.lower() or "cancelled" in out.lower() or "no changes" in out.lower()


def test_guided_mode_custom_port(
    tmp_path: Path, valid_robot_md: Path, monkeypatch
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    # NOTE: order matters — replace sys.stdin first, then patch isatty on the
    # StringIO instance. The reverse order leaves isatty() returning False
    # because monkeypatch.setattr("sys.stdin", ...) swaps in a fresh StringIO
    # whose own isatty() shadows the earlier patch.
    monkeypatch.setattr("sys.stdin", io.StringIO("\n\n9090\n\n\n\n\n"))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    # Confirm=Y, bind=default, port=9090, actuate=default, read=default,
    # systemd=default, tailscale=default

    rc = init_wizard.run(interactive=True, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0
    assert "127.0.0.1:9090" in (tmp_path / "dispatch-test.sh").read_text()


def test_guided_mode_read_tier_opt_in(
    tmp_path: Path, valid_robot_md: Path, monkeypatch
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    # Walk to the read-tier prompt and answer "y"; defaults for everything else.
    # Order matters: StringIO first, then isatty patch lands on it.
    monkeypatch.setattr("sys.stdin", io.StringIO("\n\n\n\ny\n\n\n"))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    rc = init_wizard.run(interactive=True, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0
    store = BearerStore.from_yaml(tmp_path / "bearers.yaml")
    tiers = {e.tier for e in store._by_token.values()}
    assert tiers == {"read", "actuate"}


def test_systemd_opt_in_prints_install_commands(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    # Walk to the systemd prompt and answer "y"; tailscale=default.
    # Order matters: StringIO first, then isatty patch lands on it.
    monkeypatch.setattr("sys.stdin", io.StringIO("\n\n\n\n\ny\n\n"))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    rc = init_wizard.run(interactive=True, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0
    out = capsys.readouterr().out
    assert "sudo" in out
    assert "install.sh" in out
    assert "/etc/robot-md-dispatcher" in out


def test_tailscale_opt_in_prints_funnel_commands(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    # Walk to the tailscale prompt and answer "y"; systemd=default.
    # Order matters: StringIO first, then isatty patch lands on it.
    monkeypatch.setattr("sys.stdin", io.StringIO("\n\n\n\n\n\ny\n"))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    rc = init_wizard.run(interactive=True, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 0
    out = capsys.readouterr().out
    assert "tailscale serve" in out
    assert "tailscale funnel" in out
    assert "8080" in out  # default port substituted in


def test_ctrl_c_during_prompt_returns_130_no_files(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    def boom(prompt: str) -> str:
        raise KeyboardInterrupt()

    monkeypatch.setattr("builtins.input", boom)

    rc = init_wizard.run(interactive=True, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 130
    err = capsys.readouterr().err
    assert "Aborted" in err
    assert not (tmp_path / "bearers.yaml").exists()
    assert not (tmp_path / ".env").exists()
    assert not (tmp_path / "dispatch-test.sh").exists()


def test_atomicity_rollback_on_second_write_failure(
    tmp_path: Path, valid_robot_md: Path, monkeypatch, capsys
):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/" + cmd)

    original_replace = os.replace
    calls: list[str] = []

    def flaky_replace(src, dst):
        calls.append(str(dst))
        if len(calls) == 2:  # fail on the second atomic write (.env)
            raise OSError("simulated disk full")
        return original_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)

    rc = init_wizard.run(interactive=False, cwd=tmp_path, force=False, no_token_stdout=False)
    assert rc == 1

    # Both user-facing files absent (bearers.yaml was rolled back)
    assert not (tmp_path / "bearers.yaml").exists()
    assert not (tmp_path / ".env").exists()
    assert not (tmp_path / "dispatch-test.sh").exists()

    err = capsys.readouterr().err
    assert "Write failed" in err
