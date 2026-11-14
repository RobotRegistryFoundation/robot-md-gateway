"""The clean-shutdown marker (clean_shutdown.py): read and removed first at
start, written last on the normal exit path, and every doubt means the stops
go out."""

from __future__ import annotations

import json
from pathlib import Path

from robot_md_gateway import clean_shutdown


def _env(directory: Path | str) -> dict[str, str]:
    return {"STATE_DIRECTORY": str(directory)}


def test_without_a_state_directory_the_stops_go_out(tmp_path):
    reason = clean_shutdown.consume({})
    assert reason == ("no clean-shutdown marker can be kept: STATE_DIRECTORY is not set (the "
                      "unit has no StateDirectory=)")
    assert clean_shutdown.write({}) is False


def test_no_marker_means_the_stops_go_out(tmp_path):
    assert clean_shutdown.consume(_env(tmp_path)) == (
        f"the previous process left no clean-shutdown marker in {tmp_path}")


def test_a_marker_is_honoured_once_and_removed(tmp_path):
    assert clean_shutdown.write(_env(tmp_path)) is True
    marker = tmp_path / clean_shutdown.MARKER
    assert json.loads(marker.read_text())["clean_shutdown"] is True
    assert sorted(p.name for p in tmp_path.iterdir()) == [clean_shutdown.MARKER]
    assert clean_shutdown.consume(_env(tmp_path)) is None
    assert not marker.exists()
    # The process that read it has to leave its own.
    assert clean_shutdown.consume(_env(tmp_path)).startswith(
        "the previous process left no clean-shutdown marker")


def test_the_first_of_several_state_directories_is_this_units(tmp_path):
    clean_shutdown.write(_env(tmp_path))
    assert clean_shutdown.consume(_env(f"{tmp_path}:/var/lib/other")) is None


def test_a_marker_this_gateway_did_not_write_means_the_stops_go_out(tmp_path):
    for body in (b"", b"{}", b"not json", b'{"clean_shutdown": "yes"}'):
        marker = tmp_path / clean_shutdown.MARKER
        marker.write_bytes(body)
        assert clean_shutdown.consume(_env(tmp_path)) == (
            f"the clean-shutdown marker {marker} was not one this gateway writes")
        assert not marker.exists()


def test_a_marker_that_cannot_be_read_means_the_stops_go_out(tmp_path):
    (tmp_path / clean_shutdown.MARKER).mkdir()
    assert clean_shutdown.consume(_env(tmp_path)) == (
        f"the clean-shutdown marker {tmp_path / clean_shutdown.MARKER} could not be read "
        f"(IsADirectoryError)")


def test_a_marker_that_cannot_be_removed_is_not_honoured_now_or_later(tmp_path, monkeypatch):
    """Not now, since it would still be there for a start after an unclean
    end; and not later, once it can be removed, since it is emptied."""
    clean_shutdown.write(_env(tmp_path))
    marker = tmp_path / clean_shutdown.MARKER

    def refuse(self, missing_ok=False):
        raise PermissionError("read-only")

    monkeypatch.setattr(Path, "unlink", refuse)
    assert clean_shutdown.consume(_env(tmp_path)) == (
        f"the clean-shutdown marker {marker} could not be removed (PermissionError)")
    monkeypatch.undo()
    assert marker.read_bytes() == b""
    assert clean_shutdown.consume(_env(tmp_path)) == (
        f"the clean-shutdown marker {marker} was not one this gateway writes")


def test_deciding_never_raises(monkeypatch):
    def broken(env):
        raise RuntimeError("no")

    monkeypatch.setattr(clean_shutdown, "state_directory", broken)
    assert clean_shutdown.consume({}).startswith(
        "whether the previous process shut down cleanly could not be decided")
    assert clean_shutdown.write({}) is False


def test_a_marker_that_cannot_be_written_is_only_a_warning(tmp_path, caplog):
    assert clean_shutdown.write(_env(tmp_path / "missing")) is False
    assert "the next start sends every declared stop" in caplog.text
