"""platatlas-shipper sidecar: offset persistence, POST shape, at-least-once."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from robot_md_gateway.shipper import (
    ShipperConfig,
    ShipperTamperStop,
    ship_once,
    target_url,
)


def test_target_url_default_subdomain():
    cfg = ShipperConfig(
        ingest_key="sk_live_x", org_slug="opencastor", base_url=None,
        export_file=Path("/tmp/x.ndjson"), offset_file=Path("/tmp/x.offset"),
    )
    assert target_url(cfg) == "https://opencastor.platatlas.com/api/traces?source=rcan"


def test_target_url_explicit_base():
    cfg = ShipperConfig(
        ingest_key="sk_live_x", org_slug="opencastor",
        base_url="https://platatlas.com/opencastor",
        export_file=Path("/tmp/x.ndjson"), offset_file=Path("/tmp/x.offset"),
    )
    assert target_url(cfg) == "https://platatlas.com/opencastor/api/traces?source=rcan"


def test_ship_once_posts_new_lines_and_advances_offset(tmp_path):
    export = tmp_path / "traces.ndjson"
    offset = tmp_path / "traces.offset"
    line = json.dumps({"v": "rcan-action-trace/1", "corr_id": "m1"})
    export.write_text(line + "\n")

    posted: list[tuple[str, dict, bytes]] = []

    def fake_post(url, headers, data):
        posted.append((url, headers, data))
        return 200

    cfg = ShipperConfig(
        ingest_key="sk_live_abc", org_slug="opencastor", base_url=None,
        export_file=export, offset_file=offset,
    )
    shipped = ship_once(cfg, post=fake_post)

    assert shipped == 1
    url, headers, data = posted[0]
    assert url == "https://opencastor.platatlas.com/api/traces?source=rcan"
    assert headers["Authorization"] == "Bearer sk_live_abc"
    assert data == (line + "\n").encode("utf-8")
    assert int(offset.read_text()) == len((line + "\n").encode("utf-8"))


def test_ship_once_does_not_advance_offset_on_failure(tmp_path):
    export = tmp_path / "traces.ndjson"
    offset = tmp_path / "traces.offset"
    export.write_text(json.dumps({"corr_id": "m1"}) + "\n")

    def failing_post(url, headers, data):
        return 503

    cfg = ShipperConfig(
        ingest_key="sk_live_abc", org_slug="opencastor", base_url=None,
        export_file=export, offset_file=offset,
    )
    shipped = ship_once(cfg, post=failing_post)

    assert shipped == 0
    assert not offset.exists()  # offset untouched -> at-least-once re-delivery


def test_ship_once_resumes_from_persisted_offset(tmp_path):
    export = tmp_path / "traces.ndjson"
    offset = tmp_path / "traces.offset"
    first = json.dumps({"corr_id": "m1"}) + "\n"
    second = json.dumps({"corr_id": "m2"}) + "\n"
    export.write_text(first + second)
    offset.write_text(str(len(first.encode("utf-8"))))  # already shipped line 1

    posted = []

    def fake_post(url, headers, data):
        posted.append(data)
        return 200

    cfg = ShipperConfig(
        ingest_key="sk_live_abc", org_slug="opencastor", base_url=None,
        export_file=export, offset_file=offset,
    )
    shipped = ship_once(cfg, post=fake_post)

    assert shipped == 1
    assert posted == [second.encode("utf-8")]
    assert int(offset.read_text()) == len((first + second).encode("utf-8"))


def test_ship_once_no_file_is_noop(tmp_path):
    cfg = ShipperConfig(
        ingest_key="sk_live_abc", org_slug="opencastor", base_url=None,
        export_file=tmp_path / "absent.ndjson", offset_file=tmp_path / "absent.offset",
    )
    assert ship_once(cfg, post=lambda *a, **k: 200) == 0


def test_shipper_reports_tamper_not_replay(tmp_path):
    """A persisted offset past the end of the export means bytes this shipper
    already delivered are no longer in the local file. That is reported by name
    and the shipper stops. It must NOT re-deliver from zero: re-delivery hands
    whoever cut the file the power to decide what the off-box copy holds next,
    and it does it silently."""
    export = tmp_path / "traces.ndjson"
    offset = tmp_path / "traces.offset"
    line = json.dumps({"corr_id": "m1"}) + "\n"
    export.write_text(line)            # the file after somebody cut it short
    offset.write_text("99999")         # what had already been shipped

    posted = []

    def fake_post(url, headers, data):
        posted.append(data)
        return 200

    cfg = ShipperConfig(
        ingest_key="sk_live_abc", org_slug="opencastor", base_url=None,
        export_file=export, offset_file=offset,
    )

    with pytest.raises(ShipperTamperStop) as exc:
        ship_once(cfg, post=fake_post)

    assert "TRUNCATED" in str(exc.value)
    assert posted == []                       # nothing re-delivered
    assert offset.read_text() == "99999"      # and the offset was not rewritten


def test_the_tamper_stop_is_not_swallowed_as_a_transient_error(tmp_path):
    """main()'s loop swallows transient errors and backs off. The tamper stop is
    deliberately NOT one of them: it exits 3, which the generated unit lists in
    RestartPreventExitStatus so the journal keeps the line instead of burying it
    under a restart every two seconds."""
    from robot_md_gateway import shipper as shipper_mod

    assert not issubclass(ShipperTamperStop, SystemExit)
    src = inspect.getsource(shipper_mod.main)
    assert "except ShipperTamperStop" in src
    assert "SystemExit(3)" in src


# ---------------------------------------------------------------------------
# Intent lines. Record-before-dispatch writes one per invoke, and PlatAtlas's
# rcan ingest reads `rec.outcome`, which an intent line does not have.
# ---------------------------------------------------------------------------


def _cfg(export: Path, offset: Path, **kw) -> ShipperConfig:
    return ShipperConfig(
        ingest_key="sk_live_abc", org_slug="opencastor", base_url=None,
        export_file=export, offset_file=offset, **kw,
    )


def _mixed(export: Path) -> None:
    export.write_text("\n".join([
        json.dumps({"v": "rcan-action-trace/1", "record_kind": "intent", "corr_id": "m1"}),
        json.dumps({"v": "rcan-action-trace/1", "record_kind": "outcome", "corr_id": "m1"}),
        json.dumps({"v": "rcan-action-trace/1", "record_kind": "intent", "corr_id": "m2"}),
        json.dumps({"v": "rcan-action-trace/1", "record_kind": "outcome", "corr_id": "m2"}),
    ]) + "\n")


def test_intent_lines_are_not_shipped_by_default(tmp_path, caplog):
    """The remote copy is outcomes only. Shipping an intent would store it as
    exec_verdict=verify_failed when no signature failed, and any recompute over
    the pack would then report a growing pile of failed signatures that are not
    failures. The LOCAL export keeps both halves; that is the copy a third party
    walks."""
    export, offset = tmp_path / "t.ndjson", tmp_path / "t.offset"
    _mixed(export)
    posted: list[bytes] = []
    with caplog.at_level("INFO"):
        n = ship_once(_cfg(export, offset),
                      post=lambda u, h, d: (posted.append(d), 200)[1])
    assert n == 2
    assert [json.loads(d)["record_kind"] for d in posted] == ["outcome", "outcome"]
    # Counted and logged, never silently dropped: "the remote has fewer rows
    # than the box" must never be a mystery.
    assert "2 intent line(s) kept local, not sent" in caplog.text
    assert "record_kind" in caplog.text
    # The offset still moved past every byte, so nothing is re-read next poll.
    assert int(offset.read_text()) == export.stat().st_size
    # And the local file is untouched and still complete.
    assert len(export.read_text().splitlines()) == 4


def test_ship_intents_opt_in_sends_them(tmp_path):
    """The switch the rail follow-up flips once its ingest reads record_kind."""
    export, offset = tmp_path / "t.ndjson", tmp_path / "t.offset"
    _mixed(export)
    posted: list[bytes] = []
    n = ship_once(_cfg(export, offset, ship_intents=True),
                  post=lambda u, h, d: (posted.append(d), 200)[1])
    assert n == 4
    assert [json.loads(d)["record_kind"] for d in posted] == [
        "intent", "outcome", "intent", "outcome"]


def test_a_line_that_does_not_parse_is_still_shipped(tmp_path):
    """Deciding that a malformed line is not evidence is not the shipper's call.
    Only a line that SAYS record_kind=intent is held back."""
    export, offset = tmp_path / "t.ndjson", tmp_path / "t.offset"
    export.write_text("not json at all\n" + json.dumps(
        {"v": "rcan-action-trace/1", "record_kind": "outcome"}) + "\n")
    posted: list[bytes] = []
    n = ship_once(_cfg(export, offset), post=lambda u, h, d: (posted.append(d), 200)[1])
    assert n == 2
    assert posted[0].strip() == b"not json at all"


def test_a_pre_0_5_0a8_line_with_no_record_kind_is_shipped(tmp_path):
    """Bob's 4437 existing lines carry no record_kind and mean outcome. None of
    them may be held back by this filter."""
    export, offset = tmp_path / "t.ndjson", tmp_path / "t.offset"
    export.write_text(json.dumps({"v": "rcan-action-trace/1", "corr_id": "old"}) + "\n")
    n = ship_once(_cfg(export, offset), post=lambda u, h, d: 200)
    assert n == 1
