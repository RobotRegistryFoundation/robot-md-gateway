"""platatlas-shipper sidecar: offset persistence, POST shape, at-least-once."""

from __future__ import annotations

import json
from pathlib import Path

from robot_md_gateway.shipper import ShipperConfig, ship_once, target_url


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
