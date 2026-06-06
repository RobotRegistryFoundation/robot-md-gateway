"""platatlas-shipper — tail the gateway's rcan-action-trace NDJSON and POST it
to PlatAtlas ingest. Separate console-script; NOT on the actuation hot path.

At-least-once delivery via a persisted byte offset: the offset advances ONLY
after a 2xx, so a crash/network outage re-delivers (S3 ingest is idempotent at
the trace-row grain). Source-agnostic except for ?source=rcan.
"""

from __future__ import annotations

import logging
import os
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)

# post(url, headers, data) -> http status int. Injectable for tests.
PostFn = Callable[[str, dict, bytes], int]


@dataclass(frozen=True)
class ShipperConfig:
    ingest_key: str
    org_slug: str
    base_url: str | None
    export_file: Path
    offset_file: Path

    @classmethod
    def from_env(cls) -> "ShipperConfig":
        ingest_key = os.environ.get("PLATATLAS_INGEST_KEY")
        org_slug = os.environ.get("PLATATLAS_ORG_SLUG")
        export = os.environ.get("ROBOT_MD_ATTESTATION_EXPORT_FILE")
        if not ingest_key or not org_slug or not export:
            raise SystemExit(
                "platatlas-shipper requires PLATATLAS_INGEST_KEY, PLATATLAS_ORG_SLUG, "
                "and ROBOT_MD_ATTESTATION_EXPORT_FILE"
            )
        export_file = Path(export)
        offset = os.environ.get("PLATATLAS_OFFSET_FILE")
        offset_file = Path(offset) if offset else export_file.with_suffix(
            export_file.suffix + ".offset"
        )
        return cls(
            ingest_key=ingest_key,
            org_slug=org_slug,
            base_url=os.environ.get("PLATATLAS_BASE_URL"),
            export_file=export_file,
            offset_file=offset_file,
        )


def target_url(cfg: ShipperConfig) -> str:
    base = cfg.base_url or f"https://{cfg.org_slug}.platatlas.com"
    return f"{base.rstrip('/')}/api/traces?source=rcan"


def _read_offset(cfg: ShipperConfig) -> int:
    try:
        return int(cfg.offset_file.read_text().strip())
    except (OSError, ValueError):
        return 0


def _write_offset(cfg: ShipperConfig, offset: int) -> None:
    cfg.offset_file.parent.mkdir(parents=True, exist_ok=True)
    cfg.offset_file.write_text(str(offset))


def _http_post(url: str, headers: dict, data: bytes) -> int:
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return 0


def ship_once(cfg: ShipperConfig, *, post: PostFn = _http_post) -> int:
    """Ship all unsent complete lines once. Returns the number of lines shipped.

    Reads from the persisted offset; POSTs each complete (newline-terminated)
    line; advances the offset only after a 2xx. A partial trailing line (no
    newline yet — the gateway may be mid-write) is left for the next pass.
    """
    if not cfg.export_file.exists():
        return 0
    offset = _read_offset(cfg)
    data = cfg.export_file.read_bytes()
    if offset >= len(data):
        return 0
    headers = {
        "Authorization": f"Bearer {cfg.ingest_key}",
        "Content-Type": "application/x-ndjson",
    }
    url = target_url(cfg)
    shipped = 0
    pos = offset
    while True:
        nl = data.find(b"\n", pos)
        if nl == -1:
            break  # no complete line remaining
        line = data[pos:nl + 1]
        status = post(url, headers, line)
        if not (200 <= status < 300):
            logger.warning("platatlas-shipper: POST returned %s; will retry", status)
            break  # do NOT advance offset -> at-least-once redelivery
        pos = nl + 1
        shipped += 1
        _write_offset(cfg, pos)
    return shipped


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("ROBOT_MD_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    cfg = ShipperConfig.from_env()
    poll_s = float(os.environ.get("PLATATLAS_POLL_SECONDS", "5"))
    logger.info("platatlas-shipper started: %s -> %s", cfg.export_file, target_url(cfg))
    backoff = poll_s
    while True:
        try:
            n = ship_once(cfg)
            backoff = poll_s if n >= 0 else backoff
        except Exception as exc:  # noqa: BLE001 — sidecar must not die on a transient error
            logger.warning("platatlas-shipper: ship_once error: %s", exc)
            backoff = min(backoff * 2, 60.0)
        time.sleep(backoff)


if __name__ == "__main__":
    main()
