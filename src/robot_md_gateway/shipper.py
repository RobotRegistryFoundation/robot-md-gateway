"""platatlas-shipper — tail the gateway's rcan-action-trace NDJSON and POST it
to PlatAtlas ingest. Separate console-script; NOT on the actuation hot path.

At-least-once delivery via a persisted byte offset: the offset advances ONLY
after a 2xx, so a crash/network outage re-delivers (S3 ingest is idempotent at
the trace-row grain). Source-agnostic except for ?source=rcan.

One thing is NOT retried: an offset past the end of the export file. That means
bytes already delivered are gone from the local copy, and the shipper reports it
by name and stops. See ShipperTamperStop for why stopping beats re-delivering.
"""

from __future__ import annotations

import logging
import os
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# post(url, headers, data) -> http status int. Injectable for tests.
PostFn = Callable[[str, dict, bytes], int]


class ShipperTamperStop(Exception):
    """The export file no longer contains what was already shipped, so the
    shipper stops rather than guessing.

    Raised when the persisted byte offset is past the end of the export file.
    That means bytes this shipper had already read and delivered are gone:
    truncation, a rotation nothing told the shipper about, or somebody editing
    the file. The shipper cannot tell those three apart from the outside, and
    the honest name for all of them from here is that the local copy no longer
    agrees with what was sent.

    WHY IT STOPS INSTEAD OF RE-DELIVERING FROM ZERO. Re-delivering was the old
    behaviour and it had the failure exactly backwards: truncation is the one
    event the off-box copy exists to survive, and quietly starting over turned
    it into a silent re-upload with no record that anything had been removed.
    Worse, it made the local file authoritative again: whoever cut the file
    decided what the remote end would hold next. Stopping leaves the off-box
    copy intact, leaves the offset untouched, and puts a named line in the
    journal for a person to read.

    This is a report, not a defence. Nothing here prevents tampering and
    nothing here can. It makes it visible.
    """


@dataclass(frozen=True)
class ShipperConfig:
    ingest_key: str
    org_slug: str
    base_url: str | None
    export_file: Path
    offset_file: Path

    @classmethod
    def from_env(cls) -> ShipperConfig:
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

    Tails the append-only NDJSON: seeks to the persisted byte offset and reads
    only the new bytes (so each poll is O(new) not O(total) — a long-running Pi
    sidecar never re-reads the whole ever-growing file). POSTs each complete
    (newline-terminated) line and advances the offset only after a 2xx. A partial
    trailing line (no newline yet — the gateway may be mid-write) is left for the
    next pass.
    """
    if not cfg.export_file.exists():
        return 0
    offset = _read_offset(cfg)
    # TAMPER/TRUNCATION GUARD. A persisted offset past the current EOF means the
    # bytes this shipper already delivered are no longer in the file. Report it
    # by name and stop; never re-deliver from zero. See ShipperTamperStop.
    try:
        size = cfg.export_file.stat().st_size
    except OSError:
        size = 0
    if offset > size:
        logger.error(
            "platatlas-shipper: TAMPER/TRUNCATED: persisted offset %d is past the end "
            "of %s (size %d). Bytes already shipped are no longer in the local file. "
            "Stopping; the offset is left untouched and nothing is re-delivered. "
            "Compare the off-box copy with this file, then delete %s to resume "
            "deliberately.",
            offset,
            cfg.export_file,
            size,
            cfg.offset_file,
        )
        raise ShipperTamperStop(
            f"TRUNCATED: offset {offset} past end of {cfg.export_file} (size {size})"
        )
    headers = {
        "Authorization": f"Bearer {cfg.ingest_key}",
        "Content-Type": "application/x-ndjson",
    }
    url = target_url(cfg)
    shipped = 0
    pos = offset
    # "rb": the offset is a byte count and the writer emits UTF-8 bytes, so
    # binary seek/readline keeps the offset byte-accurate.
    with cfg.export_file.open("rb") as fh:
        fh.seek(offset)
        while True:
            line = fh.readline()
            if not line.endswith(b"\n"):
                break  # EOF or partial trailing line -> leave it for next pass
            status = post(url, headers, line)
            if not (200 <= status < 300):
                logger.warning("platatlas-shipper: POST returned %s; will retry", status)
                break  # do NOT advance offset -> at-least-once redelivery
            pos += len(line)
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
            ship_once(cfg)
            backoff = poll_s  # reset backoff after a clean poll
        except ShipperTamperStop:
            # Deliberately NOT a transient error and deliberately not retried.
            # ship_once has already logged the named reason. Exit 3, which the
            # generated unit lists in RestartPreventExitStatus, so the journal
            # keeps one readable line instead of burying it under a restart
            # loop every two seconds.
            logger.error("platatlas-shipper: stopping on the tamper report above (exit 3)")
            raise SystemExit(3) from None
        except Exception as exc:  # sidecar must not die on a transient error
            logger.warning("platatlas-shipper: ship_once error: %s", exc)
            backoff = min(backoff * 2, 60.0)
        time.sleep(backoff)


if __name__ == "__main__":
    main()
