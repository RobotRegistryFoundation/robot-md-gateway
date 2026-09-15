"""platatlas-shipper — tail the gateway's rcan-action-trace NDJSON and POST it
to PlatAtlas ingest. Separate console-script; NOT on the actuation hot path.

At-least-once delivery via a persisted byte offset: the offset advances ONLY
after a 2xx, so a crash/network outage re-delivers (S3 ingest is idempotent at
the trace-row grain). Source-agnostic except for ?source=rcan.

One thing is NOT retried: an offset past the end of the export file. That means
bytes already delivered are gone from the local copy, and the shipper reports it
by name and stops. See ShipperTamperStop for why stopping beats re-delivering.

One thing is NOT SENT: an ``intent`` line. See SKIP_INTENT_REASON.
"""

from __future__ import annotations

import json
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


#: Why an ``intent`` line stays on the box for now, spelled out where the code
#: that does it can be read beside it.
#:
#: PlatAtlas's rcan ingest reads ``rec.outcome ?? {}`` and verifies it. An intent
#: line has no ``outcome`` key at all, on purpose: at the moment it is written
#: the actuator has not been called. So an intent lands over there with
#: ``exec_verdict: "verify_failed"`` and ``binding_ok: false``. The ingest never
#: rejects a record and never 4xxs the batch, and every consumer already gates
#: attribution on ``exec_verdict === "verified"``, so nothing downstream would
#: ever count an intent as an execution. Shipping them is SAFE.
#:
#: It is just not HONEST YET, and that is the reason. Record-before-dispatch
#: writes one intent per invoke, so shipping them would fill the remote store
#: with records marked as failed signature verification when not one signature
#: failed: the intent is signed, correctly, and the field says "verify_failed"
#: only because the thing it verifies is not in the record. Any recompute over
#: the pack would report a large and growing population of failed signatures
#: that are not failures, which ruins the one number an outside party would
#: look at first.
#:
#: So: the local export stays COMPLETE, both halves of every pair, and it is the
#: local file a third party walks. The remote copy is OUTCOMES ONLY and this is
#: the sentence that says so. When the rail teaches its ingest to read
#: ``record_kind`` and score an intent as an intent, set
#: ``PLATATLAS_SHIP_INTENTS=1`` and the remote copy becomes complete too. That
#: is a rail follow-up, not a blocker for this release.
#:
#: THE HONEST COST, stated rather than buried: until then, the off-box copy does
#: not hold the record that a dispatch was attempted. A dispatch that never
#: reported is visible only in the local file, which is the copy the operator
#: controls. That is a real gap in what the off-box copy proves.
SKIP_INTENT_REASON = (
    "PlatAtlas ingest reads rec.outcome and an intent line has none, so an "
    "intent would be stored as exec_verdict=verify_failed when no signature "
    "failed. Kept local until the ingest reads record_kind; set "
    "PLATATLAS_SHIP_INTENTS=1 once it does."
)


@dataclass(frozen=True)
class ShipperConfig:
    ingest_key: str
    org_slug: str
    base_url: str | None
    export_file: Path
    offset_file: Path
    #: Send ``record_kind: "intent"`` lines too. Default False. See
    #: SKIP_INTENT_REASON for what turning it on is waiting for.
    ship_intents: bool = False

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
            ship_intents=os.environ.get("PLATATLAS_SHIP_INTENTS", "").strip()
            in ("1", "true", "yes"),
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


def _is_intent_line(line: bytes) -> bool:
    """Whether this NDJSON line is an intent record.

    Only a line that SAYS it is an intent counts. A line that does not parse is
    not one, and is shipped: deciding that a malformed line is not evidence is
    not the shipper's call to make, and the remote copy should hold whatever the
    local file holds.
    """
    try:
        rec = json.loads(line)
    except ValueError:
        return False
    return isinstance(rec, dict) and rec.get("record_kind") == "intent"


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
    skipped_intents = 0
    pos = offset
    # "rb": the offset is a byte count and the writer emits UTF-8 bytes, so
    # binary seek/readline keeps the offset byte-accurate.
    with cfg.export_file.open("rb") as fh:
        fh.seek(offset)
        while True:
            line = fh.readline()
            if not line.endswith(b"\n"):
                break  # EOF or partial trailing line -> leave it for next pass
            if not cfg.ship_intents and _is_intent_line(line):
                # Counted, not dropped: the line stays in the local export, the
                # offset moves past it, and the count goes in the journal so
                # "the remote has fewer rows than the box" is never a mystery.
                skipped_intents += 1
                pos += len(line)
                _write_offset(cfg, pos)
                continue
            status = post(url, headers, line)
            if not (200 <= status < 300):
                logger.warning("platatlas-shipper: POST returned %s; will retry", status)
                break  # do NOT advance offset -> at-least-once redelivery
            pos += len(line)
            shipped += 1
            _write_offset(cfg, pos)
    if skipped_intents:
        logger.info(
            "platatlas-shipper: %d intent line(s) kept local, not sent. %s",
            skipped_intents, SKIP_INTENT_REASON,
        )
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
