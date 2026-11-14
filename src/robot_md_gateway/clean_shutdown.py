"""Whether the previous gateway process shut down cleanly: a marker file in
systemd's StateDirectory=.

A process that ends any other way can leave hardware moving: systemd's
watchdog kill (`WatchdogSec=`), an out-of-memory kill, a crash. The process
ends, but an actuator that keeps its last goal when its host process ends
keeps it (the fifth review's blocking item on #37, R5-37-01). So `serve`
sends every declared stop at start (`make_app(stops_at_start=...)`) unless the
previous process left this marker.

- `consume()` runs first in `serve`, before anything else. It reads the
  marker and removes it, so a process that then ends any way but the normal
  exit path leaves none behind.
- `write()` runs on the normal exit path only, after uvicorn has returned
  from a SIGTERM or a Ctrl-C, and only when the gateway says it may (the
  app's `clean_shutdown` state is None; see `make_app`).

Everything fails toward stops. No STATE_DIRECTORY, no marker, a marker that
cannot be read, parsed or removed, or any other error means the stops go out.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger(__name__)

MARKER = "clean-shutdown"


def state_directory(env: Mapping[str, str] = os.environ) -> Path | None:
    """The directory systemd made for this unit (`StateDirectory=`), or None.
    systemd joins several with ":" when the unit names several; the first is
    the one this unit names first."""
    value = env.get("STATE_DIRECTORY", "").split(":")[0].strip()
    return Path(value) if value else None


def _remove(path: Path) -> str | None:
    """Remove the marker; None once it is gone. When it cannot be removed, try
    to empty it, so that a later start which can remove it does not take it
    for this process's own."""
    try:
        path.unlink()
        return None
    except FileNotFoundError:
        return None
    except OSError as exc:
        with contextlib.suppress(OSError):
            path.write_bytes(b"")
        return f"the clean-shutdown marker {path} could not be removed ({type(exc).__name__})"


def consume(env: Mapping[str, str] = os.environ) -> str | None:
    """Read the marker the previous process left, and remove it.

    None when that process shut down cleanly: a valid marker was there, and
    it is gone now. Otherwise, why every declared stop must be sent at start.
    Never raises."""
    try:
        directory = state_directory(env)
        if directory is None:
            return ("no clean-shutdown marker can be kept: STATE_DIRECTORY is not set "
                    "(the unit has no StateDirectory=)")
        path = directory / MARKER
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return f"the previous process left no clean-shutdown marker in {directory}"
        except OSError as exc:
            _remove(path)
            return f"the clean-shutdown marker {path} could not be read ({type(exc).__name__})"
        not_removed = _remove(path)
        if not_removed is not None:
            return not_removed
        try:
            data = json.loads(raw)
        except ValueError:
            data = None
        if not (isinstance(data, dict) and data.get("clean_shutdown") is True):
            return f"the clean-shutdown marker {path} was not one this gateway writes"
        return None
    except Exception as exc:    # deciding must never stop the start
        return f"whether the previous process shut down cleanly could not be decided ({exc!r})"


def write(env: Mapping[str, str] = os.environ) -> bool:
    """Leave the marker for the next start. True once it is on disk. Written
    to a temporary file, flushed, then renamed, so a start never reads half
    of one. Never raises: no marker only means the next start sends the
    stops."""
    try:
        directory = state_directory(env)
        if directory is None:
            return False
        body = json.dumps({
            "clean_shutdown": True,
            "pid": os.getpid(),
            "at": datetime.now(tz=timezone.utc).isoformat(),
        }).encode("utf-8")
        tmp = directory / f".{MARKER}.{os.getpid()}"
        with open(tmp, "wb") as f:
            f.write(body)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, directory / MARKER)
        with contextlib.suppress(OSError):    # the rename is done; this is best effort
            fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        return True
    except Exception as exc:
        _log.warning("clean_shutdown: could not leave the marker (%r); the next start "
                     "sends every declared stop", exc)
        return False
