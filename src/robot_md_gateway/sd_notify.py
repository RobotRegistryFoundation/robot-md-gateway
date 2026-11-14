"""systemd's notification protocol, with no dependency: READY=1 and WATCHDOG=1.

Under a unit with `Type=notify`, systemd sets NOTIFY_SOCKET, a datagram socket
it reads, and with `WatchdogSec=` it sets WATCHDOG_USEC as well. The gateway's
safety watchdog sends READY=1 once it has ticked, and WATCHDOG=1 while it keeps
ticking. If the watchdog thread dies or stops ticking, the pings stop, and
systemd stops and restarts the gateway, which starts held. That covers the
double fault where the watchdog has died and no request or heartbeat arrives to
notice it (the second review of robot-md-gateway#35, R2-18).

Outside systemd neither variable is set, and every call here does nothing.
"""

from __future__ import annotations

import logging
import os
import socket
from collections.abc import Mapping

_log = logging.getLogger(__name__)
_warned: list[bool] = [False]      # a socket that refuses is logged once, not on every ping


def watchdog_interval_s(env: Mapping[str, str] = os.environ) -> float | None:
    """How often systemd expects a WATCHDOG=1 from this process, in seconds,
    or None when it expects none. WATCHDOG_PID, when set, must name this
    process: the variables can be inherited by a child that is not watched."""
    usec = env.get("WATCHDOG_USEC")
    pid = env.get("WATCHDOG_PID")
    if not usec or not env.get("NOTIFY_SOCKET"):
        return None
    if pid and pid != str(os.getpid()):
        return None
    try:
        interval = int(usec) / 1_000_000
    except ValueError:
        return None
    return interval if interval > 0 else None


def notify(message: str, env: Mapping[str, str] = os.environ) -> bool:
    """Send one notification (`READY=1`, `WATCHDOG=1`). True if it was sent.
    Never raises: a gateway that cannot reach systemd keeps running, and a
    unit that waits for these messages then stops or restarts it."""
    address = env.get("NOTIFY_SOCKET")
    if not address:
        return False
    if address.startswith("@"):
        address = "\0" + address[1:]           # an abstract socket
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.sendall(message.encode("utf-8"))
    except OSError as exc:
        (_log.debug if _warned[0] else _log.warning)(
            "sd_notify: could not send %r to systemd: %s", message, exc)
        _warned[0] = True
        return False
    return True
