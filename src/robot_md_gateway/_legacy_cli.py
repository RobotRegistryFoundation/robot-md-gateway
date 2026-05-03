"""Backward-compat CLI entry-point for `robot-md-dispatcher`.

Forwarded from pyproject's [project.scripts] entry. Prints a one-line
deprecation banner to stderr, then delegates to the gateway's main().
Removed in v0.5.0.
"""

from __future__ import annotations

import sys

from .__main__ import main as _gateway_main


def legacy_main() -> None:
    print(
        "warning: `robot-md-dispatcher` is deprecated; use `robot-md-gateway` instead. "
        "Both commands work through v0.4.x; the legacy alias is removed in v0.5.0.",
        file=sys.stderr,
    )
    _gateway_main()


if __name__ == "__main__":
    legacy_main()
