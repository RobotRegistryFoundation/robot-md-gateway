"""robot_md_dispatcher — legacy import shim.

This package preserves the `robot_md_dispatcher` import path during the
transition to `robot_md_gateway`. On first import it emits a
DeprecationWarning. Every submodule (auth, gating, app, init_wizard,
__main__) is forwarded to its `robot_md_gateway` counterpart. The shim
is removed in v0.5.0.

Migration: `from robot_md_dispatcher.X import Y` → `from robot_md_gateway.X import Y`.
"""

from __future__ import annotations

import importlib
import sys
import warnings

warnings.warn(
    "`robot_md_dispatcher` is deprecated; import from `robot_md_gateway` instead. "
    "The shim ships through v0.4.x and is removed in v0.5.0. "
    "See https://github.com/RobotRegistryFoundation/robot-md-gateway "
    "for migration notes.",
    DeprecationWarning,
    stacklevel=2,
)

from robot_md_gateway import __version__ as __version__  # noqa: E402

_FORWARDED_SUBMODULES = ("auth", "gating", "app", "init_wizard", "__main__")
for _name in _FORWARDED_SUBMODULES:
    _real = importlib.import_module(f"robot_md_gateway.{_name}")
    sys.modules[f"robot_md_dispatcher.{_name}"] = _real
del _name, _real
