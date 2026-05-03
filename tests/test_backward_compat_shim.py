"""Test that `robot_md_dispatcher` (legacy) shim re-exports `robot_md_gateway`."""

from __future__ import annotations

import importlib
import sys
import warnings


def _force_clean_imports():
    """Drop any cached imports so each test sees first-import semantics."""
    for key in list(sys.modules):
        if key == "robot_md_dispatcher" or key.startswith("robot_md_dispatcher."):
            del sys.modules[key]
        if key == "robot_md_gateway" or key.startswith("robot_md_gateway."):
            del sys.modules[key]


def test_dispatcher_alias_re_exports_gateway_modules():
    _force_clean_imports()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        from robot_md_dispatcher import auth as legacy_auth
        from robot_md_gateway import auth as new_auth
    assert legacy_auth is new_auth, "legacy import must be the same module object"
    assert any(issubclass(w.category, DeprecationWarning) for w in caught), \
        "first import of robot_md_dispatcher must emit DeprecationWarning"


def test_dispatcher_alias_specific_classes_resolve():
    _force_clean_imports()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        from robot_md_dispatcher.auth import AuthContext as LegacyAuthContext  # noqa: I001
        from robot_md_gateway.auth import AuthContext as NewAuthContext
    assert LegacyAuthContext is NewAuthContext


def test_dispatcher_app_module_resolves():
    _force_clean_imports()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        legacy_app = importlib.import_module("robot_md_dispatcher.app")
        new_app = importlib.import_module("robot_md_gateway.app")
    assert legacy_app is new_app


def test_dispatcher_version_matches_gateway():
    _force_clean_imports()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        from robot_md_dispatcher import __version__ as legacy_version
        from robot_md_gateway import __version__ as new_version
    assert legacy_version == new_version
