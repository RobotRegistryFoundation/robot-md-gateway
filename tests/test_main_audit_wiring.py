"""The __main__ `serve` path must wire an AuditChain so invokes are recorded.

Regression: the serve path built the app without `audit_chain` (default None), so
`_record_with_outcome` short-circuited (`if audit_chain is None: return`) and
`GET /v1/audit/last` always 404'd 'audit chain empty' — even after executed invokes
(observed live on Bob, 2026-06-05).
"""

from __future__ import annotations

import sys

from robot_md_gateway import __main__ as gw_main


def test_serve_path_wires_audit_chain(monkeypatch):
    # Capture the app uvicorn would serve, without actually serving.
    import uvicorn

    captured: dict = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: captured.__setitem__("app", app))
    monkeypatch.setattr(
        sys, "argv", ["robot-md-gateway", "serve"]
    )  # no --bearers → noop actuator branch
    for v in ("ROBOT_MD_TOOL_ALLOWLIST", "ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE"):
        monkeypatch.delenv(v, raising=False)

    gw_main.main()

    app = captured.get("app")
    assert app is not None, "uvicorn.run was not called with an app"
    assert app.state.audit_chain is not None, (
        "serve path must construct + pass an AuditChain so executed invokes are "
        "recorded and /v1/audit/last works"
    )
