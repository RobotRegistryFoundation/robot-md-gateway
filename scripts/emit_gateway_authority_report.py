#!/usr/bin/env python3
"""Emit gateway-authority-<repo>-<sha>.json with the 3 Phase 3 cert properties.

Runs the canonical evidence-generating actions for MF-001, MF-002, and GW-001
deterministically (independent of the pytest run, which has its own per-test
isolation), and serializes the resulting cert report.

Plan 6 adds release-key signing of the resulting JSON + expands to the full
12 cert properties. Phase 3 leaves the report unsigned but well-formed.
"""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

from fastapi.testclient import TestClient

from robot_md_gateway.cert import report as cert_report
from robot_md_gateway.receiver import make_app
from robot_md_gateway.udev_policy import generate_rules


class _FakeResolver:
    def __init__(self, mapping: dict[str, bytes]) -> None:
        self._mapping = mapping

    def resolve_public_key_pem(self, kid: str) -> bytes | None:
        return self._mapping.get(kid)


def _run_evidence_collection(fixtures: Path) -> None:
    """Trigger the cert reporter via real code paths, in a single process."""
    cert_report.reset()

    generate_rules(
        service_account="robot-md-gateway",
        tty_vendor_hex="2341",
        emit_evidence=True,
    )

    kid = (fixtures / "signing-key.kid").read_text().strip()
    pub = (fixtures / "signing-key.pub").read_bytes()
    app = make_app(resolver=_FakeResolver({kid: pub}))
    client = TestClient(app)

    base_envelope = {
        "msg_id": "ci-cert-emit",
        "type": "INVOKE",
        "ruri": "rcan://lab.local/test/bot/00000999",
        "scope": "READ",
        "tool_name": "mcp__robot__render",
        "tool_args": {},
    }

    client.post("/v1/invoke", json={
        **base_envelope,
        "msg_id": "ci-mf-001",
        "manifest_path": str(fixtures / "signed-good.md"),
    })

    client.post("/v1/invoke", json={
        **base_envelope,
        "msg_id": "ci-mf-002",
        "manifest_path": str(fixtures / "signed-tampered.md"),
    })


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="robot-md-gateway")
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument("--out-dir", type=Path, default=Path("dist/cert-reports"))
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=Path(__file__).parent.parent / "tests" / "fixtures" / "manifests",
    )
    args = parser.parse_args()

    sha = args.sha or _git_sha()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    _run_evidence_collection(args.fixtures)
    out = args.out_dir / f"gateway-authority-{args.repo}-{sha}.json"
    cert_report.write(out, repo=args.repo, sha=sha)
    print(f"Wrote {out}")


def _git_sha() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()


if __name__ == "__main__":
    main()
