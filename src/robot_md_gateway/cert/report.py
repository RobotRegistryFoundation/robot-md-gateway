"""Gateway Authority cert-property report assembler.

Phase 3 exercises only MF-001 / MF-002 / GW-001. The report assembler
accumulates property pass/fail records in process memory and serializes
them on demand to the JSON shape asserted by spec §5 —
`gateway-authority-<repo>-<sha>.json`.

Plan 6 expands the property set to all 12 and adds release-CI signing
of the report. Phase 3 leaves the report unsigned but well-formed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class PropertyRecord:
    property_id: str
    outcome: str
    evidence: dict
    recorded_at: str


@dataclass
class CertReport:
    repo: str
    sha: str
    schema_version: str = "0.1"
    properties: list[PropertyRecord] = field(default_factory=list)


_GLOBAL_REPORT: CertReport = CertReport(repo="robot-md-gateway", sha="HEAD")


def record_property_pass(*, property_id: str, evidence: dict) -> None:
    _record(property_id=property_id, outcome="pass", evidence=evidence)


def record_property_fail(*, property_id: str, evidence: dict) -> None:
    _record(property_id=property_id, outcome="fail", evidence=evidence)


def _record(*, property_id: str, outcome: str, evidence: dict) -> None:
    _GLOBAL_REPORT.properties.append(PropertyRecord(
        property_id=property_id,
        outcome=outcome,
        evidence=evidence,
        recorded_at=datetime.now(tz=timezone.utc).isoformat(),
    ))


def serialize(*, repo: str, sha: str) -> dict:
    return {
        "schema_version": _GLOBAL_REPORT.schema_version,
        "repo": repo,
        "sha": sha,
        "track": "gateway-authority",
        "properties": [
            {
                "property_id": r.property_id,
                "outcome": r.outcome,
                "evidence": r.evidence,
                "recorded_at": r.recorded_at,
            }
            for r in _GLOBAL_REPORT.properties
        ],
    }


def write(path: Path, *, repo: str, sha: str) -> None:
    path.write_text(json.dumps(serialize(repo=repo, sha=sha), indent=2))


def reset() -> None:
    """Test helper — clears the in-memory report."""
    _GLOBAL_REPORT.properties.clear()
