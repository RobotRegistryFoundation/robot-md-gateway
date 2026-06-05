"""MF-003 — RRN binding (envelope identity must match the manifest's metadata.rrn)."""
from robot_md_gateway.cert.rrn_binding import (
    rrn_from_manifest,
    rrn_from_ruri,
    verify_rrn_binding,
)

MANIFEST = """---
rcan_version: '3.0'
metadata:
  robot_name: bob
  rrn: RRN-000000000011
  ruri: rcan://robotregistryfoundation.org/bob-spec-b-pick-place/so-arm101/bob
---

# Bob
"""


def test_rrn_from_ruri():
    assert rrn_from_ruri("rcan://RRN-000000000011/skill") == "RRN-000000000011"
    assert rrn_from_ruri("rcan://RRN-000000000011") == "RRN-000000000011"
    assert rrn_from_ruri("https://example.com/x") is None
    assert rrn_from_ruri("rcan://robotregistryfoundation.org/bob") is None
    assert rrn_from_ruri(None) is None


def test_rrn_from_manifest_reads_metadata_rrn_not_ruri(tmp_path):
    p = tmp_path / "ROBOT.md"
    p.write_text(MANIFEST)
    # must pull metadata.rrn (RRN-...), NOT metadata.ruri (rrf.org host)
    assert rrn_from_manifest(p) == "RRN-000000000011"


def test_binding_accepts_match():
    res = verify_rrn_binding("rcan://RRN-000000000011/skill", "RRN-000000000011")
    assert res.accepted and res.reason == "ok"


def test_binding_denies_mismatch():
    res = verify_rrn_binding("rcan://RRN-000000000099/skill", "RRN-000000000011")
    assert not res.accepted and "!=" in res.reason


def test_binding_denies_non_rrn_envelope():
    res = verify_rrn_binding("rcan://robotregistryfoundation.org/bob", "RRN-000000000011")
    assert not res.accepted and "no RRN host" in res.reason


def test_binding_denies_missing_manifest_rrn():
    res = verify_rrn_binding("rcan://RRN-000000000011/skill", None)
    assert not res.accepted and "metadata.rrn" in res.reason


def test_end_to_end_with_manifest_file(tmp_path):
    p = tmp_path / "ROBOT.md"
    p.write_text(MANIFEST)
    rrn = rrn_from_manifest(p)
    assert verify_rrn_binding("rcan://RRN-000000000011/x", rrn).accepted
    assert not verify_rrn_binding("rcan://RRN-000000000012/x", rrn).accepted
