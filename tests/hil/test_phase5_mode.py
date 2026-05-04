"""Unit tests for run.py --property PHASE-5 mode (Plan 6 Phase 5 Task 3).

Tests against httpx.MockTransport — gateway is not actually called.
"""
from __future__ import annotations

import base64
import json

import httpx
import run as hil_run
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from rcan.audit_bundle import canonical_json


def _build_signed_envelope(priv, msg_id, kid="bob-operator-2026"):
    body = {
        "msg_id": msg_id,
        "type": "INVOKE",
        "ruri": "rcan://lab.local/bob/so-arm101/0",
        "scope": "MANIPULATE",
        "tool_name": "mcp__robot__execute_capability",
        "tool_args": {"capability": "wave_wrist"},
        "manifest_path": "/home/bob/bob.rcan.yaml",
    }
    canon = canonical_json(body)
    sig = priv.sign(canon)
    body["envelope_signature"] = {
        "kid": kid, "alg": "Ed25519",
        "sig": base64.b64encode(sig).decode(),
    }
    return body


def _bundle(count: int) -> dict:
    priv = Ed25519PrivateKey.generate()
    return {
        "run_id": "test-run",
        "count": count,
        "envelopes": [_build_signed_envelope(priv, f"phase5-test-{i:03d}") for i in range(count)],
    }


def test_compute_replay_indices_100_10():
    assert hil_run.compute_replay_indices(100, 10) == [5, 15, 25, 35, 45, 55, 65, 75, 85, 95]


def test_compute_replay_indices_smoke_5_1():
    assert hil_run.compute_replay_indices(5, 1) == [3]


def test_compute_replay_indices_zero_replays():
    assert hil_run.compute_replay_indices(100, 0) == []


def test_percentile_basic():
    assert hil_run._percentile([10, 20, 30, 40, 50], 50) == 30
    assert hil_run._percentile([10, 20, 30, 40, 50], 95) == 50
    assert hil_run._percentile([], 50) == 0


def test_phase5_iterates_correct_count_and_replays_subset(tmp_path):
    bundle_path = tmp_path / "b.json"
    bundle_path.write_text(json.dumps(_bundle(10)))

    invoke_calls = []
    seen = set()
    def handler2(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        invoke_calls.append(body["msg_id"])
        if body["msg_id"] in seen:
            return httpx.Response(403, json={"detail": {"deny": "replay"}})
        seen.add(body["msg_id"])
        return httpx.Response(200, json={"status": "ok"})
    transport = httpx.MockTransport(handler2)

    gm_body, rp_body = hil_run.run_phase_5(
        envelope_file=bundle_path,
        gated_motion_count=10,
        replay_count=2,
        gateway_url="http://test",
        latency_budget_ms=5000,
        http_client_factory=lambda: httpx.Client(transport=transport),
    )

    # 10 gated + 2 replays = 12 total POSTs
    assert len(invoke_calls) == 12
    # All 10 gated motions passed
    assert gm_body["summary"]["all_pass"] is True
    assert gm_body["summary"]["pass_count"] == 10
    # Replay subset is computed indices for (10, 2): spacing=5, start=3 → [3, 8]
    assert hil_run.compute_replay_indices(10, 2) == [3, 8]
    assert rp_body["summary"]["all_denied"] is True
    assert rp_body["summary"]["denied_count"] == 2
    assert all(r["http_status"] == 403 and r["deny_reason"] == "replay" for r in rp_body["replays"])


def test_phase5_records_first_failure_iteration(tmp_path):
    bundle_path = tmp_path / "b.json"
    bundle_path.write_text(json.dumps(_bundle(5)))

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        # Iteration 3 (msg_id ends 002) returns 500
        if body["msg_id"].endswith("-002"):
            return httpx.Response(500, json={"error": "driver fault"})
        return httpx.Response(200, json={"status": "ok"})
    transport = httpx.MockTransport(handler)

    gm_body, _ = hil_run.run_phase_5(
        envelope_file=bundle_path,
        gated_motion_count=5,
        replay_count=0,
        gateway_url="http://test",
        latency_budget_ms=5000,
        http_client_factory=lambda: httpx.Client(transport=transport),
    )
    assert gm_body["summary"]["all_pass"] is False
    assert gm_body["summary"]["pass_count"] == 4
    assert gm_body["summary"]["fail_count"] == 1
    assert gm_body["summary"]["first_failure_iteration"] == 3
    # Failure preserved in results array
    failed = next(r for r in gm_body["results"] if r["iteration"] == 3)
    assert failed["pass"] is False
    assert failed["http_status"] == 500


def test_phase5_replay_returns_200_is_catastrophic(tmp_path):
    """If the cache is broken (gateway returns 200 to replay), abort + record fail."""
    bundle_path = tmp_path / "b.json"
    bundle_path.write_text(json.dumps(_bundle(5)))

    def handler(request: httpx.Request) -> httpx.Response:
        # Always 200 — simulates broken cache
        return httpx.Response(200, json={"status": "ok"})
    transport = httpx.MockTransport(handler)

    _, rp_body = hil_run.run_phase_5(
        envelope_file=bundle_path,
        gated_motion_count=5,
        replay_count=2,
        gateway_url="http://test",
        latency_budget_ms=5000,
        http_client_factory=lambda: httpx.Client(transport=transport),
    )
    # Replay test should abort after first 200; rp_body has a failed entry, summary=fail
    assert rp_body["summary"]["all_denied"] is False
    assert any(r["pass"] is False and r["http_status"] == 200 for r in rp_body["replays"])


def test_phase5_emits_both_files_on_mid_run_failure(tmp_path):
    """Even if iteration N fails, both gated_motion + replay bodies are returned."""
    bundle_path = tmp_path / "b.json"
    bundle_path.write_text(json.dumps(_bundle(5)))

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["msg_id"].endswith("-001"):
            return httpx.Response(500, json={"error": "fault"})
        return httpx.Response(200, json={"status": "ok"})
    transport = httpx.MockTransport(handler)

    gm_body, rp_body = hil_run.run_phase_5(
        envelope_file=bundle_path,
        gated_motion_count=5,
        replay_count=1,
        gateway_url="http://test",
        latency_budget_ms=5000,
        http_client_factory=lambda: httpx.Client(transport=transport),
    )
    # Both bodies returned (not None / not raising)
    assert gm_body["property_id"] == "bob.local/GATED-MOTION-5"
    assert rp_body["property_id"] == "bob.local/REPLAY-1"
