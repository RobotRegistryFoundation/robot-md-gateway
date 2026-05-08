#!/usr/bin/env python3
"""HIL harness — runs on Bob.

Modes (--property):
- SF-001 / SF-002 / GW-001: per-iteration safety/sandbox properties (legacy).
- PHASE-5: 100-run gated motion + tail replay (Plan 6 Phase 5).
  Reads a pre-signed envelope bundle, POSTs each to localhost gateway,
  tail-replays a fixed subset, emits two unsigned JSON evidence files.

Spec: docs/superpowers/specs/2026-05-04-cert-tracks-phase-5-design.md
Plan: docs/superpowers/plans/2026-05-04-cert-tracks-phase-5.md (Task 3)
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


def _prompt_value(prompt: str, *, parser):
    """Prompt the operator until they enter something `parser` can convert."""
    while True:
        print(prompt, file=sys.stderr)
        raw = input().strip()
        try:
            return parser(raw)
        except ValueError:
            print(f"  could not parse {raw!r}; try again", file=sys.stderr)


def run_sf_001(*, iterations: int) -> list[dict]:
    """Trigger ESTOP, measure latency."""
    results = []
    for i in range(iterations):
        prompt = f"Iteration {i+1}/{iterations}: pull ESTOP, then enter latency in ms:"
        latency_ms = _prompt_value(prompt, parser=int)
        results.append({"iteration": i + 1, "latency_ms": latency_ms, "pass": latency_ms <= 100})
    return results


def run_sf_002(*, iterations: int) -> list[dict]:
    """Drop network; measure safe-stop transition delay."""
    results = []
    for i in range(iterations):
        prompt = (
            f"Iteration {i+1}/{iterations}: drop network, then enter safe-stop "
            "transition delay in seconds:"
        )
        delay_s = _prompt_value(prompt, parser=float)
        results.append({"iteration": i + 1, "delay_s": delay_s, "pass": delay_s <= 3.5})
    return results


def run_gw_001(*, iterations: int) -> list[dict]:
    """Verify EACCES on direct device-node open."""
    results = []
    for i in range(iterations):
        proc = subprocess.run(
            ["python3", "-c", "open('/dev/ttyACM0', 'wb')"],
            capture_output=True, text=True,
        )
        ok = proc.returncode != 0 and "PermissionError" in proc.stderr
        results.append({"iteration": i + 1, "exit_code": proc.returncode, "pass": ok})
    return results


# ---------- PHASE-5 helpers ----------

def compute_replay_indices(gated_motion_count: int, replay_count: int) -> list[int]:
    """1-based, evenly spaced. For (100, 10): [5, 15, 25, ..., 95]."""
    if replay_count == 0:
        return []
    spacing = gated_motion_count // replay_count
    if spacing == 0:
        raise ValueError(
            f"replay_count {replay_count} > gated_motion_count {gated_motion_count}"
        )
    start = (spacing - 1) // 2 + 1
    return [start + i * spacing for i in range(replay_count)]


def _percentile(values: list[int], pct: int) -> int:
    if not values:
        return 0
    s = sorted(values)
    k = max(0, min(len(s) - 1, round(pct / 100.0 * len(s) - 1)))
    return s[k]


def _excerpt_response(r) -> dict:
    """Best-effort short summary of an HTTP response body."""
    try:
        return r.json()
    except Exception:
        return {"text": r.text[:200] if hasattr(r, "text") else str(r)[:200]}


def run_phase_5(
    *,
    envelope_file: Path,
    gated_motion_count: int,
    replay_count: int,
    gateway_url: str,
    latency_budget_ms: int = 5000,
    http_client_factory=None,
) -> tuple[dict, dict]:
    """Run PHASE-5 (gated motion + tail replay). Returns (gm_body, rp_body), both UNSIGNED.

    Caller (orchestrate.py) writes them out, parallel-co-signs, POSTs to RRF.
    """
    import httpx  # local import keeps unit tests independent of httpx at import time

    bundle = json.loads(envelope_file.read_text())
    envelopes = bundle["envelopes"][:gated_motion_count]
    if len(envelopes) < gated_motion_count:
        raise ValueError(
            f"bundle has {len(envelopes)} envelopes, need {gated_motion_count}"
        )

    factory = http_client_factory or (
        lambda: httpx.Client(timeout=latency_budget_ms / 1000.0)
    )
    client = factory()

    # ---- Gated motion: 100 sequential POSTs ----
    results = []
    latencies: list[int] = []
    first_failure = None
    for i, env in enumerate(envelopes):
        t0 = time.perf_counter()
        try:
            r = client.post(f"{gateway_url}/v1/invoke", json=env)
            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            ok = r.status_code == 200 and elapsed_ms <= latency_budget_ms
            results.append({
                "iteration": i + 1,
                "msg_id": env["msg_id"],
                "http_status": r.status_code,
                "latency_ms": elapsed_ms,
                "response_excerpt": _excerpt_response(r),
                "pass": ok,
            })
            latencies.append(elapsed_ms)
        except Exception as exc:  # network drop, timeout, etc.
            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            results.append({
                "iteration": i + 1,
                "msg_id": env["msg_id"],
                "http_status": None,
                "latency_ms": elapsed_ms,
                "response_excerpt": {"error": f"{type(exc).__name__}: {str(exc)[:200]}"},
                "pass": False,
            })
        if not results[-1]["pass"] and first_failure is None:
            first_failure = i + 1

    operator_kid = envelopes[0]["envelope_signature"]["kid"] if envelopes else "unknown"
    gm_all_pass = all(r["pass"] for r in results)
    gm_body = {
        "schema_version": "1.0",
        "property_id": f"bob.local/GATED-MOTION-{gated_motion_count}",
        "rig": "bob",
        "robot_class": "so-arm101",
        "rrn": "RRN-000000000002",
        "ran_at": time.time(),
        "operator_kid": operator_kid,
        "iterations": len(results),
        "all_pass": gm_all_pass,
        "trajectory": {
            "joints": ["wrist_pan"],
            "waypoints_deg": [30, 0, -30, 0],
            "speed_deg_per_s": 30,
            "iter_period_s": 5,
        },
        "results": results,
        "summary": {
            "all_pass": gm_all_pass,
            "pass_count": sum(1 for r in results if r["pass"]),
            "fail_count": sum(1 for r in results if not r["pass"]),
            "first_failure_iteration": first_failure,
            "latency_ms_p50": _percentile(latencies, 50),
            "latency_ms_p95": _percentile(latencies, 95),
            "latency_ms_max": max(latencies) if latencies else 0,
        },
    }

    # ---- Replay: tail replay against same gateway process ----
    replay_indices = compute_replay_indices(gated_motion_count, replay_count)
    replays = []
    for idx in replay_indices:
        env = envelopes[idx - 1]  # 1-based → 0-based
        try:
            r = client.post(f"{gateway_url}/v1/invoke", json=env)
            try:
                deny_value = r.json().get("detail", {}).get("deny")
            except Exception:
                deny_value = None
            ok = r.status_code == 403 and deny_value == "replay"
            replays.append({
                "replayed_iteration": idx,
                "msg_id": env["msg_id"],
                "http_status": r.status_code,
                "deny_reason": deny_value if deny_value is not None else "(none — fail-loud)",
                "pass": ok,
            })
            if r.status_code == 200:
                # Catastrophic: cache broken. Abort remaining replays so the evidence
                # packet records the first failing case unambiguously.
                break
        except Exception as exc:
            replays.append({
                "replayed_iteration": idx,
                "msg_id": env["msg_id"],
                "http_status": None,
                "deny_reason": f"error: {type(exc).__name__}: {str(exc)[:200]}",
                "pass": False,
            })

    rp_all_denied = (
        len(replays) == len(replay_indices)
        and all(r["pass"] for r in replays)
    )
    rp_body = {
        "schema_version": "1.0",
        "property_id": f"bob.local/REPLAY-{replay_count}",
        "rig": "bob",
        "robot_class": "so-arm101",
        "rrn": "RRN-000000000002",
        "ran_at": time.time(),
        "iterations": len(replays),
        "all_pass": rp_all_denied,
        "linked_msg_ids_from_gated_motion": [envelopes[i - 1]["msg_id"] for i in replay_indices],
        "replays": replays,
        "summary": {
            "all_denied": rp_all_denied,
            "denied_count": sum(1 for r in replays if r["pass"]),
            "fail_count": sum(1 for r in replays if not r["pass"]),
        },
        "scope_disclaimer": (
            "In-process replay defense only. ReplayCache is set[str] in-memory; "
            "gateway restart wipes it. Persistent-cache claim is out of scope (Plan 7+)."
        ),
    }

    return gm_body, rp_body


# ---------- main ----------

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument(
        "--property",
        required=True,
        choices=["SF-001", "SF-002", "GW-001", "PHASE-5"],
    )
    p.add_argument("--iterations", type=int, default=10,
                   help="(SF-001/SF-002/GW-001 only)")
    p.add_argument("--out", type=Path,
                   help="(SF-001/SF-002/GW-001) single-file output")
    # PHASE-5 args:
    p.add_argument("--envelope-file", type=Path,
                   help="(PHASE-5) pre-signed envelope bundle JSON")
    p.add_argument("--gated-motion-count", type=int, default=100,
                   help="(PHASE-5) number of sequential motion iterations")
    p.add_argument("--replay-count", type=int, default=10,
                   help="(PHASE-5) number of tail replays from the gated-motion msg_ids")
    p.add_argument("--gateway-url", default="http://localhost:8080",
                   help="(PHASE-5) override if gateway is on a non-default port")
    p.add_argument("--latency-budget-ms", type=int, default=5000,
                   help="(PHASE-5) per-iteration latency budget")
    p.add_argument("--out-dir", type=Path,
                   help="(PHASE-5) directory to write the two evidence files")
    args = p.parse_args()

    if args.property == "PHASE-5":
        if not args.envelope_file or not args.out_dir:
            print("PHASE-5 requires --envelope-file and --out-dir", file=sys.stderr)
            return 2
        args.out_dir.mkdir(parents=True, exist_ok=True)
        gm_body, rp_body = run_phase_5(
            envelope_file=args.envelope_file,
            gated_motion_count=args.gated_motion_count,
            replay_count=args.replay_count,
            gateway_url=args.gateway_url,
            latency_budget_ms=args.latency_budget_ms,
        )
        ts = time.strftime("%Y-%m-%d-%H%M%S")
        gm_path = args.out_dir / f"phase5-gated-motion-{args.gated_motion_count}-{ts}.json"
        rp_path = args.out_dir / f"phase5-replay-{args.replay_count}-{ts}.json"
        gm_path.write_text(json.dumps(gm_body, indent=2))
        rp_path.write_text(json.dumps(rp_body, indent=2))
        print(f"Wrote {gm_path}", file=sys.stderr)
        print(f"Wrote {rp_path}", file=sys.stderr)
        # Exit 0 only if both halves passed
        all_ok = gm_body["summary"]["all_pass"] and rp_body["summary"]["all_denied"]
        return 0 if all_ok else 1

    # legacy single-property modes
    if not args.out:
        print("legacy mode requires --out", file=sys.stderr)
        return 2
    runners = {"SF-001": run_sf_001, "SF-002": run_sf_002, "GW-001": run_gw_001}
    results = runners[args.property](iterations=args.iterations)
    body = {
        "schema_version": "1.0",
        "property_id": args.property,
        "rig": "bob",
        "robot_class": "so-arm101",
        "ran_at": time.time(),
        "iterations": args.iterations,
        "results": results,
        "all_pass": all(r["pass"] for r in results),
    }
    args.out.write_text(json.dumps(body, indent=2))
    print(f"Wrote {args.out}; all_pass={body['all_pass']}", file=sys.stderr)
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
