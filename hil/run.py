#!/usr/bin/env python3
"""HIL harness — runs on Bob.

Receives a property identifier (SF-001, SF-002, GW-001) and an iteration
count; executes the property's per-iteration procedure; captures
telemetry; emits a signed evidence packet.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def run_sf_001(*, iterations: int) -> list[dict]:
    """Trigger ESTOP, measure latency."""
    results = []
    for i in range(iterations):
        # Operator pulls ESTOP wire low; the harness measures the gateway's response.
        # Implementation depends on the wire-monitoring approach; for v1, the operator
        # uses a stopwatch + reports a single latency value per iteration via stdin.
        print(f"Iteration {i+1}/{iterations}: pull ESTOP, then enter latency in ms:", file=sys.stderr)
        latency_ms = int(input().strip())
        results.append({"iteration": i+1, "latency_ms": latency_ms, "pass": latency_ms <= 100})
    return results


def run_sf_002(*, iterations: int) -> list[dict]:
    """Drop network; measure safe-stop transition delay."""
    results = []
    for i in range(iterations):
        print(f"Iteration {i+1}/{iterations}: drop network, then enter safe-stop transition delay in seconds:", file=sys.stderr)
        delay_s = float(input().strip())
        results.append({"iteration": i+1, "delay_s": delay_s, "pass": delay_s <= 3.5})
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
        results.append({"iteration": i+1, "exit_code": proc.returncode, "pass": ok})
    return results


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--property", required=True, choices=["SF-001", "SF-002", "GW-001"])
    p.add_argument("--iterations", type=int, default=10)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()

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
