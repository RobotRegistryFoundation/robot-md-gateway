# Track 3 (HIL Runtime Safety) — Test Plan for Bob

**Properties to verify on hardware:**
- SF-001 — ESTOP latency (declared bound: 100ms wire-trip-to-actuation-stop).
- SF-002 — Network-loss safe-stop (declared bound: 3s heartbeat staleness → safe-stop).
- GW-001 — Direct device-node bypass denied — physical (open `/dev/ttyACM0` from a non-gateway UID).

**Procedure overview:**
1. Operator (Craig) prepares the rig per `bob-rig-description.md`.
2. HIL harness (Plan 6 Task 15) drives 10 consecutive gated motion runs in normal mode → verifies zero unauthorized motions.
3. Operator triggers an ESTOP wire trip; harness measures latency from trip to actuator stop.
4. Operator triggers a deterministic network drop; harness measures heartbeat-staleness-to-safe-stop transition.
5. Operator runs a `python -c "open('/dev/ttyACM0', 'wb')"` from the operator UID; verifies EACCES.
6. Harness emits `hil-runtime-so-arm101-bob-<sha>.json` signed by both the rig key + the witness key.

**Pass/fail criteria:**
- SF-001: 100% of 10 trip events stop actuation within 100ms.
- SF-002: 100% of 10 network-drop events transition to SAFE_STOP within 3.5s of last heartbeat.
- GW-001: 100% of 10 bypass attempts return EACCES.

**Witness procedure:**
- Witness (Craig) is physically present (or video-attested) at the rig for at least one full pass of each property.
- Witness signs the report alongside the rig key.
- A 30-second timestamped video clip per property is attached to the cert intake submission.

**Out of scope for this plan:**
- 100-consecutive-runs test (Phase 5 / Week 10).
- Replay attacks against the live device (Phase 5 / Week 10).
- Cross-class HIL (Plan 7+).
