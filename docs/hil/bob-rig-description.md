# Bob — HIL rig description

**Rig name:** Bob
**Robot class:** SO-ARM101 (per memory `project_so_arm101_hardware_constraints.md`)
**RRN:** RRN-000000000002

## Hardware

- Raspberry Pi 5, 8GB RAM, 64-bit Pi OS Bookworm.
- SO-ARM101 6-DoF arm, mounted on standard test fixture.
- Servos connected via USB-CDC at `/dev/ttyACM0` (per memory: known stable mount).
- Optional: OAK-D stereo camera (per memory: known to need physical replug for USB wedge).

## Software

- robot-md-gateway v0.4.0a1+ as systemd service.
- udev rules from Plan 3 Task 17 installed at `/etc/udev/rules.d/99-robot-md-gateway.rules`.
- Operator user `pi` (NOT in the gateway service account group).
- HIL harness scripts at `~/hil/` (Plan 6 Task 15 installs them).

## Witness

- Witness key: separate Ed25519 keypair held by Craig, registered with RRF as `witness-bob-craigm`.
- Witness signs every HIL property's evidence packet alongside the rig's signature.

## Constraints from memory

- `wrist_flex` servo stalls at sustained high-angle (per memory `project_so_arm101_hardware_constraints.md`); HIL test envelopes avoid this position.
- Preset extrinsic wrong for most physical mounts; HIL uses Bob's calibrated extrinsic loaded at gateway start.

## Network

- Bob has wired ethernet + WiFi failover. SF-002 network-loss tests require a *deterministic* network drop — physical ethernet unplug while WiFi is also disabled (HIL operator's hand on the cable).
