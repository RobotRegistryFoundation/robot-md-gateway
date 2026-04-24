---
rcan_version: "3.0"
metadata:
  robot_name: so-arm101
  manufacturer: huggingface
  model: so-arm101
  license: Apache-2.0

physics:
  type: arm
  dof: 6
  kinematics:
    - id: shoulder_pan
      axis: z
      limits_deg: [-180, 180]
      length_mm: 60
    - id: shoulder_lift
      axis: y
      limits_deg: [-90, 90]
      length_mm: 125
    - id: elbow_flex
      axis: y
      limits_deg: [-90, 90]
      length_mm: 125
    - id: wrist_flex
      axis: y
      limits_deg: [-90, 90]
      length_mm: 60
    - id: wrist_roll
      axis: x
      limits_deg: [-180, 180]
      length_mm: 30
    - id: gripper
      axis: y
      limits_deg: [0, 90]
      length_mm: 40

drivers:
  - id: arm_servos
    protocol: feetech
    port: /dev/ttyUSB0
    baud_rate: 1000000
    model: STS3215
    count: 6

capabilities:
  - arm.pick
  - arm.place
  - arm.reach
  - status.report

safety:
  max_joint_velocity_dps: 180
  payload_kg: 0.5
  estop:
    hardware: false
    software: true
    response_ms: 100
  hitl_gates:
    - scope: destructive
      require_auth: true
---

# so-arm101

## Identity

The Hugging Face SO-ARM101 is an open-source 6-DOF follower arm kit (~$300 BOM) built around six Feetech STS3215 serial bus servos. This ROBOT.md is the generic preset — copy and customize for your specific build. No camera, no brain: add a `brain:` block when you wire up a planner.

## What so-arm101 Can Do

- **Pick** — grasp an object at a declared pose. Gripper is joint 6 (servo ID 6).
- **Place** — lower to a declared pose and release.
- **Reach** — move the tool center point to a declared pose without grasping.
- **Status** — query servo health across the bus.

## Safety Gates

1. Software E-stop with 100 ms response time. No hardware E-stop by default — add one for anything beyond desktop experimentation.
2. Max payload 0.5 kg. Exceeding this risks servo overtemperature within seconds.
3. Max joint velocity 180 deg/sec. Faster moves need the servo temperature curve from the datasheet.
4. `destructive` scope requires HITL authorization.
