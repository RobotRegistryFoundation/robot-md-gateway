# GW-001 — Direct device-node bypass denied (HIL procedure)

**Property:** A non-gateway process attempting to open a robot-owned
device node (`/dev/ttyACM*`, `/dev/ttyUSB*`, `/dev/i2c-*`,
`/dev/gpiochip*`) must be denied with `EACCES`.

**Rig:** Bob (RPi 5 + SO-ARM101). Service account: `robot-md-gateway`.
udev rules from `udev_policy.generate_rules()` installed at
`/etc/udev/rules.d/99-robot-md-gateway.rules`.

## Procedure

1. SSH to Bob as the operator user (NOT `robot-md-gateway`).
2. Verify the gateway is running and owns `/dev/ttyACM0`:
   ```bash
   ls -l /dev/ttyACM0
   ```
   Expected: `crw-rw---- 1 robot-md-gateway robot-md-gateway /dev/ttyACM0`.
3. As the operator user, attempt to open the device:
   ```bash
   python3 -c "open('/dev/ttyACM0', 'wb')" && echo "BUG: opened" || echo "OK: EACCES"
   ```
   Expected: `OK: EACCES`. (The Python process raises `PermissionError`.)
4. Sign the result and append it to the gateway-authority report:
   ```bash
   robot-md-gateway record-property-pass \
       --property-id GW-001 \
       --evidence '{"rig": "bob", "outcome": "EACCES", "operator_uid": <UID>}' \
       --report-out /var/log/robot-md-gateway/gateway-authority-bob.json
   ```

The HIL evidence packet pairs with the unit-test evidence; both go
into the gateway-authority report. Plan 6 wires this into nightly
HIL runs on Bob.
