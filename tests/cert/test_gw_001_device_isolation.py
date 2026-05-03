"""GW-001 — Direct device-node bypass denied (Track 2 Gateway Authority).

Unit test verifies the udev policy generator emits a rules file that, when
installed, restricts /dev/ttyACM*, /dev/ttyUSB*, /dev/i2c-*, and
/dev/gpiochip* to the gateway's service account. The HIL spot check
(running a non-gateway process and confirming EACCES) lives in
docs/hil/gw-001-procedure.md and runs on Bob in Plan 6 / Plan 7.
"""

from __future__ import annotations

from robot_md_gateway.udev_policy import generate_rules


def test_gw_001_generates_rules_for_default_serial_devices():
    rules = generate_rules(service_account="robot-md-gateway")
    assert 'KERNEL=="ttyACM[0-9]*"' in rules
    assert 'KERNEL=="ttyUSB[0-9]*"' in rules
    assert 'OWNER="robot-md-gateway"' in rules
    assert 'MODE="0660"' in rules


def test_gw_001_includes_i2c_and_gpio():
    rules = generate_rules(service_account="robot-md-gateway")
    assert 'KERNEL=="i2c-[0-9]*"' in rules
    assert 'KERNEL=="gpiochip[0-9]*"' in rules


def test_gw_001_custom_service_account_is_substituted():
    rules = generate_rules(service_account="my-robot-svc")
    assert 'OWNER="my-robot-svc"' in rules
    assert 'OWNER="robot-md-gateway"' not in rules


def test_gw_001_optional_tty_vendor_is_substituted():
    rules = generate_rules(service_account="robot-md-gateway", tty_vendor_hex="2341")
    assert 'ATTRS{idVendor}=="2341"' in rules
    assert "@TTY_VENDOR_HEX@" not in rules


def test_gw_001_no_unsubstituted_placeholders():
    rules = generate_rules(service_account="robot-md-gateway", tty_vendor_hex="2341")
    assert "@" not in rules


def test_gw_001_records_cert_evidence():
    """Generation itself records a GW-001 pass with the rules digest."""
    from robot_md_gateway.cert import report as cert_report
    cert_report.reset()
    generate_rules(service_account="robot-md-gateway", tty_vendor_hex="2341", emit_evidence=True)
    serialized = cert_report.serialize(repo="robot-md-gateway", sha="HEAD")
    gw_001 = [p for p in serialized["properties"] if p["property_id"] == "GW-001"]
    assert len(gw_001) == 1
    assert gw_001[0]["outcome"] == "pass"
    assert "rules_sha256" in gw_001[0]["evidence"]
