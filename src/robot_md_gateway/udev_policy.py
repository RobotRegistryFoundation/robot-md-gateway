"""udev policy generator for cert property GW-001.

Reads the template at robot_md_gateway/udev/99-robot-md-gateway.rules.in
and substitutes the service account + (optional) USB vendor hex. Emits
the resulting rules text. The init wizard installs this file at
/etc/udev/rules.d/99-robot-md-gateway.rules.
"""

from __future__ import annotations

import hashlib
from importlib.resources import files


def generate_rules(
    *,
    service_account: str,
    tty_vendor_hex: str | None = None,
    emit_evidence: bool = False,
) -> str:
    template = (
        files("robot_md_gateway").joinpath("udev", "99-robot-md-gateway.rules.in").read_text()
    )
    vendor = tty_vendor_hex or "0000"
    rules = template.replace("@SERVICE_ACCOUNT@", service_account).replace(
        "@TTY_VENDOR_HEX@", vendor
    )
    if emit_evidence:
        from .cert import report as cert_report
        cert_report.record_property_pass(
            property_id="GW-001",
            evidence={
                "rules_sha256": hashlib.sha256(rules.encode("utf-8")).hexdigest(),
                "service_account": service_account,
                "tty_vendor_hex": vendor,
                "scope": "ci",
            },
        )
    return rules
