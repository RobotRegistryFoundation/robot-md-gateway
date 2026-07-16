"""B2 — COMMISSION scope + commission tier (extends GW-003)."""
from robot_md_gateway.cert.policy import ACTUATION_SCOPES, check_tier


def test_commission_is_actuation_scope():
    assert "COMMISSION" in ACTUATION_SCOPES


def test_read_tier_denied_commission():
    ok, reason = check_tier("read", "COMMISSION", msg_id="m")
    assert not ok and "read-tier" in reason


def test_actuate_tier_denied_commission():
    # the general actuate bearer is NOT enough — commissioning needs its own tier
    ok, reason = check_tier("actuate", "COMMISSION", msg_id="m")
    assert not ok and "commission" in reason.lower()


def test_commission_tier_allows_commission():
    ok, _ = check_tier("commission", "COMMISSION", msg_id="m")
    assert ok


def test_commission_tier_allows_manipulate():
    # commission tier isn't read, and MANIPULATE isn't COMMISSION-gated → allowed
    ok, _ = check_tier("commission", "MANIPULATE", msg_id="m")
    assert ok


def test_existing_flows_unchanged():
    assert check_tier("read", "READ", msg_id="m")[0] is True
    assert check_tier("actuate", "MANIPULATE", msg_id="m")[0] is True
    assert check_tier("read", "MANIPULATE", msg_id="m")[0] is False


# T-003 — anon fail-open fix. `anon` (no/unknown bearer) must be denied actuation
# exactly like `read`, while read/discover on non-actuation scopes stays open.
def test_anon_tier_denied_actuation():
    for scope in ("MANIPULATE", "NAVIGATE", "ACTUATE", "EXECUTE"):
        ok, reason = check_tier("anon", scope, msg_id="m")
        assert not ok, f"anon should be denied {scope}"
        assert "anon-tier" in reason


def test_anon_tier_denied_commission():
    ok, _reason = check_tier("anon", "COMMISSION", msg_id="m")
    assert not ok


def test_anon_tier_allows_read_scope():
    # read/discover on a non-actuation scope stays open for anon.
    assert check_tier("anon", "READ", msg_id="m")[0] is True
