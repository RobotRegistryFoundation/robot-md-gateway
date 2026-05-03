"""RC-003 — Confidence threshold gate."""

from robot_md_gateway.cert.gates import ConfidencePolicy, check_confidence


def test_rc_003_above_threshold_allowed():
    env = {"msg_id": "1", "scope": "MANIPULATE", "payload": {"inference_confidence": 0.92}}
    ok, _ = check_confidence(env, ConfidencePolicy())
    assert ok


def test_rc_003_below_threshold_denied():
    env = {"msg_id": "2", "scope": "MANIPULATE", "payload": {"inference_confidence": 0.7}}
    ok, reason = check_confidence(env, ConfidencePolicy())
    assert not ok and "below threshold" in reason


def test_rc_003_missing_confidence_denied():
    env = {"msg_id": "3", "scope": "MANIPULATE", "payload": {}}
    ok, _ = check_confidence(env, ConfidencePolicy())
    assert not ok


def test_rc_003_unknown_scope_strict_default():
    env = {"msg_id": "4", "scope": "WEIRD_NEW_SCOPE", "payload": {"inference_confidence": 0.9}}
    ok, _ = check_confidence(env, ConfidencePolicy())
    assert not ok  # default 0.95 threshold rejects 0.9
