"""RC-004 — HiTL authorization chain."""

from robot_md_gateway.cert.gates import HiTLPolicy, check_hitl


def test_rc_004_manipulate_with_chain_allowed():
    env = {"msg_id": "1", "scope": "MANIPULATE",
           "delegation_chain": [{"scope": "MANIPULATE", "human_subject": "operator@x.com"}]}
    assert check_hitl(env, HiTLPolicy())[0]


def test_rc_004_manipulate_without_chain_denied():
    env = {"msg_id": "2", "scope": "MANIPULATE", "delegation_chain": []}
    ok, _ = check_hitl(env, HiTLPolicy())
    assert not ok


def test_rc_004_navigate_does_not_require_hitl():
    env = {"msg_id": "3", "scope": "NAVIGATE"}
    assert check_hitl(env, HiTLPolicy())[0]


def test_rc_004_chain_scope_mismatch_denied():
    env = {"msg_id": "4", "scope": "MANIPULATE",
           "delegation_chain": [{"scope": "READ", "human_subject": "operator@x.com"}]}
    ok, reason = check_hitl(env, HiTLPolicy())
    assert not ok
    assert "scope" in reason


def test_rc_004_chain_missing_human_subject_denied():
    env = {"msg_id": "5", "scope": "MANIPULATE",
           "delegation_chain": [{"scope": "MANIPULATE"}]}
    ok, reason = check_hitl(env, HiTLPolicy())
    assert not ok
    assert "human_subject" in reason
