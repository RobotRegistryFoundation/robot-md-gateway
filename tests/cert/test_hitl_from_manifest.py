"""B3 — manifest-driven HiTL policy (replaces the hardcoded {MANIPULATE})."""
from robot_md_gateway.cert.gates import HiTLPolicy, check_hitl


def test_default_matches_legacy():
    assert HiTLPolicy().required_for_scopes == frozenset({"MANIPULATE"})


def test_from_manifest_maps_gate_scopes():
    gates = [
        {"scope": "destructive", "require_auth": True},
        {"scope": "system", "require_auth": True},
    ]
    p = HiTLPolicy.from_manifest_gates(gates)
    assert p.required_for_scopes == frozenset({"MANIPULATE", "EXECUTE", "ACTUATE"})


def test_from_manifest_commission_gate():
    p = HiTLPolicy.from_manifest_gates([{"scope": "commission", "require_auth": True}])
    assert p.required_for_scopes == frozenset({"COMMISSION"})


def test_require_auth_false_excluded():
    p = HiTLPolicy.from_manifest_gates([{"scope": "destructive", "require_auth": False}])
    assert p.required_for_scopes == frozenset()


def test_unknown_gate_scope_ignored():
    p = HiTLPolicy.from_manifest_gates([{"scope": "made_up", "require_auth": True}])
    assert p.required_for_scopes == frozenset()


def test_none_and_empty():
    assert HiTLPolicy.from_manifest_gates(None).required_for_scopes == frozenset()
    assert HiTLPolicy.from_manifest_gates([]).required_for_scopes == frozenset()


def test_check_hitl_uses_manifest_policy_for_commission():
    p = HiTLPolicy.from_manifest_gates([{"scope": "commission", "require_auth": True}])
    # COMMISSION now requires a delegation chain
    ok, reason = check_hitl({"msg_id": "m", "scope": "COMMISSION"}, p)
    assert not ok and "delegation_chain" in reason
    # with a valid human-subject chain → allowed
    env = {"msg_id": "m", "scope": "COMMISSION",
           "delegation_chain": [{"scope": "COMMISSION", "human_subject": "op@example.com"}]}
    assert check_hitl(env, p)[0] is True
    # a scope NOT in the manifest policy is not required
    assert check_hitl({"msg_id": "m", "scope": "MANIPULATE"}, p)[0] is True
