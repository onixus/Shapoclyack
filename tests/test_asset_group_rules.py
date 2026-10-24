"""Rules cannot turn unknown evidence or guessed OS inventory into membership."""

import pytest

from api.services.asset_group_rules import evaluate_rules, validate_context, validate_rules


def leaf(field="fqdn", op="eq", value="app.example", **kwargs):
    return {"field": field, "op": op, "value": value, **kwargs}


@pytest.mark.parametrize("op,value", [("eq", "app.example"), ("ne", "app.example"),
                                      ("in", ["app.example"]), ("not_in", ["app.example"])])
@pytest.mark.parametrize("snapshot", [{}, {"fqdn": None}, {"fqdn": []}, {"fqdn": [None]}, {"fqdn": "unknown"}])
@pytest.mark.parametrize("negate", [False, True])
def test_unknown_never_becomes_membership(op, value, snapshot, negate):
    result = evaluate_rules(leaf(op=op, value=value, negate=negate), snapshot)
    assert result["matched"] is False
    assert result["result"] == "unknown"


def test_and_or_use_three_valued_logic():
    known = leaf("status", "eq", "active")
    absent = leaf("business_unit", "ne", "external")
    snapshot = {"status": "active"}
    assert evaluate_rules({"any": [known, absent]}, snapshot)["matched"] is True
    assert evaluate_rules({"all": [known, absent]}, snapshot)["result"] == "unknown"
    assert evaluate_rules({"all": [known, absent], "negate": True}, snapshot)["matched"] is False
    assert evaluate_rules({"any": [leaf("status", "eq", "stale"), absent]}, snapshot)["matched"] is False


def test_network_dns_tags_and_typed_context():
    rules = {"all": [leaf("ip", "cidr", "10.0.0.0/8"),
                     {"any": [leaf("fqdn", "ends_with", ".example"), leaf("tag:team", "eq", "blue")]},
                     leaf("asset_criticality", "eq", 4)]}
    snapshot = {"ip": ["192.0.2.1", "10.1.1.1"], "fqdn": ["APP.EXAMPLE."],
                "tags": {"team": "Blue"}, "asset_criticality": 4}
    assert evaluate_rules(rules, snapshot)["matched"] is True
    assert evaluate_rules(leaf("tag:missing", "ne", "yes"), snapshot)["result"] == "unknown"
    assert evaluate_rules(leaf("ip", "cidr", "2001:db8::/32"), {"ip": ["2001:db8::1"]})["matched"] is True


def test_negative_collection_conditions_require_all_known_values_to_disagree():
    rule = leaf(op="not_in", value=["app.example"])
    assert evaluate_rules(rule, {"fqdn": ["other.example", "app.example"]})["matched"] is False
    assert evaluate_rules(rule, {"fqdn": ["other.example", None]})["result"] == "unknown"
    assert evaluate_rules(rule, {"fqdn": ["other.example"]})["matched"] is True


@pytest.mark.parametrize("rule", [
    {}, {"all": []}, {"all": [], "any": []}, {"all": [leaf()], "extra": True},
    leaf("os", "eq", "windows"), leaf("os_name", "eq", "windows"),
    leaf("port", "eq", True), leaf("port", "eq", "443"), leaf("port", "contains", 443),
    leaf("port", "eq", 0), leaf("asset_criticality", "eq", 5),
    leaf("environment", "eq", "prod"), leaf("ip", "cidr", "invalid"),
    leaf("fqdn", "cidr", "10.0.0.0/8"), leaf("ip", "contains", "10.0.0.1"),
    leaf("ip", "eq", "10.0.0.0/8"), leaf(value=""), leaf(value="a" * 257),
    leaf(op="regex", value=".*"), leaf(op="in", value=[]), leaf(op="in", value=["a"] * 51),
    leaf(negate="yes"), leaf(value=None), leaf("tag:", "eq", "yes"),
])
def test_rejects_unsupported_or_mistyped_rules(rule):
    with pytest.raises(ValueError):
        validate_rules(rule)


def test_depth_node_and_byte_limits():
    rule = leaf()
    for _ in range(6):
        rule = {"all": [rule]}
    with pytest.raises(ValueError):
        validate_rules(rule)
    with pytest.raises(ValueError):
        validate_rules({"any": [{"all": [leaf()] * 50}] * 3})
    with pytest.raises(ValueError):
        validate_rules({"any": [leaf(value="Ж" * 256)] * 50})


def test_no_implicit_conversions_or_input_mutation():
    rule = leaf("asset_criticality", "eq", 4)
    assert evaluate_rules(rule, {"asset_criticality": "4"})["result"] == "unknown"
    assert rule == leaf("asset_criticality", "eq", 4)
    copy = validate_rules({"all": [rule]})
    copy["all"][0]["value"] = 22
    assert rule["value"] == 4


def test_context_assignments_match_existing_vocabularies():
    context = {"owner_email": "ops@example.com", "asset_criticality": 0, "environment": "production",
               "business_unit": "Ops", "business_service": "Payments",
               "data_classification": "restricted"}
    assert validate_context(context) == context


@pytest.mark.parametrize("context", [{"status": "stale"}, {"context_source": "operator"}, {"exposure_level": "internet"},
    {"asset_criticality": True}, {"asset_criticality": -1}, {"business_service": None},
    {"business_unit": "=formula"}, {"business_unit": "x\x00y"},
    {"business_service": "a" * 201}, {"owner_email": "not email"}, {"environment": "prod"}])
def test_invalid_context_assignments(context):
    with pytest.raises(ValueError):
        validate_context(context)


@pytest.mark.parametrize("family", ["windows", "linux", "macos"])
def test_os_conditions_require_proven_fresh_endpoint_snapshot(family):
    evidence = {"source": "endpoint_inventory", "state": "confirmed", "device_ids": ["device"],
                "snapshot_ids": ["snapshot"], "collected_at": "2026-10-24T10:00:00+00:00"}
    result = evaluate_rules(leaf("os_family", "eq", family), {"os_family": family, "_os_evidence": evidence})
    assert result["matched"] is True
    assert result["reasons"][0]["evidence"] == evidence


@pytest.mark.parametrize("state", ["missing", "stale", "conflict", "unknown"])
@pytest.mark.parametrize("negate", [False, True])
def test_unconfirmed_os_evidence_never_matches_including_negation(state, negate):
    rule = leaf("os_family", "ne", "windows", negate=negate)
    result = evaluate_rules(rule, {"os_family": "linux", "_os_evidence": {
        "source": "endpoint_inventory", "state": state,
    }})
    assert result["matched"] is False
    assert result["result"] == "unknown"
    assert result["reasons"][0]["evidence"]["state"] == state


def test_scan_os_guess_or_raw_scalar_cannot_claim_confirmation():
    rule = leaf("os_family", "eq", "windows")
    assert evaluate_rules(rule, {"os_family": "windows"})["result"] == "unknown"
    assert evaluate_rules(rule, {"os_family": "windows", "_os_evidence": {
        "source": "nmap", "state": "confirmed", "accuracy": 100,
    }})["result"] == "unknown"


@pytest.mark.parametrize("rule", [leaf("os_family", "eq", "Windows"),
    leaf("os_family", "eq", "darwin"), leaf("os_family", "contains", "windows"),
    leaf("os_family", "in", ["linux", "unknown"])])
def test_os_family_is_closed_typed_vocabulary(rule):
    with pytest.raises(ValueError):
        validate_rules(rule)
