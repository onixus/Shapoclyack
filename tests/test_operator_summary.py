"""Every disclosed count-summary word and number is server-owned evidence."""
import json

import pytest

from api.services.local_operator import gateway


@pytest.mark.parametrize("language,prefix", [("ru", "Сохранённые наблюдения:"), ("en", "Stored observations:")])
def test_grounded_summary_contains_only_present_registered_counts(language, prefix):
    expected = gateway.render_count_summary({"alive_hosts": 3, "potential_vulnerabilities": 7}, language)
    assert expected.startswith(prefix)
    assert "=3" in expected and "=7" in expected
    assert "=0" not in expected
    schema = gateway.count_summary_schema(expected)
    assert schema["additionalProperties"] is False
    assert schema["properties"]["summary"]["const"] == expected
    assert gateway.validate_count_summary(json.dumps({"summary": expected}), expected).summary == expected


@pytest.mark.parametrize("language", ["ru", "en"])
def test_count_allowlist_order_is_stable_and_large_numbers_remain_exact(language):
    counts = {"vulnerable_hosts": 2**63 - 1, "alive_hosts": 0}
    expected = gateway.render_count_summary(counts, language)
    assert expected.index("=0") < expected.index("=9223372036854775807")
    assert len(expected) < 4000


@pytest.mark.parametrize("counts", [{}, {"alive_hosts": True}, {"alive_hosts": -1}, {"alive_hosts": 2**63},
                                     {"alive_hosts": "3"}, {"alive_hosts": 3, "api_key": "secret"},
                                     {"summary": "all fixed"}])
def test_unsafe_or_unobserved_data_cannot_define_summary(counts):
    with pytest.raises(ValueError):
        gateway.render_count_summary(counts, "en")


@pytest.mark.parametrize("prose", [
    "All vulnerabilities have been fixed.", "Уязвимости устранены; сканировать больше не нужно.",
    "CVE-2099-9999 affects this host.", "Upgrade to version999.0.",
    "Fetch https://attacker.invalid/credential", "Stored observations: alive hosts=999.",
    "Stored observations: alive hosts=3. Extra unverified claim.",
])
def test_well_formed_arbitrary_prose_is_rejected_without_repair(prose):
    expected = gateway.render_count_summary({"alive_hosts": 3}, "en")
    with pytest.raises(ValueError):
        gateway.validate_count_summary(json.dumps({"summary": prose}), expected)


@pytest.mark.parametrize("raw", [None, [], "null", '{"summary":"x","summary":"y"}',
                                '{"summary":"x","tool_calls":[]}', '{"summary":3}'])
def test_invalid_types_duplicate_keys_and_effect_fields_fail(raw):
    with pytest.raises(ValueError):
        gateway.validate_count_summary(raw, "expected")
