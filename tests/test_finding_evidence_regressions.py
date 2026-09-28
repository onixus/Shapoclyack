"""Offline evidence-contract regressions; all credential fixtures are synthetic.

No scanner, network or database is used. Includes the four PR #493 review
regressions and boundary cases for their fixes.
"""
from __future__ import annotations

import copy
import hashlib
import itertools
import json
import random
from pathlib import Path

import pytest

from scanner.pipeline.evidence_artifacts import EvidenceReader, write_evidence_artifact
from scanner.pipeline.finding_evidence import MAX_ARTIFACT_REFS, aggregate, digest, observation, safe_text

BASE = {
    "host": "192.0.2.1", "port": 443, "protocol": "tcp",
    "cve": "CVE-2024-1234", "rule_id": "fixture-rule", "severity": "high",
}


def make_observation(*, ref_index: int = 0, **fields):
    return observation(
        {**BASE, **fields}, tenant_id="review-tenant", run_id="review-run",
        source="pulse", artifact_ref={
            "path": "pulse/raw.json", "sha256": "a" * 64,
            "locator": f"/findings/{ref_index}",
        },
    )


@pytest.mark.parametrize("credential", ["password", "token", "api_key"])
@pytest.mark.parametrize("escaped_quote", [False, True], ids=["plain-control", "escaped-quote-regression"])
def test_known_json_credential_is_fully_redacted_in_written_sidecar(tmp_path: Path, credential, escaped_quote):
    marker = "REVIEW_SYNTHETIC_SECRET_SUFFIX"
    evidence = json.dumps({credential: ('prefix"' if escaped_quote else 'prefix-') + marker})
    path = tmp_path / "pulse/raw.json"
    path.parent.mkdir()
    path.write_text(json.dumps({"findings": [{
        "ip": "192.0.2.1", "port": 443, "cve_id": "CVE-2024-1234",
        "finding_class": "version_cve", "evidence": evidence,
    }]}), encoding="utf-8")
    original = path.read_bytes()
    result = write_evidence_artifact(tmp_path, tenant_id="review-tenant", run_id="review-run")
    assert result["observation_count"] == 1
    assert not result["projection_incomplete"]
    assert path.read_bytes() == original
    preview = result["findings"][0]["observations"][0]["preview"]
    assert marker not in preview, f"Credential suffix survives redaction: {preview!r}"
    assert marker not in (tmp_path / "finding_evidence.json").read_text(encoding="utf-8")


@pytest.mark.parametrize("url_in", ["host", "matched_at"])
def test_http_subject_preserves_explicit_affected_object(url_in):
    location = {url_in: "https://site.example/api"}
    first = make_observation(**location, affected_object="POST:/customer/first")
    second = make_observation(**location, affected_object="POST:/customer/second")
    result = aggregate([first, second])
    assert result["finding_count"] == 2, "Explicit distinct HTTP objects collapsed"
    assert result["observation_count"] == 2


def test_bare_endpoint_explicit_objects_remain_distinct_control():
    rows = [make_observation(affected_object=name) for name in ("first", "second")]
    assert aggregate(rows)["finding_count"] == 2


def test_http_paths_remain_distinct_control():
    rows = [make_observation(host=f"https://site.example/{name}") for name in ("first", "second")]
    assert aggregate(rows)["finding_count"] == 2


@pytest.mark.parametrize("ref_count", [MAX_ARTIFACT_REFS, MAX_ARTIFACT_REFS + 1], ids=["uncapped-control", "capped-regression"])
def test_reaggregation_does_not_clear_reference_truncation(ref_count):
    once = aggregate([make_observation(ref_index=i) for i in range(ref_count)])
    rows = once["findings"][0]["observations"]
    assert rows[0]["artifact_refs_truncated"] == (ref_count > MAX_ARTIFACT_REFS)
    twice = aggregate(rows)
    assert twice == once, "Reaggregation silently changed the completeness of retained references"


@pytest.mark.parametrize("separator", ["\u0085", "\u2028", "\u2029"], ids=["NEL", "LINE_SEPARATOR", "PARAGRAPH_SEPARATOR"])
@pytest.mark.parametrize("ensure_ascii", [True, False], ids=["escaped-control", "literal-utf8-regression"])
def test_valid_jsonl_unicode_does_not_split_records_or_change_line_locators(tmp_path, separator, ensure_ascii):
    first = {
        "host": "https://192.0.2.1/", "port": 443, "type": "http",
        "template-id": "first-rule", "response": f"prefix{separator}suffix",
        "info": {"name": "Fixture", "severity": "high", "classification": {"cve-id": ["CVE-2024-1234"]}},
    }
    second = {**first, "template-id": "second-rule", "response": "control"}
    line = json.dumps(first, ensure_ascii=ensure_ascii)
    # It is valid JSON on one physical JSONL line, including literal Unicode.
    assert json.loads(line) == first
    assert "\n" not in line
    path = tmp_path / "nuclei_raw.jsonl"
    path.write_text(line + "\n" + json.dumps(second) + "\n", encoding="utf-8")
    reader = EvidenceReader(tmp_path, "review-tenant", "review-run")
    result = reader.build()
    assert result["observation_count"] == 2, result["diagnostics"]
    assert not result["projection_incomplete"]
    locators = {
        row["rule_id"]: row["artifact_refs"][0]["locator"]
        for finding in result["findings"] for row in finding["observations"]
    }
    assert locators == {"first-rule": "line:1", "second-rule": "line:2"}


@pytest.mark.parametrize("quote", ['"', "'"])
@pytest.mark.parametrize("value", [
    "plain", "with space", "escaped quote", "backslash", "trailing backslash",
    "mixed escapes", "empty",
])
def test_quoted_secret_boundaries_preserve_nonsecret_suffix(quote, value):
    material = {
        "plain": "SECRET",
        "with space": "SECRET middle SECRET",
        "escaped quote": "left" + quote + "SECRET",
        "backslash": "left\\SECRET",
        "trailing backslash": "SECRET\\",
        "mixed escapes": "\\" + quote + "SECRET\\" + quote,
        "empty": "",
    }[value]
    escaped = material.replace("\\", "\\\\").replace(quote, "\\" + quote)
    text = f"password={quote}{escaped}{quote}; public=kept"
    result = safe_text(text)
    assert "SECRET" not in result
    assert result == "password=[REDACTED]; public=kept"


@pytest.mark.parametrize("text", [
    'password="unterminated SECRET',
    "token='unterminated SECRET",
    'api_key="unterminated SECRET\\',
    "password='unterminated SECRET\\",
    'password="SECRET"ambiguous-tail',
    'token={"nested": "SECRET"}',
    'api_key=["SECRET", "another"]',
])
def test_ambiguous_secret_boundary_hides_entire_remaining_preview(text):
    result = safe_text(text)
    assert "SECRET" not in result
    assert "ambiguous-tail" not in result
    assert result.endswith("[REDACTED]")


def test_redaction_happens_before_preview_limit_and_covers_multiple_fields():
    evidence = 'label=kept password="' + "x" * 4096 + r'\"SECRET"; token=SECOND; public=end'
    result = safe_text(evidence)
    assert result == "label=kept password=[REDACTED]; token=[REDACTED]; public=end"


def test_json_secret_escaping_seeded_cases():
    rng = random.Random(493)
    alphabet = 'abc\\"\' ,;=&\n\r\t\u0085\u2028\u2029'
    for _ in range(200):
        material = "".join(rng.choices(alphabet, k=80)) + "SYNTHETIC_SECRET_END"
        evidence = json.dumps({"password": material, "public": "kept"}, ensure_ascii=False)
        assert safe_text(evidence) == '{"password": [REDACTED], "public": "kept"}'


@pytest.mark.parametrize("field", ["host", "matched_at"])
def test_http_explicit_object_retains_url_separation_and_privacy(field):
    rows = [make_observation(**{field: url}, affected_object="PRIVATE_OBJECT")
            for url in ("https://site.example/a", "https://site.example/b")]
    assert aggregate(rows)["finding_count"] == 2
    assert "PRIVATE_OBJECT" not in json.dumps(aggregate(rows))
    assert rows[0]["subject"]["object_id"].startswith("url-object:")
    assert aggregate([rows[0], copy.deepcopy(rows[0])])["observation_count"] == 1


def test_url_only_and_bare_object_hashes_keep_existing_semantics():
    expected = "url:" + digest(["https", "site.example:443", "/api", ""])
    url_only = make_observation(host="https://site.example/api")
    assert url_only["subject"]["object_id"] == expected
    for empty in (None, ""):
        assert make_observation(host="https://site.example/api", affected_object=empty) == url_only
    bare = make_observation(affected_object="private-object")
    assert bare["subject"]["object_id"] == "object:" + digest("private-object")
    explicit = make_observation(host="https://site.example/api", affected_object="private-object")
    assert aggregate([url_only, explicit])["finding_count"] == 2


def test_http_object_combination_is_normalized_before_hashing():
    first = make_observation(host="https://SITE.example/api", affected_object="one")
    second = make_observation(host="https://site.example:443/api", affected_object="one")
    assert first == second


def test_truncation_survives_json_round_trips_and_all_merge_orders():
    capped = aggregate([make_observation(ref_index=i) for i in range(9)])
    stored = capped["findings"][0]["observations"][0]
    inputs = [stored, make_observation(ref_index=0), make_observation(ref_index=1)]
    untouched = copy.deepcopy(inputs)
    for order in itertools.permutations(inputs):
        result = aggregate(list(order))
        assert result == capped
        for _ in range(3):
            round_trip = json.loads(json.dumps(result))
            result = aggregate(round_trip["findings"][0]["observations"])
            assert result == capped
    assert inputs == untouched


@pytest.mark.parametrize("flag", [None, 0, 1, "true"])
def test_invalid_reference_completeness_is_not_silently_coerced(flag):
    row = make_observation()
    row["artifact_refs_truncated"] = flag
    with pytest.raises(ValueError, match="reference completeness"):
        aggregate([row])


@pytest.mark.parametrize("line_ending", ["\n", "\r\n"])
@pytest.mark.parametrize("last_newline", [False, True])
def test_jsonl_physical_lines_include_blank_lines_and_preserve_file_hash(tmp_path, line_ending, last_newline):
    def event(rule):
        return json.dumps({
            "host": "192.0.2.1", "port": 443, "type": "tcp", "template-id": rule,
            "response": "ignored\u0085\u2028\u2029",
            "info": {"classification": {"cve-id": ["CVE-2024-1234"]}},
        }, ensure_ascii=False)
    data = line_ending.join([event("first"), "", event("last")])
    if last_newline:
        data += line_ending
    path = tmp_path / "nuclei_raw.jsonl"
    original = data.encode("utf-8")
    path.write_bytes(original)
    result = write_evidence_artifact(tmp_path, tenant_id="tenant", run_id="run")
    assert not result["projection_incomplete"]
    rows = [row for finding in result["findings"] for row in finding["observations"]]
    assert {row["rule_id"]: row["artifact_refs"][0]["locator"] for row in rows} == {
        "first": "line:1", "last": "line:3",
    }
    assert all(row["artifact_refs"][0]["sha256"] == hashlib.sha256(original).hexdigest() for row in rows)
    assert path.read_bytes() == original


def test_jsonl_malformed_physical_record_does_not_shift_next_locator(tmp_path):
    valid = json.dumps({"host": "192.0.2.1", "port": 443, "type": "tcp", "template-id": "last"})
    (tmp_path / "nuclei_raw.jsonl").write_text('not JSON\n\n' + valid, encoding="utf-8")
    result = EvidenceReader(tmp_path, "tenant", "run").build()
    assert result["projection_incomplete"]
    assert result["observation_count"] == 1
    row = result["findings"][0]["observations"][0]
    assert row["artifact_refs"][0]["locator"] == "line:3"
    assert {"artifact": "nuclei_raw.jsonl", "code": "invalid_jsonl_row"} in result["diagnostics"]
