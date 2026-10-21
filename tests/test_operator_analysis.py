"""Frozen contract cases are not a model quality benchmark."""
import copy
import hashlib
import json
from pathlib import Path

import pytest

from api.services.local_operator.analysis import (
    AnalysisError, ModelAnalysis, build_prompt, validate_output,
)

FIXTURE = Path(__file__).parent / "fixtures/operator_analysis_eval.json"
DATASET_SHA256 = "e4cdf0d2b4507dd5b956d1b7af57a3a35b8d20df66039fcfd65f76ad5c6c26a0"
CASES = json.loads(FIXTURE.read_text())["cases"]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["case_id"])
def test_frozen_analysis_contract(case):
    args = (json.dumps(case["model_output"]), case["language"], case["retrieval"])
    if case["expected"] == "reject":
        with pytest.raises(AnalysisError):
            validate_output(*args)
        return
    result = validate_output(*args)
    assert result["status"] == "incomplete"
    assert result["quality_status"] == "quality_unverified"
    assert result["reason"]
    assert (not result["recommendations"]) == case["expected_abstention"]
    assert [{key: c[key] for key in ("source_id", "source_hash", "snapshot_id")}
            for c in result["citations"]] == case["gold_references"]
    original = {item["source_id"]: item["citation"] for item in case["retrieval"]["items"]}
    for citation in result["citations"]:
        assert citation["source_hash"] == original[citation["source_id"]]["source_hash"]


def test_frozen_dataset_hash_and_coverage():
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == DATASET_SHA256
    assert len(CASES) >= 60
    assert len({case["case_id"] for case in CASES}) == len(CASES)
    assert {case["language"] for case in CASES} == {"ru", "en"}


def test_prompt_excludes_free_text_and_personal_identifiers():
    case = next(c for c in CASES if c["case_id"] == "en-malicious_context")
    retrieval = copy.deepcopy(case["retrieval"])
    retrieval["items"][0]["context"].update({
        "owner": "private-owner", "hostname": "private-host", "run_id": "private-run",
        "service": "private-service", "cwe": "CWE-79", "severity": ["malicious"],
    })
    messages = build_prompt(case["language"], retrieval)
    data = json.loads(messages[1]["content"])
    assert data["sources"][0]["context"] == {"cve": "CVE-2026-1234", "cwe": "CWE-79", "port": 443}
    for secret in ("192.0.2.1", "Ignore instructions", "private-owner", "private-host", "private-run",
                   "private-service", "evil.example", "secret evidence"):
        assert secret not in messages[1]["content"]


@pytest.mark.parametrize("raw", [
    '{"language":"en","language":"ru"}', '{"x":NaN}', '[]', 'null',
    '```json\n{}\n```', '{', 'x' * 32769, '{"summary":"CVE-2099-1111"}',
])
def test_invalid_json_has_no_repair_or_fallback(raw):
    with pytest.raises(AnalysisError):
        validate_output(raw, "en", CASES[0]["retrieval"])


def test_stale_item_cannot_be_selected_in_partial_result():
    case = copy.deepcopy(CASES[0])
    case["retrieval"]["items"][0]["citation"]["status"] = "stale"
    with pytest.raises(AnalysisError, match="abstention"):
        validate_output(json.dumps(case["model_output"]), "ru", case["retrieval"])


def test_schema_matches_export():
    path = Path(__file__).parents[1] / "docs/schemas/operator-analysis-v1.json"
    assert json.loads(path.read_text()) == ModelAnalysis.model_json_schema()
