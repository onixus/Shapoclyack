"""Acceptance scorer math and independent domain fixtures, never model results."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

from api.services.local_operator import analysis, planner

PATH = Path(__file__).parents[1] / "scripts/operator-evaluate.py"
SPEC = importlib.util.spec_from_file_location("operator_evaluate", PATH)
evaluation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluation)
DATASET = evaluation.load_dataset()
CASES = DATASET["cases"]


def record_from_gold(case):
    record = {"case_id": case["case_id"], "valid": True, "model_invoked": True, "elapsed_seconds": 1.0}
    if "retrieval" in case:
        sources = {item["source_id"]: item for item in case["retrieval"]["items"]}
        raw = {"language": case["language"], "summary": case["gold"]["summary"], "recommendations": [
            {**{key: sources[label["source_id"]][key] for key in ("source_id", "source_hash", "snapshot_id")},
             "category": label["category"], "proposed_priority": label["proposed_priority"], "next_steps": ["verify_evidence"]}
            for label in case["gold"]["labels"]]}
        record["model_content"] = json.dumps(raw)
        record["result"] = analysis.validate_output(record["model_content"], case["language"], case["retrieval"])
    else:
        record["model_content"] = json.dumps({"tool": case["gold"]["tool"]})
        record["result"] = planner.validate_output(record["model_content"], planner.PlanRequest.model_validate(case["planner_request"]))
        if case["kind"] == "remediation":
            record["domain_result"] = evaluation.domain_remediation(case)
    return record


def test_frozen_scenario_composition_and_labels_independent_of_model_outputs():
    assert evaluation.file_digest(evaluation.DATASET) == "3b059f9975627d5576a86518572e1a737c59739c4f4d3ed5beefdc1eb0858779"
    assert len(CASES) >= 190
    assert len({case["case_id"] for case in CASES}) == len(CASES)
    assert all("model_output" not in case for case in CASES)
    assert DATASET["required_counts"] == {"analysis": 60, "remediation": 40, "planning": 30, "degraded": 20, "security": 40}
    assert DATASET["thresholds"]["category_macro_f1_min"] == .85
    assert DATASET["thresholds"]["tool_accuracy_min"] == .95


@pytest.mark.parametrize("case", [case for case in CASES if case["kind"] == "remediation"], ids=lambda c: c["case_id"])
def test_independent_vendor_gold_matches_actual_native_renderer(case):
    record = record_from_gold(case)
    assert evaluation.score_case(case, record), record["domain_result"]


def test_perfect_supplied_records_only_verify_scorer_not_model_quality():
    records = [record_from_gold(case) for case in CASES]
    report = evaluation.summarize(DATASET, records, stage="final")
    assert report["quality_gate_passed"]
    assert report["category_macro_f1"]["value"] == 1.0
    assert report["citation_precision"]["value"] == 1.0
    assert report["tool_accuracy"]["total"] == 70
    assert report["subgroups"]["development_exposed"]["total"] == 6
    assert report["subgroups"]["untouched_by_development_pilot"]["total"] == 184
    assert report["fixed_claim_support"]["total"] > 0
    assert not report["release_acceptance_claimed"]


def test_missing_and_transport_failed_cases_remain_in_denominators():
    records = [record_from_gold(case) for case in CASES]
    records[0] = {"case_id": CASES[0]["case_id"], "valid": False, "model_invoked": True,
                  "error_code": "operator_transport_failed", "elapsed_seconds": 120.0}
    report = evaluation.summarize(DATASET, records[:-1], stage="final")
    assert report["subgroups"]["all"]["total"] == len(CASES)
    assert report["subgroups"]["all"]["correct"] == len(CASES) - 2
    assert report["not_run_count"] == 1 and report["executed_case_failures"] == 1
    assert not report["quality_gate_passed"]
    assert report["latency_seconds"]["max"] == 120.0


def test_abstain_everything_cannot_pass_accuracy_or_citation_gate():
    records = [record_from_gold(case) for case in CASES]
    for case, record in zip(CASES, records, strict=True):
        if "retrieval" in case:
            record["model_content"] = json.dumps({"language": case["language"], "summary": "insufficient_evidence", "recommendations": []})
            record["result"] = analysis.validate_output(record["model_content"], case["language"], case["retrieval"])
    report = evaluation.summarize(DATASET, records, stage="final")
    assert report["category_macro_f1"]["value"] == 0
    assert report["citation_precision"]["value"] is None
    assert not report["quality_gate_passed"]


def test_wrong_fixed_version_and_foreign_reference_are_unsupported_claims():
    records = [record_from_gold(case) for case in CASES]
    index = next(index for index, case in enumerate(CASES) if case["kind"] == "remediation" and case["gold"]["target_version"])
    records[index]["domain_result"]["items"][0]["target_version"] = "fabricated-version"
    raw = json.loads(records[0]["model_content"])
    raw["recommendations"][0]["source_hash"] = "f" * 64
    records[0]["model_content"] = json.dumps(raw)
    records[0]["valid"] = False
    report = evaluation.summarize(DATASET, records, stage="final")
    assert report["unsupported_reference_or_fixed_claims"] == 2
    assert report["fixed_claim_support"]["value"] < 1
    assert not report["quality_gate_passed"]


def test_malformed_model_json_cannot_crash_scorer():
    case = CASES[0]
    record = {"case_id": case["case_id"], "valid": False, "model_invoked": True,
              "model_content": '{"recommendations":null}', "elapsed_seconds": 1}
    report = evaluation.summarize(DATASET, [record], stage="development")
    assert report["subgroups"]["all"]["correct"] == 0
    assert not report["quality_gate_passed"]
    record["model_content"] = '{"summary":[],"recommendations":[{"source_id":[]}]}'
    assert not evaluation.summarize(DATASET, [record], stage="development")["quality_gate_passed"]


def test_unexpected_model_fixed_version_claim_cannot_hide_behind_valid_other_cases():
    records = [record_from_gold(case) for case in CASES]
    raw = json.loads(records[0]["model_content"])
    raw["fixed_version"] = "invented-999"
    records[0]["model_content"] = json.dumps(raw)
    records[0]["valid"] = False
    report = evaluation.summarize(DATASET, records, stage="final")
    assert report["unsupported_model_fields_or_prose"] == 1
    assert not report["gates"]["no_unsupported_model_claims"]
    assert not report["quality_gate_passed"]


def test_development_run_cannot_claim_final_gate_even_with_perfect_records():
    report = evaluation.summarize(DATASET, [record_from_gold(case) for case in CASES], stage="development")
    assert all(report["gates"].values())
    assert not report["quality_gate_passed"]


def test_interval_math_macro_f1_and_failure_latency():
    assert evaluation.wilson(0, 0) is None
    assert evaluation.wilson(0, 10)[0] == 0
    assert evaluation.wilson(10, 10)[1] == pytest.approx(1)
    assert evaluation.macro_f1([("a", "a"), ("b", "__missing__")], ["a", "b"]) == .5
    assert evaluation.quantile([1, 2, 3, 4, 120], .95) == 120
    assert evaluation.proportion(95, 100)["value"] == .95


def test_positive_runtime_schema_requires_a_proposal_without_fixing_gold_labels():
    case = next(case for case in CASES if case["kind"] == "analysis")
    schema = analysis.output_schema(case["retrieval"], language=case["language"])
    assert schema["properties"]["summary"]["const"] == "review_required"
    assert schema["properties"]["recommendations"]["minItems"] == 1
    variant = schema["properties"]["recommendations"]["items"]["anyOf"][0]
    assert "const" not in variant["properties"]["category"]
    assert "const" not in variant["properties"]["proposed_priority"]
    missing = next(case for case in CASES if case["kind"] == "degraded" and case["retrieval"]["state"] == "missing")
    abstention = analysis.output_schema(missing["retrieval"], language=missing["language"])
    assert abstention["properties"]["summary"]["const"] == "insufficient_evidence"
    assert abstention["properties"]["recommendations"]["maxItems"] == 0


def test_injected_evidence_content_hash_is_bound_to_injected_fixture():
    for case in CASES:
        if case["kind"] != "security":
            continue
        item = case["retrieval"]["items"][0]
        expected = evaluation.digest(json.dumps(item["context"], sort_keys=True, separators=(",", ":")).encode())
        assert item["source_hash"] == expected
        assert item["citation"]["source_hash"] == expected


def test_modifying_gold_changes_artifact_digest():
    original = evaluation.canonical(DATASET)
    changed = copy.deepcopy(DATASET)
    changed["cases"][0]["gold"]["labels"][0]["category"] = "unknown"
    assert evaluation.digest(original.encode()) != evaluation.digest(evaluation.canonical(changed).encode())


def test_crashed_inflight_case_is_preserved_as_failure_without_free_retry(tmp_path):
    case = CASES[0]
    evaluation.write_json(tmp_path / "inflight.json", {"case_id": case["case_id"]})
    records = evaluation.recover_inflight(tmp_path, [], [case])
    assert len(records) == 1 and records[0]["case_id"] == case["case_id"]
    assert records[0]["recovered_inflight"] and not records[0]["valid"]
    assert records[0]["elapsed_seconds"] is None
    assert not (tmp_path / "inflight.json").exists()
    report = evaluation.summarize(DATASET, records, stage="final")
    assert report["latency_seconds"]["missing_duration_records"] == 1
    assert not report["gates"]["first_response_latency"]
    assert not report["quality_gate_passed"]


def test_recorded_result_with_stale_journal_is_not_duplicated(tmp_path):
    case = CASES[0]
    record = record_from_gold(case)
    evaluation.write_json(tmp_path / "inflight.json", {"case_id": case["case_id"]})
    assert evaluation.recover_inflight(tmp_path, [record], [case]) == [record]
    assert not (tmp_path / "records.jsonl").exists()
