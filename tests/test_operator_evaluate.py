"""Acceptance scorer math and independent domain fixtures, never model results."""
import copy
import asyncio
import errno
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from api.services.local_operator import analysis, planner

PATH = Path(__file__).parents[1] / "scripts/operator-evaluate.py"
SPEC = importlib.util.spec_from_file_location("operator_evaluate", PATH)
evaluation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluation)
DATASET = evaluation.load_dataset()
CASES = DATASET["cases"]


def test_durability_preflight_exercises_rename_readback_and_directory_fsync(tmp_path):
    proof = evaluation.durable_storage_preflight(tmp_path)
    assert proof["passed"] is True
    assert proof["version"] == "file-rename-directory-fsync-v1"
    assert list(tmp_path.iterdir()) == []


def test_virtiofs_directory_ebadf_aborts_before_any_model_call(tmp_path, monkeypatch):
    def unsupported(_):
        raise OSError(errno.EBADF, "Directory fsync unsupported")
    monkeypatch.setattr(evaluation, "_sync_directory", unsupported)
    monkeypatch.setattr(evaluation, "evaluate_one", lambda *_: pytest.fail("Storage failure reached model"))
    args = SimpleNamespace(provenance_json=None, soak_seconds=0, limit=None, case_id=None,
        manifest=None, development=True, output=str(tmp_path / "results"), resume=False,
        require_native_filesystem=False)
    with pytest.raises(OSError) as caught:
        asyncio.run(evaluation.run(args))
    assert caught.value.errno == errno.EBADF
    assert not (tmp_path / "results/inflight.json").exists()
    assert not (tmp_path / "results/run.json").exists()


def test_new_output_ancestors_have_parent_links_fsynced_before_preflight(tmp_path, monkeypatch):
    synced = []
    monkeypatch.setattr(evaluation, "_sync_directory", lambda path: synced.append(path))
    def after_links(directory, **_):
        assert synced == [tmp_path, tmp_path / "a", tmp_path / "a/b"]
        assert directory == tmp_path / "a/b/results"
        raise ValueError("stopped_after_parent_link_validation")
    monkeypatch.setattr(evaluation, "durable_storage_preflight", after_links)
    args = SimpleNamespace(provenance_json=None, soak_seconds=0, limit=None, case_id=None,
        manifest=None, development=True, output=str(tmp_path / "a/b/results"), resume=False,
        require_native_filesystem=False)
    with pytest.raises(ValueError, match="parent_link_validation"):
        asyncio.run(evaluation.run(args))


@pytest.mark.parametrize("filesystem", ["ext4", "virtiofs", "overlay"])
def test_native_mode_requires_actual_ext4_mount_before_inference(tmp_path, monkeypatch, filesystem):
    is_file, read_text = Path.is_file, Path.read_text
    monkeypatch.setattr(Path, "is_file", lambda p: True if str(p) == "/proc/self/mountinfo" else is_file(p))
    monkeypatch.setattr(Path, "read_text", lambda p, *a, **kw:
        f"1 0 0:1 / / rw - {filesystem} device rw\n" if str(p) == "/proc/self/mountinfo" else read_text(p, *a, **kw))
    if filesystem != "ext4":
        with pytest.raises(ValueError, match="requires_native_ext4"):
            evaluation.durable_storage_preflight(tmp_path, require_native=True)
    else:
        proof = evaluation.durable_storage_preflight(tmp_path, require_native=True)
        assert proof["passed"] and proof["filesystem_type"] == "ext4" and proof["native_ext4_required"]


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
    assert report["subgroups"]["development_exposed"]["total"] == 11
    assert report["subgroups"]["untouched_by_development_pilot"]["total"] == 179
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


def test_soak_inflight_recovery_preserves_initial_gold_and_failed_iteration(tmp_path):
    case = CASES[0]
    initial = record_from_gold(case)
    initial_bytes = evaluation.canonical(initial) + "\n"
    (tmp_path / "records.jsonl").write_text(initial_bytes)
    identity = evaluation.begin_execution(tmp_path, case, phase="soak", soak_iteration=1)
    result = evaluation.recover_inflight(tmp_path, [initial], [case])
    assert result == [initial] and initial["valid"]
    assert (tmp_path / "records.jsonl").read_text() == initial_bytes
    recovered = json.loads((tmp_path / "soak-records.jsonl").read_text())
    assert recovered["execution_id"] == identity["execution_id"]
    assert recovered["phase"] == "soak" and recovered["soak_iteration"] == 1
    assert not recovered["valid"] and recovered["recovered_inflight"]
    assert recovered["error_code"] == "evaluation_interrupted_before_receipt"
    next_identity = evaluation.begin_execution(tmp_path, case, phase="soak", soak_iteration=2)
    assert next_identity["execution_id"] != recovered["execution_id"]


def test_completed_soak_with_stale_journal_is_not_duplicated_or_moved_to_initial(tmp_path):
    case = CASES[0]
    identity = evaluation.begin_execution(tmp_path, case, phase="soak", soak_iteration=3)
    record = {**record_from_gold(case), **identity}
    (tmp_path / "soak-records.jsonl").write_text(evaluation.canonical(record) + "\n")
    assert evaluation.recover_inflight(tmp_path, [], [case]) == []
    assert len((tmp_path / "soak-records.jsonl").read_text().splitlines()) == 1
    assert not (tmp_path / "records.jsonl").exists()
    assert not (tmp_path / "inflight.json").exists()


def test_journal_is_atomic_fsynced_and_cannot_overwrite_uncertain_execution(tmp_path, monkeypatch):
    syncs = []
    replacements = []
    original_replace = evaluation.os.replace
    def replace(source, target):
        assert json.loads(Path(source).read_text())["phase"] == "initial"
        replacements.append((source, target))
        original_replace(source, target)
    monkeypatch.setattr(evaluation.os, "replace", replace)
    monkeypatch.setattr(evaluation.os, "fsync", lambda descriptor: syncs.append(descriptor))
    identity = evaluation.begin_execution(tmp_path, CASES[0], phase="initial", ordinal=1)
    assert identity["execution_id"] == "initial:" + CASES[0]["case_id"]
    assert len(replacements) == 1 and len(syncs) == 2
    assert not list(tmp_path.glob(".inflight-*"))
    with pytest.raises(ValueError, match="Recover"):
        evaluation.begin_execution(tmp_path, CASES[0], phase="soak", soak_iteration=1)


def test_resume_cannot_count_a_duplicated_soak_execution_as_new_load(tmp_path):
    case = CASES[0]
    record = {**record_from_gold(case), "phase": "soak", "soak_iteration": 1,
              "execution_id": f"soak:1:{case['case_id']}"}
    (tmp_path / "soak-records.jsonl").write_text((evaluation.canonical(record) + "\n") * 2)
    with pytest.raises(ValueError, match="execution order/identity"):
        evaluation.soak_history(tmp_path)
