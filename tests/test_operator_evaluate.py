"""Acceptance scorer math and independent domain fixtures, never model results."""
import copy
import asyncio
import errno
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from datetime import UTC, datetime, timedelta

import pytest

from api.services.local_operator import analysis, planner
from tests.operator_planner_wire import intent_wire

PATH = Path(__file__).parents[1] / "scripts/operator-evaluate.py"
SPEC = importlib.util.spec_from_file_location("operator_evaluate", PATH)
evaluation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluation)
DATASET = evaluation.load_dataset()
CASES = DATASET["cases"]


def launch_permit(nonce="c" * 32, cid="a" * 64, now=None):
    now = now or datetime.now(UTC)
    return {"schema_version": 1, "nonce": nonce, "container_id": cid,
            "requested_at": (now - timedelta(seconds=1)).isoformat(), "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=59)).isoformat()}


@pytest.mark.parametrize("mutation", ["missing_after_late_start", "foreign_nonce", "foreign_cid", "expired", "excessive_ttl"])
def test_unauthorized_launch_never_reaches_provider(tmp_path, monkeypatch, mutation):
    nonce = "c" * 32
    monkeypatch.setenv(evaluation.LAUNCH_NONCE_ENV, nonce)
    monkeypatch.setattr(evaluation.socket, "gethostname", lambda: "a" * 12)
    monkeypatch.setattr(evaluation, "evaluate_one", lambda *_: pytest.fail("Unauthorized launch reached provider"))
    permit = launch_permit()
    if mutation == "missing_after_late_start":
        clock = iter([0, 61])
        monkeypatch.setattr(evaluation, "monotonic", lambda: next(clock))
    else:
        if mutation == "foreign_nonce":
            permit["nonce"] = "d" * 32
        elif mutation == "foreign_cid":
            permit["container_id"] = "b" * 64
        elif mutation == "expired":
            permit = launch_permit(now=datetime.now(UTC) - timedelta(seconds=120))
        else:
            permit["expires_at"] = (datetime.now(UTC) + timedelta(seconds=3600)).isoformat()
        (tmp_path / ("launch-permit-" + nonce + ".json")).write_text(json.dumps(permit))
    args = SimpleNamespace(provenance_json=None, soak_seconds=0, limit=None, case_id=None,
        manifest=None, development=True, output=str(tmp_path / "results"), resume=False,
        require_native_filesystem=False, require_launch_permit=True)
    with pytest.raises(ValueError, match="launch_permit"):
        asyncio.run(evaluation.run(args))
    assert not (tmp_path / "results/inflight.json").exists()
    assert not (tmp_path / "results/records.jsonl").exists()


def test_valid_launch_permit_is_cid_bound_and_durably_copied_for_export(tmp_path, monkeypatch):
    nonce = "c" * 32
    monkeypatch.setenv(evaluation.LAUNCH_NONCE_ENV, nonce)
    monkeypatch.setattr(evaluation.socket, "gethostname", lambda: "a" * 12)
    permit = launch_permit()
    (tmp_path / ("launch-permit-" + nonce + ".json")).write_text(json.dumps(permit))
    output = tmp_path / "results"
    output.mkdir()
    proof = asyncio.run(evaluation.authorize_launch(output, required=True))
    assert proof["container_id"] == "a" * 64 and proof["nonce"] == nonce
    copied = output / ("launch-authorization-" + nonce + ".json")
    assert json.loads(copied.read_text()) == permit
    assert proof["permit_sha256"] == evaluation.file_digest(copied)


def test_permit_is_rechecked_at_first_provider_dispatch_after_preparation_delay(monkeypatch):
    monkeypatch.setenv(evaluation.LAUNCH_NONCE_ENV, "c" * 32)
    monkeypatch.setattr(evaluation.socket, "gethostname", lambda: "a" * 12)
    monkeypatch.setattr(evaluation, "InferenceProvider", lambda *a, **kw: pytest.fail("Expired authority reached provider"))
    expired = launch_permit(now=datetime.now(UTC) - timedelta(seconds=120))
    record = asyncio.run(evaluation.evaluate_one(CASES[0], None, expired))
    assert record["launch_authorization_rejected"] and record["model_invoked"] is False and record["valid"] is False
    assert record["request_wire"] is None


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
        sources = {item["source_id"]: index for index, item in enumerate(
            item for item in case["retrieval"]["items"] if item["citation"]["status"] != "stale")}
        raw = {"language": case["language"], "summary": case["gold"]["summary"], "recommendations": [
            {"source_ref": sources[label["source_id"]],
             "category": label["category"], "proposed_priority": label["proposed_priority"], "next_steps": ["verify_evidence"]}
            for label in case["gold"]["labels"]]}
        record["model_content"] = json.dumps(raw)
        record["result"] = analysis.validate_output(record["model_content"], case["language"], analysis.bind(case["retrieval"]))
    else:
        record["model_content"] = intent_wire(case["gold"]["tool"])
        record["result"] = planner.validate_output(record["model_content"], planner.PlanRequest.model_validate(case["planner_request"]))
        if case["kind"] == "remediation":
            record["domain_result"] = evaluation.domain_remediation(case)
    return record


def test_contextfree_intent_wire_is_closed_in_unsupported_claim_accounting():
    case = {"kind": "planning"}
    raw = json.loads(intent_wire("cancel_scan"))
    assert evaluation.unsupported_model_fields(case, {"model_content": json.dumps(raw)}) == 0
    raw["arguments"] = {"job_id": "model-owned"}
    assert evaluation.unsupported_model_fields(case, {"model_content": json.dumps(raw)}) == 1
    with pytest.raises(evaluation.planner.gateway.GatewayError):
        planner.validate_output(json.dumps(raw), planner.PlanRequest(request="Cancel selected job.", context={"job_id": "server-owned"}))


def test_contextfree_literal_spans_cannot_smuggle_identity_fields():
    raw = json.loads(intent_wire("cancel_scan", selector="explicit", mentions=[
        {"start": 0, "end": 9, "job_id": "model-owned"}]))
    assert evaluation.unsupported_model_fields({"kind": "planning"}, {"model_content": json.dumps(raw)}) == 1
    with pytest.raises(evaluation.planner.gateway.GatewayError):
        planner.validate_output(json.dumps(raw), planner.PlanRequest(request="job-larch", context={"job_id": "job-larch"}))


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


def _with_untouched_cases(monkeypatch, keep=1):
    """Pretend all but the first `keep` cases are untouched by the development pilots."""
    real = evaluation.exposure_provenance
    monkeypatch.setattr(evaluation, "exposure_provenance", lambda dataset: {
        **real(dataset), "development_exposed_case_ids": [c["case_id"] for c in dataset["cases"]][:keep],
        "untouched_case_count": len(dataset["cases"]) - keep})


def _gate_failures(records, stage="final"):
    report = evaluation.summarize(DATASET, records, stage=stage)
    return {name for name, ok in report["gates"].items() if not ok and name != "first_response_latency"}


def _break_category(records):
    for case, record in zip(CASES, records, strict=True):
        if case["kind"] == "analysis":
            raw = json.loads(record["model_content"])
            for item in raw["recommendations"]:
                item["category"] = "__wrong__"
            record["model_content"] = json.dumps(raw)


def _break_fixed_recall(records):
    for case, record in zip(CASES, records, strict=True):
        if case["kind"] == "remediation" and case["gold"]["target_version"]:
            record["domain_result"]["items"] = []  # the fix exists but was not supplied
            return


def _break_citation(records):
    # Dangling compact references: not a registered source, so they only enter the citation denominator.
    for case, record in list(zip(CASES, records, strict=True))[:60]:
        if "retrieval" in case:
            raw = json.loads(record["model_content"])
            raw["recommendations"].append({"source_ref": 999, "category": "unknown",
                                           "proposed_priority": "unknown", "next_steps": ["verify_evidence"]})
            record["model_content"] = json.dumps(raw)


def _break_security(records):
    for case, record in zip(CASES, records, strict=True):
        if case["kind"] == "security" and record["result"]["recommendations"]:
            record["result"]["recommendations"][0]["category"] = "__wrong__"
            return


def _break_planning(records):
    broken = 0
    for case, record in zip(CASES, records, strict=True):
        if case["kind"] == "planning" and broken < 2:  # 28/30 < .95 while tool accuracy stays >= .95
            record["result"]["tool"] = "__wrong__"
            broken += 1


@pytest.mark.parametrize("gate,mutate", [
    ("category_macro_f1", _break_category), ("fixed_claim_recall", _break_fixed_recall),
    ("citation_precision", _break_citation), ("security", _break_security),
    ("planning_accuracy", _break_planning)])
def test_spoiling_one_indicator_turns_exactly_that_gate_red(gate, mutate):
    records = [record_from_gold(case) for case in CASES]
    assert _gate_failures(records) == set()
    mutate(records)
    assert _gate_failures(records) == {gate}
    assert not evaluation.summarize(DATASET, records, stage="final")["quality_gate_passed"]


def test_security_gate_reads_its_threshold_from_the_frozen_fixture(monkeypatch):
    real = evaluation.exposure_provenance  # the edited copy below would fail the corpus-digest check
    monkeypatch.setattr(evaluation, "exposure_provenance", lambda dataset: real(DATASET))
    records = [record_from_gold(case) for case in CASES]
    _break_security(records)
    relaxed = copy.deepcopy(DATASET)
    relaxed["thresholds"]["security_pass_fraction_min"] = .9
    assert evaluation.summarize(relaxed, records, stage="final")["gates"]["security"]
    assert not evaluation.summarize(DATASET, records, stage="final")["gates"]["security"]


def test_priority_abstention_and_degraded_are_reported_but_informational():
    # The frozen thresholds have no minimum for them, so a failure there must not be hidden or silently gated.
    assert not {"proposed_priority_macro_f1_min", "abstention_accuracy_min"} & set(DATASET["thresholds"])
    records = [record_from_gold(case) for case in CASES]
    for case, record in zip(CASES, records, strict=True):
        if case["kind"] == "analysis":
            raw = json.loads(record["model_content"])
            for item in raw["recommendations"]:
                item["proposed_priority"] = "__wrong__"
            record["model_content"] = json.dumps(raw)
    report = evaluation.summarize(DATASET, records, stage="final")
    assert report["proposed_priority_macro_f1"]["value"] < 1
    assert report["informational_metrics"] == ["proposed_priority_macro_f1", "abstention_accuracy", "subgroups.degraded"]
    assert not set(report["informational_metrics"]) & set(report["gates"])


def test_full_response_latency_keeps_the_deprecated_first_response_alias():
    report = evaluation.summarize(DATASET, [record_from_gold(case) for case in CASES], stage="final")
    assert report["gates"]["first_response_latency"] == report["gates"]["full_response_latency"]
    assert report["latency_seconds"]["scope"].startswith("model call")
    slow = [record_from_gold(case) for case in CASES]
    for record in slow:
        record["elapsed_seconds"] = 60.0
    report = evaluation.summarize(DATASET, slow, stage="final")
    assert not report["gates"]["full_response_latency"] and not report["gates"]["first_response_latency"]


def test_fully_exposed_corpus_is_exposed_only_never_a_passed_gate():
    report = evaluation.summarize(DATASET, [record_from_gold(case) for case in CASES], stage="final")
    assert all(v for k, v in report["gates"].items())
    assert report["quality_gate_status"] == "exposed_only"
    assert not report["quality_gate_passed"]
    assert report["category_macro_f1"]["value"] == 1.0  # the informative report is still complete


def test_gate_passes_only_with_untouched_cases(monkeypatch):
    _with_untouched_cases(monkeypatch)
    report = evaluation.summarize(DATASET, [record_from_gold(case) for case in CASES], stage="final")
    assert report["quality_gate_status"] == "passed" and report["quality_gate_passed"]
    dev = evaluation.summarize(DATASET, [record_from_gold(case) for case in CASES], stage="development")
    assert dev["quality_gate_status"] == "failed" and not dev["quality_gate_passed"]


def _final_args(tmp_path, soak):
    return SimpleNamespace(provenance_json=None, soak_seconds=soak, limit=None, case_id=None, kind=None,
        manifest=str(tmp_path / "manifest.json"), development=False, output=str(tmp_path / "results"), resume=False,
        require_native_filesystem=False, require_launch_permit=False, external_resource_sampling=True,
        base_url="http://127.0.0.1:1/v1")


@pytest.mark.parametrize("soak,status,expected_exit", [(0, "passed", 1), (3599, "passed", 1), (3600, "passed", 0),
                                                       (3600, "exposed_only", 1)])
def test_final_run_needs_an_hour_of_soak_and_a_non_exposed_corpus(tmp_path, monkeypatch, soak, status, expected_exit):
    clock = {"now": 0.0}
    monkeypatch.setattr(evaluation, "monotonic", lambda: clock.__setitem__("now", clock["now"] + soak / 40) or clock["now"])
    # Live provenance shells out to docker, which the CI container does not have.
    monkeypatch.setattr(evaluation, "runtime_provenance", lambda: {"sealed_for_test": True})
    (tmp_path / "manifest.json").write_text(json.dumps({
        "dataset_sha256": evaluation.file_digest(evaluation.DATASET), "source_sha256": evaluation.source_provenance(),
        "thresholds": DATASET["thresholds"], "runtime": evaluation.runtime_provenance()}))
    monkeypatch.setattr(evaluation, "durable_storage_preflight", lambda *a, **k: {})
    monkeypatch.setattr(evaluation, "sample_resources", lambda *a, **k: asyncio.sleep(0))
    by_id = {case["case_id"]: record_from_gold(case) for case in CASES}

    async def fake_evaluate(case, *_):
        return dict(by_id[case["case_id"]], elapsed_seconds=1.0)
    monkeypatch.setattr(evaluation, "evaluate_one", fake_evaluate)
    if status == "passed":
        _with_untouched_cases(monkeypatch)
    assert asyncio.run(evaluation.run(_final_args(tmp_path, soak))) == expected_exit
    report = json.loads((tmp_path / "results/report.json").read_text())
    assert report["quality_gate_status"] == status  # the informative report is saved either way
    assert report["run_gate_passed"] == (expected_exit == 0)
    if soak < 3600:
        assert not report["load"]["final_soak_requirement_met"]


def test_perfect_supplied_records_only_verify_scorer_not_model_quality():
    records = [record_from_gold(case) for case in CASES]
    report = evaluation.summarize(DATASET, records, stage="final")
    assert report["quality_gate_status"] == "exposed_only"
    assert report["category_macro_f1"]["value"] == 1.0
    assert report["citation_precision"]["value"] == 1.0
    assert report["tool_accuracy"]["total"] == 70
    assert report["subgroups"]["development_exposed"]["total"] == 190
    assert report["subgroups"]["untouched_by_development_pilot"]["total"] == 0
    assert report["subgroups"]["untouched_by_development_pilot"]["value"] is None
    assert report["development_exposure"]["historical_pre_attempt_split"] == {"exposed": 11, "untouched": 179}
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


def test_fast_503s_cannot_pass_latency_gates_by_diluting_the_percentile():
    records = [record_from_gold(case) for case in CASES]
    for i in range(20, len(records)):
        records[i] = {"case_id": CASES[i]["case_id"], "valid": False, "model_invoked": True,
                      "response_status": 503, "error_code": "operator_upstream_rejected", "elapsed_seconds": .005}
    report = evaluation.summarize(DATASET, records, stage="final")
    assert report["latency_seconds"]["count"] == 190
    assert report["latency_seconds"]["p95"] == 1.0  # Preserve all-attempt timing, including fast failures.
    assert report["latency_seconds"]["valid_response_count"] == 20
    assert report["latency_seconds"]["required_response_count"] == 190
    assert report["latency_seconds"]["valid_response_p95"] == 1.0
    assert not report["latency_seconds"]["valid_response_coverage_complete"]
    assert not report["gates"]["full_response_latency"]
    assert not report["gates"]["task_component_latency"]
    assert not report["quality_gate_passed"]


@pytest.mark.parametrize("duration", [None, float("nan"), float("inf"), -1, True])
def test_invalid_valid_response_duration_cannot_complete_latency_coverage(duration):
    records = [record_from_gold(case) for case in CASES]
    records[0]["elapsed_seconds"] = duration
    report = evaluation.summarize(DATASET, records, stage="final")
    assert report["latency_seconds"]["valid_response_count"] == 189
    assert not report["gates"]["full_response_latency"]
    assert not report["gates"]["task_component_latency"]


def test_unreviewed_corpus_cannot_inherit_a_hidden_or_exposed_claim():
    changed = copy.deepcopy(DATASET)
    changed["cases"][0]["case_id"] = "new-independent-case"
    with pytest.raises(ValueError, match="exposure-policy review"):
        evaluation.exposure_provenance(changed)


@pytest.mark.parametrize("case_id,source_id,field,wrong", [
    ("analysis-ru-cve-low-http", "a-ru-04-secondary", "category", "vulnerability"),
    ("analysis-ru-cve-info-dns", "a-ru-05", "category", "exposure"),
    ("analysis-ru-cve-unknown-redis", "a-ru-06", "category", "unknown"),
    ("analysis-ru-cve-missing-severity", "a-ru-07", "proposed_priority", "high"),
    ("analysis-ru-cve-no-service", "a-ru-10", "category", "exposure"),
    ("analysis-ru-cve-ftp-low", "a-ru-13", "category", "exposure"),
    ("analysis-ru-cve-snmp-unknown", "a-ru-15", "category", "unknown"),
    ("analysis-ru-cwe-credentials", "a-ru-17", "category", "vulnerability"),
    ("analysis-ru-cwe-authentication", "a-ru-18", "category", "vulnerability"),
])
def test_actual_failed_run_label_errors_stay_wrong_without_auto_repair(case_id, source_id, field, wrong):
    case = next(c for c in CASES if c["case_id"] == case_id)
    record = record_from_gold(case)
    raw = json.loads(record["model_content"])
    source_ref = next(i for i, item in enumerate(case["retrieval"]["items"]) if item["source_id"] == source_id)
    selected = next(item for item in raw["recommendations"] if item["source_ref"] == source_ref)
    assert selected[field] != wrong
    selected[field] = wrong
    record["model_content"] = json.dumps(raw)
    record["result"] = analysis.validate_output(record["model_content"], case["language"], analysis.bind(case["retrieval"]))
    assert next(item for item in record["result"]["recommendations"] if item["source_id"] == source_id)[field] == wrong
    assert not evaluation.score_case(case, record)
    selection = analysis.output_schema(analysis.bind(case["retrieval"]), language=case["language"])["$defs"]["CompactSelection"]
    assert "const" not in selection["properties"][field]
    assert wrong in selection["properties"][field]["enum"]


def test_valid_but_wrong_labels_do_not_turn_latency_into_a_stricter_accuracy_threshold():
    records = [record_from_gold(case) for case in CASES]
    records[0]["result"]["recommendations"][0]["category"] = "unknown"
    report = evaluation.summarize(DATASET, records, stage="final")
    assert not evaluation.score_case(CASES[0], records[0])
    assert report["gates"]["full_response_latency"]
    assert report["gates"]["task_component_latency"]


def test_abstain_everything_cannot_pass_accuracy_or_citation_gate():
    records = [record_from_gold(case) for case in CASES]
    for case, record in zip(CASES, records, strict=True):
        if "retrieval" in case:
            record["model_content"] = json.dumps({"language": case["language"], "summary": "insufficient_evidence", "recommendations": []})
            record["result"] = analysis.validate_output(record["model_content"], case["language"], analysis.bind(case["retrieval"]))
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


@pytest.mark.parametrize("ref", [True, 0.0, "0", -1, 999, None, {}, []])
def test_invalid_compact_references_count_as_unsupported_even_when_output_is_invalid(ref):
    case = CASES[0]
    raw = json.loads(record_from_gold(case)["model_content"])
    raw["recommendations"][0]["source_ref"] = ref
    record = {"case_id": case["case_id"], "valid": False, "model_invoked": True,
              "model_content": json.dumps(raw), "elapsed_seconds": 1.0}
    report = evaluation.summarize(DATASET, [record], stage="development")
    assert report["citation_precision"]["total"] == 1
    assert report["citation_precision"]["correct"] == 0
    assert report["unsupported_reference_or_fixed_claims"] == 1


def test_duplicate_compact_ref_cannot_inflate_reference_precision_or_recall():
    case = CASES[0]
    raw = json.loads(record_from_gold(case)["model_content"])
    raw["recommendations"].append(copy.deepcopy(raw["recommendations"][0]))
    record = {"case_id": case["case_id"], "valid": False, "model_invoked": True,
              "model_content": json.dumps(raw), "elapsed_seconds": 1.0}
    report = evaluation.summarize(DATASET, [record], stage="development")
    assert report["citation_precision"] == evaluation.proportion(1, 2)
    assert report["source_selection_recall"]["correct"] == 1
    assert report["unsupported_reference_or_fixed_claims"] == 1


@pytest.mark.parametrize("malformed", [[None], ["source-ref-0"], {"source_ref": 0}, None])
def test_malformed_compact_selection_claims_are_not_dropped_from_denominator(malformed):
    record = {"case_id": CASES[0]["case_id"], "valid": False, "model_invoked": True,
              "model_content": json.dumps({"recommendations": malformed}), "elapsed_seconds": 1.0}
    report = evaluation.summarize(DATASET, [record], stage="development")
    assert report["citation_precision"]["total"] == 1
    assert report["citation_precision"]["correct"] == 0


def test_evaluator_checks_expanded_public_citation_against_original_registry():
    case = CASES[0]
    record = record_from_gold(case)
    record["result"]["recommendations"][0]["source_hash"] = "f" * 64
    report = evaluation.summarize(DATASET, [record], stage="development")
    assert report["citation_precision"]["value"] == 0
    assert report["unsupported_reference_or_fixed_claims"] == 1


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
    schema = analysis.output_schema(analysis.bind(case["retrieval"]), language=case["language"])
    assert schema["properties"]["summary"]["const"] == "review_required"
    assert schema["properties"]["recommendations"]["minItems"] == 1
    variant = schema["$defs"]["CompactSelection"]
    assert "const" not in variant["properties"]["category"]
    assert "const" not in variant["properties"]["proposed_priority"]
    missing = next(case for case in CASES if case["kind"] == "degraded" and case["retrieval"]["state"] == "missing")
    abstention = analysis.output_schema(analysis.bind(missing["retrieval"]), language=missing["language"])
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
    assert not report["gates"]["full_response_latency"]
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
