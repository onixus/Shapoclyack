"""Parsed subject assertions are resolved against typed server context, never substituted."""
import json

import pytest

from api.services.local_operator import planner
from api.services.local_operator.gateway import GatewayError
from tests.operator_planner_wire import intent_wire


CONTEXT = {"run_id": "run-alder", "previous_run_id": "run-birch", "device_id": "asset-cedar",
           "job_id": "job-larch", "vuln_id": "finding-pine",
           "scan": {"ranges": "192.0.2.77", "ports": "8443", "mode": "safe"}}
KINDS = {"summarize_run": {"run"}, "analyze_run": {"run"}, "compare_runs": {"run"},
         "find_remediation": {"device", "finding"}, "cancel_scan": {"job"},
         "verify_finding": {"finding"}, "prepare_scan": {"scan_scope"}}
SUBJECTS = ["run", "device", "job", "finding", "scan_scope", "unspecified", "ambiguous"]


@pytest.mark.parametrize("intent", list(KINDS))
@pytest.mark.parametrize("kind", SUBJECTS)
def test_operation_subject_matrix_never_substitutes_resource_kind(intent, kind):
    request = planner.PlanRequest(request="Review the selected object.", context=CONTEXT)
    result = planner.validate_output(intent_wire(intent, kind), request)
    assert result["tool"] == (intent if kind in KINDS[intent] else "abstain")
    assert result["effect_executed"] is False
    assert result["requires_confirmation"] == (result["tool"] in {"prepare_scan", "cancel_scan", "verify_finding"})
    if result["tool"] == "find_remediation":
        field = "device_id" if kind == "device" else "vuln_id"
        assert result["arguments"] == {field: CONTEXT[field]}


@pytest.mark.parametrize("intent,kind,missing", [
    ("summarize_run", "run", "run_id"), ("analyze_run", "run", "run_id"),
    ("compare_runs", "run", "run_id"), ("compare_runs", "run", "previous_run_id"),
    ("find_remediation", "device", "device_id"), ("find_remediation", "finding", "vuln_id"),
    ("cancel_scan", "job", "job_id"), ("verify_finding", "finding", "vuln_id"),
    ("prepare_scan", "scan_scope", "scan"),
])
def test_missing_requested_reference_cannot_fall_back_to_other_selected_objects(intent, kind, missing):
    context = {k: v for k, v in CONTEXT.items() if k != missing}
    result = planner.validate_output(intent_wire(intent, kind), planner.PlanRequest(request="Review selected object.", context=context))
    assert result["tool"] == "abstain"
    assert result["arguments"] == {}
    assert result["effect_executed"] is False


def spans(text, literals):
    return [{"start": text.index(value), "end": text.index(value) + len(value)} for value in literals]


@pytest.mark.parametrize("language,prefix", [("ru", "Рассмотри объект"), ("en", "Review object")])
@pytest.mark.parametrize("intent,kind,fields", [
    ("summarize_run", "run", ["run_id"]), ("analyze_run", "run", ["run_id"]),
    ("compare_runs", "run", ["previous_run_id", "run_id"]),
    ("find_remediation", "device", ["device_id"]), ("find_remediation", "finding", ["vuln_id"]),
    ("cancel_scan", "job", ["job_id"]), ("verify_finding", "finding", ["vuln_id"]),
])
@pytest.mark.parametrize("foreign", [False, True])
def test_literal_identity_is_exact_in_both_languages(language, prefix, intent, kind, fields, foreign):
    values = [CONTEXT[field] for field in fields]
    if foreign:
        values[0] = "object-foreign"
    text = prefix + " " + ", ".join(repr(value) for value in values)
    request = planner.PlanRequest(request=text, language=language, context=CONTEXT)
    result = planner.validate_output(intent_wire(intent, kind, selector="explicit", mentions=spans(text, values)), request)
    assert result["tool"] == ("abstain" if foreign else intent)
    if not foreign and intent == "compare_runs":
        assert result["arguments"] == {"previous_run_id": CONTEXT["previous_run_id"], "current_run_id": CONTEXT["run_id"]}
    assert "object-foreign" not in json.dumps(result["arguments"])


@pytest.mark.parametrize("mentions", [
    [{"start": -1, "end": 10}], [{"start": 5, "end": 5}], [{"start": 8, "end": 3}],
    [{"start": 0, "end": 1001}], [{"start": True, "end": 8}], [{"start": 0.0, "end": 8}],
    [{"start": "0", "end": 8}], [{"start": 0, "end": False}],
    [{"start": 0, "end": 3}, {"start": 2, "end": 4}],
    [{"start": 0, "end": 3, "value": "injected"}],
])
def test_malformed_span_cannot_become_a_reference(mentions):
    request = planner.PlanRequest(request="job-larch", context=CONTEXT)
    with pytest.raises(GatewayError, match="operator_invalid_model_output"):
        planner.validate_output(intent_wire("cancel_scan", selector="explicit", mentions=mentions), request)


@pytest.mark.parametrize("text,literal", [
    ("prefixjob-larch", "job-larch"), ("job-larch.suffix", "job-larch"),
    ("яjob-larch", "job-larch"), ("job-larchя", "job-larch"),
    ("'job larch'", "job larch"), ("'job／larch'", "job／larch"),
])
def test_partial_identifier_and_noncanonical_identity_fail_closed(text, literal):
    request = planner.PlanRequest(request=text, context=CONTEXT)
    with pytest.raises(GatewayError):
        planner.validate_output(intent_wire("cancel_scan", selector="explicit", mentions=spans(text, [literal])), request)


@pytest.mark.parametrize("selector,mentions", [("explicit", []), ("contextual", [{"start": 0, "end": 9}])])
def test_selector_does_not_hide_or_invent_literal_evidence(selector, mentions):
    request = planner.PlanRequest(request="job-larch", context=CONTEXT)
    with pytest.raises(GatewayError):
        planner.validate_output(intent_wire("cancel_scan", selector=selector, mentions=mentions), request)


def test_comparison_preserves_roles_and_rejects_duplicate_or_incomplete_pair():
    text = "'run-alder', 'run-birch', 'run-alder'"
    request = planner.PlanRequest(request=text, context=CONTEXT)
    for values in [["run-alder"], ["run-alder", "run-alder"]]:
        mentions = spans(text, values)
        if len(values) == 2:
            mentions[1] = {"start": text.rindex(values[1]), "end": text.rindex(values[1]) + len(values[1])}
        result = planner.validate_output(intent_wire("compare_runs", selector="explicit", mentions=mentions), request)
        assert result["tool"] == "abstain"


def test_prompt_and_schema_are_independent_of_every_context_reference_and_scope():
    requests = [planner.PlanRequest(request="Review selected object.", context=context)
                for context in [{}, CONTEXT, {**CONTEXT, "job_id": "replacement", "device_id": "alternate"}]]
    assert all(planner.build_prompt(r) == planner.build_prompt(requests[0]) for r in requests)
    assert all(planner.output_schema(r) == planner.output_schema(requests[0]) for r in requests)
    user = json.loads(planner.build_prompt(requests[0])[1]["content"])
    assert set(user) == {"request", "language"}
    wire = json.dumps(planner.build_prompt(requests[1]))
    for value in ["192.0.2.77", "8443", "run-alder", "asset-cedar", "job-larch", "finding-pine"]:
        assert value not in wire


def test_prompt_credentials_stay_redacted_and_model_cannot_supply_arguments():
    request = planner.PlanRequest(request="Review; password=private-canary", context=CONTEXT)
    assert "private-canary" not in json.dumps(planner.build_prompt(request))
    raw = json.loads(intent_wire("prepare_scan"))
    raw["arguments"] = {"ranges": "203.0.113.8"}
    with pytest.raises(GatewayError):
        planner.validate_output(json.dumps(raw), request)
    result = planner.validate_output(intent_wire("prepare_scan"), request)
    assert result["arguments"] == planner.actions.ScanArguments.model_validate(CONTEXT["scan"]).model_dump()
    assert result["requires_confirmation"] is True
    assert result["effect_executed"] is False


def test_explicit_scan_literal_never_overrides_template():
    request = planner.PlanRequest(request="'203.0.113.8'", context=CONTEXT)
    result = planner.validate_output(intent_wire("prepare_scan", selector="explicit", mentions=spans(request.request, ["203.0.113.8"])), request)
    assert result["tool"] == "abstain"
