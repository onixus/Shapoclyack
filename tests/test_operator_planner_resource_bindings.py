"""The planner sees precisely the object kinds the server will actually bind."""
import json

import pytest

from api.services.local_operator import planner


@pytest.mark.parametrize(("context", "tool", "kind", "fields"), [
    ({"run_id": "run-alpha"}, "summarize_run", "run", ["run_id"]),
    ({"run_id": "run-alpha"}, "analyze_run", "run", ["run_id"]),
    ({"run_id": "run-alpha", "previous_run_id": "run-before"}, "compare_runs", "run",
     ["previous_run_id", "current_run_id"]),
    ({"device_id": "asset-alpha"}, "find_remediation", "device", ["device_id"]),
    ({"vuln_id": "finding-alpha"}, "find_remediation", "finding", ["vuln_id"]),
    ({"vuln_id": "finding-alpha"}, "verify_finding", "finding", ["vuln_id"]),
    ({"job_id": "job-alpha"}, "cancel_scan", "job", ["job_id"]),
    ({"scan": {"ranges": "192.0.2.77", "ports": "8443", "mode": "safe"}},
     "prepare_scan", "scan_scope", []),
])
def test_binding_describes_actual_server_arguments(context, tool, kind, fields):
    request = planner.PlanRequest(request="Review the selected object.", context=context)
    user = json.loads(planner.build_prompt(request)[1]["content"])
    assert user["tool_resource_bindings"][tool] == {"resource_kind": kind, "reference_fields": fields}
    arguments = planner.available_tools(request)[tool]
    assert all(field in arguments for field in fields)
    validated = planner.validate_output(json.dumps({"tool": tool}), request)
    assert validated["arguments"] == arguments
    assert validated["effect_executed"] is False


def test_binding_exposes_actual_remediation_precedence_when_both_objects_exist():
    request = planner.PlanRequest(request="Review a selected object.",
        context={"device_id": "asset-alpha", "vuln_id": "finding-alpha"})
    user = json.loads(planner.build_prompt(request)[1]["content"])
    assert user["resource_references"] == {"device_id": "asset-alpha", "vuln_id": "finding-alpha"}
    assert user["tool_resource_bindings"]["find_remediation"]["resource_kind"] == "device"
    assert user["tool_resource_bindings"]["verify_finding"]["resource_kind"] == "finding"
    assert planner.validate_output('{"tool":"find_remediation"}', request)["arguments"] == {"device_id": "asset-alpha"}


@pytest.mark.parametrize("context", [{}, {"vuln_id": "finding-alpha"}, {"device_id": "asset-alpha"}])
def test_prompt_adds_no_missing_object_reference_or_model_argument_authority(context):
    request = planner.PlanRequest(request="Inspect the selected resource.", context=context)
    user = json.loads(planner.build_prompt(request)[1]["content"])
    assert user["resource_references"] == context
    assert set(user["tool_resource_bindings"]) == set(user["available_tools"]) - {"abstain"}
    schema = planner.output_schema(request)
    assert set(schema["properties"]) == {"tool"}
    assert schema["properties"]["tool"]["enum"] == user["available_tools"]
    system = planner.build_prompt(request)[0]["content"]
    assert "First identify the kind and identity" in system
    assert "references are never interchangeable" in system
    assert "even when that tool is available for another kind" in system


def test_scope_and_credentials_stay_outside_binding_metadata():
    request = planner.PlanRequest(request="Prepare scan; password=canary-secret",
        context={"scan": {"ranges": "192.0.2.77", "ports": "8443", "mode": "safe"}})
    prompt = json.dumps(planner.build_prompt(request))
    assert "canary-secret" not in prompt
    assert "192.0.2.77" not in prompt
    assert "8443" not in prompt
    assert "ranges" not in prompt
    assert planner.validate_output('{"tool":"prepare_scan"}', request)["requires_confirmation"] is True
