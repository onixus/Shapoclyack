"""Evidence quality and trust-boundary fixtures for local-operator v1."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from api.services.local_operator.contracts import (
    ActionProposal, AnswerPayload, Citation, ExecutionResult, OperatorAnswer,
    ServerContext, ToolResult, contract_json_schema,
)

NOW = datetime(2026, 10, 21, tzinfo=timezone.utc)


def context():
    return ServerContext(tenant_id="tenant-a", actor_id="viewer-a", request_id="req-1",
                         snapshot_id="snapshot-1", captured_at=NOW)


def citation(**overrides):
    return Citation(**dict(dict(source_id="finding-7", source_type="finding",
                                source_hash="a" * 64, snapshot_id="snapshot-1",
                                observed_at=NOW), **overrides))


@pytest.mark.parametrize("status,evidence,reason", [
    ("complete", (citation(),), None),
    ("empty", (), "No authorized sources in the requested window."),
    ("partial", (citation(status="partial"),), "Sensor results are partial."),
    ("incomplete", (citation(status="partial"),), "Required sensor results are missing."),
    ("unknown", (), "The available evidence cannot determine the result."),
    ("unsupported", (), "The requested assessment is unsupported."),
    ("stale", (citation(status="stale"),), "Evidence predates the freshness limit."),
])
def test_evidence_fixtures_survive_json_roundtrip(status, evidence, reason):
    result = OperatorAnswer(context=context(), answer=AnswerPayload(
        status=status, summary="Evidence-limited result", citations=evidence, reason=reason))
    restored = OperatorAnswer.model_validate_json(result.model_dump_json())
    assert restored == result
    assert restored.answer.status == status


@pytest.mark.parametrize("values", [
    {"status": "complete", "citations": ()},
    {"status": "complete", "citations": (citation(status="stale"),)},
    {"status": "complete", "citations": (citation(status="partial"),)},
    {"status": "partial", "citations": ()},
    {"status": "empty", "citations": (citation(),), "reason": "Nothing found"},
    {"status": "complete", "citations": (citation(), citation())},
])
def test_inconsistent_evidence_cannot_be_promoted(values):
    with pytest.raises(ValidationError):
        AnswerPayload(summary="Unsupported claim", **values)


@pytest.mark.parametrize("injection", [
    {"tenant_id": "other-tenant"}, {"actor_id": "admin"}, {"role": "admin"},
    {"permissions": ["scan_scope.approve"]}, {"schema_version": "2"},
])
def test_model_payload_cannot_select_authority_or_future_schema(injection):
    with pytest.raises(ValidationError):
        AnswerPayload(**dict(dict(status="empty", summary="No sources",
                                  reason="Empty authorized snapshot"), **injection))


def test_server_envelope_rejects_foreign_snapshot():
    with pytest.raises(ValidationError, match="server-selected snapshot"):
        OperatorAnswer(context=context(), answer=AnswerPayload(
            status="complete", summary="Other snapshot",
            citations=(citation(snapshot_id="other-snapshot"),)))


@pytest.mark.parametrize("kind", ["denied", "failed", "cancelled", "empty"])
def test_tool_failure_cannot_carry_success_data(kind):
    with pytest.raises(ValidationError):
        ToolResult(context=context(), tool_name="assets.list", status=kind,
                   data={"assets": ["secret"]}, reason="No authorized result")


def proposal(**overrides):
    return ActionProposal(**dict(dict(
        context=context(), proposal_id="proposal-1", tool_name="scan.start",
        arguments={"target": "approved.example"}, arguments_hash="b" * 64,
        expected_effect="Create one scan within the approved scope.",
        citations=(citation(),), idempotency_key="request-1",
        expires_at=NOW + timedelta(minutes=5)), **overrides))


@pytest.mark.parametrize("overrides", [
    {"requires_confirmation": False}, {"expires_at": NOW},
    {"citations": (citation(status="stale"),)}, {"tool_name": "shell.exec"},
    {"arguments_hash": "not-a-digest"},
])
def test_proposals_require_bounded_confirmed_supported_actions(overrides):
    with pytest.raises(ValidationError):
        proposal(**overrides)


def test_proposal_and_execution_roundtrip():
    planned = proposal()
    assert ActionProposal.model_validate_json(planned.model_dump_json()) == planned
    result = ExecutionResult(context=context(), proposal_id=planned.proposal_id,
                             arguments_hash=planned.arguments_hash,
                             idempotency_key=planned.idempotency_key,
                             status="succeeded", resource_ids=("job-1",))
    assert ExecutionResult.model_validate_json(result.model_dump_json()) == result


def test_failed_execution_cannot_claim_created_resources():
    with pytest.raises(ValidationError):
        ExecutionResult(context=context(), proposal_id="proposal-1", arguments_hash="b" * 64,
                        idempotency_key="request-1", status="denied",
                        reason="Membership revoked", resource_ids=("job-1",))


def test_naive_capture_timestamp_is_rejected():
    with pytest.raises(ValidationError):
        ServerContext(tenant_id="t", actor_id="a", request_id="r", snapshot_id="s",
                      captured_at=datetime(2026, 10, 21))


@pytest.mark.parametrize("status", ["unknown", "unsupported", "incomplete"])
def test_explicit_knowledge_states_require_reasons(status):
    with pytest.raises(ValidationError):
        AnswerPayload(status=status, summary="Indeterminate")
    result = ToolResult(context=context(), tool_name="coverage.read", status=status,
                        reason="Required observation unavailable")
    assert result.status == status


def test_published_json_schema_matches_runtime_contracts():
    path = Path(__file__).resolve().parents[1] / "docs/schemas/local-operator-v1.json"
    assert json.loads(path.read_text()) == contract_json_schema()


@pytest.mark.parametrize("status", ["denied", "failed", "cancelled", "empty"])
def test_tool_no_data_outcomes_cannot_leak_source_identifiers(status):
    with pytest.raises(ValidationError):
        ToolResult(context=context(), tool_name="runs.read", status=status,
                   citations=(citation(),), reason="No authorized result")
