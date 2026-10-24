"""Confirmed control-plane actions. Model text never grants authority.

A durable claim precedes dispatch. Starts reconcile by their proposal-owned
idempotency key. An uncertain verification/cancellation is never redispatched.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
from datetime import timedelta
from hashlib import sha256
import json
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select

from api.core.permissions import SCAN_CANCEL
from api.db import models, tenant_scope
from api.db.engine import get_session
from api.schemas import StartScanRequest
from api.services import audit, jobs, rbac, scan_admission, vulnerabilities, vuln_states
from api.services.local_operator import store

Id = Annotated[str, Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")]


class ScanArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    mode: Literal["safe", "balanced", "fast", "test"] = "safe"
    intent: str | None = Field(default=None, max_length=64)
    ranges: str = Field(default="", max_length=8192)
    domains: str = Field(default="", max_length=8192)
    ports: str = Field(min_length=1, max_length=2048)
    ports_udp: str = Field(default="", max_length=2048)
    agent_group: str | None = Field(default=None, max_length=63)

    @model_validator(mode="after")
    def explicit_targets(self):
        if not self.ranges.strip() and not self.domains.strip():
            raise ValueError("Explicit targets required")
        # Validate the platform's vocabulary instead of maintaining an AI copy.
        StartScanRequest(**self.model_dump())
        return self


class CancelArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    job_id: Id


class VerifyArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    vuln_id: Id


class PrepareAction(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    action: Literal["start_scan", "cancel_scan", "verify_finding"]
    arguments: dict

    @model_validator(mode="after")
    def validate_arguments(self):
        schema = {"start_scan": ScanArguments, "cancel_scan": CancelArguments,
                  "verify_finding": VerifyArguments}[self.action]
        self.arguments = schema.model_validate(self.arguments).model_dump()
        return self


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _request(tenant_id, arguments):
    return StartScanRequest(**arguments, tenant_id=tenant_id, priority=0)


def _preview(settings, tenant_id, username, action, arguments, permissions):
    if action == "start_scan":
        if not settings.allow_scan_start:
            raise store.OperatorStoreError("action_unavailable")
        admission = scan_admission.admit_scan(settings, _request(tenant_id, arguments),
            username=username, job_id="operator-preview", execution=settings.job_execution_mode,
            widen_with_promoted=False)
        snapshot = {"scope": asdict(admission.scope), "policy": admission.policy_snapshot,
                    "execution": settings.job_execution_mode,
                    "agent_group": admission.agent_group,
                    "targets": asdict(admission.parsed_targets) if admission.parsed_targets else None}
        return {"effect": "create_scan", "network_access": True,
                "targets": snapshot["targets"], "agent_group": admission.agent_group,
                "policy": admission.policy_snapshot,
                "approved_scope": admission.scope.to_document(),
                "ports_udp": arguments["ports_udp"] or "server_default",
                "promoted_domains_added": False}, scan_admission.admission_digest(admission, execution=settings.job_execution_mode)
    if action == "cancel_scan":
        if SCAN_CANCEL not in permissions:
            raise store.OperatorStoreError("access_revoked")
        job = jobs.get_job(settings, arguments["job_id"])
        if job is None or job.tenant_id != tenant_id:
            raise store.OperatorStoreError("not_found")
        return {"effect": "request_cancellation", "job_id": job.job_id,
                "job_status": job.status, "stopping_is_asynchronous": True}, digest({"job_id": job.job_id})
    finding = vulnerabilities.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=arguments["vuln_id"])
    if finding is None:
        raise store.OperatorStoreError("not_found")
    if finding.get("source") in {"endpoint_software", "retro_match"}:
        raise store.OperatorStoreError("verification_unsupported")
    vuln_states.check_transition(arguments["vuln_id"], finding["state"], vuln_states.VERIFYING)
    with get_session(settings.postgres_url) as db:
        source = db.scalar(select(models.Vulnerability).where(models.Vulnerability.tenant_id == tenant_id,
            models.Vulnerability.vuln_id == arguments["vuln_id"]))
        if source is None:
            raise store.OperatorStoreError("not_found")
        typed_plan = vulnerabilities._verification_plan(db, source)
        plan = asdict(typed_plan)
        plan_sha256 = vulnerabilities.verification_plan_digest(source, typed_plan)
    snapshot = {key: finding.get(key) for key in ("vuln_id", "asset_id", "host", "port", "state",
                "source", "last_seen", "verification_job_id")}
    snapshot["verification_plan"] = plan
    return {"effect": "verification_scan", "vuln_id": arguments["vuln_id"],
            "network_access": True, "finding_state": finding.get("state"),
            "targets": {"ranges": plan["ips"], "domains": plan["names"]},
            "agent_group": plan["agent_group"], "detector_plan": plan,
            "plan_sha256": plan_sha256,
            "ports": finding.get("port"),
            "machine_verified": False}, digest(snapshot)


def _view(row, execution=None):
    payload = row.payload
    return {"proposal_id": row.proposal_id, "session_id": row.session_id,
            "tenant_id": row.tenant_id, "action": payload["action"],
            "arguments": payload["arguments"], "arguments_sha256": payload["arguments_sha256"],
            "expires_at": payload["expires_at"], "status": row.status,
            "impact": payload["impact"], "execution": execution}


def _execution_view(row):
    return {"execution_id": row.execution_id, "status": row.status, **(row.payload or {})}


def _audit(db, row, action, context, **data):
    audit.record(db, context, action="operator.action." + action, resource_type="operator",
        resource_id=row.proposal_id, tenant_id=row.tenant_id,
        after={"action": row.payload["action"], "arguments_sha256": row.payload["arguments_sha256"], **data})


@contextmanager
def _authority(settings, context):
    """Hold current account/session, tenant and membership authority through dispatch.

    Shared tenant locks allow the ordinary job writer's own tenant status lock.
    The lock order follows the personal store: account, auth session, tenant.
    """
    principal = context.principal
    with tenant_scope.system("operator confirmed action authority"), get_session(settings.postgres_url) as db:
        # FOR UPDATE also conflicts with the FK key-share lock of a first
        # membership INSERT, fencing the legacy no-grants fallback.
        user = store._lock_actor(db, settings, principal.username, context.auth_session_id, writer=True)
        tenant = db.scalar(select(models.Tenant).where(models.Tenant.tenant_id == principal.tenant_id)
            .with_for_update(read=True))
        if tenant is None or tenant.status != "active":
            raise store.OperatorStoreError("access_revoked")
        list(db.scalars(select(models.UserTenant).where(models.UserTenant.username == user.username)
                        .with_for_update(read=True)))
        current = store.resolve_role(db, user, principal.tenant_id)
        if current is None or current[1] < 2:
            raise store.OperatorStoreError("access_revoked")
        resolved = rbac.role_in_session(db, principal.tenant_id, current[0], lock="share")
        if resolved is None:
            raise store.OperatorStoreError("access_revoked")
        yield db, resolved.permissions, user


def _owned(db, context, proposal_id, *, lock=False):
    p = context.principal
    statement = select(models.OperatorProposal).where(models.OperatorProposal.proposal_id == proposal_id,
        models.OperatorProposal.tenant_id == p.tenant_id, models.OperatorProposal.username == p.username)
    row = db.scalar(statement.with_for_update() if lock else statement)
    if row is None:
        raise store.OperatorStoreError("not_found")
    return row


def prepare(settings, context, session_id, body, audit_context):
    with _authority(settings, context) as (db, permissions, user):
        p = context.principal
        conversation = db.scalar(select(models.OperatorSession).where(models.OperatorSession.session_id == session_id,
            models.OperatorSession.tenant_id == p.tenant_id, models.OperatorSession.username == p.username)
            .with_for_update())
        if conversation is None:
            raise store.OperatorStoreError("not_found")
        if db.scalar(select(func.count()).select_from(models.OperatorProposal).where(
                models.OperatorProposal.session_id == session_id)) >= 100:
            raise store.OperatorStoreError("queue_full")
        impact, policy_sha256 = _preview(settings, p.tenant_id, p.username, body.action, body.arguments, permissions)
        now = store._now()
        payload = {"action": body.action, "arguments": body.arguments,
            "arguments_sha256": digest({"action": body.action, "arguments": body.arguments}),
            "expires_at": (now + timedelta(minutes=5)).isoformat() + "Z", "impact": impact,
            "policy_sha256": policy_sha256, "actor_token_version": user.token_version,
            "auth_session_sha256": digest(context.auth_session_id)}
        row = models.OperatorProposal(proposal_id=str(uuid4()), tenant_id=p.tenant_id, username=p.username,
            session_id=session_id, payload=payload, status="preview", created_at=now)
        db.add(row)
        conversation.updated_at = now
        _audit(db, row, "prepare", audit_context)
        db.flush()
        return _view(row)


def get(settings, context, proposal_id):
    with _authority(settings, context) as (db, permissions, user):
        row = _owned(db, context, proposal_id)
        execution = db.scalar(select(models.OperatorExecution).where(models.OperatorExecution.proposal_id == row.proposal_id,
            models.OperatorExecution.tenant_id == row.tenant_id, models.OperatorExecution.username == row.username))
        return _view(row, _execution_view(execution) if execution else None)


def _dispatch(settings, row, permissions, audit_context):
    action, arguments = row.payload["action"], row.payload["arguments"]
    if action == "start_scan":
        try:
            job = jobs.start_scan(settings, _request(row.tenant_id, arguments), username=row.username,
                idempotency_key="operator:" + row.proposal_id, widen_with_promoted=False,
                expected_admission_sha256=row.payload["policy_sha256"])
        except jobs.IdempotentReplay as replay:
            job = replay.job
        return {"job_id": job.job_id, "job_status": job.status}
    if action == "cancel_scan":
        if SCAN_CANCEL not in permissions:
            raise store.OperatorStoreError("access_revoked")
        job = jobs.cancel_job(settings, arguments["job_id"], username=row.username,
            tenant_id=row.tenant_id, audit=audit_context)
        return {"job_id": job.job_id, "job_status": job.status}
    result = vulnerabilities.trigger_verification(settings, tenant_id=row.tenant_id,
        vuln_id=arguments["vuln_id"], actor=row.username,
        expected_plan_sha256=row.payload["impact"]["plan_sha256"])
    if result is None:
        raise store.OperatorStoreError("not_found")
    return {"vuln_id": arguments["vuln_id"], "job_id": result.get("verification_job_id"),
            "finding_state": result.get("state"), "machine_verified": False}


def confirm(settings, context, proposal_id, arguments_sha256, audit_context):
    # Commit the claim before any effect. Concurrent clicks reconcile only.
    with _authority(settings, context) as (db, permissions, user):
        row = _owned(db, context, proposal_id, lock=True)
        if row.payload["arguments_sha256"] != arguments_sha256 or arguments_sha256 != digest(
                {"action": row.payload["action"], "arguments": row.payload["arguments"]}):
            raise store.OperatorStoreError("idempotency_conflict")
        if row.payload["auth_session_sha256"] != digest(context.auth_session_id) or user.token_version != row.payload["actor_token_version"]:
            raise store.OperatorStoreError("access_revoked")
        execution = db.scalar(select(models.OperatorExecution).where(models.OperatorExecution.proposal_id == proposal_id))
        if execution is not None:
            if execution.status in {"executing", "unknown"} and row.payload["action"] == "start_scan":
                job = jobs.find_by_idempotency_key(settings, tenant_id=row.tenant_id,
                    key="operator:" + proposal_id, request=_request(row.tenant_id, row.payload["arguments"]))
                if job is not None:
                    row.status = execution.status = "succeeded"
                    execution.payload = {"result": {"job_id": job.job_id, "job_status": job.status}, "reconciled": True}
                    _audit(db, row, "reconcile", audit_context, execution_id=execution.execution_id)
            return _view(row, _execution_view(execution))
        if row.status != "preview" or store._now().isoformat() + "Z" >= row.payload["expires_at"]:
            raise store.OperatorStoreError("stale_proposal")
        _, current = _preview(settings, row.tenant_id, row.username, row.payload["action"], row.payload["arguments"], permissions)
        if current != row.payload["policy_sha256"]:
            raise store.OperatorStoreError("stale_proposal")
        execution_id = str(uuid4())
        execution = models.OperatorExecution(execution_id=execution_id, proposal_id=proposal_id,
            tenant_id=row.tenant_id, username=row.username, status="executing", payload={}, created_at=store._now())
        row.status = "executing"
        db.add(execution)
        _audit(db, row, "confirm", audit_context, execution_id=execution_id)
    # Recheck after waiting for persistence, with authority locks through effect.
    with _authority(settings, context) as (db, permissions, user):
        row = _owned(db, context, proposal_id, lock=True)
        execution = db.get(models.OperatorExecution, execution_id)
        if row.status != "executing" or execution is None or execution.status != "executing":
            raise store.OperatorStoreError("idempotency_conflict")
        try:
            if (row.payload["auth_session_sha256"] != digest(context.auth_session_id)
                    or user.token_version != row.payload["actor_token_version"]
                    or store._now().isoformat() + "Z" >= row.payload["expires_at"]
                    or row.payload["arguments_sha256"] != digest({"action": row.payload["action"], "arguments": row.payload["arguments"]})):
                raise store.OperatorStoreError("stale_proposal")
            _, current = _preview(settings, row.tenant_id, row.username, row.payload["action"], row.payload["arguments"], permissions)
            if current != row.payload["policy_sha256"]:
                raise store.OperatorStoreError("stale_proposal")
        except Exception:
            row.status = execution.status = "failed"
            execution.payload = {"error": "preconditions_changed"}
        else:
            try:
                result = _dispatch(settings, row, permissions, audit_context)
            except Exception:
                # The effect may already have committed. Never replay it.
                row.status = execution.status = "unknown"
                execution.payload = {"error": "dispatch_outcome_unknown", "requires_reconciliation": True}
            else:
                row.status = execution.status = "succeeded"
                execution.payload = {"result": result}
        _audit(db, row, "result", audit_context, execution_id=execution_id, status=execution.status)
        return _view(row, _execution_view(execution))
