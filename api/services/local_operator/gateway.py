"""One read-only summary operation with fresh authority and bound evidence.

This pilot accepts no free-form prompt. Only whitelisted integer counts reach
inference; generated prose stays explicitly quality-unverified.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool

from api.auth import TenantPrincipal
from api.db import models, tenant_scope
from api.db.engine import get_session
from api.services import artifact_store, rbac
from api.services.artifact_store import keys
from api.services.local_operator.config import OperatorConfig
from api.services.local_operator.contracts import (
    AnswerPayload, Citation, OperatorAnswer, ServerContext,
)
from api.services.local_operator.providers import InferenceProvider, OperatorProviderError
from api.services.local_operator import store as operator_store

PROMPT_VERSION = "run-counts-v1"
TOOL_VERSION = "published-summary-v1"
MAX_SOURCE_BYTES = 65536
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
COUNT_FIELDS = ("alive_hosts", "open_host_port_pairs", "potential_vulnerabilities",
                "unconfirmed_findings", "vulnerable_hosts")


class GatewayError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class SummaryText(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    summary: str = Field(min_length=1, max_length=4000)


def authorize_actor(settings, task) -> TenantPrincipal:
    """Resolve a queued actor from current rows, never a stored role claim."""
    username, tenant_id = task["username"], task["tenant_id"]
    with tenant_scope.system("operator queued actor authorization"):
        with get_session(settings.postgres_url) as db:
            user = db.get(models.User, username)
            tenant = db.get(models.Tenant, tenant_id)
            if (user is None or user.disabled_at is not None or tenant is None
                    or tenant.status != "active"
                    or user.token_version != task.get("actor_token_version")):
                raise GatewayError("operator_access_revoked")
            if user.role == "admin":
                role, rank = "admin", 3
            else:
                grants = db.execute(select(models.UserTenant.tenant_id, models.UserTenant.role)
                                    .where(models.UserTenant.username == username)).all()
                granted = dict(grants)
                role = granted.get(tenant_id)
                if role is None and not grants and tenant_id == "default":
                    role = user.role
                resolved = rbac.role_in_session(db, tenant_id, role or "")
                if resolved is None or resolved.rank < 2:
                    raise GatewayError("operator_access_revoked")
                rank = resolved.rank
            return TenantPrincipal(username=username, tenant_id=tenant_id, role=role,
                                   rank=rank, tenant_requested=True, is_platform_admin=False)


def _json(data: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result

    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid number")))


def _read(store, key, limit):
    info = store.stat(key)
    if info is None:
        raise GatewayError("operator_source_unavailable")
    if info.size > limit:
        raise GatewayError("operator_source_too_large")
    data = bytearray()
    for chunk in store.stream(key, chunk_size=8192):
        if len(data) + len(chunk) > limit:
            raise GatewayError("operator_source_too_large")
        data.extend(chunk)
    return bytes(data)


def read_evidence(settings, principal, run_id):
    """Require a completed, fully published control-plane run, not a staged tree."""
    if not ID.fullmatch(run_id):
        raise GatewayError("operator_invalid_run")
    store = artifact_store.get_store(settings)
    ref = keys.run_ref(run_id, principal.tenant_id)
    if not store.exists(keys.run_artifact(ref, "summary.json")):
        ref = keys.run_ref(run_id)
    try:
        marker = _json(_read(store, keys.run_artifact(ref, "tenant.json"), 8192))
        if (not isinstance(marker, dict) or marker.get("tenant_id") != principal.tenant_id
                or not isinstance(marker.get("job_id"), str)
                or not isinstance(marker.get("publication_id"), str)):
            raise GatewayError("operator_source_unavailable")
        with tenant_scope.tenant(principal.tenant_id):
            with get_session(settings.postgres_url) as db:
                job = db.scalar(select(models.Job).where(models.Job.job_id == marker["job_id"],
                    models.Job.tenant_id == principal.tenant_id, models.Job.run_id == run_id,
                    models.Job.status == "succeeded"))
                pending = db.scalar(select(models.RunPublication.publication_id).where(
                    models.RunPublication.tenant_id == principal.tenant_id,
                    models.RunPublication.run_id == run_id).limit(1))
                if job is None or pending is not None:
                    raise GatewayError("operator_source_unavailable")
        raw = _read(store, keys.run_artifact(ref, "summary.json"), MAX_SOURCE_BYTES)
        source = _json(raw)
        if not isinstance(source, dict):
            raise GatewayError("operator_source_invalid")
        counts = {key: source[key] for key in COUNT_FIELDS
                  if key in source and type(source[key]) is int and 0 <= source[key] <= 2**63 - 1}
        if not counts:
            raise GatewayError("operator_source_incomplete")
        digest = hashlib.sha256(raw).hexdigest()
        snapshot = hashlib.sha256((marker["publication_id"] + ":" + digest).encode()).hexdigest()
        # File modification time is a source-storage timestamp, not scan freshness.
        info = store.stat(keys.run_artifact(ref, "summary.json"))
        if info is None:
            raise GatewayError("operator_source_unavailable")
        citation = Citation(source_id=run_id, source_type="run", source_hash=digest,
                            snapshot_id=snapshot, observed_at=datetime.fromtimestamp(info.modified, UTC),
                            status="partial")
        return counts, citation
    except GatewayError:
        raise
    except (artifact_store.ArtifactStoreError, ValueError, TypeError, RecursionError, OSError):
        raise GatewayError("operator_source_unavailable") from None


async def execute_task(settings, task):
    if not settings.operator_enabled or not settings.operator_worker_enabled:
        raise GatewayError("operator_disabled")
    if task.get("kind") == "analyze_run" and task.get("language") in {"ru", "en"}:
        from .analyzer_gateway import execute
        return await execute(settings, task)
    if task.get("kind") != "summarize_run" or task.get("language") not in {"ru", "en"}:
        raise GatewayError("operator_unsupported_task")
    principal = await run_in_threadpool(authorize_actor, settings, task)
    counts, citation = await run_in_threadpool(read_evidence, settings, principal, task["run_id"])
    prompt = [
        {"role": "system", "content": "Return only JSON with one string field summary. Summarize only "
         "the supplied integer scan counts in the requested language. Counts are stored observations, "
         "not proof of exploitation, safety, remediation, ownership, severity or current coverage. "
         "Do not add CVEs, commands, versions, URLs, tools or facts absent from these counts."},
        {"role": "user", "content": json.dumps({"language": task["language"], "counts": counts}, sort_keys=True)},
    ]
    await run_in_threadpool(authorize_actor, settings, task)
    try:
        config = OperatorConfig.from_settings(settings)
        attempt = {"provider": config.provider, "model": config.model,
                   "prompt_version": PROMPT_VERSION, "tool_version": TOOL_VERSION,
                   "prompt_hash": hashlib.sha256(json.dumps(prompt, sort_keys=True).encode()).hexdigest(),
                   "source_references": [citation.model_dump(mode="json")]}
        if not await run_in_threadpool(
                operator_store.record_inference_attempt, settings, task, attempt):
            raise GatewayError("operator_interrupted")
        output = await InferenceProvider(config).complete(prompt)
        summary = SummaryText.model_validate(_json(output.content.encode()))
        if config.api_key:
            summary.summary = summary.summary.replace(config.api_key, "[redacted]")
    except OperatorProviderError as exc:
        raise GatewayError(exc.args[0]) from None
    except (ValueError, ValidationError, TypeError, RecursionError):
        raise GatewayError("operator_invalid_model_output") from None
    await run_in_threadpool(authorize_actor, settings, task)
    # Reject a source changed/deleted while inference was running.
    _, current = await run_in_threadpool(read_evidence, settings, principal, task["run_id"])
    if current.source_hash != citation.source_hash or current.snapshot_id != citation.snapshot_id:
        raise GatewayError("operator_source_changed")
    answer = OperatorAnswer(context=ServerContext(tenant_id=principal.tenant_id,
        actor_id=principal.username, request_id=task["task_id"], snapshot_id=citation.snapshot_id,
        captured_at=datetime.now(UTC)), answer=AnswerPayload(status="incomplete", summary=summary.summary,
        citations=(citation,), reason="Pilot count summary; source freshness, coverage and model quality are unverified."))
    return {"schema_version": "1", "answer": answer.model_dump(mode="json"),
            "quality_status": "quality_unverified", "audit": {
                "provider": output.provider, "model": output.model, "prompt_version": PROMPT_VERSION,
                "tool_version": TOOL_VERSION,
                "prompt_hash": hashlib.sha256(json.dumps(prompt, sort_keys=True).encode()).hexdigest(),
                "output_hash": hashlib.sha256(output.content.encode()).hexdigest(),
                "source_references": [citation.model_dump(mode="json")]}}
