"""Agent-side job control: policy tightening, claim, heartbeat and cancel."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import or_, select

from api.db import models
from api.db.engine import get_session
from api.schemas import AgentClaimResponse, JobInfo
from api.services import agents as agents_service
from api.services import audit as audit_service
from api.services import job_inputs
from api.services import job_leases
from api.services import job_states
from api.services import job_store
from api.services import metrics as metrics_service
from api.services import run_ids
from api.services import scan_policy
from api.services import tenants as tenants_service
from api.settings import Settings

if TYPE_CHECKING:
    from api.services.audit import AuditContext

_log = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _read_job_inputs(settings: Settings, job_id: str) -> dict[str, str]:
    inputs_dir = job_inputs.ensure_local(settings, job_id)
    if not inputs_dir.is_dir():
        return {}
    out: dict[str, str] = {}
    for name in job_inputs.JOB_INPUT_FILES:
        path = inputs_dir / name
        if path.is_file():
            out[name] = path.read_text(encoding="utf-8")
    return out


def apply_policy_to_queued(
    settings: Settings,
    *,
    tenant_id: str,
    resolved: dict[str, Any] | None,
) -> int:
    """Tighten still-queued jobs after a tenant policy changes."""
    if resolved is None:
        return 0
    touched = 0
    with get_session(settings.postgres_url) as session:
        rows = (
            session.execute(
                select(models.Job).where(
                    models.Job.tenant_id == tenant_id,
                    models.Job.status == job_states.QUEUED,
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            options = dict(row.scan_options or {})
            frozen = options.get("scan_policy")
            merged = scan_policy.snapshot(
                scan_policy.tighten(frozen, resolved)
            )
            if merged is None or merged == frozen:
                continue

            command = list(row.command or [])
            policy_path = job_inputs.write_policy_input(
                job_inputs.job_inputs_dir(settings, row.job_id),
                merged,
            )
            job_inputs.publish(settings, row.job_id)
            if "--scan-policy" not in command:
                command.extend(["--scan-policy", str(policy_path)])
            options["scan_policy"] = merged
            if merged.get("skip_service_probe"):
                options["skip_nse"] = True
                if "--skip-nse" not in command:
                    command.append("--skip-nse")
            row.scan_options = options
            row.command = command
            touched += 1

    if touched:
        _log.info(
            "Scan policy for tenant %s applied to %d queued job(s)",
            tenant_id,
            touched,
        )
    return touched


def claim_job(
    settings: Settings,
    agent_id: str,
    *,
    job_id: str | None = None,
    tenant_id: str | None = None,
) -> AgentClaimResponse | None:
    """Atomically assign one eligible queued job to an agent."""
    agent = agents_service.get_agent(agent_id)
    if agent is None:
        raise LookupError("Unknown agent_id; register first")
    effective_tenant = tenant_id or agent.tenant_id

    with get_session(settings.postgres_url) as session:
        query = (
            select(models.Job)
            .where(
                models.Job.execution == "agent",
                models.Job.status == job_states.QUEUED,
                models.Job.assigned_agent_id.is_(None),
                models.Job.tenant_id == effective_tenant,
                (
                    models.Job.agent_group.is_(None)
                    if not agent.agent_group
                    else or_(
                        models.Job.agent_group.is_(None),
                        models.Job.agent_group == agent.agent_group,
                    )
                ),
            )
            .order_by(models.Job.queued_at, models.Job.job_id)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        if job_id:
            query = query.where(models.Job.job_id == job_id)
        row = session.execute(query).scalars().first()
        if row is None:
            return None

        if (row.scan_options or {}).get("scan_policy") and (
            scan_policy.AGENT_CAPABILITY not in (agent.capabilities or [])
        ):
            scan_policy.note_refusal("agent_unsupported")
            _log.warning(
                "Agent %s asked for job %s with scan policy but lacks %s",
                agent_id,
                row.job_id,
                scan_policy.AGENT_CAPABILITY,
            )
            raise scan_policy.AgentPolicyUnsupported(
                f"agent {agent_id} does not support tenant scan policies "
                f"(capability {scan_policy.AGENT_CAPABILITY}); upgrade the agent — "
                "its jobs carry rate limits it cannot currently apply"
            )

        job_states.check_transition(
            row.job_id, row.status, job_states.CLAIMED
        )
        row.status = job_states.CLAIMED
        row.assigned_agent_id = agent_id
        row.started_at = None
        row.claimed_until = job_leases.lease_deadline(settings)
        row.attempts = (row.attempts or 0) + 1
        attempt = row.attempts
        if not row.run_id:
            row.run_id = run_ids.mint()
        session.flush()

        opts = dict(row.scan_options or {})
        claimed_id = row.job_id
        response = AgentClaimResponse(
            job_id=claimed_id,
            run_id=row.run_id,
            mode=row.mode or opts.get("mode") or "balanced",
            delta=bool(opts.get("delta", False)),
            skip_nse=bool(opts.get("skip_nse", False)),
            notify=bool(opts.get("notify", False)),
            export_defectdojo=bool(
                opts.get("export_defectdojo", False)
            ),
            inputs=_read_job_inputs(settings, claimed_id),
            tenant_id=(
                row.tenant_id or tenants_service.DEFAULT_TENANT_ID
            ),
            attempt=attempt,
        )

    job_store.refresh_job_gauges(settings)
    agents_service.touch_job(agent_id, claimed_id, status="busy")
    return response


def mark_running(
    settings: Settings, job_id: str, *, agent_id: str
) -> bool:
    """Renew ownership and promote claimed to running on first heartbeat."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None or row.assigned_agent_id != agent_id:
            return False
        if row.status == job_states.CANCELLING:
            return True
        if row.status not in job_states.IN_FLIGHT:
            return False

        job_leases.extend_lease(
            row, job_leases.lease_deadline(settings)
        )
        if row.status != job_states.CLAIMED:
            return False
        row.status = job_states.RUNNING
        if row.started_at is None:
            row.started_at = _now()

    job_store.refresh_job_gauges(settings)
    return False


def _stalled_ingest(settings: Settings, row: models.Job) -> bool:
    if row.ingest_started_at is None:
        return False
    lease = timedelta(
        seconds=max(settings.job_ingest_lease_seconds, 1)
    )
    return (_now() - row.ingest_started_at) > lease


def cancel_job(
    settings: Settings,
    job_id: str,
    *,
    username: str,
    tenant_id: str | None = None,
    audit: AuditContext | None = None,
) -> JobInfo:
    """Cancel queued work or request cancellation from a remote agent."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id, with_for_update=True)
        if row is None:
            raise LookupError("Job not found")

        job_tenant = (
            row.tenant_id or tenants_service.DEFAULT_TENANT_ID
        )
        if tenant_id is not None and job_tenant != tenant_id:
            raise PermissionError("Cross-tenant job access denied")

        before = row.status
        if before == job_states.CANCELLING:
            if _stalled_ingest(settings, row):
                _log.warning(
                    "Job %s is stopping with a stale ingest since %s; "
                    "%s asked again, dropping the ingest hold",
                    job_id,
                    row.ingest_started_at,
                    username,
                )
                row.ingest_token = None
                row.ingest_attempt = None
                row.ingest_agent_id = None
                row.ingest_started_at = None
                audit_service.record(
                    session,
                    audit,
                    action=audit_service.ACTION_SCAN_CANCEL,
                    resource_type="job",
                    resource_id=job_id,
                    tenant_id=job_tenant,
                    before={
                        "status": before,
                        "ingest_open": True,
                    },
                    after={
                        "status": before,
                        "ingest_open": False,
                        "requested_by": username,
                    },
                )
                return job_store.to_info(row)
            _log.info(
                "Job %s is already stopping; %s's request is a no-op",
                job_id,
                username,
            )
            return job_store.to_info(row)

        if (
            before in job_states.IN_FLIGHT
            and row.execution != "agent"
        ):
            raise job_states.InvalidJobTransition(
                f"Job {job_id} is {before} in the API process itself; "
                "a local scan cannot be stopped once it has started, "
                "only an agent job can"
            )

        target = (
            job_states.CANCELLING
            if before in job_states.IN_FLIGHT
            else job_states.CANCELLED
        )
        job_states.check_transition(job_id, before, target)
        row.status = target

        if target == job_states.CANCELLING:
            row.cancel_requested_at = _now()
            row.claimed_until = None
            row.error = f"Cancellation requested by {username}"[:2000]
        else:
            row.finished_at = _now()
            row.claimed_until = None
            row.error = f"Cancelled by {username}"[:2000]
            metrics_service.JOB_CANCELLATIONS_TOTAL.labels(
                outcome="queued"
            ).inc()

        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_SCAN_CANCEL,
            resource_type="job",
            resource_id=job_id,
            tenant_id=job_tenant,
            before={
                "status": before,
                "assigned_agent_id": row.assigned_agent_id,
            },
            after={
                "status": target,
                "requested_by": username,
            },
        )

    job_store.refresh_job_gauges(settings)
    result = job_store.get_job(settings, job_id)
    assert result is not None
    return result
