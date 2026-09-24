"""Agent-side job control: policy tightening, claim, heartbeat and cancel."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import or_, select

from api.db import models
from api.db.engine import get_session
from api.schemas import AgentClaimResponse, AgentInfo, JobInfo
from api.services import agents as agents_service
from api.services import audit as audit_service
from api.services import config_override
from api.services import job_inputs
from api.services import job_leases
from api.services import job_repository
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
    """Naive UTC, matching the other Postgres-backed services."""
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
    """Hold this tenant's still-queued jobs to a policy written after they queued.

    Returns how many jobs were changed, which the PUT reports back: the number
    is what tells an operator that writing ``fragile`` at 09:00 also caught the
    scan that has been waiting for an offline agent since 02:00 — the one that
    would otherwise have started at the pace it was admitted with.

    Tightening only, through ``scan_policy.tighten``: a queued job keeps every
    ceiling it was admitted under and gains the stricter ones. A job that
    carried no policy at all gains one, which also means the claim check will
    now hold it for an agent that declares the capability (#362) — deliberately,
    because "not scanned yet" is the better outcome on the estate this profile
    describes, and the PUT's count is where the operator sees it.

    Deleting a policy does not run this: the frozen snapshots stay, and a scan
    already admitted under a ceiling is not loosened behind the operator's back.

    Best-effort against a job being claimed at the same moment — a job that
    leaves ``queued`` between the select and the write keeps the snapshot it
    was handed. The window is one transaction wide and the next scan of that
    tenant is admitted under the new policy in any case.
    """
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
            # Reassigned rather than mutated: both columns are JSON, and an
            # in-place edit of the loaded value is not seen as a change.
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
    agent: AgentInfo | None = None,
) -> AgentClaimResponse | None:
    """Assign a queued agent job to ``agent_id``, or return None.

    When ``job_id`` is set (NATS pull path), assign that specific job if still queued.
    When ``tenant_id`` is set, only jobs for that tenant are eligible.

    Since #361 the tenant is not the only boundary: a job addressed to an agent
    group is claimable only by an agent an operator put in that group, and a
    job addressed to none is claimable by anybody in the tenant — which is
    every job that existed before that revision, and still the default. The
    filter is in the SQL rather than in a check after the fact so a claim that
    is not permitted never takes the row's lock, and the NATS pull path (which
    names a specific ``job_id``) is filtered by the same predicate: an agent
    handed an offer for another group's job gets nothing back.

    Since #362 there is a second thing the claim can refuse over: a job whose
    tenant has a scan policy is only handed to an agent that declares it can
    apply one. That check is after the row is selected rather than in the SQL
    on purpose — it is a property of the *agent*, and refusing it loudly is the
    point, where the group filter above is a property of the job and silently
    excluding it is correct.

    The candidate row is locked with ``FOR UPDATE SKIP LOCKED`` (a no-op on the
    SQLite fallback, which has a single writer anyway): two agents claiming
    concurrently — against the same replica or different ones — each get a
    different job instead of both being handed the head of the queue.
    """
    if agent is None:
        agent = agents_service.get_agent(agent_id)
    if agent is None:
        raise LookupError("Unknown agent_id; register first")
    effective_tenant = tenant_id or agent.tenant_id

    # What this agent cannot run, as scan_options keys (#362, #338). Filtered
    # out of the claim rather than refused at the head of the queue: a sensor
    # that predates the config overlay used to be handed the oldest job, refuse
    # it, and never reach the plain jobs queued behind it (review round 2).
    capabilities = set(agent.capabilities or [])
    unsupported = [
        key
        for key, capability in (
            ("scan_policy", scan_policy.AGENT_CAPABILITY),
            ("config_overlay", config_override.AGENT_CAPABILITY),
        )
        if capability not in capabilities
    ]

    with get_session(settings.postgres_url) as session:
        eligible = (
            select(models.Job)
            .where(
                models.Job.execution == "agent",
                models.Job.status == job_states.QUEUED,
                models.Job.assigned_agent_id.is_(None),
                models.Job.tenant_id == effective_tenant,
                (
                    # An ungrouped agent takes only ungrouped jobs; a grouped one
                    # takes its own group's and the ungrouped ones, so putting an
                    # agent into a group narrows what it may reach without taking
                    # away the queue it already served.
                    models.Job.agent_group.is_(None)
                    if not agent.agent_group
                    else or_(
                        models.Job.agent_group.is_(None),
                        models.Job.agent_group == agent.agent_group,
                    )
                ),
            )
            .order_by(models.Job.queued_at, models.Job.job_id)
        )
        if job_id:
            eligible = eligible.where(models.Job.job_id == job_id)
        # ``->>`` is NULL for an absent key and for a NULL document alike.
        runnable = [models.Job.scan_options[key].as_string().is_(None) for key in unsupported]
        row = (
            session.execute(
                eligible.where(*runnable).limit(1).with_for_update(skip_locked=True)
            )
            .scalars()
            .first()
        )
        if row is None:
            # Nothing this agent can run. If something it cannot run is
            # waiting, say so (426, below) instead of a quiet 204: that line in
            # the agent's journal is how its operator learns to upgrade.
            # Only jobs it cannot run: a runnable one seen here is one another
            # claim holds the lock on, and must not be handed out twice.
            blocked = [models.Job.scan_options[key].as_string().is_not(None) for key in unsupported]
            row = (
                session.execute(eligible.where(or_(*blocked)).limit(1)).scalars().first()
                if blocked
                else None
            )
            if row is None:
                return None

        # A job whose tenant has a scan policy may only be handed to a worker
        # that can honour it (#362). The policy is applied by the executor —
        # the API cannot shape somebody else's packets — so an agent that does
        # not declare the ``scan_policy`` capability would run this scan at
        # whatever its local ``default.yaml`` says, which on a fragile estate
        # is the failure the policy exists to prevent.
        #
        # Reached only when nothing this agent can run is waiting (the query
        # above hands those out first). Refused rather than answered 204: a
        # quiet empty queue would leave the operator with jobs that do not
        # move and an agent that reports itself healthy, while a 426 lands in
        # that agent's own journal, keeps it visible in the fleet view and
        # names the upgrade — the same shape #363 gives an agent below the
        # version floor. The job stays queued for a worker that can take it.
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
        # The same rule for the job's config overlay (#338 review): an agent
        # that predates it would run the scan on its own config alone — nuclei
        # on for an ``inventory`` job, the ConfigMap's rate instead of the
        # console's — while the job record says otherwise.
        if (row.scan_options or {}).get("config_overlay") and (
            config_override.AGENT_CAPABILITY not in (agent.capabilities or [])
        ):
            scan_policy.note_refusal("config_overlay_unsupported")
            _log.warning(
                "Agent %s asked for job %s with a config overlay but lacks %s",
                agent_id,
                row.job_id,
                config_override.AGENT_CAPABILITY,
            )
            raise config_override.AgentOverlayUnsupported(
                f"agent {agent_id} cannot apply the job's config overlay "
                f"(capability {config_override.AGENT_CAPABILITY}); upgrade the "
                "agent — its jobs carry the scan intent and the console's config "
                "overrides, which it would currently ignore"
            )

        # ``claimed``, not ``running`` (P1.3): the agent owns the job but has
        # not reported working on it. Its first heartbeat naming this job
        # promotes it (see mark_running), which is also the signal the P1.4
        # reaper needs to tell "taken by a worker that died" from "actually
        # scanning".
        job_states.check_transition(
            row.job_id, row.status, job_states.CLAIMED
        )
        row.status = job_states.CLAIMED
        row.assigned_agent_id = agent_id
        # `started_at` deliberately stays unset until the agent reports
        # starting (mark_running). Stamping it here would fold the
        # claim-to-heartbeat delay into every job-duration observation, and
        # would show a job that never ran as having executed.
        row.started_at = None
        # The lease starts at the claim, not at the first heartbeat: an agent
        # that dies between the two is exactly the case P1.4 has to catch.
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
            # The fencing token for this hand-out: a lease that expired and was
            # reissued bumps it, so a late upload from the previous attempt can
            # be told apart from the current one even when both come from the
            # same agent_id (a restarted worker keeps its id).
            attempt=attempt,
        )

    job_store.refresh_job_gauges(settings)
    agents_service.touch_job(agent_id, claimed_id, status="busy")
    return response


def mark_running(settings: Settings, job_id: str, *, agent_id: str) -> bool:
    """Record an agent's heartbeat, and answer whether the job was cancelled.

    Three things ride on this one signal: a claimed job is promoted to running,
    an in-flight job's lease is pushed forward (P1.4) — the heartbeat is the
    only regular evidence the API gets that a remote worker is still alive —
    and, since #360, the reply carries the one instruction that travels the
    other way. The return value is ``True`` when an operator has asked for this
    job to stop and the agent holding it must put the scan down; the route puts
    it on the heartbeat response.

    Any other state is left alone: repeated heartbeats during a scan would
    otherwise attempt running → running, and a heartbeat arriving after the
    results upload must not resurrect a finished job. A heartbeat from an agent
    that does not hold the job is ignored outright — including the cancellation
    answer, which is an instruction about somebody else's work.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None or row.assigned_agent_id != agent_id:
            return False
        if row.status == job_states.CANCELLING:
            # Repeated on every heartbeat until the agent confirms with a
            # cancelled upload: the answer to one heartbeat can be lost, and
            # the instruction has to survive that. No lease renewal — a
            # cancelling job is not in flight, and its clock is the grace
            # period in ``reap_stale_cancellations`` instead.
            return True
        if row.status not in job_states.IN_FLIGHT:
            return False
        job_leases.extend_lease(row, job_leases.lease_deadline(settings))
        if row.status != job_states.CLAIMED:
            return False
        row.status = job_states.RUNNING
        if row.started_at is None:
            row.started_at = _now()
    job_store.refresh_job_gauges(settings)
    return False


def _stalled_ingest(settings: Settings, row: models.Job) -> bool:
    """Whether this row's open ingest has outlived the stop it is holding.

    An ingest marker is proof that an upload is being processed, and nothing
    clears it for a job that is already ``cancelling``: the lease reaper takes
    IN_FLIGHT rows only, and the process that would have cleared it is the one
    that died. Past the ingest lease the marker is no longer evidence of a
    confirmation in progress — it is the shape one left behind.

    The clock is ``job_ingest_lease_seconds``, not the cancellation grace: an
    upload is allowed to take the whole ingest lease (a branch office's uplink
    plus the extraction, which is what the sensor's own upload timeout is
    sized for), so a marker younger than that can be a live confirmation still
    inside its window. Dropping it would refuse that upload at the fence and
    take the partial archive with it. A marker left by a dead replica is older
    than the lease just as surely as it is older than the grace — the longer
    clock costs nothing but the wait.
    """
    if row.ingest_started_at is None:
        return False
    lease = timedelta(seconds=max(settings.job_ingest_lease_seconds, 1))
    return (_now() - row.ingest_started_at) > lease


def cancel_job(
    settings: Settings,
    job_id: str,
    *,
    username: str,
    tenant_id: str | None = None,
    audit: AuditContext | None = None,
) -> JobInfo:
    """Stop a scan: refuse to hand it out, or ask the agent to put it down.

    Two outcomes, and which one an operator gets is a property of the job:

    - ``queued`` -> ``cancelled`` at once. Nothing has taken the job, so
      refusing to hand it out *is* the stop, and the answer is final.
    - ``claimed``/``running`` on an **agent** -> ``cancelling`` (#360). The
      instruction rides the next heartbeat, the agent signals its scanner's
      process group and uploads whatever the run produced as a cancelled
      result, and only that upload — or the grace period expiring in
      ``reap_stale_cancellations`` — writes the terminal state. The API says
      "stopping", not "stopped", because at this moment it has not been told
      the scan stopped.
    - ``cancelling`` -> itself, unchanged. The stop has been asked for and the
      clock on it is running; re-asking is not a second decision. A stale
      console, a second operator or a retried POST must not be able to
      terminalize a scan nobody has confirmed stopped. The one thing a
      deliberate second press does is drop an *abandoned* ingest hold — see
      the branch below — which returns the stop to the grace period it was
      promised instead of the ingest lease's much longer one.

    A ``running`` **local** job is still refused, and by execution rather than
    by state: its scanner is a ``subprocess`` in one replica's thread, which
    the replica handling this request may not be, so there is no signal to send
    and reporting a stop would be a lie. The message says so rather than
    reading as a generic lifecycle refusal.

    The reason is stored in ``error`` rather than a new column: it is the field
    the UI and API already surface for "why did this job end this way".
    """
    with get_session(settings.postgres_url) as session:
        # Locked for the same reason as job_store.update_job: a local job's executor
        # thread may be transitioning the very same row to running right now,
        # and cancelling a job that has already started is exactly the outcome
        # this endpoint must never report.
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
            # Idempotent, and deliberately *before* the transition table gets a
            # say: `cancelling` is not in IN_FLIGHT, so the target below would
            # be computed as `cancelled` — a legal move that would have the
            # API report a stop nobody confirmed, clear `cancel_requested`
            # before the agent has read it, and collapse the grace period to
            # nothing. Two consoles four seconds apart, or one proxy retry,
            # are enough to reach here; the answer is the job as it stands.
            #
            # With one exception, which is the only thing a second press can
            # usefully do: an ingest marker older than the grace period.
            # ``reap_stale_cancellations`` passes a stopping job over while an
            # ingest is open, and ``reap_expired_leases`` does not clear that
            # marker (it takes IN_FLIGHT rows only), so a replica killed in the
            # middle of a confirming upload holds the stop for the whole
            # ``job_ingest_lease_seconds`` — three times the grace an operator
            # was promised, with no way to say "I know, kill it". Dropping the
            # marker hands the row back to the reaper's ordinary clock.
            #
            # Bounded by the *ingest lease*, not by the grace period: an
            # upload younger than the lease is a confirmation still inside the
            # window the sensor was given, and is left alone so a slow branch
            # office does not lose the partial archive it is in the middle of
            # delivering. A marker a dead replica left behind is past the lease
            # too, so the longer clock only costs the wait.
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
    result = job_repository.get_job(settings, job_id)
    assert result is not None
    return result
