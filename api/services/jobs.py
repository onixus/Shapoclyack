"""Scan jobs — the control plane's unit of work (Postgres-backed since P1.2).

Jobs used to live in a module-level ``_JOBS`` dict guarded by a
``threading.Lock`` and dumped to ``state/api_jobs.json`` after every mutation.
That has three failure modes this module no longer has: a second API replica
kept its own queue (so an agent could claim a job twice, once per replica),
the lock only serialised claims *within* one process, and anything not yet
flushed to the file died with the process.

The table is the queue now. ``claim_job`` takes a row lock
(``SELECT … FOR UPDATE SKIP LOCKED``) so concurrent claims across replicas
hand out distinct jobs, and every status change is a committed UPDATE rather
than a whole-file rewrite.

Since P1.3 every status write goes through ``api/services/job_states.py``:
statuses are no longer assigned, they are *transitioned*, and an illegal move
(a late upload for a job that already failed, a second terminal write) raises
instead of silently overwriting. Leases and idempotency keys are the next
slices (ROADMAP P1.4-P1.5).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import subprocess
import sys
import threading
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError

from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.schemas import AgentClaimResponse, JobInfo, StartScanRequest
from api.services import agent_groups as agent_groups_service
from api.services import agents as agents_service
from api.services import asset_events
from api.services import assets as assets_service
from api.services import audit as audit_service
from api.services import config_override as config_override_service
from api.services import job_states
from api.services import maintenance
from api.services import metrics as metrics_service
from api.services import nats_bus
from api.services import pagination
from api.services import quotas
from api.services import promoted_domains
from api.services import auth_audit
from api.services import results_ingest
from api.services.integrations import channels as channels_service
from api.services import runs as runs_service
from api.services import scan_policy
from api.services import scan_scopes
from api.services import tenants as tenants_service
from api.services import scan_intents
from api.services import scan_surface
from api.services import vulnerabilities as vulns_service
from api.services import wordlists as wordlists_service
from api.services import workflow_events
from api.services.targets import parse_target_payload
from api.settings import Settings
from scanner.pipeline import scan_scope

_log = logging.getLogger(__name__)

#: The tenant's approved scope, handed to the run beside its target files so the
#: scanner can hold the resolution it actually scans on to the same rules (#244).
SCAN_SCOPE_INPUT = "scan_scope.json"

#: What a job hands to its worker. The scope rides the same channel as the
#: targets on purpose: a worker that receives one receives the other.
#: Related domains the tenant's operators promoted (org_profile M4). A separate
#: file rather than lines appended to ``domains.txt``: the scanner merges it
#: into the name scope *in addition to* whatever target files the run reads, so
#: a run on the installation's default targets is widened rather than replaced.
PROMOTED_DOMAINS_INPUT = "promoted_domains.txt"

#: The tenant's scan policy as it stood when this job was admitted (#362) —
#: the rate ceilings, the host concurrency and the ports the run must not
#: touch. It rides the same channel as the scope for the same reason: it is a
#: server-decided constraint the worker hands to the scanner unread, and a
#: worker that receives the targets receives what it may do to them. Absent for
#: a tenant with no policy, which is the pre-#362 behaviour.
SCAN_POLICY_INPUT = "scan_policy.json"
_JOB_INPUT_FILES = (
    "ranges.txt",
    "domains.txt",
    "ports.txt",
    "ports_udp.txt",
    SCAN_SCOPE_INPUT,
    PROMOTED_DOMAINS_INPUT,
    SCAN_POLICY_INPUT,
)


def _now() -> datetime:
    """Naive UTC, matching the other Postgres-backed services."""
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(dt: datetime | None) -> str | None:
    return dt.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z") if dt else None


def _parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC).replace(tzinfo=None) if parsed.tzinfo else parsed


def _to_info(row: models.Job, live_groups: set[tuple[str, str]] | None = None) -> JobInfo:
    """One job row as the API reports it.

    ``live_groups`` is the ``(tenant, group)`` pairs that have an agent able to
    take a job right now — see ``agent_groups.live_groups``. Passed in by the
    read paths that render a queue so one query answers a whole page; ``None``
    from the write paths, which report the job they just changed and make no
    claim about who is listening.
    """
    return JobInfo(
        job_id=row.job_id,
        status=row.status,  # type: ignore[arg-type]
        run_id=row.run_id,
        mode=row.mode,
        command=list(row.command or []),
        started_at=_iso(row.started_at),
        finished_at=_iso(row.finished_at),
        exit_code=row.exit_code,
        error=row.error,
        requested_by=row.requested_by or "",
        target_counts=dict(row.target_counts) if row.target_counts else None,
        execution=row.execution,  # type: ignore[arg-type]
        assigned_agent_id=row.assigned_agent_id,
        tenant_id=row.tenant_id or tenants_service.DEFAULT_TENANT_ID,
        asset_upsert_error=row.asset_upsert_error,
        attempts=row.attempts or 0,
        scan_options=dict(row.scan_options) if row.scan_options else None,
        surface=(row.scan_options or {}).get("surface"),
        surface_source=(row.scan_options or {}).get("surface_source"),
        agent_group=row.agent_group,
        # Answered now, not at queue time: a job addressed to a group whose
        # only agent was restarting when it was queued is claimable the moment
        # that agent is back, and a flag frozen at queue time went on saying
        # "nothing can execute this" for the rest of the job's life. Only for a
        # job still waiting — once one is claimed, who was listening an hour
        # ago is not a thing to report.
        agent_group_unavailable=(
            bool(row.agent_group)
            and row.status == job_states.QUEUED
            and live_groups is not None
            and (row.tenant_id or tenants_service.DEFAULT_TENANT_ID, row.agent_group)
            not in live_groups
        ),
    )


def load_jobs(settings: Settings) -> None:
    """Import the pre-P1 JSON queue once, then reconcile this replica's orphans.

    Local-mode jobs run in an in-process thread (see ``_run_job``): that
    executor dies with the process, so a local job still ``queued``/``running``
    at startup was orphaned by a crash or restart and will never be updated
    again — fail it here rather than leaving it stuck forever.

    Unlike the pre-P1 version, the queue is now shared, so "still running" no
    longer implies "mine": only rows carrying this replica's ``owner_id`` are
    reconciled. A local job orphaned by a replica that never returns under the
    same id stays running until the P1.4 lease reaper lands. Agent-mode jobs
    are untouched in either case — their executor is a remote process
    independent of this one.
    """
    path = settings.state_dir / "api_jobs.json"
    if path.is_file():
        _import_legacy_jobs(settings, path)

    now = _now()
    with get_session(settings.postgres_url) as session:
        orphans = session.execute(
            select(models.Job).where(
                models.Job.execution == "local",
                # `claimed` is an agent-only state, so it cannot appear here.
                models.Job.status.in_((job_states.QUEUED, job_states.RUNNING)),
                or_(
                    models.Job.owner_id == settings.instance_id,
                    models.Job.owner_id.is_(None),
                ),
            )
        ).scalars().all()
        for row in orphans:
            job_states.check_transition(row.job_id, row.status, job_states.FAILED)
            row.status = job_states.FAILED
            row.finished_at = now
            row.claimed_until = None
            row.error = "Interrupted by API process restart before completion"
    if orphans:
        _log.info("Reconciled %d orphaned local job(s) after restart", len(orphans))
    _refresh_job_gauges(settings)


def _import_legacy_jobs(settings: Settings, path: Path) -> None:
    """Copy ``state/api_jobs.json`` into the table, once.

    The file is renamed to ``*.imported`` afterwards so a restart cannot
    resurrect jobs that were since deleted, and so an operator can still see
    what was carried over.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _log.warning("Ignoring unreadable legacy job queue at %s", path)
        return
    if not isinstance(raw, list):
        return

    known_tenants = {tenant["tenant_id"] for tenant in tenants_service.list_tenants()}
    imported = 0
    with get_session(settings.postgres_url) as session:
        for item in raw:
            if not (isinstance(item, dict) and item.get("job_id")):
                continue
            job_id = str(item["job_id"])
            if session.get(models.Job, job_id) is not None:
                continue
            tenant_id = str(item.get("tenant_id") or tenants_service.DEFAULT_TENANT_ID)
            if tenant_id not in known_tenants:
                # The column is a FK; a job whose tenant was deleted would
                # abort the whole import, so re-home it rather than drop it.
                _log.warning(
                    "Legacy job %s references unknown tenant %s; importing under %s",
                    job_id,
                    tenant_id,
                    tenants_service.DEFAULT_TENANT_ID,
                )
                tenant_id = tenants_service.DEFAULT_TENANT_ID
            options = dict(item.get("scan_options") or {})
            row = models.Job(
                job_id=job_id,
                tenant_id=tenant_id,
                status=str(item.get("status") or "queued"),
                execution=str(item.get("execution") or "local"),
                mode=str(item.get("mode") or options.get("mode") or "balanced"),
                run_id=item.get("run_id"),
                command=list(item.get("command") or []),
                scan_options=options,
                target_counts=item.get("target_counts"),
                requested_by=str(item.get("requested_by") or ""),
                assigned_agent_id=item.get("assigned_agent_id"),
                # Pre-P1 jobs have no owner; load_jobs treats NULL as
                # "this replica" so they still get reconciled once.
                owner_id=None,
                queued_at=_parse_iso(item.get("queued_at"))
                or _parse_iso(item.get("started_at"))
                or _now(),
                started_at=_parse_iso(item.get("started_at")),
                finished_at=_parse_iso(item.get("finished_at")),
                exit_code=item.get("exit_code"),
                error=item.get("error"),
                asset_upsert_error=item.get("asset_upsert_error"),
            )
            if insert_if_absent(session, row, job_id):
                imported += 1
    try:
        path.replace(path.with_suffix(path.suffix + ".imported"))
    except OSError:
        _log.warning("Could not rename %s after import; it will be re-imported", path)
    if imported:
        _log.info("Imported %d job(s) from the pre-P1 queue at %s", imported, path)


JOB_SORT_FIELDS = ("started_at", "finished_at", "status", "job_id", "mode", "tenant_id")
JOB_QUERY_FIELDS = ("job_id", "run_id", "mode", "status", "requested_by", "tenant_id", "assigned_agent_id")

JOB_SORT_COLUMNS = {
    "started_at": models.Job.started_at,
    "finished_at": models.Job.finished_at,
    "status": models.Job.status,
    "job_id": models.Job.job_id,
    "mode": models.Job.mode,
    "tenant_id": models.Job.tenant_id,
}


def list_jobs(
    settings: Settings,
    *,
    offset: int = 0,
    limit: int = pagination.DEFAULT_LIMIT,
    q: str | None = None,
    sort: str | None = None,
    order: str | None = None,
    tenant_id: str | None = None,
    surface: str | None = None,
) -> tuple[list[JobInfo], int]:
    """Return ``(page, total_after_filtering)`` — see api/services/pagination.py.

    Filtered, counted, and sliced in SQL. ``NULLS LAST`` keeps the documented
    ordering rule that a job which never started does not outrank one that
    did, in both directions.

    ``surface`` filters on ``scan_options->>'surface'`` (see
    api.services.scan_surface). ``"unknown"`` selects the rows where the key is
    absent or null — jobs started before this shipped, and scans of the
    server's default input files — so the three surfaces plus ``unknown``
    partition the list and no job is invisible under every filter.
    """
    column = JOB_SORT_COLUMNS.get(sort or "", models.Job.started_at)
    ascending = (order or "").lower() == "asc"
    direction = column.asc().nullslast() if ascending else column.desc().nullslast()

    with get_session(settings.postgres_url) as session:
        filters = []
        if tenant_id:
            filters.append(models.Job.tenant_id == tenant_id)
        if surface:
            stored = models.Job.scan_options["surface"].as_string()
            filters.append(stored.is_(None) if surface == "unknown" else stored == surface)
        if q and q.strip():
            needle = f"%{q.strip().lower()}%"
            filters.append(
                or_(
                    func.lower(models.Job.job_id).like(needle),
                    func.lower(func.coalesce(models.Job.run_id, "")).like(needle),
                    func.lower(models.Job.mode).like(needle),
                    func.lower(models.Job.status).like(needle),
                    func.lower(models.Job.requested_by).like(needle),
                    func.lower(models.Job.tenant_id).like(needle),
                    func.lower(func.coalesce(models.Job.assigned_agent_id, "")).like(needle),
                )
            )
        total = session.execute(
            select(func.count()).select_from(models.Job).where(*filters)
        ).scalar_one()
        rows = session.execute(
            select(models.Job)
            .where(*filters)
            .order_by(direction, models.Job.job_id)
            .offset(offset)
            .limit(limit)
        ).scalars().all()
    # Outside the session, and only when the page actually has a grouped job:
    # the overwhelming majority of installations have no groups at all and must
    # not pay a second query per listing for a column they never show.
    live = _live_groups_for(settings, rows)
    return [_to_info(row, live) for row in rows], total


#: The surface buckets ``summary`` reports, in the order a console renders
#: them. ``unknown`` is the NULL bucket, exactly as in ``list_jobs``.
SUMMARY_SURFACES = (*scan_surface.SURFACES, "unknown")


def summary(settings: Settings, *, tenant_id: str | None = None) -> dict[str, Any]:
    """Queue depth by status and by surface, in one grouped query.

    The counts a scan console shows above the job list. ``tenant_id`` of
    ``None`` counts the whole fleet, which only an unscoped platform admin
    reaches — the same rule as ``list_jobs``.

    ``queued`` here is queued *plus* claimed: the question the number answers
    is "how much work is waiting to be done", and a job an agent has taken but
    not started is still waiting. Note this differs from the ``octo_jobs_*``
    gauges in docs/slo.md, which count ``claimed`` as running because they are
    measuring executor occupancy instead.
    """
    by_status = dict.fromkeys(sorted(job_states.ALL), 0)
    by_surface = {
        surface: {"running": 0, "queued": 0, "total": 0} for surface in SUMMARY_SURFACES
    }
    stored_surface = models.Job.scan_options["surface"].as_string()

    with get_session(settings.postgres_url) as session:
        filters = [models.Job.tenant_id == tenant_id] if tenant_id else []
        rows = session.execute(
            select(models.Job.status, stored_surface, func.count())
            .where(*filters)
            .group_by(models.Job.status, stored_surface)
        ).all()

    for status, surface, count in rows:
        # A status outside the lifecycle cannot be produced by job_states, but
        # a hand-edited row must not make the whole summary disappear.
        by_status[str(status)] = by_status.get(str(status), 0) + count
        bucket = by_surface[surface if surface in by_surface else "unknown"]
        bucket["total"] += count
        if status in (job_states.RUNNING, job_states.CANCELLING):
            bucket["running"] += count
        elif status in (job_states.QUEUED, job_states.CLAIMED):
            bucket["queued"] += count

    return {
        "by_status": by_status,
        # A job being stopped is still on a worker, so it is counted with the
        # running ones rather than disappearing from both tiles (#360).
        "running": by_status.get(job_states.RUNNING, 0)
        + by_status.get(job_states.CANCELLING, 0),
        "queued": by_status.get(job_states.QUEUED, 0) + by_status.get(job_states.CLAIMED, 0),
        "by_surface": by_surface,
        "generated_at": _iso(_now()),
    }


def _live_groups_for(
    settings: Settings, rows: Sequence[models.Job]
) -> set[tuple[str, str]] | None:
    """``live_groups`` for the tenants of these rows, or None if none is grouped."""
    tenants = {
        row.tenant_id or tenants_service.DEFAULT_TENANT_ID
        for row in rows
        if row.agent_group and row.status == job_states.QUEUED
    }
    if not tenants:
        return None
    return agent_groups_service.live_groups(settings, tenants)


def get_job(settings: Settings, job_id: str) -> JobInfo | None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None:
            return None
        live = _live_groups_for(settings, [row])
        return _to_info(row, live)


def reset_for_tests(settings: Settings) -> None:
    with get_session(settings.postgres_url) as session:
        session.query(models.Job).delete()


def _update_job(settings: Settings, job_id: str, **fields: Any) -> None:
    """Apply ``fields`` to a job row, validating any status change.

    Validation lives here rather than at each call site so a future writer
    cannot reintroduce a bare assignment: every path that moves a job — local
    executor, agent claim, result upload, restart reconciliation, cancel — goes
    through this function. Use ``force_status`` for the rare repair/test case
    that must ignore the lifecycle.
    """
    with get_session(settings.postgres_url) as session:
        # Locked, not just read: two writers racing on one job (an operator
        # cancelling while the local executor starts it, say) would otherwise
        # both validate against the same stale status and the later commit
        # would win regardless of what the earlier one decided.
        row = session.get(models.Job, job_id, with_for_update=True)
        if row is None:
            return
        if "status" in fields:
            job_states.check_transition(job_id, row.status, str(fields["status"]))
            if fields["status"] in job_states.TERMINAL:
                # A finished job holds no lease. Cleared here rather than at
                # each terminal call site so the reaper can never see a
                # leftover deadline on a row it has no business touching.
                fields.setdefault("claimed_until", None)
        for key, value in fields.items():
            setattr(row, key, value)
        session.flush()
        snapshot = (
            (row.status, row.execution, row.started_at, row.finished_at)
            if "status" in fields
            else None
        )
        # Snapshotted here rather than re-read after the commit: the row is
        # loaded and locked, and a job that failed is terminal, so this is the
        # one moment it moved into ``failed``.
        failure = (
            _scan_failure_event(row)
            if fields.get("status") == job_states.FAILED
            else None
        )
    if snapshot is not None:
        _record_job_metrics(settings, *snapshot)
    if failure is not None:
        # After the commit: an event announcing a failure that then rolled back
        # would be a notification about something that did not happen (#349).
        workflow_events.emit(settings, "scan_failed", **failure)


def _scan_failure_event(row: models.Job) -> dict[str, Any]:
    """``workflow_events.emit`` keyword arguments for one failed job (#349).

    ``marker`` is the attempt count, not the job id alone: an agent job whose
    lease expired is requeued and may fail again on a later attempt, and those
    are two failures somebody has to hear about separately. The error string
    is truncated because it is a scanner's stderr and ends up in a webhook
    payload column.
    """
    return {
        "tenant_id": row.tenant_id or tenants_service.DEFAULT_TENANT_ID,
        "subject_id": row.job_id,
        "marker": str(row.attempts or 0),
        "data": {
            "job_id": row.job_id,
            "run_id": row.run_id,
            "execution": row.execution,
            "mode": row.mode,
            # The scan's surface, not its target list: a target list can be a
            # /16 and this payload is stored per delivery.
            "surface": (row.scan_options or {}).get("surface"),
            "attempts": row.attempts,
            "assigned_agent_id": row.assigned_agent_id,
            "exit_code": row.exit_code,
            "requested_by": row.requested_by,
            "error": (row.error or "")[:1000] or None,
        },
    }


def force_status(settings: Settings, job_id: str, status: str, **fields: Any) -> None:
    """Set a status without lifecycle validation.

    The escape hatch for tests that need to stage a state directly, and for an
    operator repair where the row is already wrong. Nothing in the request path
    may call this — use the transitions in ``job_states``.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None:
            return
        row.status = status
        for key, value in fields.items():
            setattr(row, key, value)
    _refresh_job_gauges(settings)


def _record_job_metrics(
    settings: Settings,
    status: str,
    execution: str,
    started_at: datetime | None,
    finished_at: datetime | None,
) -> None:
    if status in {"succeeded", "failed"} and started_at and finished_at:
        duration = (finished_at - started_at).total_seconds()
        if duration >= 0:
            metrics_service.JOB_DURATION_SECONDS.labels(
                status=status, execution=execution or "local"
            ).observe(duration)
    _refresh_job_gauges(settings)


def _refresh_job_gauges(settings: Settings) -> None:
    """Publish queued/running counts.

    These are now counted in the shared table rather than per-process, so two
    replicas no longer report two different queue depths for the same queue —
    one of the known gaps called out in docs/slo.md.

    ``claimed`` (P1.3) counts as running: the job is out with a worker and no
    longer waiting, so folding it into the queue depth would read as a backlog
    that nothing is working on. ``cancelling`` (#360) counts as running for the
    same reason — the agent is still busy with it until it confirms — even
    though it is deliberately outside ``IN_FLIGHT``, which is the lease set.
    """
    with get_session(settings.postgres_url) as session:
        counts = dict(
            session.execute(
                select(models.Job.status, func.count())
                .where(models.Job.status.in_(tuple(job_states.ACTIVE)))
                .group_by(models.Job.status)
            ).all()
        )
    metrics_service.JOBS_QUEUED.set(counts.get(job_states.QUEUED, 0))
    metrics_service.JOBS_RUNNING.set(
        sum(counts.get(s, 0) for s in (*job_states.IN_FLIGHT, job_states.CANCELLING))
    )


def _write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(lines)
    if body:
        body += "\n"
    path.write_text(body, encoding="utf-8")


def _prepare_target_inputs(
    settings: Settings,
    job_id: str,
    request: StartScanRequest,
    *,
    tenant_id: str,
    promoted: list[str] | None = None,
    scope: scan_scopes.ScanScope | None = None,
    policy: dict[str, Any] | None = None,
) -> tuple[Path | None, dict[str, int] | None, list[str]]:
    """Write per-job input files, and the scope the run is to be held to.

    Returns (inputs_dir, target_counts, extra_cli_args). Raises
    ``scan_scopes.ScanScopeDenied`` when the tenant's approved scope does not
    cover the requested targets — the first of the two barriers (#226).

    The scope document is written for *every* job, including one that carries no
    target overrides at all (#244). That is the case the API cannot check any
    other way: such a run reads the installation's own target files, which the
    API never opens, so the only thing #226 could ask was whether the tenant had
    a scope — not whether the files agree with it. The scanner opens them, and
    now has the scope in hand when it does.
    """
    if scope is None:
        scope = scan_scopes.load_scope(settings, tenant_id)
    parsed = parse_target_payload(
        scope=scope,
        ranges_text=request.ranges,
        domains_text=request.domains,
        ports_text=request.ports,
        ports_udp_text=request.ports_udp,
    )

    inputs_dir = job_inputs_dir(settings, job_id)
    inputs_dir.mkdir(parents=True, exist_ok=True)
    scope_path = inputs_dir / SCAN_SCOPE_INPUT
    scope_path.write_text(
        json.dumps(scope.to_document(), indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    extra: list[str] = ["--scan-scope", str(scope_path)]
    counts: dict[str, int] = {}

    if policy is not None:
        # Written for the local runner and read back for the agent's claim
        # response by ``_read_job_inputs``, so both executors are handed the
        # same document by the same mechanism — a policy only one of the two
        # paths applied would be a ceiling that depends on where the scan
        # happened to run.
        extra.extend(["--scan-policy", str(_write_policy_input(inputs_dir, policy))])

    if promoted:
        promoted_path = inputs_dir / PROMOTED_DOMAINS_INPUT
        _write_lines(promoted_path, promoted)
        extra.extend(["--promoted-domains", str(promoted_path)])
        counts["promoted_domains"] = len(promoted)

    if parsed is None:
        return inputs_dir, counts or None, extra

    if parsed.ranges is not None and parsed.domains is not None:
        ranges_path = inputs_dir / "ranges.txt"
        domains_path = inputs_dir / "domains.txt"
        _write_lines(ranges_path, parsed.ranges)
        _write_lines(domains_path, parsed.domains)
        extra.extend(["--ranges", str(ranges_path), "--domains", str(domains_path)])
        counts["ranges"] = len(parsed.ranges)
        counts["domains"] = len(parsed.domains)

    if parsed.ports is not None:
        ports_path = inputs_dir / "ports.txt"
        _write_lines(ports_path, parsed.ports)
        extra.extend(["--ports-file", str(ports_path)])
        counts["ports"] = len(parsed.ports)

    if parsed.ports_udp is not None:
        ports_udp_path = inputs_dir / "ports_udp.txt"
        _write_lines(ports_udp_path, parsed.ports_udp)
        extra.extend(["--ports-udp-file", str(ports_udp_path)])
        counts["ports_udp"] = len(parsed.ports_udp)

    return inputs_dir, counts or None, extra


def wordlist_file_for_job(settings: Settings, job_id: str) -> Path:
    """Where a job's materialized wordlist lives. One place, so the writer and
    the post-run cleanup cannot drift apart."""
    return settings.state_dir / "wordlists" / f"{job_id}.txt"


def _discard_job_wordlist(settings: Settings, job_id: str) -> None:
    """Drop a finished job's materialized wordlist.

    Each selecting scan writes its own copy of a list that may approach the
    upload cap, and the state dir is persistent, so without this an
    installation that routinely brute-forces grows a directory nothing ever
    reads again until the volume fills. The row in Postgres remains the source
    of truth — this only removes the per-job copy. Best-effort: a scan that
    finished must not be reported as failed because its scratch file could not
    be unlinked."""
    try:
        wordlist_file_for_job(settings, job_id).unlink(missing_ok=True)
    except OSError:
        _log.warning("Could not remove wordlist scratch file for job %s", job_id, exc_info=True)


def _write_policy_input(inputs_dir: Path, policy: dict[str, Any]) -> Path:
    """Write one job's ``scan_policy.json`` and answer where it went.

    The same file for both executors: the local runner is handed its path on
    the command line, and the agent reads its contents out of the claim
    response (``_read_job_inputs``). One writer, so a job cannot end up with a
    policy that depends on where it happened to run.
    """
    inputs_dir.mkdir(parents=True, exist_ok=True)
    path = inputs_dir / SCAN_POLICY_INPUT
    path.write_text(
        json.dumps(policy, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def job_inputs_dir(settings: Settings, job_id: str) -> Path:
    """Where a job's input files live. One place, so the writer, the reader and
    the cleanup cannot drift apart."""
    return settings.state_dir / "job_inputs" / job_id


def _discard_job_inputs(settings: Settings, job_id: str) -> None:
    """Drop a finished job's input directory (#258).

    Before #244 the directory existed only for a job carrying target
    overrides. #244 writes ``scan_scope.json`` for every job, so it is now
    created once per scan and growth went from occasional to linear in runs --
    on a persistent volume, in one flat tree, with a product that advertises
    50k assets and continuous schedules. That is the same class of unbounded
    growth #187 closed for ClickHouse rows and run artifacts, which job_inputs
    was simply not part of.

    Called only where the job is terminal or was never started: the scanner
    reads these files while it runs, and an agent job is read again on every
    claim, so removing them earlier would break the run rather than tidy after
    it. Best-effort, like :func:`_discard_job_wordlist` -- a scan that finished
    must not be reported as failed because its scratch directory would not
    unlink -- and idempotent, since the reaper may have swept it already.
    """
    try:
        shutil.rmtree(job_inputs_dir(settings, job_id), ignore_errors=False)
    except FileNotFoundError:
        pass
    except OSError:
        _log.warning("Could not remove input files for job %s", job_id, exc_info=True)


def _wordlist_overrides(
    settings: Settings, job_id: str, tenant_id: str, wordlist_id: str | None
) -> tuple[dict, dict] | None:
    """Materialize a tenant's selected brute-force wordlist to a job-scoped file
    and return ``(config_override, provenance)``.

    Returns ``None`` when no wordlist was requested. Raises ``ValueError`` when
    the id is unknown or belongs to another tenant — selecting a wordlist that
    cannot be found must fail the scan request, not run it without one.

    The override is nested under ``discovery`` because that is where the
    scanner's ``AppConfig`` actually holds these stages. A top-level ``ct``/
    ``cloud`` key validates cleanly (the schema does not forbid extras) and is
    then ignored, so the scan would run with the stage still disabled and
    succeed — a silent no-op rather than an error. The scan-start tests assert
    through ``load_config`` for exactly this reason.

    Selecting a *subdomain* list turns on the CT/brute-force discovery stage
    (``ct.enabled`` + ``ct.brute_force.enabled``) with the uploaded list; a
    *bucket* list turns on cloud discovery. Enabling ``ct`` also lets its
    configured providers run (default ``crtsh``, a passive third-party CT-log
    query) — brute force is nested under that stage and cannot run without it.
    """
    if not wordlist_id:
        return None
    resolved = wordlists_service.get_for_scan(wordlist_id, tenant_id=tenant_id)
    if resolved is None:
        raise ValueError(f"Unknown wordlist_id: {wordlist_id}")

    dest = wordlist_file_for_job(settings, job_id)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(resolved.content + "\n", encoding="utf-8")
    path = str(dest)

    if resolved.kind == "bucket":
        stage = {"cloud": {"enabled": True, "wordlist_file": path}}
    else:
        stage = {"ct": {"enabled": True, "brute_force": {"enabled": True, "wordlist_file": path}}}
    # Recorded on the job so a completed run can still answer "which dictionary
    # produced this?" after the wordlist is renamed, replaced or deleted.
    provenance = {
        "wordlist_id": wordlist_id,
        "wordlist_name": resolved.name,
        "wordlist_kind": resolved.kind,
        "wordlist_sha256": resolved.sha256,
        "wordlist_entries": resolved.line_count,
    }
    return {"discovery": stage}, provenance


def _build_command(
    settings: Settings,
    *,
    mode: str,
    delta: bool,
    skip_nse: bool,
    notify: bool,
    export_defectdojo: bool,
    run_id: str | None,
    target_args: list[str],
    config_path: str,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "scanner.main",
        "--config",
        config_path,
        "--mode",
        mode,
    ]
    if delta:
        command.append("--delta")
    if skip_nse:
        command.append("--skip-nse")
    if notify:
        command.append("--notify")
    if export_defectdojo:
        command.append("--export-defectdojo")
    if run_id:
        command.extend(["--run-id", run_id])
    command.extend(target_args)
    return command


def _upsert_assets_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, job_id: str | None = None
) -> None:
    """Best-effort asset-registry upsert (Phase 7) — never fails the scan/upload.

    Covers both execution paths: local-mode scans land here from _run_job,
    agent-uploaded results land here from complete_job.

    A failure here used to leave no trace outside the pod log: the job still
    read as "succeeded", the scan artifacts were all present, and the asset list
    was simply empty — so the only way to learn why was to catch the log before
    the pod was replaced. Record the reason on the job instead.
    """
    if not run_id:
        return
    try:
        assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id=run_id)
    except Exception as exc:  # noqa: BLE001
        logging.exception("Asset upsert failed for run %s (tenant=%s)", run_id, tenant_id)
        if job_id:
            _update_job(settings, job_id, asset_upsert_error=f"{type(exc).__name__}: {exc}"[:2000])


def _track_vulnerabilities_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, job_id: str | None = None
) -> None:
    """Best-effort fold of the run's findings into the tracker (#145).

    Runs after the asset upsert in both completion paths, and only for a
    *succeeded* run: a finding is attached to an asset, so the registry has to
    be current first, and a failed run's ``vulnerabilities.json`` may be a
    partial write from a scan that stopped mid-stage. Findings the tracker
    misses are not lost — the next successful scan observes them again.

    Quiet on failure, like the event publish and unlike the asset upsert: an
    un-tracked finding is still in the run's artifacts and in ClickHouse, so
    nothing is unrecoverable, whereas an empty asset list means the run
    produced no inventory at all.
    """
    if not run_id:
        return
    try:
        vulns_service.register_findings_from_run(settings, tenant_id=tenant_id, run_id=run_id)
    except Exception:  # noqa: BLE001
        logging.exception(
            "Vulnerability tracking failed for run %s (tenant=%s, job=%s)",
            run_id,
            tenant_id,
            job_id,
        )


def _publish_asset_events_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, job_id: str | None = None
) -> None:
    """Best-effort publish of the run's Phase 10.1 events (Phase 10.2).

    Called from the same two places as ``_upsert_assets_best_effort`` and for
    the same reason — those are the only two points where a finished run's
    artifacts are on disk under a known tenant, whether the scan ran locally or
    came up from an agent.

    Deliberately quieter than the asset upsert on failure: an empty asset list
    is a broken installation worth recording on the job, while an unpublished
    event is a missed notification whose payload is still in ``diff.json``.
    """
    if not run_id or not settings.asset_events_enabled or not settings.nats_url:
        return
    try:
        asset_events.publish_run_events(
            nats_url=settings.nats_url,
            run_dir=settings.output_dir / "runs" / run_id,
            tenant_id=tenant_id,
            run_id=run_id,
            job_id=job_id,
            max_events=settings.asset_events_max_per_run,
        )
    except Exception:  # noqa: BLE001
        logging.exception("Asset event publish failed for run %s (tenant=%s)", run_id, tenant_id)


def _notify_channels_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, job_id: str | None = None
) -> None:
    """Announce a finished run to the tenant's notification channels (#351).

    Called from the same two points as the asset-event publish above, and that
    is the fix: those are the only places where a finished run's artifacts are
    on disk *under a known tenant*. The alert used to be a scanner stage, which
    ran with installation-wide credentials and no tenant id at all, so on an
    MSSP installation every tenant's scan announced itself in one Slack channel.

    Quiet on failure like the event publish, and for a stronger reason: an
    unreachable Slack must not turn a successful scan into a failed job. The
    per-channel outcome is recorded on the channel row (``last_status``), which
    is where an operator looks when a channel goes silent.

    Asynchronous, unlike the hooks above it, because it is the only one that
    dials a third party. ``complete_job`` runs inside ``async def
    upload_results``, so a blocking send there stalls the API's event loop for
    the timeout budget of every channel in turn — see the note in
    ``channels.notify_run_complete_async``. The hooks above touch Postgres and
    the local NATS and are left alone.
    """
    if not run_id or not settings.notification_channels_enabled:
        return
    try:
        channels_service.notify_run_complete_async(
            tenant_id=tenant_id,
            run_id=run_id,
            run_dir=settings.output_dir / "runs" / run_id,
        )
    except Exception:  # noqa: BLE001 - a thread that would not start
        logging.exception(
            "Notification fan-out failed for run %s (tenant=%s, job=%s)",
            run_id,
            tenant_id,
            job_id,
        )


def _requested_by(settings: Settings, job_id: str) -> str:
    """Who asked for this scan, or "" when the row is gone."""
    job = get_job(settings, job_id)
    return job.requested_by if job else ""


def _record_scope_denials_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, requested_by: str
) -> None:
    """Fold the scanner's own scope refusals into the access-decision journal (#244).

    The scanner drops a target that the tenant's approved scope refuses, but it
    runs on the agent's host with no database, no ``auth_events`` and no route
    to either — so it writes what it refused into ``scan_scope_denied.json`` and
    the decision is journalled here, where the run's artifacts land. Without
    this the refusals the *scanner* makes would be the only access decisions in
    the platform that leave no trail, and "who was stopped from scanning what"
    would have two answers depending on which barrier stopped them.

    Attributed to the job's requester, not to the agent: the agent executed a
    scan somebody else asked for, and it is the asker whose request was cut
    down. Called for a failed run too — a refusal happened whether or not the
    scan that followed it succeeded.

    Best-effort, like ``record_denial``: the scan is long over by the time this
    runs, and a lost journal write must not turn a completed upload into a 500.
    """
    if not run_id:
        return
    artifact = settings.output_dir / "runs" / run_id / scan_scope.DENIED_ARTIFACT
    try:
        report = json.loads(artifact.read_text(encoding="utf-8"))
        denied = [str(item) for item in (report.get("denied") or [])]
        if not denied:
            return
        auth_audit.record_denied(
            username=requested_by or "scanner",
            reason=auth_audit.REASON_SCAN_SCOPE,
            detail=f"tenant={tenant_id} run={run_id} dropped by the scanner: "
            f"{', '.join(denied[:8])}"[:1000],
        )
    except FileNotFoundError:
        # An older agent, or a run the pipeline never got far enough to filter.
        return
    except Exception:  # noqa: BLE001 - see docstring
        logging.exception(
            "Failed to record scanner scan-scope denials for run %s (tenant=%s)",
            run_id,
            tenant_id,
        )


def _lease_deadline(settings: Settings) -> datetime:
    return _now() + timedelta(seconds=max(settings.job_lease_seconds, 1))


def renew_lease(settings: Settings, job_id: str, *, agent_id: str | None = None) -> bool:
    """Push a job's lease deadline forward. Returns whether it applied.

    The proof of life for an in-flight job: agents renew from their heartbeat,
    local jobs from a thread beside the scan (``_renewing_lease``). Only jobs
    that are actually in flight are touched, and when ``agent_id`` is given it
    must be the agent holding the job — a stray heartbeat naming someone else's
    job must not keep that job alive.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None or row.status not in job_states.IN_FLIGHT:
            return False
        if agent_id is not None and row.assigned_agent_id != agent_id:
            return False
        row.claimed_until = _lease_deadline(settings)
        return True


@contextmanager
def _renewing_lease(settings: Settings, job_id: str) -> Iterator[None]:
    """Keep a local job's lease alive for as long as this process runs it.

    A local scan has no heartbeat to ride on — it is a ``subprocess`` in a
    thread — so without this its lease would lapse mid-scan and the reaper
    would fail a job that is running perfectly well. Renewing from beside the
    scan is also what finally closes the P1.2 residual: if this replica dies,
    the renewals stop with it and the job stops looking attended.

    Failures are logged, not raised: a database blip during a two-hour scan
    should cost a renewal, not the scan.
    """
    stop = threading.Event()
    # Renew several times per lease so a single missed tick is not fatal.
    interval = max(settings.job_lease_seconds / 3.0, 1.0)

    def _loop() -> None:
        while not stop.wait(interval):
            try:
                if not renew_lease(settings, job_id):
                    return  # Terminal already — nothing left to hold.
            except Exception:  # noqa: BLE001
                _log.warning("Lease renewal failed for job %s", job_id, exc_info=True)

    thread = threading.Thread(target=_loop, name=f"octo-lease-{job_id}", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=1.0)


def reap_expired_leases(settings: Settings) -> dict[str, int]:
    """Sweep jobs whose executor stopped renewing, and return what was done.

    An expired lease means the executor is gone rather than slow — it had the
    whole lease window, several renewal intervals, to say otherwise. What
    happens next differs by execution mode:

    - **agent** jobs go back to ``queued`` for another worker, until
      ``job_max_attempts`` hand-outs have been used. A target that kills
      whatever picks it up would otherwise cycle through the fleet forever.
    - **local** jobs are failed outright. Their only executor was the thread in
      the process that died; no other replica will ever pick the row up, so
      requeueing it would just park it in the queue for good.

    Safe to run in every replica (there is no leader election until P1.6): rows
    are taken with ``FOR UPDATE SKIP LOCKED``, so two reapers sweeping at once
    handle different jobs rather than the same one twice.
    """
    now = _now()
    outcome = {"requeued": 0, "failed": 0}
    requeued_agent_jobs: list[str] = []
    # (execution, started_at) per job failed here, so the duration histogram
    # sees them once the transaction commits. Without this, giving up on a job
    # would be invisible to SLO 3 exactly when executors are dying.
    failed_for_metrics: list[tuple[str, datetime | None]] = []
    # Same shape, for the #349 event. This path does not go through
    # ``_update_job`` — it writes the status on a row it already holds — so the
    # emitter there does not see it, and a lease that expired is exactly the
    # failure nobody is watching a console for.
    failed_events: list[dict[str, Any]] = []
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.Job)
            .where(
                models.Job.status.in_(tuple(job_states.IN_FLIGHT)),
                models.Job.claimed_until.is_not(None),
                models.Job.claimed_until < now,
            )
            .with_for_update(skip_locked=True)
        ).scalars().all()
        for row in rows:
            retriable = row.execution == "agent" and row.attempts < settings.job_max_attempts
            if retriable:
                job_states.check_transition(row.job_id, row.status, job_states.QUEUED)
                row.status = job_states.QUEUED
                row.assigned_agent_id = None
                row.claimed_until = None
                # The attempt never produced a run, so it must not be counted
                # as a started job by the duration histogram.
                row.started_at = None
                outcome["requeued"] += 1
                requeued_agent_jobs.append(row.job_id)
                _log.warning(
                    "Requeued job %s: lease expired after attempt %d/%d",
                    row.job_id,
                    row.attempts,
                    settings.job_max_attempts,
                )
            else:
                job_states.check_transition(row.job_id, row.status, job_states.FAILED)
                row.status = job_states.FAILED
                row.finished_at = now
                row.claimed_until = None
                row.error = (
                    f"Lease expired after {row.attempts} attempt(s): the {row.execution} "
                    "executor stopped reporting and never returned"
                )
                outcome["failed"] += 1
                failed_for_metrics.append((row.execution or "local", row.started_at))
                failed_events.append(_scan_failure_event(row))
                _log.warning(
                    "Failed job %s: lease expired after %d attempt(s) (execution=%s)",
                    row.job_id,
                    row.attempts,
                    row.execution,
                )
    for name, count in outcome.items():
        if count:
            metrics_service.JOB_LEASE_EXPIRED_TOTAL.labels(outcome=name).inc(count)
    for execution, started_at in failed_for_metrics:
        _record_job_metrics(settings, job_states.FAILED, execution, started_at, now)
    for failure in failed_events:
        workflow_events.emit(settings, "scan_failed", **failure)
    if outcome["requeued"] or outcome["failed"]:
        _refresh_job_gauges(settings)
    # Republished after the transaction commits, so an agent cannot claim the
    # offer before the row is actually back on the queue.
    if settings.nats_url:
        for job_id in requeued_agent_jobs:
            _publish_job_offer(settings, job_id)
    return outcome


def _run_job(settings: Settings, job_id: str, command: list[str]) -> None:
    try:
        # A local job goes queued → running with no claim step: this process is
        # the worker. If it was cancelled while the thread was still starting,
        # the transition is rejected and the scan never launches.
        _update_job(
            settings,
            job_id,
            status=job_states.RUNNING,
            started_at=_now(),
            claimed_until=_lease_deadline(settings),
            attempts=1,
        )
    except job_states.InvalidJobTransition as exc:
        _log.info("Not starting job %s: %s", job_id, exc)
        # Cancelled between the insert and this thread getting scheduled: the
        # scan never launches, so nothing will ever read the wordlist copy or
        # the input files.
        _discard_job_wordlist(settings, job_id)
        _discard_job_inputs(settings, job_id)
        return
    try:
        with _renewing_lease(settings, job_id):
            completed = subprocess.run(command, check=False, capture_output=True, text=True)
        # Best-effort: read latest_run.json after completion.
        run_id = None
        pointer = settings.state_dir / "latest_run.json"
        if pointer.exists():
            try:
                run_id = json.loads(pointer.read_text(encoding="utf-8")).get("run_id")
            except json.JSONDecodeError:
                run_id = None
        status = job_states.SUCCEEDED if completed.returncode == 0 else job_states.FAILED
        error = None
        if completed.returncode != 0:
            error = (completed.stderr or completed.stdout or f"exit {completed.returncode}")[:2000]
        _update_job(
            settings,
            job_id,
            status=status,
            finished_at=_now(),
            exit_code=completed.returncode,
            run_id=str(run_id) if run_id else None,
            error=error,
        )
        job = get_job(settings, job_id)
        tenant_id = job.tenant_id if job else tenants_service.DEFAULT_TENANT_ID
        # Outside the success gate: a target the scanner refused was refused
        # whether or not the scan that followed it finished cleanly.
        _record_scope_denials_best_effort(
            settings,
            tenant_id=tenant_id,
            run_id=str(run_id) if run_id else None,
            requested_by=job.requested_by if job else "",
        )
        if status == job_states.SUCCEEDED:
            # Tag the run before the asset upsert: an untagged run reads back as
            # the default tenant, which would leak it to every tenant's run list.
            if run_id:
                runs_service.write_run_tenant(
                    settings,
                    str(run_id),
                    tenant_id,
                    job_id=job_id,
                    surface=(job.scan_options or {}).get("surface") if job else None,
                )
            _upsert_assets_best_effort(
                settings, tenant_id=tenant_id, run_id=str(run_id) if run_id else None, job_id=job_id
            )
            _track_vulnerabilities_best_effort(
                settings, tenant_id=tenant_id, run_id=str(run_id) if run_id else None, job_id=job_id
            )
            _publish_asset_events_best_effort(
                settings, tenant_id=tenant_id, run_id=str(run_id) if run_id else None, job_id=job_id
            )
            # Last of the post-run hooks: the summary it sends describes the
            # tracker and the registry as they are *after* the folds above.
            _notify_channels_best_effort(
                settings, tenant_id=tenant_id, run_id=str(run_id) if run_id else None, job_id=job_id
            )
    except Exception as exc:  # noqa: BLE001
        logging.exception("Scan job %s failed", job_id)
        try:
            _update_job(
                settings,
                job_id,
                status=job_states.FAILED,
                finished_at=_now(),
                error=str(exc)[:2000],
            )
        except job_states.InvalidJobTransition:
            # The scan itself finished and the job is already terminal — this
            # is post-completion bookkeeping (run tagging) blowing up. Record it
            # without rewriting the outcome the scan actually had.
            _update_job(settings, job_id, error=str(exc)[:2000])
    finally:
        # The scanner has exited either way, so its copy of the wordlist and
        # its input files have been read for the last time.
        _discard_job_wordlist(settings, job_id)
        _discard_job_inputs(settings, job_id)


#: Request fields that define *which scan* a start asks for. ``tenant_id`` is
#: decided by the route rather than the caller, and ``run_id`` only names the
#: output directory, so neither makes two calls a different request.
_IDEMPOTENCY_FIELDS = (
    "mode",
    "intent",
    "delta",
    "skip_nse",
    "notify",
    "export_defectdojo",
    "surface",
    "wordlist_id",
    # Which agents may execute the scan is part of what was asked for (#361):
    # answering a request for one group with the job of another would report a
    # scan that reached the targets from somewhere else entirely.
    "agent_group",
)

#: Target fields, compared line by line rather than character by character.
_IDEMPOTENCY_TARGET_FIELDS = ("ranges", "domains", "ports", "ports_udp")


def _normalised_target_text(text: str | None) -> str | None:
    """The same target list typed with different whitespace, spelled one way.

    Not ``split_target_lines``: that also drops comments and splits on commas,
    which are edits to the request rather than formatting of it. A retry is a
    resend of the same body, so trimming each line and dropping blank ones is
    as far as this may go without calling two different requests the same.
    """
    if text is None:
        return None
    return "\n".join(line.strip() for line in text.splitlines() if line.strip())


def _idempotency_digest(request: StartScanRequest) -> str:
    """A fingerprint of the scan a start request asks for (ROADMAP P1.5).

    A key on its own only says "the client called this request X"; it cannot
    say whether the second call is the retry it claims to be. The digest is
    what lets the second call be answered with the first job only when it is
    in fact the same scan — see ``IdempotencyMismatch``.
    """
    payload: dict[str, Any] = {
        field: getattr(request, field) for field in _IDEMPOTENCY_FIELDS
    }
    payload.update(
        {
            field: _normalised_target_text(getattr(request, field))
            for field in _IDEMPOTENCY_TARGET_FIELDS
        }
    )
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class IdempotencyMismatch(Exception):
    """A key an earlier request used, sent with a *different* scan request.

    Deliberately not a replay: answering with the earlier job would report a
    scan of targets this caller never asked for, and starting a second one
    would break the promise the key was given for. Neither is right, so the
    caller is told the key is taken (409) and picks another.

    Not a ``ValueError``: the body is well-formed, and the route maps
    ``ValueError`` to 422.
    """

    def __init__(self, job: JobInfo) -> None:
        super().__init__(
            "Idempotency-Key already used for a different scan request "
            f"(job {job.job_id})"
        )
        self.job = job


class IdempotentReplay(Exception):
    """A scan start whose key already created a job. Carries that job.

    An exception rather than a return value because the caller has to answer
    differently (200, not 202): nothing was accepted by this request.
    """

    def __init__(self, job: JobInfo) -> None:
        super().__init__(f"Idempotency key already started job {job.job_id}")
        self.job = job


def note_start_replay() -> None:
    """Count a scan-start request answered from an existing job."""
    metrics_service.JOB_IDEMPOTENT_REPLAYS_TOTAL.labels(operation="start").inc()


def find_by_idempotency_key(
    settings: Settings,
    *,
    tenant_id: str,
    key: str,
    request: StartScanRequest | None = None,
) -> JobInfo | None:
    """The job a previous request with this key created, if any (P1.5).

    With ``request``, the hit is also checked against what this caller is
    asking for and a key reused for a different scan raises
    ``IdempotencyMismatch`` instead of replaying. A job stored before the
    digest shipped carries none and is treated as a match: the alternative is
    to start 409-ing keys that worked yesterday.
    """
    if not key:
        return None
    with get_session(settings.postgres_url) as session:
        row = session.execute(
            select(models.Job).where(
                models.Job.tenant_id == tenant_id,
                models.Job.idempotency_key == key,
            )
        ).scalars().first()
        if row is None:
            return None
        info = _to_info(row)
    if request is not None:
        stored = (row.scan_options or {}).get("idempotency_digest")
        if stored and stored != _idempotency_digest(request):
            raise IdempotencyMismatch(info)
    return info


# A run id names one directory under ``output_dir/runs``. The scanner mints
# them as ``%Y%m%dT%H%M%SZ``; operators may supply their own for a local run.
# Either way it must stay a single path segment: it is joined onto the output
# directory unescaped, so anything with a separator or ``..`` in it would name
# a directory the caller was never given.
_RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


def validate_run_id(value: str) -> str:
    """Refuse a run id that is not one safe path segment."""
    if not _RUN_ID_RE.fullmatch(value):
        raise ValueError("run_id must be 1-64 characters of [A-Za-z0-9_-]")
    return value


def _confirm_run_id(expected: str | None, offered: str | None) -> str | None:
    """Resolve the run id an upload lands in.

    The server decided the run id at ``start_scan`` or at the claim, and the
    agent only echoes it back. The echo is accepted as confirmation, never as
    a choice: before this check an agent could name any directory — another
    tenant's run, or a path outside ``runs/`` — and have its archive extracted
    there and the run's ``tenant.json`` rewritten to its own tenant.
    """
    if expected and offered and offered != expected:
        raise ValueError("run_id does not match the job")
    resolved = expected or offered
    if resolved:
        validate_run_id(str(resolved))
    return resolved


def start_scan(
    settings: Settings,
    request: StartScanRequest,
    *,
    username: str,
    idempotency_key: str | None = None,
    quota_exempt: bool = False,
    widen_with_promoted: bool = True,
) -> JobInfo:
    """``widen_with_promoted`` is whether this scan carries the related domains
    the tenant's operators promoted (org_profile M4) on top of its own targets.
    On by default — that is what promotion means — and off for a dispatch
    that is aimed at one thing, today the verification re-scan of #183. A
    separate switch from ``quota_exempt`` on purpose: billing and targeting
    are different policies that happen to coincide on that one caller.

    ``quota_exempt`` marks a scan the platform dispatched to close its own
    loop — today only the verification re-scan of #183. It is neither refused
    by the tenant's monthly quota nor counted against it, and it is a property
    of *this dispatch*: the requester's name is the analyst's on that path, so
    recognising the exemption by username would be both wrong and forgeable.
    """
    if not settings.allow_scan_start:
        raise RuntimeError("Scan start disabled by OCTO_ALLOW_SCAN_START")

    tenant_id = (request.tenant_id or tenants_service.DEFAULT_TENANT_ID).strip()
    tenant = tenants_service.get_tenant(tenant_id)
    if tenant is None:
        raise ValueError(f"Unknown tenant_id: {tenant_id}")
    if tenant.get("status") != "active":
        raise ValueError(f"Tenant is not active: {tenant_id}")

    # Before any work is prepared: what the tenant bought (Track E, MSSP
    # operations). Placed here rather than in the route because the recurring
    # dispatcher and every other caller reach start_scan and none of them
    # reach the route — a quota only one entry point honours is not a quota.
    if not quota_exempt:
        quotas.assert_scan_quota(settings, tenant_id=tenant_id)

    job_id = uuid.uuid4().hex[:12]
    execution = "agent" if settings.job_execution_mode == "agent" else "local"
    run_id = request.run_id
    if run_id:
        validate_run_id(run_id)
    if execution == "agent" and not run_id:
        run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")

    # Loaded once here and handed to both barriers below: the scope cannot
    # change inside this call frame, and each load is a round trip.
    scope = scan_scopes.load_scope(settings, tenant_id)

    # Related domains the tenant's operators promoted (org_profile M4) ride
    # along with every ordinary scan — that is what promotion means. Held to
    # the approved scope as it stands *now*, suffix and resolve-time checks
    # both: a domain promoted under a wider scope is dropped and recorded,
    # not a reason to refuse the operator's own targets.
    promoted_admitted: list[str] = []
    promoted_refused: list[str] = []
    if widen_with_promoted:
        promoted_admitted, promoted_refused = promoted_domains.split_for_scan(
            settings, scope, promoted_domains.promoted_names(settings, tenant_id)
        )
        if promoted_refused:
            _log.warning(
                "Tenant %s: %d promoted domain(s) outside the approved scan scope "
                "dropped from job %s: %s",
                tenant_id,
                len(promoted_refused),
                job_id,
                ", ".join(promoted_refused[:8]),
            )

    # What the tenant consented to *right now* (#352): a blackout window or a
    # change freeze. In start_scan rather than in the route for the same reason
    # the quota is here — the recurring dispatcher never touches a route, and a
    # blackout the scheduler walks through at 02:00 is not a blackout.
    #
    # Below the promoted-domain widening on purpose: a promoted related domain
    # is a target of every scan the tenant starts, so an asset-group window
    # covering it has to see it. Checking the operator's typed targets alone
    # would let a scan of an unrelated domain carry the promoted one straight
    # into the group the window was protecting.
    #
    # Deliberately not exempted for `quota_exempt` dispatches: a verification
    # re-scan still reaches the customer's network, and the calendar is about
    # the network rather than the invoice.
    try:
        maintenance.assert_scan_admitted(
            settings,
            tenant_id=tenant_id,
            ranges_text=request.ranges,
            domains_text="\n".join([request.domains or "", *promoted_admitted]),
        )
    except maintenance.MaintenanceBlocked as blocked:
        maintenance.record_block(username=username, blocked=blocked)
        raise

    # How hard this tenant may be scanned (#362). Here, beside the quota and
    # the calendar, for the same reason both are here: the recurring dispatcher
    # and the platform's own re-scans never touch a route, and a rate ceiling
    # the nightly sweep ignores is not a rate ceiling.
    #
    # ``request.mode`` rather than the resolved CLI mode below, so the refusal
    # lands before any input file is written. The two agree on the only
    # question asked here — ``scan_intents`` maps the API's ``test`` onto
    # ``balanced`` and leaves ``safe`` alone, so "the operator asked for safe"
    # is the same statement before and after that mapping.
    try:
        policy = scan_policy.assert_scan_admitted(
            settings,
            tenant_id=tenant_id,
            mode=request.mode,
            ports_text=request.ports,
            ports_udp_text=request.ports_udp,
        )
    except scan_policy.ScanPolicyViolation as violation:
        scan_policy.record_block(username=username, violation=violation)
        raise
    # The document the run is held to, frozen now: a policy edited while the
    # job sits in the queue must not change what was admitted, and the run has
    # to be answerable afterwards for the ceiling it actually ran under.
    policy_snapshot = scan_policy.snapshot(policy)

    try:
        _, target_counts, target_args = _prepare_target_inputs(
            settings,
            job_id,
            request,
            tenant_id=tenant_id,
            promoted=promoted_admitted,
            scope=scope,
            policy=policy_snapshot,
        )
        # Second barrier, deliberately redundant. start_scan is also reached
        # from schedule_dispatcher, which replays targets stored days ago and
        # never passed through the check above, and the approved scope may
        # have been narrowed since the targets were entered — the moment that
        # matters is the moment the scan starts, not the moment it was typed.
        scan_scopes.assert_scan_allowed(
            settings,
            tenant_id=tenant_id,
            ranges_text=request.ranges,
            domains_text=request.domains,
            scope=scope,
        )
    except scan_scopes.ScanScopeDenied as denied:
        scan_scopes.record_denial(username=username, denied=denied)
        raise

    # Which of the tenant's agents may execute this scan (#361). Two inputs,
    # and the request's is the one that is not trusted: the scope decides which
    # groups these targets may be reached from, and a selector naming anything
    # else is refused rather than honoured.
    #
    # The operator's targets only — unlike the maintenance check above, which
    # does look at the promoted domains. A window is a statement about an
    # asset, so a scan that reaches a promoted domain has to respect it; a
    # group restriction is a statement about *this* scan, and letting a
    # promoted domain contribute to it meant an ordinary external scan of
    # ``www.customer.example`` inherited the ``pci`` requirement of a promoted
    # ``pci.customer.example`` and went out from the card-data segment — the
    # reverse of what the control is for. Two promoted domains restricted to
    # disjoint groups did worse: they intersected to nothing and refused every
    # scan the tenant started, with advice ("split into separate scans") the
    # operator had no way to follow, because the form cannot exclude them.
    if promoted_admitted:
        _log.debug(
            "Job %s: %d promoted domain(s) are scanned but excluded from the "
            "agent-group requirement (#361); it follows the requested targets",
            job_id,
            len(promoted_admitted),
        )
    try:
        required_groups = scan_scopes.required_agent_groups(
            settings,
            tenant_id=tenant_id,
            ranges_text=request.ranges,
            domains_text=request.domains,
        )
        agent_group = agent_groups_service.resolve_for_scan(
            settings,
            tenant_id=tenant_id,
            requested=request.agent_group,
            required=required_groups,
        )
    except scan_scopes.ScanScopeDenied as denied:
        scan_scopes.record_denial(username=username, denied=denied)
        raise
    if agent_group and execution != "agent":
        # The group names remote workers, and a local scan runs in this
        # container, which is in no group. Refused rather than quietly ignored:
        # a scope entry that restricts targets to an agent group is an
        # instruction about where the packets come from, and running it here
        # anyway would be the control silently not applying.
        raise ValueError(
            f"agent_group {agent_group} requires a remote agent, but this "
            "installation runs scans locally (OCTO_JOB_EXECUTION_MODE=local)"
        )
    group_has_live_agent = not agent_group or bool(
        agent_groups_service.live_agent_count(settings, tenant_id=tenant_id, name=agent_group)
    )
    if not group_has_live_agent:
        # A warning rather than a refusal: an agent that is restarting is back
        # in seconds, so refusing here would turn a blip into a failed scan.
        # Only a log line, though — nothing is written onto the job. What the
        # console shows next to a queued job is ``agent_group_unavailable``,
        # recomputed on every read (see ``_to_info``), because the answer this
        # line gives is only true for as long as it takes the operator to start
        # the agent. See docs/operations.md.
        _log.warning(
            "Job %s (tenant %s) is addressed to agent group %s, which has no "
            "active agent seen within OCTO_AGENT_STALE_SECONDS: it stays queued "
            "until one registers",
            job_id,
            tenant_id,
            agent_group,
        )

    try:
        resolved = scan_intents.resolve_scan_options(
            intent=request.intent,
            mode=request.mode,
            delta=request.delta,
            skip_nse=request.skip_nse,
        )
    except ValueError:
        raise

    # Local scans run in this container, so apply the installation config
    # overrides by merging them into a job-specific config file. Agents run
    # their own mounted config, so overrides don't reach them — they keep the
    # base config (documented limitation). Intent nuclei/top_ports overlays
    # are local-only for the same reason.
    wordlist_options: dict[str, Any] = {}
    intent_extra = resolved.config_extra
    if execution == "local":
        selected = _wordlist_overrides(settings, job_id, tenant_id, request.wordlist_id)
        wordlist_extra: dict[str, Any] | None = None
        if selected:
            wordlist_extra, wordlist_options = selected
        extra = scan_intents.merge_config_extras(intent_extra, wordlist_extra)
        config_path = config_override_service.effective_config_path(settings, job_id, extra)
    else:
        if request.wordlist_id:
            # A custom wordlist lives in the API's Postgres and is materialized
            # onto the API pod's filesystem; a remote agent runs its own mounted
            # config and never sees it. Rather than silently ignore the request,
            # refuse it — the same class of limitation as installation overrides
            # not reaching agents.
            raise ValueError(
                "wordlist_id is only supported in local execution mode, "
                "not with remote agents"
            )
        if intent_extra:
            # Agent workers do not receive the merged effective-config file;
            # surface that so operators do not think nuclei floors applied.
            _log.warning(
                "intent=%s config overlays (nuclei/top_ports) are skipped in agent mode; "
                "CLI flags delta=%s skip_nse=%s still apply",
                resolved.intent,
                resolved.delta,
                resolved.skip_nse,
            )
        config_path = str(settings.config_path)
    # Derived from the targets as the operator entered them, not from the
    # widened set: a promoted related domain rides along with every scan and
    # would turn an internal sweep into a "mixed" one it was never asked to be.
    surface = scan_surface.resolve(request.surface, request.ranges, request.domains)
    # A fragile (OT/ICS) policy turns the service-probe stage off: nmap's NSE
    # scripts and pulse's banner grabs are the packets that put a PLC into a
    # fault state, and the port inventory a fragile run is really asked for
    # does not need them. Expressed on the command line as well as in the
    # policy document the scanner applies, so a reader of the job — and the
    # ``--skip-nse`` the scanner sees — says the same thing.
    skip_nse = resolved.skip_nse or bool((policy_snapshot or {}).get("skip_service_probe"))
    command = _build_command(
        settings,
        mode=resolved.mode,
        delta=resolved.delta,
        skip_nse=skip_nse,
        notify=request.notify,
        export_defectdojo=request.export_defectdojo,
        run_id=run_id,
        target_args=target_args,
        config_path=config_path,
    )

    row = models.Job(
        job_id=job_id,
        tenant_id=tenant_id,
        status=job_states.QUEUED,
        execution=execution,
        mode=resolved.mode,
        run_id=run_id,
        command=command,
        scan_options={
            "mode": resolved.mode,
            "intent": resolved.intent,
            "intent_summary": resolved.summary if resolved.intent else None,
            "delta": resolved.delta,
            # Visible on the job rather than only in the log: which promoted
            # domains this scan carried, and which the scope kept out.
            **({"promoted_domains": promoted_admitted} if promoted_admitted else {}),
            **({"promoted_domains_refused": promoted_refused} if promoted_refused else {}),
            "skip_nse": skip_nse,
            # The policy this scan was admitted under (#362), on the job rather
            # than only derivable from a table that has since moved on. Absent
            # for a tenant with no policy, so a job started before one was
            # written reads exactly as it did.
            **({"scan_policy": policy_snapshot} if policy_snapshot else {}),
            # External / internal / mixed, or None when the scan runs the
            # server's default input files and nothing here can tell (see
            # api.services.scan_surface).
            "surface": surface,
            # Whether that value is the operator's declaration or the server's
            # reading of the targets. Risk scoring treats only a declared
            # external scan as network-exposure evidence, and without this the
            # two are indistinguishable once stored.
            "surface_source": (
                "operator" if request.surface else ("derived" if surface else None)
            ),
            "notify": request.notify,
            "export_defectdojo": request.export_defectdojo,
            # Mirrored into the options so a schedule replaying this job's
            # settings, and the idempotency digest, both see the selector.
            **({"agent_group": agent_group} if agent_group else {}),
            # Only alongside a key: it exists to tell this request apart from
            # the next one carrying the same key, and nothing else reads it.
            **(
                {"idempotency_digest": _idempotency_digest(request)}
                if idempotency_key
                else {}
            ),
            **wordlist_options,
        },
        target_counts=target_counts,
        requested_by=username,
        agent_group=agent_group,
        assigned_agent_id=None,
        # Only local jobs are bound to this process; an agent job is claimable
        # by any worker and must not be reconciled when this replica restarts.
        owner_id=settings.instance_id if execution == "local" else None,
        idempotency_key=(idempotency_key or None),
        quota_exempt=quota_exempt,
        queued_at=_now(),
    )
    try:
        with get_session(settings.postgres_url) as session:
            if agent_group:
                # Re-asked here, holding the group row, rather than trusted
                # from the resolution above: that ran on a connection of its
                # own and this insert is another, so a concurrent
                # ``DELETE /api/agent-groups/{name}`` could count the pending
                # jobs of the group, find this one not yet inserted, and take
                # the row. What was left is a ``queued`` job addressed to a
                # group that is gone — no agent can be put into one, so it is
                # claimed by nobody, shows ``agent_group_unavailable`` in the
                # console and raises no error anywhere (#361).
                if not agent_groups_service.lock_existing_names(
                    session, tenant_id=tenant_id, names={agent_group}
                ):
                    raise ValueError(
                        f"Unknown agent_group for tenant {tenant_id}: {agent_group}"
                    )
            session.add(row)
            session.flush()
            info = _to_info(
                row,
                # What the check a few lines above found, so the answer to the
                # request that created the job is the same one the queue view
                # will show. Every later read recomputes it.
                (
                    ({(tenant_id, agent_group)} if group_has_live_agent else set())
                    if agent_group
                    else None
                ),
            )
    except ValueError:
        # The group this scan is addressed to went while the row was being
        # written. Nothing became a job, so the input files staged for it —
        # and the merged config beside them — would be read by nobody;
        # discarded here the way the idempotency loser's are.
        _discard_job_wordlist(settings, job_id)
        _discard_job_inputs(settings, job_id)
        raise
    except IntegrityError:
        # Lost the race on (tenant_id, idempotency_key): another replica — or
        # this one, serving the client's retry concurrently — already created
        # the job. The caller wanted one scan for this key and there is one.
        # This job_id never became a row, so its materialized wordlist (and the
        # merged config beside it) and its input files would be read by nobody
        # — discarded first, so the mismatch below does not leak them either.
        _discard_job_wordlist(settings, job_id)
        _discard_job_inputs(settings, job_id)
        # ``request=`` here too: the racing pair may not be the same scan, and
        # the loser of the race must hear that rather than be handed a job for
        # targets it never asked about.
        existing = find_by_idempotency_key(
            settings, tenant_id=tenant_id, key=idempotency_key or "", request=request
        )
        if existing is None:
            raise
        _log.info("Idempotent scan start: key already created job %s", existing.job_id)
        # Raised rather than returned so the caller can answer 200 here too:
        # this request accepted nothing, exactly like the sequential replay the
        # route detects before calling in.
        raise IdempotentReplay(existing) from None
    _refresh_job_gauges(settings)

    if execution == "local":
        thread = threading.Thread(target=_run_job, args=(settings, job_id, command), daemon=True)
        thread.start()
    elif execution == "agent" and settings.nats_url:
        _publish_job_offer(settings, job_id)

    return info


def _publish_job_offer(settings: Settings, job_id: str) -> None:
    """Announce one queued job on the subject its entitled agents listen to.

    The offer is a notification, not a hand-out: it names the job and nothing
    about what the job reaches. ``inputs`` used to travel in it, which made the
    body of every offer a copy of the scan's target list — and since the body
    is read before the claim, an agent could read the targets of a job it was
    then refused (#361). The claim response carries them instead, to the one
    agent the API has just bound the job to.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None:
            return
        opts = dict(row.scan_options or {})
        payload = {
            "job_id": row.job_id,
            "run_id": row.run_id or "",
            "mode": row.mode or opts.get("mode") or "balanced",
            "delta": bool(opts.get("delta", False)),
            "skip_nse": bool(opts.get("skip_nse", False)),
            "notify": bool(opts.get("notify", False)),
            "export_defectdojo": bool(opts.get("export_defectdojo", False)),
            "tenant_id": row.tenant_id or tenants_service.DEFAULT_TENANT_ID,
            # Decides the subject, so only the group's own agents are offered
            # it at all; repeated in the body so a subscriber can tell a
            # misrouted offer from one of its own.
            "agent_group": row.agent_group,
        }
    bus = nats_bus.get_bus(settings.nats_url)
    if bus is None:
        _log.warning(
            "NATS configured but unavailable; job %s stays queued for HTTP claim",
            job_id,
        )
        return
    tenant_subject = nats_bus.jobs_scan_subject(
        str(payload["tenant_id"]), payload["agent_group"]
    )
    if bus.publish_job_offer(payload):
        _log.info("Published %s offer for %s", tenant_subject, job_id)
    else:
        _log.warning(
            "Failed to publish %s for %s; HTTP claim still available",
            tenant_subject,
            job_id,
        )


def _read_job_inputs(settings: Settings, job_id: str) -> dict[str, str]:
    inputs_dir = job_inputs_dir(settings, job_id)
    if not inputs_dir.is_dir():
        return {}
    out: dict[str, str] = {}
    for name in _JOB_INPUT_FILES:
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
            merged = scan_policy.snapshot(scan_policy.tighten(frozen, resolved))
            if merged is None or merged == frozen:
                continue
            command = list(row.command or [])
            policy_path = _write_policy_input(job_inputs_dir(settings, row.job_id), merged)
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
            "Scan policy for tenant %s applied to %d queued job(s)", tenant_id, touched
        )
    return touched


def claim_job(
    settings: Settings,
    agent_id: str,
    *,
    job_id: str | None = None,
    tenant_id: str | None = None,
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
    agent = agents_service.get_agent(agent_id)
    if agent is None:
        raise LookupError("Unknown agent_id; register first")
    effective_tenant = tenant_id or agent.tenant_id

    with get_session(settings.postgres_url) as session:
        query = (
            select(models.Job)
            .where(
                models.Job.execution == "agent",
                models.Job.status == "queued",
                models.Job.assigned_agent_id.is_(None),
                models.Job.tenant_id == effective_tenant,
                # An ungrouped agent takes only ungrouped jobs; a grouped one
                # takes its own group's and the ungrouped ones, so putting an
                # agent into a group narrows what it may reach without taking
                # away the queue it already served.
                models.Job.agent_group.is_(None)
                if not agent.agent_group
                else or_(
                    models.Job.agent_group.is_(None),
                    models.Job.agent_group == agent.agent_group,
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

        # A job whose tenant has a scan policy may only be handed to a worker
        # that can honour it (#362). The policy is applied by the executor —
        # the API cannot shape somebody else's packets — so an agent that does
        # not declare the ``scan_policy`` capability would run this scan at
        # whatever its local ``default.yaml`` says, which on a fragile estate
        # is the failure the policy exists to prevent.
        #
        # Refused rather than skipped over: skipping would leave the operator
        # with a queue that does not move and an agent that reports itself
        # healthy, while a 426 lands in that agent's own journal, keeps it
        # visible in the fleet view and names the upgrade — the same shape
        # #363 gives an agent below the version floor. The job stays queued
        # for a worker that can take it.
        if (row.scan_options or {}).get("scan_policy") and (
            scan_policy.AGENT_CAPABILITY not in (agent.capabilities or [])
        ):
            scan_policy.note_refusal("agent_unsupported")
            _log.warning(
                "Agent %s asked for job %s, whose tenant has a scan policy, but does not "
                "declare the %s capability; the job stays queued",
                agent_id,
                row.job_id,
                scan_policy.AGENT_CAPABILITY,
            )
            raise scan_policy.AgentPolicyUnsupported(
                f"agent {agent_id} does not support tenant scan policies "
                f"(capability {scan_policy.AGENT_CAPABILITY}); upgrade the agent — "
                "its jobs carry rate limits it cannot currently apply"
            )

        # `claimed`, not `running` (P1.3): the agent owns the job but has not
        # reported working on it. Its first heartbeat naming this job promotes
        # it (see mark_running), which is also the signal the P1.4 reaper needs
        # to tell "taken by a worker that died" from "actually scanning".
        job_states.check_transition(row.job_id, row.status, job_states.CLAIMED)
        row.status = job_states.CLAIMED
        row.assigned_agent_id = agent_id
        # `started_at` deliberately stays unset until the agent reports
        # starting (mark_running). Stamping it here would fold the
        # claim-to-heartbeat delay into every job-duration observation, and
        # would show a job that never ran as having executed.
        row.started_at = None
        # The lease starts at the claim, not at the first heartbeat: an agent
        # that dies between the two is exactly the case P1.4 has to catch.
        row.claimed_until = _lease_deadline(settings)
        row.attempts = (row.attempts or 0) + 1
        attempt = row.attempts
        if not row.run_id:
            row.run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
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
            export_defectdojo=bool(opts.get("export_defectdojo", False)),
            inputs=_read_job_inputs(settings, claimed_id),
            tenant_id=row.tenant_id or tenants_service.DEFAULT_TENANT_ID,
            # The fencing token for this hand-out: a lease that expired and was
            # reissued bumps it, so a late upload from the previous attempt can
            # be told apart from the current one even when both come from the
            # same agent_id (a restarted worker keeps its id).
            attempt=attempt,
        )
    _refresh_job_gauges(settings)
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
        row.claimed_until = _lease_deadline(settings)
        if row.status != job_states.CLAIMED:
            return False
        row.status = job_states.RUNNING
        if row.started_at is None:
            row.started_at = _now()
    _refresh_job_gauges(settings)
    return False


def cancel_job(
    settings: Settings,
    job_id: str,
    *,
    username: str,
    tenant_id: str | None = None,
    audit: "audit_service.AuditContext | None" = None,
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
      terminalize a scan nobody has confirmed stopped.

    A ``running`` **local** job is still refused, and by execution rather than
    by state: its scanner is a ``subprocess`` in one replica's thread, which
    the replica handling this request may not be, so there is no signal to send
    and reporting a stop would be a lie. The message says so rather than
    reading as a generic lifecycle refusal.

    The reason is stored in ``error`` rather than a new column: it is the field
    the UI and API already surface for "why did this job end this way".
    """
    with get_session(settings.postgres_url) as session:
        # Locked for the same reason as _update_job: a local job's executor
        # thread may be transitioning the very same row to running right now,
        # and cancelling a job that has already started is exactly the outcome
        # this endpoint must never report.
        row = session.get(models.Job, job_id, with_for_update=True)
        if row is None:
            raise LookupError("Job not found")
        job_tenant = row.tenant_id or tenants_service.DEFAULT_TENANT_ID
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
            _log.info("Job %s is already stopping; %s's request is a no-op", job_id, username)
            result = _to_info(row)
            return result
        if before in job_states.IN_FLIGHT and row.execution != "agent":
            raise job_states.InvalidJobTransition(
                f"Job {job_id} is {before} in the API process itself; a local scan "
                "cannot be stopped once it has started, only an agent job can"
            )
        target = (
            job_states.CANCELLING if before in job_states.IN_FLIGHT else job_states.CANCELLED
        )
        job_states.check_transition(job_id, before, target)
        row.status = target
        if target == job_states.CANCELLING:
            row.cancel_requested_at = _now()
            # Cleared although the job is not terminal: the lease is what the
            # reaper requeues on, and a job on its way down must not be handed
            # to a second agent while the first is still stopping.
            row.claimed_until = None
            row.error = f"Cancellation requested by {username}"[:2000]
        else:
            row.finished_at = _now()
            row.claimed_until = None
            row.error = f"Cancelled by {username}"[:2000]
            metrics_service.JOB_CANCELLATIONS_TOTAL.labels(outcome="queued").inc()
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_SCAN_CANCEL,
            resource_type="job",
            resource_id=job_id,
            tenant_id=job_tenant,
            before={"status": before, "assigned_agent_id": row.assigned_agent_id},
            after={"status": target, "requested_by": username},
        )
    _refresh_job_gauges(settings)
    result = get_job(settings, job_id)
    assert result is not None
    return result


def reap_stale_cancellations(settings: Settings) -> int:
    """Finish jobs whose agent never confirmed the stop, and say how many (#360).

    ``cancelling`` is the one non-terminal state nothing else will leave: the
    lease reaper deliberately ignores it (it is not in ``IN_FLIGHT``, or the
    job would be handed to a second agent while the first is putting it down),
    and the confirmation that would terminalize it is exactly what an agent too
    old to understand the request never sends. So this is the other end of the
    clock — past ``job_cancel_grace_seconds`` the job is written ``cancelled``,
    which is the honest outcome: the operator's decision stands, and the row
    says the agent never answered rather than pretending it did.

    A late upload from such an agent then meets a terminal job and is refused
    by ``complete_job``, the same way a result for any cancelled job is.

    Safe in every replica, like the lease sweep beside it: rows are taken with
    ``FOR UPDATE SKIP LOCKED``.
    """
    now = _now()
    deadline = now - timedelta(seconds=max(settings.job_cancel_grace_seconds, 1))
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.Job)
            .where(
                models.Job.status == job_states.CANCELLING,
                models.Job.cancel_requested_at.is_not(None),
                models.Job.cancel_requested_at < deadline,
            )
            .with_for_update(skip_locked=True)
        ).scalars().all()
        for row in rows:
            job_states.check_transition(row.job_id, row.status, job_states.CANCELLED)
            row.status = job_states.CANCELLED
            row.finished_at = now
            row.claimed_until = None
            row.error = (
                f"{row.error or 'Cancellation requested'}; agent "
                f"{row.assigned_agent_id or 'unknown'} did not confirm within "
                f"{settings.job_cancel_grace_seconds}s"
            )[:2000]
            _log.warning(
                "Cancelled job %s without confirmation: agent %s stayed silent for %ds",
                row.job_id,
                row.assigned_agent_id,
                settings.job_cancel_grace_seconds,
            )
        count = len(rows)
    if count:
        metrics_service.JOB_CANCELLATIONS_TOTAL.labels(outcome="unconfirmed").inc(count)
        _refresh_job_gauges(settings)
    return count


class ResultsConflict(ValueError):
    """A second upload for a finished job that is not a replay of the first."""


class ResultsInFlight(ResultsConflict):
    """A duplicate upload arrived while the first one is still being ingested."""


class StaleAttempt(ValueError):
    """An upload from a lease that has already expired and been reissued."""


def _release_results_reservation(settings: Settings, job_id: str, key: str) -> None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id, with_for_update=True)
        # Only clear our own reservation, and only while the job is still
        # unfinished: once it is terminal the key is the record of what
        # produced that outcome, not a reservation.
        if row is not None and row.status not in job_states.TERMINAL:
            if row.results_idempotency_key == key:
                row.results_idempotency_key = None


def _classify_replay(
    row: models.Job, *, exit_code: int, idempotency_key: str | None
) -> JobInfo | None:
    """Decide whether an upload for an already-finished job is a replay.

    Returns the stored outcome for a replay, raises ``ResultsConflict`` for an
    upload that contradicts it, and returns ``None`` when this is not a replay
    question at all, so the caller's normal transition check produces the
    error.

    A ``cancelled`` job is the narrow case (#360). Since a confirmed
    cancellation *is* an upload, its retry is a replay like any other — but
    only an exact key proves that. Without one, this is a late result for a
    stop the row never recorded a confirmation of (the reaper's row carries no
    key), and that still meets the transition check rather than being answered
    with an outcome it did not produce.

    With a key, the comparison is exact. Without one — older agents, and the
    legacy shared-token path — the fallback is the natural key: the same agent
    reporting the same exit code for a job it still owns is the retry we are
    trying to survive, and it cannot be confused with a different result,
    because a different result carries a different exit code.
    """
    if row.status == job_states.CANCELLED:
        if idempotency_key and row.results_idempotency_key == idempotency_key:
            return _replayed(row)
        return None
    if idempotency_key:
        if row.results_idempotency_key == idempotency_key:
            return _replayed(row)
        if row.results_idempotency_key:
            raise ResultsConflict(
                f"Job {row.job_id} already has results from a different upload"
            )
        return None
    if row.exit_code == exit_code:
        return _replayed(row)
    return None


def _merge_cancellation_reason(requested: str | None, reported: str | None) -> str | None:
    """Keep "Cancellation requested by X" when the agent confirms the stop (#360).

    ``requested`` is what ``cancel_job`` wrote and is ``None`` for every
    outcome that is not a confirmed cancellation, which makes this the plain
    truncation the other paths always did. For a cancellation it is the only
    place the actor survives after the job is finished: without it the agent's
    string — or, when it sends none, ``NULL`` — is all a drawer shows for a
    scan somebody deliberately stopped, and "who killed my scan at 3am" is a
    hop away in the audit trail instead of being on the job.
    """
    merged = "; ".join(part for part in (requested, reported) if part)
    return merged[:2000] or None


def _replayed(row: models.Job) -> JobInfo:
    metrics_service.JOB_IDEMPOTENT_REPLAYS_TOTAL.labels(operation="results").inc()
    _log.info("Replayed results upload for job %s; returning the stored outcome", row.job_id)
    return _to_info(row)


def complete_job(
    settings: Settings,
    job_id: str,
    *,
    agent_id: str,
    exit_code: int,
    error: str | None = None,
    run_id: str | None = None,
    archive_bytes: bytes | None = None,
    tenant_id: str | None = None,
    idempotency_key: str | None = None,
    attempt: int | None = None,
    cancelled: bool = False,
) -> JobInfo:
    """Record an agent's result upload. Replays return the original outcome.

    P1.3 made a second upload an error, which is right for a *different*
    result but wrong for the case that actually happens: the upload succeeded
    and the response never made it back, so the agent sends the same bytes
    again. Under P1.5 that replay is answered with the job as it already
    stands — no re-extraction, no second NATS publish, no error for the agent
    to interpret. Two uploads that genuinely disagree still conflict.

    ``attempt`` is the fencing token from the claim response. A lease that
    expired and was reissued bumped it, so an upload carrying an older value is
    a straggler from an attempt that has already been replaced — and since a
    restarted worker keeps its ``agent_id``, that is the only way to tell the
    two apart. Omitted by pre-P1.5 agents, which are then unfenced.

    ``cancelled`` is the agent confirming it put the scan down because the API
    asked it to (#360), and it decides the outcome on its own: the scanner was
    signalled, so it exits non-zero, and without this flag every stop would be
    filed as a scan that failed. The archive is still ingested — whatever the
    run had written before the signal is real data an operator asked to keep —
    but, like a failed run, it does not feed the vulnerability tracker, the
    asset event stream or the notification channels: a partial sweep read as a
    complete one would report hosts and ports as *gone* that the scan simply
    never reached.
    """
    replay_result: JobInfo | None = None
    with get_session(settings.postgres_url) as session:
        # Locked for the whole check: concurrent uploads for the same job must
        # be decided one at a time, or both would read a non-terminal row and
        # both go on to extract the archive.
        row = session.get(models.Job, job_id, with_for_update=True)
        if row is None:
            raise LookupError("Job not found")
        if row.execution != "agent":
            raise ValueError("Job is not an agent job")
        if row.assigned_agent_id != agent_id:
            raise PermissionError("Job is assigned to a different agent")
        job_tenant = row.tenant_id or tenants_service.DEFAULT_TENANT_ID
        if tenant_id is not None and job_tenant != tenant_id:
            raise PermissionError("Cross-tenant job access denied")
        if attempt is not None and attempt != (row.attempts or 0):
            raise StaleAttempt(
                f"Job {job_id} is on attempt {row.attempts}; upload is from attempt {attempt}"
            )
        status = job_states.SUCCEEDED if exit_code == 0 else job_states.FAILED
        if cancelled:
            # Only from a job the API actually asked to stop. An agent that
            # reported a cancellation nobody requested would otherwise be able
            # to retire any job it holds as "cancelled" — and the honest
            # reading of a scan that stopped for the agent's own reasons is a
            # failure, which is what the exit code already says.
            #
            # A row already ``cancelled`` is included so that an upload this
            # function is about to refuse is refused for what it reported: a
            # retry whose key does not match is a second cancellation result,
            # and telling its agent the job "cannot move from cancelled to
            # failed" would name an outcome nobody claimed.
            status = (
                job_states.CANCELLED
                if row.status in (job_states.CANCELLING, job_states.CANCELLED)
                else status
            )
        if row.status in job_states.TERMINAL:
            replay = _classify_replay(row, exit_code=exit_code, idempotency_key=idempotency_key)
            if replay is not None:
                # Answered below, once the row lock is released: the cleanup
                # this replay triggers is filesystem work, and holding the lock
                # across it would make a second agent's retry wait on the disk
                # rather than on the decision.
                replay_result = replay
        elif idempotency_key:
            if row.results_idempotency_key == idempotency_key:
                # Same key, job not finished: the first request holding this key
                # is still ingesting. Answering 409 tells the client to retry
                # rather than letting two handlers extract into one run
                # directory and race to terminalize the job.
                raise ResultsInFlight(
                    f"An upload with this key is already being processed for job {job_id}"
                )
            # Reserve the key inside the locked transaction, so the duplicate
            # above can recognise it. Cleared again if this upload fails.
            row.results_idempotency_key = idempotency_key
        # Checked before the archive is ingested, not after: a duplicate upload
        # for a job that already finished — or one an operator cancelled while
        # the agent was still working — must not overwrite the run directory
        # and re-publish to NATS before being rejected.
        if replay_result is None:
            job_states.check_transition(job_id, row.status, status)
        # Read under the lock, for the same reason the surface below is: the
        # confirming upload is the only writer that would otherwise erase who
        # asked for the stop, and `error` is where docs/api-and-rbac.md says
        # that reason lives for the life of the job (#360).
        requested_reason = row.error if status == job_states.CANCELLED else None
        resolved_run_id = _confirm_run_id(row.run_id, run_id)
        # Read here rather than re-fetched at the write below: the row is
        # already loaded and locked, and the surface was decided at start_scan.
        job_surface = (row.scan_options or {}).get("surface")

    if replay_result is not None:
        # Reached only for a job that is already terminal, so the agent is not
        # still reading these -- a replay arrives after the run has finished,
        # not while it is executing. A first upload whose response was lost may
        # already have swept the directory, which is why this is idempotent
        # (#258).
        _discard_job_inputs(settings, job_id)
        return replay_result

    try:
        if archive_bytes:
            if not resolved_run_id:
                raise ValueError("run_id required when uploading results")
            # Gateway: validate + publish to ingest.raw_results (idempotent Msg-Id).
            if settings.nats_url:
                try:
                    results_ingest.publish_raw_results(
                        nats_url=settings.nats_url,
                        job_id=job_id,
                        run_id=str(resolved_run_id),
                        agent_id=agent_id,
                        exit_code=exit_code,
                        archive_bytes=archive_bytes,
                        error=error,
                        tenant_id=job_tenant,
                    )
                except results_ingest.IngestError as exc:
                    raise ValueError(str(exc)) from exc
            dest = settings.output_dir / "runs" / str(resolved_run_id)
            try:
                results_ingest.extract_run_archive(archive_bytes, dest)
                results_ingest.update_latest_run_pointer(settings.state_dir, str(resolved_run_id))
                runs_service.write_run_tenant(
                    settings,
                    str(resolved_run_id),
                    job_tenant,
                    job_id=job_id,
                    surface=job_surface,
                )
            except results_ingest.IngestError as exc:
                raise ValueError(str(exc)) from exc
            _upsert_assets_best_effort(
                settings, tenant_id=job_tenant, run_id=str(resolved_run_id), job_id=job_id
            )
            # Ungated, matching the local path: this is where the agent's copy
            # of the run reaches disk, and a refusal the scanner made is a
            # decision to journal regardless of how the scan ended (#244).
            _record_scope_denials_best_effort(
                settings,
                tenant_id=job_tenant,
                run_id=str(resolved_run_id),
                requested_by=_requested_by(settings, job_id),
            )
            # Gated on the outcome, matching the local path. An agent may attach
            # diagnostics to a *failed* run, and a partial diff read as a change
            # set would alert on hosts and ports that a broken scan simply
            # failed to observe — a disappearance is not a discovery.
            if status == job_states.SUCCEEDED:
                _track_vulnerabilities_best_effort(
                    settings, tenant_id=job_tenant, run_id=str(resolved_run_id), job_id=job_id
                )
                _publish_asset_events_best_effort(
                    settings, tenant_id=job_tenant, run_id=str(resolved_run_id), job_id=job_id
                )

        _update_job(
            settings,
            job_id,
            status=status,
            finished_at=_now(),
            exit_code=exit_code,
            run_id=str(resolved_run_id) if resolved_run_id else None,
            error=_merge_cancellation_reason(requested_reason, error),
            # Recorded with the outcome, so a later upload can be told apart from
            # the one that produced it.
            results_idempotency_key=(idempotency_key or None),
        )
    except Exception:
        # The reservation above is only meaningful while this upload is in
        # flight. Releasing it lets the agent retry with the same key instead
        # of meeting its own abandoned reservation forever.
        if idempotency_key:
            _release_results_reservation(settings, job_id, idempotency_key)
        raise
    if status == job_states.CANCELLED:
        metrics_service.JOB_CANCELLATIONS_TOTAL.labels(outcome="confirmed").inc()
    agents_service.touch_job(agent_id, None, status="idle")
    # The job is terminal now: no further claim will serve these files (#258).
    # After the _update_job above, so a raise in ingestion leaves them for the
    # agent's retry rather than deleting what the retry needs.
    _discard_job_inputs(settings, job_id)
    # Last, and after the status is written — the asymmetry with the local path
    # (``_run_job``, which already announced *after* ``_update_job``) is what
    # made this bite: a fan-out that hung held the terminal status hostage, so
    # the agent's retry met its own in-flight reservation and got a 409 for an
    # upload that had in fact landed. The send itself is on a thread, so this
    # line costs the request one ``Thread.start``.
    if archive_bytes and status == job_states.SUCCEEDED:
        _notify_channels_best_effort(
            settings, tenant_id=job_tenant, run_id=str(resolved_run_id), job_id=job_id
        )
    result = get_job(settings, job_id)
    assert result is not None
    return result
