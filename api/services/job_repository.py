"""Job repository and read models.

Owns persistence-oriented reads, legacy queue import, startup reconciliation and
the queue summary/list projections. Execution, admission and result ingestion
live in their own services.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, or_, select

from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.schemas import JobInfo
from api.services import agent_groups as agent_groups_service
from api.services import job_states
from api.services import job_store
from api.services import pagination
from api.services import scan_surface
from api.services import tenants as tenants_service
from api.settings import Settings

_log = logging.getLogger(__name__)

JOB_SORT_FIELDS = (
    "started_at",
    "finished_at",
    "status",
    "job_id",
    "mode",
    "tenant_id",
)
JOB_QUERY_FIELDS = (
    "job_id",
    "run_id",
    "mode",
    "status",
    "requested_by",
    "tenant_id",
    "assigned_agent_id",
)
JOB_SORT_COLUMNS = {
    "started_at": models.Job.started_at,
    "finished_at": models.Job.finished_at,
    "status": models.Job.status,
    "job_id": models.Job.job_id,
    "mode": models.Job.mode,
    "tenant_id": models.Job.tenant_id,
}
SUMMARY_SURFACES = (*scan_surface.SURFACES, "unknown")


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(dt: datetime | None) -> str | None:
    return (
        dt.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")
        if dt
        else None
    )


def _parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (
        parsed.astimezone(UTC).replace(tzinfo=None)
        if parsed.tzinfo
        else parsed
    )


def load_jobs(settings: Settings) -> None:
    """Import legacy jobs once and reconcile local work orphaned by restart."""
    path = settings.state_dir / "api_jobs.json"
    if path.is_file():
        _import_legacy_jobs(settings, path)

    now = _now()
    with get_session(settings.postgres_url) as session:
        orphans = (
            session.execute(
                select(models.Job).where(
                    models.Job.execution == "local",
                    models.Job.status.in_(
                        (job_states.QUEUED, job_states.RUNNING)
                    ),
                    or_(
                        models.Job.owner_id == settings.instance_id,
                        models.Job.owner_id.is_(None),
                    ),
                )
            )
            .scalars()
            .all()
        )
        for row in orphans:
            job_states.check_transition(
                row.job_id, row.status, job_states.FAILED
            )
            row.status = job_states.FAILED
            row.finished_at = now
            row.claimed_until = None
            row.error = (
                "Interrupted by API process restart before completion"
            )

    if orphans:
        _log.info(
            "Reconciled %d orphaned local job(s) after restart",
            len(orphans),
        )
    job_store.refresh_job_gauges(settings)


def _import_legacy_jobs(settings: Settings, path: Path) -> None:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _log.warning("Ignoring unreadable legacy job queue at %s", path)
        return
    if not isinstance(raw, list):
        return

    known_tenants = {
        tenant["tenant_id"] for tenant in tenants_service.list_tenants()
    }
    imported = 0
    with get_session(settings.postgres_url) as session:
        for item in raw:
            if not (isinstance(item, dict) and item.get("job_id")):
                continue
            job_id = str(item["job_id"])
            if session.get(models.Job, job_id) is not None:
                continue

            tenant_id = str(
                item.get("tenant_id")
                or tenants_service.DEFAULT_TENANT_ID
            )
            if tenant_id not in known_tenants:
                _log.warning(
                    "Legacy job %s references unknown tenant %s; "
                    "importing under %s",
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
                mode=str(
                    item.get("mode")
                    or options.get("mode")
                    or "balanced"
                ),
                run_id=item.get("run_id"),
                command=list(item.get("command") or []),
                scan_options=options,
                target_counts=item.get("target_counts"),
                requested_by=str(item.get("requested_by") or ""),
                assigned_agent_id=item.get("assigned_agent_id"),
                owner_id=None,
                queued_at=(
                    _parse_iso(item.get("queued_at"))
                    or _parse_iso(item.get("started_at"))
                    or _now()
                ),
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
        _log.warning(
            "Could not rename %s after import; it will be re-imported",
            path,
        )
    if imported:
        _log.info(
            "Imported %d job(s) from the pre-P1 queue at %s",
            imported,
            path,
        )


def _live_groups_for(
    settings: Settings, rows: Sequence[models.Job]
) -> set[tuple[str, str]] | None:
    tenants = {
        row.tenant_id or tenants_service.DEFAULT_TENANT_ID
        for row in rows
        if row.agent_group and row.status == job_states.QUEUED
    }
    if not tenants:
        return None
    return agent_groups_service.live_groups(settings, tenants)


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
    column = JOB_SORT_COLUMNS.get(sort or "", models.Job.started_at)
    ascending = (order or "").lower() == "asc"
    direction = (
        column.asc().nullslast()
        if ascending
        else column.desc().nullslast()
    )

    with get_session(settings.postgres_url) as session:
        filters = []
        if tenant_id:
            filters.append(models.Job.tenant_id == tenant_id)
        if surface:
            stored = models.Job.scan_options["surface"].as_string()
            filters.append(
                stored.is_(None)
                if surface == "unknown"
                else stored == surface
            )
        if q and q.strip():
            needle = f"%{q.strip().lower()}%"
            filters.append(
                or_(
                    func.lower(models.Job.job_id).like(needle),
                    func.lower(
                        func.coalesce(models.Job.run_id, "")
                    ).like(needle),
                    func.lower(models.Job.mode).like(needle),
                    func.lower(models.Job.status).like(needle),
                    func.lower(models.Job.requested_by).like(needle),
                    func.lower(models.Job.tenant_id).like(needle),
                    func.lower(
                        func.coalesce(
                            models.Job.assigned_agent_id, ""
                        )
                    ).like(needle),
                )
            )

        total = session.execute(
            select(func.count())
            .select_from(models.Job)
            .where(*filters)
        ).scalar_one()
        rows = (
            session.execute(
                select(models.Job)
                .where(*filters)
                .order_by(direction, models.Job.job_id)
                .offset(offset)
                .limit(limit)
            )
            .scalars()
            .all()
        )

    live = _live_groups_for(settings, rows)
    return [job_store.to_info(row, live) for row in rows], total


def summary(
    settings: Settings, *, tenant_id: str | None = None
) -> dict[str, Any]:
    by_status = dict.fromkeys(sorted(job_states.ALL), 0)
    by_surface = {
        surface: {"running": 0, "queued": 0, "total": 0}
        for surface in SUMMARY_SURFACES
    }
    stored_surface = models.Job.scan_options["surface"].as_string()

    with get_session(settings.postgres_url) as session:
        filters = (
            [models.Job.tenant_id == tenant_id] if tenant_id else []
        )
        rows = session.execute(
            select(models.Job.status, stored_surface, func.count())
            .where(*filters)
            .group_by(models.Job.status, stored_surface)
        ).all()

    for status, surface, count in rows:
        by_status[str(status)] = by_status.get(str(status), 0) + count
        bucket = by_surface[
            surface if surface in by_surface else "unknown"
        ]
        bucket["total"] += count
        if status in (job_states.RUNNING, job_states.CANCELLING):
            bucket["running"] += count
        elif status in (job_states.QUEUED, job_states.CLAIMED):
            bucket["queued"] += count

    return {
        "by_status": by_status,
        "running": (
            by_status.get(job_states.RUNNING, 0)
            + by_status.get(job_states.CANCELLING, 0)
        ),
        "queued": (
            by_status.get(job_states.QUEUED, 0)
            + by_status.get(job_states.CLAIMED, 0)
        ),
        "by_surface": by_surface,
        "generated_at": _iso(_now()),
    }


def get_job(settings: Settings, job_id: str) -> JobInfo | None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None:
            return None
        live = _live_groups_for(settings, [row])
        return job_store.to_info(row, live)


def reset_for_tests(settings: Settings) -> None:
    with get_session(settings.postgres_url) as session:
        session.query(models.Job).delete()
