"""Per-tenant recurring scan schedules (Phase 8.5).

Stores the "when" and "what" of a recurring scan (cron or fixed interval,
plus the same mode/delta/target options ``StartScanRequest`` already
accepts). Dispatch itself lives in ``api.services.schedule_dispatcher``,
which polls ``due_schedules`` and calls ``api.services.jobs.start_scan``.

``cron`` and ``interval_seconds`` are mutually exclusive. Cron parsing reuses
``scanner.scheduler``'s hand-rolled 5-field parser rather than reimplementing
one.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import tenants as tenants_service
from api.settings import Settings
from scanner.scheduler import next_cron_time, parse_cron

_settings: Settings | None = None

_SCAN_OPTION_KEYS = ("mode", "delta", "skip_nse", "notify", "export_defectdojo")
_TARGET_KEYS = ("ranges", "domains", "ports", "ports_udp")


def _now() -> datetime:
    return datetime.now(UTC)


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "scan_schedules.configure() not called"
    return _settings


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def _to_dict(row: models.ScanSchedule) -> dict[str, Any]:
    return {
        "schedule_id": row.schedule_id,
        "tenant_id": row.tenant_id,
        "name": row.name,
        "enabled": row.enabled,
        "cron": row.cron,
        "interval_seconds": row.interval_seconds,
        "scan_options": dict(row.scan_options or {}),
        "targets": dict(row.targets or {}),
        "next_run_at": _iso(row.next_run_at),
        "last_run_at": _iso(row.last_run_at),
        "last_job_id": row.last_job_id,
        "created_at": _iso(row.created_at),
        "created_by": row.created_by,
    }


def _validate_cadence(cron: str | None, interval_seconds: int | None) -> None:
    if bool(cron) == bool(interval_seconds):
        raise ValueError("exactly one of cron or interval_seconds is required")
    if cron:
        parse_cron(cron)  # raises ValueError on malformed cron
    else:
        assert interval_seconds is not None
        if interval_seconds < 60:
            raise ValueError("interval_seconds must be at least 60")


def _compute_next_run(cron: str | None, interval_seconds: int | None, *, after: datetime) -> datetime:
    if cron:
        return next_cron_time(cron, after=after)
    assert interval_seconds is not None
    return after + timedelta(seconds=interval_seconds)


def reset_for_tests() -> None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        session.query(models.ScanSchedule).delete()


def create_schedule(
    *,
    tenant_id: str,
    name: str,
    cron: str | None,
    interval_seconds: int | None,
    scan_options: dict[str, Any],
    targets: dict[str, Any],
    created_by: str | None,
) -> dict[str, Any]:
    settings = _require_settings()
    name = name.strip()
    if not name:
        raise ValueError("schedule name required")
    _validate_cadence(cron, interval_seconds)

    tenant = tenants_service.get_tenant(tenant_id)
    if tenant is None:
        raise ValueError(f"Unknown tenant_id: {tenant_id}")

    now = _now()
    row = models.ScanSchedule(
        schedule_id=f"sch_{uuid.uuid4().hex[:12]}",
        tenant_id=tenant_id,
        name=name,
        enabled=True,
        cron=cron,
        interval_seconds=interval_seconds,
        scan_options={k: scan_options[k] for k in _SCAN_OPTION_KEYS if k in scan_options},
        targets={k: targets[k] for k in _TARGET_KEYS if k in targets and targets[k] is not None},
        next_run_at=_compute_next_run(cron, interval_seconds, after=now),
        last_run_at=None,
        last_job_id=None,
        created_at=now,
        created_by=created_by,
    )
    with get_session(settings.postgres_url) as session:
        session.add(row)
        session.flush()
        return _to_dict(row)


def list_schedules(tenant_id: str | None = None) -> list[dict[str, Any]]:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        stmt = select(models.ScanSchedule)
        if tenant_id:
            stmt = stmt.where(models.ScanSchedule.tenant_id == tenant_id)
        rows = session.execute(stmt).scalars().all()
    items = [_to_dict(row) for row in rows]
    items.sort(key=lambda s: str(s.get("created_at") or ""), reverse=True)
    return items


def get_schedule(schedule_id: str) -> dict[str, Any] | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.ScanSchedule, schedule_id)
        return _to_dict(row) if row else None


def update_schedule(schedule_id: str, **fields: Any) -> dict[str, Any] | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.ScanSchedule, schedule_id)
        if row is None:
            return None

        cron = fields.get("cron", row.cron)
        interval_seconds = fields.get("interval_seconds", row.interval_seconds)
        cadence_changed = "cron" in fields or "interval_seconds" in fields
        if cadence_changed:
            _validate_cadence(cron, interval_seconds)
            row.cron = cron
            row.interval_seconds = interval_seconds
            row.next_run_at = _compute_next_run(cron, interval_seconds, after=_now())

        if "name" in fields:
            name = str(fields["name"]).strip()
            if not name:
                raise ValueError("schedule name required")
            row.name = name
        if "enabled" in fields:
            row.enabled = bool(fields["enabled"])
        if "scan_options" in fields and fields["scan_options"] is not None:
            merged = dict(row.scan_options or {})
            merged.update({k: v for k, v in fields["scan_options"].items() if k in _SCAN_OPTION_KEYS})
            row.scan_options = merged
        if "targets" in fields and fields["targets"] is not None:
            merged_targets = dict(row.targets or {})
            merged_targets.update(
                {k: v for k, v in fields["targets"].items() if k in _TARGET_KEYS and v is not None}
            )
            row.targets = merged_targets

        session.flush()
        return _to_dict(row)


def delete_schedule(schedule_id: str) -> bool:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.ScanSchedule, schedule_id)
        if row is None:
            return False
        session.delete(row)
        return True


def due_schedules(now: datetime) -> list[dict[str, Any]]:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        stmt = select(models.ScanSchedule).where(
            models.ScanSchedule.enabled.is_(True),
            (models.ScanSchedule.next_run_at.is_(None)) | (models.ScanSchedule.next_run_at <= now),
        )
        rows = session.execute(stmt).scalars().all()
    return [_to_dict(row) for row in rows]


def record_dispatch(schedule_id: str, *, job_id: str, ran_at: datetime) -> dict[str, Any] | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.ScanSchedule, schedule_id)
        if row is None:
            return None
        row.last_run_at = ran_at
        row.last_job_id = job_id
        row.next_run_at = _compute_next_run(row.cron, row.interval_seconds, after=ran_at)
        session.flush()
        return _to_dict(row)
