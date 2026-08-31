"""Report templates, schedules, generation and retrieval (Sprint 4).

The generation path is deliberately synchronous and small: build the body,
render it, write the bytes, record the row. It is called from the API (an
operator pressing "generate") and from the schedule dispatcher, and a single
implementation is what makes the scheduled report identical to the one the
operator previewed.

Bytes go to ``output_dir/reports/<tenant>/<report_id>.<ext>`` and the row keeps
a path *relative to* ``output_dir``. Relative because an absolute path stored
in a row stops resolving the moment the deployment's volume layout changes, and
because a path from the database that is later joined onto a directory is the
classic traversal sink — ``resolve_report_file`` re-derives the path from the
row's own id instead of trusting the stored string.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services.compliance import frameworks as catalog
from api.services.reports import content as content_builder
from api.services.reports import render as renderer
from api.settings import Settings
from scanner.scheduler import next_cron_time, parse_cron

LOG = logging.getLogger("shapoclyack.reports")

REPORTS_SUBDIR = "reports"
MAX_TEMPLATES_PER_TENANT = 50
MAX_SCHEDULES_PER_TENANT = 20
MAX_RECIPIENTS = 20

TRANSPORTS = ("email", "webhook")

_EXTENSIONS = {"pdf": "pdf", "html": "html", "json": "json"}
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class ReportError(ValueError):
    """Invalid report input; a 400, not a 500."""


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None


# ------------------------------------------------------------------ templates


def _template_dict(row: models.ReportTemplate) -> dict[str, Any]:
    return {
        "template_id": row.template_id,
        "tenant_id": row.tenant_id,
        "name": row.name,
        "kind": row.kind,
        "framework_id": row.framework_id,
        "sections": dict(row.sections or {}),
        "created_at": _iso(row.created_at),
        "created_by": row.created_by,
        "updated_at": _iso(row.updated_at),
    }


def _validate_template(kind: str, framework_id: str | None, sections: dict[str, Any]) -> None:
    if kind not in content_builder.KINDS:
        raise ReportError(
            f"unknown kind {kind!r}; expected one of {', '.join(content_builder.KINDS)}"
        )
    if kind == "compliance" and not framework_id:
        raise ReportError("a compliance template needs framework_id")
    if framework_id and catalog.get_framework(framework_id) is None:
        raise ReportError(f"unknown compliance framework {framework_id!r}")
    unknown = sorted(set(sections) - set(content_builder.SECTIONS))
    if unknown:
        raise ReportError(f"unknown report sections: {', '.join(unknown)}")


def create_template(
    settings: Settings,
    *,
    tenant_id: str,
    name: str,
    kind: str = "executive",
    framework_id: str | None = None,
    sections: dict[str, Any] | None = None,
    actor: str | None = None,
) -> dict[str, Any]:
    sections = dict(sections or {})
    _validate_template(kind, framework_id, sections)
    now = _now()
    with get_session(settings.postgres_url) as session:
        existing = session.execute(
            select(models.ReportTemplate).where(models.ReportTemplate.tenant_id == tenant_id)
        ).scalars().all()
        if len(existing) >= MAX_TEMPLATES_PER_TENANT:
            raise ReportError(f"tenant already has {MAX_TEMPLATES_PER_TENANT} report templates")
        if any(row.name == name for row in existing):
            raise ReportError(f"a template named {name!r} already exists")
        row = models.ReportTemplate(
            template_id=f"rtpl_{uuid.uuid4().hex[:16]}",
            tenant_id=tenant_id,
            name=name,
            kind=kind,
            framework_id=framework_id,
            sections=sections,
            created_at=now,
            created_by=actor,
            updated_at=now,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return _template_dict(row)


def list_templates(settings: Settings, *, tenant_id: str | None = None) -> list[dict[str, Any]]:
    filters = [models.ReportTemplate.tenant_id == tenant_id] if tenant_id else []
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.ReportTemplate).where(*filters).order_by(models.ReportTemplate.name)
        ).scalars().all()
        return [_template_dict(row) for row in rows]


def get_template(
    settings: Settings, template_id: str, *, tenant_id: str | None = None
) -> dict[str, Any] | None:
    filters = [models.ReportTemplate.template_id == template_id]
    if tenant_id:
        filters.append(models.ReportTemplate.tenant_id == tenant_id)
    with get_session(settings.postgres_url) as session:
        row = session.execute(select(models.ReportTemplate).where(*filters)).scalar_one_or_none()
        return _template_dict(row) if row else None


def update_template(
    settings: Settings, template_id: str, *, tenant_id: str | None = None, **fields: Any
) -> dict[str, Any] | None:
    filters = [models.ReportTemplate.template_id == template_id]
    if tenant_id:
        filters.append(models.ReportTemplate.tenant_id == tenant_id)
    with get_session(settings.postgres_url) as session:
        row = session.execute(select(models.ReportTemplate).where(*filters)).scalar_one_or_none()
        if row is None:
            return None
        kind = fields.get("kind", row.kind)
        framework_id = fields.get("framework_id", row.framework_id)
        sections = dict(fields.get("sections", row.sections) or {})
        _validate_template(kind, framework_id, sections)
        row.kind = kind
        row.framework_id = framework_id
        row.sections = sections
        if fields.get("name"):
            row.name = fields["name"]
        row.updated_at = _now()
        session.commit()
        session.refresh(row)
        return _template_dict(row)


def delete_template(
    settings: Settings, template_id: str, *, tenant_id: str | None = None
) -> bool:
    filters = [models.ReportTemplate.template_id == template_id]
    if tenant_id:
        filters.append(models.ReportTemplate.tenant_id == tenant_id)
    with get_session(settings.postgres_url) as session:
        row = session.execute(select(models.ReportTemplate).where(*filters)).scalar_one_or_none()
        if row is None:
            return False
        session.delete(row)
        session.commit()
        return True


# ------------------------------------------------------------------ schedules


def _schedule_dict(row: models.ReportSchedule) -> dict[str, Any]:
    return {
        "schedule_id": row.schedule_id,
        "tenant_id": row.tenant_id,
        "template_id": row.template_id,
        "name": row.name,
        "enabled": row.enabled,
        "cron": row.cron,
        "format": row.fmt,
        "recipients": list(row.recipients or []),
        "next_run_at": _iso(row.next_run_at),
        "last_run_at": _iso(row.last_run_at),
        "last_report_id": row.last_report_id,
        "created_at": _iso(row.created_at),
        "created_by": row.created_by,
    }


def _validate_recipients(recipients: list[dict[str, Any]] | None) -> list[dict[str, str]]:
    """Shape and transport check only.

    A webhook URL is *not* SSRF-validated here and then trusted at send time:
    the check happens again in the delivery path, because a hostname that
    resolved publicly when the schedule was written can resolve to 169.254.169.254
    by the time the schedule fires."""

    entries = list(recipients or [])
    if len(entries) > MAX_RECIPIENTS:
        raise ReportError(f"at most {MAX_RECIPIENTS} recipients per schedule")
    cleaned: list[dict[str, str]] = []
    for entry in entries:
        transport = str(entry.get("transport") or "").strip()
        target = str(entry.get("target") or "").strip()
        if transport not in TRANSPORTS:
            raise ReportError(
                f"unknown transport {transport!r}; expected one of {', '.join(TRANSPORTS)}"
            )
        if not target:
            raise ReportError("recipient target is required")
        if transport == "email" and not _EMAIL_RE.match(target):
            raise ReportError(f"{target!r} is not an email address")
        if transport == "webhook" and not target.lower().startswith(("http://", "https://")):
            raise ReportError("a webhook target must be an http(s) URL")
        cleaned.append({"transport": transport, "target": target})
    return cleaned


def create_schedule(
    settings: Settings,
    *,
    tenant_id: str,
    template_id: str,
    name: str,
    cron: str,
    fmt: str = "pdf",
    recipients: list[dict[str, Any]] | None = None,
    enabled: bool = True,
    actor: str | None = None,
) -> dict[str, Any]:
    if fmt not in _EXTENSIONS:
        raise ReportError(f"unknown format {fmt!r}; expected one of {', '.join(_EXTENSIONS)}")
    try:
        parse_cron(cron)
    except ValueError as exc:
        raise ReportError(str(exc)) from exc
    cleaned = _validate_recipients(recipients)
    now = _now()
    with get_session(settings.postgres_url) as session:
        template = session.execute(
            select(models.ReportTemplate).where(
                models.ReportTemplate.template_id == template_id,
                models.ReportTemplate.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
        if template is None:
            raise ReportError("template not found in this tenant")
        count = len(
            session.execute(
                select(models.ReportSchedule).where(models.ReportSchedule.tenant_id == tenant_id)
            ).scalars().all()
        )
        if count >= MAX_SCHEDULES_PER_TENANT:
            raise ReportError(f"tenant already has {MAX_SCHEDULES_PER_TENANT} report schedules")
        row = models.ReportSchedule(
            schedule_id=f"rsch_{uuid.uuid4().hex[:16]}",
            tenant_id=tenant_id,
            template_id=template_id,
            name=name,
            enabled=enabled,
            cron=cron,
            fmt=fmt,
            recipients=cleaned,
            next_run_at=next_cron_time(cron, after=now),
            created_at=now,
            created_by=actor,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return _schedule_dict(row)


def list_schedules(settings: Settings, *, tenant_id: str | None = None) -> list[dict[str, Any]]:
    filters = [models.ReportSchedule.tenant_id == tenant_id] if tenant_id else []
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.ReportSchedule).where(*filters).order_by(models.ReportSchedule.name)
        ).scalars().all()
        return [_schedule_dict(row) for row in rows]


def get_schedule(
    settings: Settings, schedule_id: str, *, tenant_id: str | None = None
) -> dict[str, Any] | None:
    filters = [models.ReportSchedule.schedule_id == schedule_id]
    if tenant_id:
        filters.append(models.ReportSchedule.tenant_id == tenant_id)
    with get_session(settings.postgres_url) as session:
        row = session.execute(select(models.ReportSchedule).where(*filters)).scalar_one_or_none()
        return _schedule_dict(row) if row else None


def update_schedule(
    settings: Settings, schedule_id: str, *, tenant_id: str | None = None, **fields: Any
) -> dict[str, Any] | None:
    filters = [models.ReportSchedule.schedule_id == schedule_id]
    if tenant_id:
        filters.append(models.ReportSchedule.tenant_id == tenant_id)
    with get_session(settings.postgres_url) as session:
        row = session.execute(select(models.ReportSchedule).where(*filters)).scalar_one_or_none()
        if row is None:
            return None
        if "cron" in fields and fields["cron"] != row.cron:
            try:
                parse_cron(fields["cron"])
            except ValueError as exc:
                raise ReportError(str(exc)) from exc
            row.cron = fields["cron"]
            # A cadence change re-anchors the next run. Leaving the old
            # ``next_run_at`` would send the next report on the old schedule
            # and only then adopt the new one.
            row.next_run_at = next_cron_time(row.cron, after=_now())
        if "format" in fields:
            if fields["format"] not in _EXTENSIONS:
                raise ReportError(f"unknown format {fields['format']!r}")
            row.fmt = fields["format"]
        if "recipients" in fields:
            row.recipients = _validate_recipients(fields["recipients"])
        if "name" in fields and fields["name"]:
            row.name = fields["name"]
        if "enabled" in fields and fields["enabled"] is not None:
            row.enabled = bool(fields["enabled"])
            if row.enabled and row.next_run_at is None:
                row.next_run_at = next_cron_time(row.cron, after=_now())
        session.commit()
        session.refresh(row)
        return _schedule_dict(row)


def delete_schedule(
    settings: Settings, schedule_id: str, *, tenant_id: str | None = None
) -> bool:
    filters = [models.ReportSchedule.schedule_id == schedule_id]
    if tenant_id:
        filters.append(models.ReportSchedule.tenant_id == tenant_id)
    with get_session(settings.postgres_url) as session:
        row = session.execute(select(models.ReportSchedule).where(*filters)).scalar_one_or_none()
        if row is None:
            return False
        session.delete(row)
        session.commit()
        return True


def due_schedules(settings: Settings, now: datetime) -> list[dict[str, Any]]:
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.ReportSchedule).where(
                models.ReportSchedule.enabled.is_(True),
                models.ReportSchedule.next_run_at.is_not(None),
                models.ReportSchedule.next_run_at <= now,
            )
        ).scalars().all()
        return [_schedule_dict(row) for row in rows]


def record_dispatch(
    settings: Settings, schedule_id: str, *, report_id: str | None, ran_at: datetime
) -> None:
    """Advance the schedule whether or not the render succeeded.

    A failed render that left ``next_run_at`` in the past would be retried on
    every dispatcher tick — a report every 30 seconds to every recipient, for
    as long as the failure lasts. The failure is recorded on the report row
    instead, where an operator can see it."""

    with get_session(settings.postgres_url) as session:
        row = session.execute(
            select(models.ReportSchedule).where(models.ReportSchedule.schedule_id == schedule_id)
        ).scalar_one_or_none()
        if row is None:
            return
        row.last_run_at = ran_at
        if report_id:
            row.last_report_id = report_id
        row.next_run_at = next_cron_time(row.cron, after=ran_at)
        session.commit()


# ---------------------------------------------------------------- generation


def _report_dict(row: models.GeneratedReport) -> dict[str, Any]:
    return {
        "report_id": row.report_id,
        "tenant_id": row.tenant_id,
        "template_id": row.template_id,
        "schedule_id": row.schedule_id,
        "kind": row.kind,
        "format": row.fmt,
        "status": row.status,
        "title": row.title,
        "size_bytes": row.size_bytes,
        "error": row.error,
        "delivery": list(row.delivery or []),
        "generated_at": _iso(row.generated_at),
        "generated_by": row.generated_by,
    }


def reports_root(settings: Settings) -> Path:
    return Path(settings.output_dir) / REPORTS_SUBDIR


def _report_path(settings: Settings, tenant_id: str, report_id: str, fmt: str) -> Path:
    # Both components are platform-generated ids, but they are still checked:
    # this is the one place a stored string becomes a filesystem path.
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", tenant_id):
        raise ReportError("tenant_id is not usable as a path component")
    if not re.fullmatch(r"rpt_[0-9a-f]{16}", report_id):
        raise ReportError("report_id is not a generated report id")
    return reports_root(settings) / tenant_id / f"{report_id}.{_EXTENSIONS[fmt]}"


def generate(
    settings: Settings,
    *,
    tenant_id: str,
    template_id: str | None = None,
    kind: str = "executive",
    framework_id: str | None = None,
    sections: dict[str, Any] | None = None,
    fmt: str = "pdf",
    title: str | None = None,
    schedule_id: str | None = None,
    actor: str | None = None,
) -> dict[str, Any]:
    """Render one report now and record it. Raises ``ReportError`` on bad input.

    A render that fails *after* the input was accepted (a template that names a
    framework a later release removed, say) is recorded as a ``failed`` row
    rather than raised away: a scheduled report that vanished without trace is
    indistinguishable, to the customer waiting for it, from one nobody
    scheduled."""

    if fmt not in _EXTENSIONS:
        raise ReportError(f"unknown format {fmt!r}; expected one of {', '.join(_EXTENSIONS)}")
    if template_id:
        template = get_template(settings, template_id, tenant_id=tenant_id)
        if template is None:
            raise ReportError("template not found in this tenant")
        kind = template["kind"]
        framework_id = template["framework_id"]
        sections = template["sections"]
        title = title or template["name"]
    _validate_template(kind, framework_id, dict(sections or {}))

    report_id = f"rpt_{uuid.uuid4().hex[:16]}"
    now = _now()
    row = models.GeneratedReport(
        report_id=report_id,
        tenant_id=tenant_id,
        template_id=template_id,
        schedule_id=schedule_id,
        kind=kind,
        fmt=fmt,
        status="pending",
        title=title or "",
        generated_at=now,
        generated_by=actor,
    )

    error: str | None = None
    size = 0
    storage_path: str | None = None
    try:
        body = content_builder.build(
            settings,
            tenant_id=tenant_id,
            kind=kind,
            framework_id=framework_id,
            sections=sections,
            title=title,
        )
        payload = renderer.render(body, fmt)
        target = _report_path(settings, tenant_id, report_id, fmt)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        size = len(payload)
        storage_path = str(target.relative_to(Path(settings.output_dir)))
        row.title = row.title or str(body.get("title") or "")
    except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
        LOG.exception("Report generation failed for tenant %s", tenant_id)
        error = f"{type(exc).__name__}: {exc}"[:500]

    row.status = "failed" if error else "ready"
    row.error = error
    row.size_bytes = size
    row.storage_path = storage_path
    with get_session(settings.postgres_url) as session:
        session.add(row)
        session.commit()
        session.refresh(row)
        return _report_dict(row)


def list_reports(
    settings: Settings, *, tenant_id: str | None = None, limit: int = 50
) -> list[dict[str, Any]]:
    filters = [models.GeneratedReport.tenant_id == tenant_id] if tenant_id else []
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.GeneratedReport)
            .where(*filters)
            .order_by(models.GeneratedReport.generated_at.desc())
            .limit(max(1, min(limit, 200)))
        ).scalars().all()
        return [_report_dict(row) for row in rows]


def get_report(
    settings: Settings, report_id: str, *, tenant_id: str | None = None
) -> dict[str, Any] | None:
    filters = [models.GeneratedReport.report_id == report_id]
    if tenant_id:
        filters.append(models.GeneratedReport.tenant_id == tenant_id)
    with get_session(settings.postgres_url) as session:
        row = session.execute(select(models.GeneratedReport).where(*filters)).scalar_one_or_none()
        return _report_dict(row) if row else None


def resolve_report_file(
    settings: Settings, report_id: str, *, tenant_id: str | None = None
) -> tuple[Path, str, str] | None:
    """``(path, media_type, filename)`` for a ready report, or ``None``.

    The path is recomputed from the row's tenant, id and format rather than
    read from ``storage_path``: the stored string is bookkeeping, and a value
    from the database joined onto a directory is how a path traversal reaches
    a file server."""

    row = get_report(settings, report_id, tenant_id=tenant_id)
    if row is None or row["status"] != "ready":
        return None
    try:
        path = _report_path(settings, row["tenant_id"], row["report_id"], row["format"])
    except ReportError:
        return None
    if not path.is_file():
        return None
    return path, renderer.MEDIA_TYPES[row["format"]], path.name


def delete_report(
    settings: Settings, report_id: str, *, tenant_id: str | None = None
) -> bool:
    row = get_report(settings, report_id, tenant_id=tenant_id)
    if row is None:
        return False
    try:
        path = _report_path(settings, row["tenant_id"], row["report_id"], row["format"])
        path.unlink(missing_ok=True)
    except ReportError:
        pass
    with get_session(settings.postgres_url) as session:
        db_row = session.execute(
            select(models.GeneratedReport).where(models.GeneratedReport.report_id == report_id)
        ).scalar_one_or_none()
        if db_row is None:
            return False
        session.delete(db_row)
        session.commit()
    return True


def record_delivery(settings: Settings, report_id: str, entries: list[dict[str, Any]]) -> None:
    with get_session(settings.postgres_url) as session:
        row = session.execute(
            select(models.GeneratedReport).where(models.GeneratedReport.report_id == report_id)
        ).scalar_one_or_none()
        if row is None:
            return
        row.delivery = list(entries)
        session.commit()


def prune_reports(settings: Settings, *, now: datetime | None = None) -> dict[str, int]:
    """Delete generated reports past ``report_retention_days``, files included.

    Rows and files are removed together, in that order per report, so a crash
    between the two leaves an orphaned file rather than a row pointing at
    nothing — an operator finding an extra PDF on disk is a smaller problem
    than a console listing a report that 404s on download."""

    if settings.report_retention_days <= 0:
        return {"deleted": 0, "errors": 0}
    cutoff = (now or _now()) - timedelta(days=settings.report_retention_days)
    deleted = 0
    errors = 0
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.GeneratedReport).where(models.GeneratedReport.generated_at < cutoff)
        ).scalars().all()
        for row in rows:
            try:
                path = _report_path(settings, row.tenant_id, row.report_id, row.fmt)
                path.unlink(missing_ok=True)
            except (ReportError, OSError):
                errors += 1
            session.delete(row)
            deleted += 1
        session.commit()
    if deleted:
        LOG.info("Pruned %d generated reports older than %s", deleted, cutoff.isoformat())
    return {"deleted": deleted, "errors": errors}
