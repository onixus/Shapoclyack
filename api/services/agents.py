"""Remote agent registry (Phase 3; Postgres-backed since ROADMAP P1.2).

The registry used to be a module-level dict mirrored to
``state/api_agents.json``. That made an agent visible only to the API replica
that happened to serve its registration, and every write rewrote the whole
file. Rows in ``agents`` replace both: any replica sees the same registry, and
a heartbeat is a single-row UPDATE.

Staleness stays derived rather than stored — ``status`` holds what the agent
last reported (idle/busy/error), and "stale" is computed on read from
``last_seen_at`` against ``OCTO_AGENT_STALE_SECONDS``. Storing it would mean
one replica's clock deciding a flag every other replica then reads back.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import case, func, or_, select

from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.schemas import AgentInfo
from api.services import pagination
from api.services import tenants as tenants_service
from api.settings import Settings

_settings: Settings | None = None
_log = logging.getLogger(__name__)


def _now() -> datetime:
    """Naive UTC, matching the other Postgres-backed services."""
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(dt: datetime | None) -> str | None:
    return dt.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z") if dt else None


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "agents.configure() not called"
    return _settings


def load_agents(settings: Settings) -> None:
    """Configure the service and import the pre-P1 JSON registry once.

    Upgrades carry their agents over without an operator step: the file is
    read, missing rows are inserted, and it is renamed to ``*.imported`` so a
    later restart cannot resurrect agents that were deliberately deleted.
    Agents that re-register on their next heartbeat would recreate themselves
    anyway; the import exists so the console is not empty in between.
    """
    configure(settings)
    path = settings.state_dir / "api_agents.json"
    if not path.is_file():
        return
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _log.warning("Ignoring unreadable legacy agent registry at %s", path)
        return
    if not isinstance(raw, list):
        return

    known_tenants = {tenant["tenant_id"] for tenant in tenants_service.list_tenants()}
    imported = 0
    with get_session(settings.postgres_url) as session:
        for item in raw:
            if not (isinstance(item, dict) and item.get("agent_id")):
                continue
            agent_id = str(item["agent_id"])
            if session.get(models.Agent, agent_id) is not None:
                continue
            now = _now()
            status = str(item.get("status") or "idle")
            tenant_id = str(item.get("tenant_id") or tenants_service.DEFAULT_TENANT_ID)
            if tenant_id not in known_tenants:
                # The column is a FK, and this runs inside create_app(): an
                # agent whose tenant is gone (a tenant DB restored separately
                # from the state volume, say) would otherwise fail startup and
                # do it again on every restart. Re-home it, as the job
                # importer does.
                _log.warning(
                    "Legacy agent %s references unknown tenant %s; importing under %s",
                    agent_id,
                    tenant_id,
                    tenants_service.DEFAULT_TENANT_ID,
                )
                tenant_id = tenants_service.DEFAULT_TENANT_ID
            row = models.Agent(
                agent_id=agent_id,
                tenant_id=tenant_id,
                hostname=str(item.get("hostname") or ""),
                version=str(item.get("version") or ""),
                labels=dict(item.get("labels") or {}),
                # "stale" was a derived value that the old code persisted;
                # it is not a reported status, so it does not survive.
                status="idle" if status == "stale" else status,
                current_job_id=item.get("current_job_id"),
                detail=item.get("detail"),
                registered_at=_parse_iso(item.get("registered_at")) or now,
                last_seen_at=_parse_iso(item.get("last_seen_at")) or now,
            )
            if insert_if_absent(session, row, agent_id):
                imported += 1
    _retire(path)
    if imported:
        _log.info("Imported %d agent(s) from the pre-P1 registry at %s", imported, path)


def _parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC).replace(tzinfo=None) if parsed.tzinfo else parsed


def _retire(path: Path) -> None:
    """Rename an imported legacy state file so it is imported exactly once."""
    try:
        path.replace(path.with_suffix(path.suffix + ".imported"))
    except OSError:
        _log.warning("Could not rename %s after import; it will be re-imported", path)


def _is_online(last_seen: datetime | None) -> bool:
    if last_seen is None:
        return False
    age = (datetime.now(UTC) - last_seen.replace(tzinfo=UTC)).total_seconds()
    return age <= _require_settings().agent_stale_seconds


def _to_info(row: models.Agent) -> AgentInfo:
    online = _is_online(row.last_seen_at)
    return AgentInfo(
        agent_id=row.agent_id,
        hostname=row.hostname or "",
        version=row.version or "",
        labels=dict(row.labels or {}),
        status=(row.status or "idle") if online else "stale",  # type: ignore[arg-type]
        current_job_id=row.current_job_id,
        detail=row.detail,
        registered_at=_iso(row.registered_at),
        last_seen_at=_iso(row.last_seen_at),
        online=online,
        tenant_id=row.tenant_id or "default",
    )


def reset_for_tests() -> None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        session.query(models.Agent).delete()


def register_agent(
    *,
    agent_id: str | None = None,
    hostname: str = "",
    version: str = "",
    labels: dict[str, str] | None = None,
    tenant_id: str = "default",
) -> AgentInfo:
    settings = _require_settings()
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Agent, agent_id) if agent_id else None
        if row is not None:
            if row.tenant_id and row.tenant_id != tenant_id:
                raise PermissionError("agent_id belongs to a different tenant")
            row.hostname = hostname or row.hostname or ""
            row.version = version or row.version or ""
            row.tenant_id = tenant_id
            if labels is not None:
                row.labels = dict(labels)
            row.last_seen_at = now
            if row.status == "stale":
                row.status = "idle"
            session.flush()
            return _to_info(row)

        row = models.Agent(
            agent_id=(agent_id or "").strip() or uuid.uuid4().hex,
            tenant_id=tenant_id,
            hostname=hostname or "",
            version=version or "",
            labels=dict(labels or {}),
            status="idle",
            current_job_id=None,
            detail=None,
            registered_at=now,
            last_seen_at=now,
        )
        session.add(row)
        session.flush()
        return _to_info(row)


def heartbeat(
    agent_id: str,
    *,
    status: str = "idle",
    current_job_id: str | None = None,
    detail: str | None = None,
) -> AgentInfo | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Agent, agent_id)
        if row is None:
            return None
        row.last_seen_at = _now()
        row.status = status
        row.current_job_id = current_job_id
        row.detail = detail
        session.flush()
        return _to_info(row)


AGENT_SORT_FIELDS = ("hostname", "agent_id", "status", "last_seen_at", "registered_at", "tenant_id")
AGENT_QUERY_FIELDS = ("agent_id", "hostname", "version", "status", "tenant_id", "current_job_id")

def _reported_status_expr() -> Any:
    """The status the API will actually return, as SQL.

    ``status`` on the row is what the agent last reported; the response says
    "stale" once ``last_seen_at`` is older than ``agent_stale_seconds``. That
    derivation has to happen inside the query too, or searching for "stale"
    would match nothing and ``sort=status`` would order the page by values the
    caller never sees.
    """
    cutoff = _now() - timedelta(seconds=_require_settings().agent_stale_seconds)
    return case((models.Agent.last_seen_at < cutoff, "stale"), else_=models.Agent.status)


def _sort_columns() -> dict[str, Any]:
    return {
        # Unnamed agents sort by their id rather than sinking to the bottom.
        "hostname": func.coalesce(func.nullif(models.Agent.hostname, ""), models.Agent.agent_id),
        "agent_id": models.Agent.agent_id,
        "status": _reported_status_expr(),
        "last_seen_at": models.Agent.last_seen_at,
        "registered_at": models.Agent.registered_at,
        "tenant_id": models.Agent.tenant_id,
    }


def list_agents(
    *,
    offset: int = 0,
    limit: int = pagination.DEFAULT_LIMIT,
    q: str | None = None,
    sort: str | None = None,
    order: str | None = None,
    tenant_id: str | None = None,
) -> tuple[list[AgentInfo], int]:
    """Return ``(page, total_after_filtering)`` — filtered, counted, and sliced
    in SQL (ROADMAP P3.2 semantics, P1.2 storage).

    Both the search and the sort run against the *reported* status (see
    ``_reported_status_expr``), so a page ordered or filtered by status matches
    what the response body says.
    """
    settings = _require_settings()
    columns = _sort_columns()
    column = columns.get(sort or "", columns["hostname"])
    # Matches pagination.apply_sort: descending unless "asc" is asked for.
    direction = column.asc() if (order or "").lower() == "asc" else column.desc()

    with get_session(settings.postgres_url) as session:
        filters = []
        if tenant_id:
            filters.append(models.Agent.tenant_id == tenant_id)
        if q and q.strip():
            needle = f"%{q.strip().lower()}%"
            filters.append(
                or_(
                    func.lower(models.Agent.agent_id).like(needle),
                    func.lower(models.Agent.hostname).like(needle),
                    func.lower(models.Agent.version).like(needle),
                    func.lower(_reported_status_expr()).like(needle),
                    func.lower(models.Agent.tenant_id).like(needle),
                    func.lower(func.coalesce(models.Agent.current_job_id, "")).like(needle),
                )
            )
        total = session.execute(
            select(func.count()).select_from(models.Agent).where(*filters)
        ).scalar_one()
        rows = session.execute(
            select(models.Agent)
            .where(*filters)
            .order_by(direction, models.Agent.agent_id)
            .offset(offset)
            .limit(limit)
        ).scalars().all()
        return [_to_info(row) for row in rows], total


def get_agent(agent_id: str) -> AgentInfo | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Agent, agent_id)
        return _to_info(row) if row else None


def touch_job(agent_id: str, job_id: str | None, *, status: str = "busy") -> None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Agent, agent_id)
        if row is None:
            return
        row.last_seen_at = _now()
        row.current_job_id = job_id
        row.status = status if job_id else "idle"
