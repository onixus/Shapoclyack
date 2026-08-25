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
from api.schemas import AgentFleetSummary, AgentInfo
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


LATEST_AGENT_VERSION = "0.42.0"


def _extract_detail(
    raw: str | None,
) -> tuple[str | None, dict[str, Any], list[str], bool]:
    """Extract (human_detail, metrics_dict, capabilities_list, upgrade_requested)
    from the row's detail string, which may be plain text or JSON."""
    if not raw:
        return None, {}, [], False
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            human_detail = data.get("detail") or data.get("raw_detail")
            metrics = data.get("metrics") if isinstance(data.get("metrics"), dict) else {}
            capabilities = data.get("capabilities") if isinstance(data.get("capabilities"), list) else []
            upgrade_requested = bool(data.get("upgrade_requested"))
            return human_detail, metrics, capabilities, upgrade_requested
    except Exception:
        pass
    return raw, {}, [], False


def _pack_detail(
    detail: str | None = None,
    metrics: dict[str, Any] | None = None,
    capabilities: list[str] | None = None,
    upgrade_requested: bool | None = None,
) -> str | None:
    if not detail and not metrics and not capabilities and not upgrade_requested:
        return None
    payload: dict[str, Any] = {}
    if detail:
        payload["detail"] = detail
    if metrics:
        payload["metrics"] = metrics
    if capabilities:
        payload["capabilities"] = capabilities
    if upgrade_requested is not None:
        payload["upgrade_requested"] = upgrade_requested
    return json.dumps(payload)


def _to_info(row: models.Agent) -> AgentInfo:
    online = _is_online(row.last_seen_at)
    human_detail, metrics, capabilities, upgrade_requested = _extract_detail(row.detail)
    version = row.version or ""
    is_outdated = bool(version and version != LATEST_AGENT_VERSION)
    return AgentInfo(
        agent_id=row.agent_id,
        hostname=row.hostname or "",
        version=version,
        labels=dict(row.labels or {}),
        status=(row.status or "idle") if online else "stale",  # type: ignore[arg-type]
        current_job_id=row.current_job_id,
        detail=human_detail,
        registered_at=_iso(row.registered_at),
        last_seen_at=_iso(row.last_seen_at),
        online=online,
        tenant_id=row.tenant_id or "default",
        metrics=metrics,
        capabilities=capabilities,
        is_outdated=is_outdated,
        latest_version=LATEST_AGENT_VERSION,
        upgrade_requested=upgrade_requested,
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
    metrics: dict[str, Any] | None = None,
    capabilities: list[str] | None = None,
) -> AgentInfo:
    settings = _require_settings()
    now = _now()
    packed_detail = _pack_detail(metrics=metrics, capabilities=capabilities)
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
            if packed_detail:
                row.detail = packed_detail
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
            detail=packed_detail,
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
    metrics: dict[str, Any] | None = None,
    capabilities: list[str] | None = None,
) -> AgentInfo | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Agent, agent_id)
        if row is None:
            return None
        row.last_seen_at = _now()
        row.status = status
        row.current_job_id = current_job_id
        # Preserve upgrade_requested if previously set
        _, prev_metrics, prev_caps, prev_upgrade = _extract_detail(row.detail)
        final_metrics = metrics if metrics is not None else prev_metrics
        final_caps = capabilities if capabilities is not None else prev_caps
        row.detail = _pack_detail(
            detail=detail,
            metrics=final_metrics,
            capabilities=final_caps,
            upgrade_requested=prev_upgrade,
        )
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


def get_agent(agent_id: str, tenant_id: str | None = None) -> AgentInfo | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Agent, agent_id)
        if not row:
            return None
        if tenant_id and row.tenant_id != tenant_id:
            raise PermissionError("Cross-tenant agent access denied")
        return _to_info(row)


def touch_job(agent_id: str, job_id: str | None, *, status: str = "busy") -> None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Agent, agent_id)
        if row is None:
            return
        row.last_seen_at = _now()
        row.current_job_id = job_id
        row.status = status if job_id else "idle"


def get_fleet_summary(tenant_id: str | None = None) -> AgentFleetSummary:
    settings = _require_settings()
    now = _now()
    with get_session(settings.postgres_url) as session:
        query = select(models.Agent)
        if tenant_id:
            query = query.where(models.Agent.tenant_id == tenant_id)
        rows = session.execute(query).scalars().all()

    total = len(rows)
    online = 0
    busy = 0
    stale = 0
    error = 0
    outdated = 0
    by_tenant: dict[str, int] = {}

    for r in rows:
        t = r.tenant_id or "default"
        by_tenant[t] = by_tenant.get(t, 0) + 1
        is_on = r.last_seen_at and (now - r.last_seen_at).total_seconds() <= settings.agent_stale_seconds
        if not is_on:
            stale += 1
        else:
            online += 1
            if r.status == "busy":
                busy += 1
            elif r.status == "error":
                error += 1
        if r.version and r.version != LATEST_AGENT_VERSION:
            outdated += 1

    return AgentFleetSummary(
        total_agents=total,
        online_agents=online,
        busy_agents=busy,
        stale_agents=stale,
        error_agents=error,
        outdated_agents=outdated,
        latest_version=LATEST_AGENT_VERSION,
        by_tenant=by_tenant,
    )


def delete_agent(agent_id: str, tenant_id: str | None = None) -> bool:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Agent, agent_id)
        if row is None:
            return False
        if tenant_id and row.tenant_id != tenant_id:
            raise PermissionError("Cross-tenant agent access denied")
        session.delete(row)
        session.flush()
        return True


def request_upgrade(agent_id: str, tenant_id: str | None = None) -> dict[str, Any]:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Agent, agent_id)
        if row is None:
            raise LookupError("Agent not found")
        if tenant_id and row.tenant_id != tenant_id:
            raise PermissionError("Cross-tenant agent access denied")
        human_detail, metrics, capabilities, _ = _extract_detail(row.detail)
        row.detail = _pack_detail(
            detail=human_detail,
            metrics=metrics,
            capabilities=capabilities,
            upgrade_requested=True,
        )
        session.flush()
        return {
            "status": "upgrade_queued",
            "agent_id": agent_id,
            "target_version": LATEST_AGENT_VERSION,
        }


DEPLOYMENT_KEY_LABEL = "Web UI Deployment Key"
# Shown in place of a real key when the caller only asked to *see* the
# snippets. Minting a tenant provisioning key is a privileged, stateful act,
# so it happens on POST, never as a side effect of a GET.
DEPLOYMENT_KEY_PLACEHOLDER = "<PROVISIONING_KEY>"


def get_deployment_snippets(
    tenant_id: str,
    server_url: str,
    *,
    provisioning_key: str | None = None,
) -> dict[str, Any]:
    """Render the install snippets. Never mints a key.

    Without ``provisioning_key`` the snippets carry a placeholder the operator
    is expected to replace with a key minted through
    :func:`mint_deployment_snippets` (or an existing tenant key).
    """
    key_minted = bool(provisioning_key)
    if not provisioning_key:
        provisioning_key = DEPLOYMENT_KEY_PLACEHOLDER
    clean_server = server_url.rstrip("/")
    install_url = f"{clean_server}/api/agent/install.sh"

    systemd_oneliner = (
        f"curl -sSL {install_url} | sudo bash -s -- "
        f"--server {clean_server} --key {provisioning_key} --tenant {tenant_id}"
    )
    docker_run = (
        f"docker run -d --name shapoclyack-agent --restart always "
        f"-e OCTO_SERVER_URL={clean_server} -e OCTO_PROVISIONING_KEY={provisioning_key} -e OCTO_TENANT_ID={tenant_id} "
        f"ghcr.io/onixus/shapoclyack:latest python -m agent.worker --server {clean_server} --key {provisioning_key}"
    )
    docker_compose = f"""version: '3.8'
services:
  shapoclyack-agent:
    image: ghcr.io/onixus/shapoclyack:latest
    container_name: shapoclyack-agent
    restart: always
    environment:
      - OCTO_SERVER_URL={clean_server}
      - OCTO_PROVISIONING_KEY={provisioning_key}
      - OCTO_TENANT_ID={tenant_id}
    command: python -m agent.worker --server {clean_server} --key {provisioning_key}
"""
    kubernetes_yaml = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: shapoclyack-agent
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: shapoclyack-agent
  template:
    metadata:
      labels:
        app: shapoclyack-agent
    spec:
      containers:
      - name: agent
        image: ghcr.io/onixus/shapoclyack:latest
        env:
        - name: OCTO_SERVER_URL
          value: "{clean_server}"
        - name: OCTO_PROVISIONING_KEY
          value: "{provisioning_key}"
        - name: OCTO_TENANT_ID
          value: "{tenant_id}"
        command: ["python", "-m", "agent.worker", "--server", "{clean_server}", "--key", "{provisioning_key}"]
"""
    return {
        "tenant_id": tenant_id,
        "provisioning_key": provisioning_key if key_minted else None,
        "key_minted": key_minted,
        "server_url": clean_server,
        "systemd_oneliner": systemd_oneliner,
        "docker_run": docker_run,
        "docker_compose": docker_compose.strip(),
        "kubernetes_yaml": kubernetes_yaml.strip(),
    }


def mint_deployment_snippets(
    tenant_id: str,
    server_url: str,
    *,
    label: str = "",
) -> dict[str, Any]:
    """Mint one tenant provisioning key and render the snippets around it.

    The plaintext key is returned here only; it is hashed at rest and cannot
    be read back, so a fresh key is the only way to fill in the snippets.
    """
    key_res = tenants_service.create_provisioning_key(
        tenant_id=tenant_id,
        label=label.strip() or DEPLOYMENT_KEY_LABEL,
    )
    return get_deployment_snippets(
        tenant_id=tenant_id,
        server_url=server_url,
        provisioning_key=key_res["key"],
    )
