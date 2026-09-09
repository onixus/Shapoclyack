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

from api import __version__
from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.schemas import AgentFleetSummary, AgentInfo
from api.services import pagination
from api.services import tenants as tenants_service
from api.services import version_compare
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


# The operator-set lifecycle states an agent row can be in (#308). Kept apart
# from the reported ``status`` column (idle/busy/error, "stale" derived on
# read): one is what an operator decided, the other is what the agent said.
LIFECYCLE_ACTIVE = "active"
LIFECYCLE_STATES = (LIFECYCLE_ACTIVE, "disabled", "quarantined")

_LIFECYCLE_MESSAGES = {
    "disabled": (
        "This agent is disabled by an operator; job claims and result uploads "
        "are refused until it is re-enabled."
    ),
    "quarantined": (
        "This agent is quarantined by an operator; job claims and result "
        "uploads are refused until the quarantine is lifted."
    ),
}


def lifecycle_message(lifecycle_status: str, reason: str | None = None) -> str | None:
    """The sentence a non-active agent is told, reason appended when there is one.

    Built here rather than at each call site so the heartbeat response, the
    refused claim and the refused upload all say the same thing — the agent
    logs whichever one it meets first, and an operator comparing the API's
    answer with the agent's journal should not have to match two wordings.
    """
    base = _LIFECYCLE_MESSAGES.get(lifecycle_status)
    if base is None:
        return None
    reason = (reason or "").strip()
    return f"{base} Reason: {reason}" if reason else base


class AgentVersionTooOld(RuntimeError):
    """An agent reported a version below ``OCTO_AGENT_MIN_VERSION``.

    Its own class rather than ``PermissionError`` because the route answers
    ``426 Upgrade Required``, not ``403``: the credential is genuine and the
    tenant is right, the software is what is refused.
    """


# The agent ships in the same release as the API and is versioned with it, so
# the app version *is* the latest agent version (#363). These used to be two
# literals -- ``0.42.0`` here against ``0.3.2.1`` in ``agent/__init__.py`` --
# which made every agent in every installation permanently "outdated" and, worse,
# meant ``upgrade_requested`` could never clear: register_agent() clears it only
# when the reported version *changes*, and no upgrade could ever reach a version
# this constant agreed with.
#
# ``agent/__init__.py`` keeps its own literal because the scanner image ships
# the ``agent`` package without ``api`` and the API image ships ``api`` without
# ``agent``: neither can import the other. ``tests/test_agent_version.py`` is
# what holds the two together -- it fails the moment they drift.
LATEST_AGENT_VERSION = __version__


def _min_version() -> str:
    return (_require_settings().agent_min_version or "").strip()


def is_below_min_version(version: str) -> bool:
    """Whether ``version`` is refused by ``OCTO_AGENT_MIN_VERSION``.

    An unset minimum admits everything, including an agent that reports no
    version at all: the gate is opt-in, and an installation that has not set a
    floor has not asked for its fleet to be fenced off. Once a floor *is* set,
    a blank version is refused -- an agent old enough not to report one is
    exactly what the floor is for.
    """
    minimum = _min_version()
    if not minimum:
        return False
    try:
        # dpkg ordering rather than PEP 440: releases here look like
        # ``0.44-0907`` (a date suffix, not a patch level) and agent builds
        # like ``0.3.2.1``, which ``packaging`` -- not a declared dependency of
        # this service -- reads as a post-release. The matcher's comparator is
        # already in this codebase and already tested against dpkg's own
        # ``t-version`` table, so reusing it beats a third version grammar.
        return version_compare.compare_dpkg_version(version, minimum) < 0
    except version_compare.VersionParseError:
        return True


def require_min_version(version: str) -> None:
    """Raise :class:`AgentVersionTooOld` when the floor refuses ``version``."""
    if is_below_min_version(version):
        raise AgentVersionTooOld(
            f"Agent version {version or 'unknown'} is below the required minimum "
            f"{_min_version()}; upgrade the agent (see docs/operations.md "
            "§ Agent installation and upgrade)."
        )


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
    lifecycle_status = row.lifecycle_status or LIFECYCLE_ACTIVE
    human_detail, metrics, capabilities, upgrade_requested = _extract_detail(row.detail)
    version = row.version or ""
    is_outdated = bool(version and version != LATEST_AGENT_VERSION)
    upgrade_required = is_below_min_version(version)
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
        min_version=_min_version(),
        upgrade_required=upgrade_required,
        # The heartbeat response is the only channel that reaches a running
        # agent, so the refusal it is about to meet on claim is spelled out
        # here rather than left as a bare 426 in its log.
        upgrade_message=(
            f"This installation requires agent {_min_version()} or newer; "
            f"this agent reports {version or 'no version'}. Job claims are refused "
            "until it is upgraded."
        )
        if upgrade_required
        else None,
        lifecycle_status=lifecycle_status,  # type: ignore[arg-type]
        lifecycle_reason=row.lifecycle_reason,
        lifecycle_message=lifecycle_message(lifecycle_status, row.lifecycle_reason),
    )


def reset_for_tests() -> None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        session.query(models.Agent).delete()


class AgentCredentialRevoked(RuntimeError):
    """The credential behind an agent JWT is no longer good.

    Its own class rather than ``PermissionError`` because the route answers
    ``401``, not ``403``: nothing is wrong with what the agent is asking for,
    the credential itself has stopped being one. It is also what tells the
    agent's run loop to re-exchange its provisioning key instead of backing
    off — and when the key is what was revoked, that exchange fails too, which
    is the intended end state.
    """


def check_credential(
    *,
    agent_id: str | None,
    tenant_id: str,
    key_id: str | None,
) -> None:
    """Re-check an authenticated agent's credential against the database (#308).

    An agent JWT is valid for two hours and, until now, nothing between minting
    and expiry could stop it: revoking the provisioning key it came from,
    deleting the agent, or disabling it all left the token working. This runs
    on every agent request, so those acts take effect at once.

    Two checks, and deliberately only two:

    * the provisioning key still exists, is not revoked and is not expired
      (:class:`AgentCredentialRevoked` → 401);
    * the agent row, **if there is one**, belongs to the token's tenant
      (``PermissionError`` → 403).

    A *missing* row is not refused, because the very first request an agent
    makes is the registration that creates it — and because a deleted agent and
    a never-registered one are the same absence. Making a delete stick is what
    ``?revoke_key=true`` is for: it takes away the key, which the first check
    above then catches. Lifecycle state is not checked here either; the routes
    apply it, so a heartbeat from a disabled agent can still be answered with
    the reason it is disabled.
    """
    settings = _require_settings()
    if key_id:
        state = tenants_service.provisioning_key_state(key_id)
        if state != "active":
            raise AgentCredentialRevoked(
                f"The provisioning key behind this agent token is {state}; "
                "re-provision the agent with a current key"
            )
    if not agent_id:
        return
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Agent, agent_id)
        if row is not None and row.tenant_id != tenant_id:
            raise PermissionError("Cross-tenant agent access denied")


def require_identity_match(token_agent_id: str | None, requested_agent_id: str | None) -> None:
    """Refuse a request that acts as an agent other than the credential's own (#308).

    The agent JWT carries the ``agent_id`` it was minted for, and until now
    nothing compared it with the id in the body, the form or the query string:
    a token for one agent could heartbeat as, claim for, and upload results as
    any other agent in the same tenant, which is the whole fleet of an MSSP
    customer.

    **A legacy shared-token agent (``OCTO_AGENT_TOKEN``) has no identity to
    bind to**, so it keeps working exactly as before — the shared token is one
    credential for every agent in the ``default`` tenant by construction, and
    the tenant check is still the only boundary it has. That is why the legacy
    mode is documented as lab-only; this function cannot improve it, only
    decline to pretend otherwise.
    """
    if not token_agent_id:
        return
    requested = (requested_agent_id or "").strip()
    if requested and requested != token_agent_id:
        raise PermissionError(
            "Agent token is bound to a different agent_id; a token may only act as itself"
        )


def require_active(agent_id: str) -> None:
    """Raise :class:`PermissionError` unless the agent row is ``active``.

    An unregistered id passes: this gates the work an agent asks *for*, and the
    routes that need the row to exist already answer 404 for a missing one.
    """
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Agent, agent_id)
        if row is None:
            return
        lifecycle_status = row.lifecycle_status or LIFECYCLE_ACTIVE
        if lifecycle_status == LIFECYCLE_ACTIVE:
            return
        raise PermissionError(lifecycle_message(lifecycle_status, row.lifecycle_reason))


def set_lifecycle_status(
    agent_id: str,
    *,
    lifecycle_status: str,
    reason: str = "",
    tenant_id: str | None = None,
    actor: str = "",
) -> AgentInfo:
    """Move one agent between lifecycle states.

    Returning to ``active`` clears the reason: the sentence explained a state
    the agent is no longer in, and keeping it would leave the console showing a
    stale accusation against a working agent.
    """
    if lifecycle_status not in LIFECYCLE_STATES:
        raise ValueError(f"status must be one of {', '.join(LIFECYCLE_STATES)}")
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Agent, agent_id)
        if row is None or (tenant_id and row.tenant_id != tenant_id):
            # Same LookupError either way — see get_agent on the id oracle.
            raise LookupError("Agent not found")
        previous = row.lifecycle_status or LIFECYCLE_ACTIVE
        row.lifecycle_status = lifecycle_status
        row.lifecycle_reason = (
            None if lifecycle_status == LIFECYCLE_ACTIVE else (reason or "").strip()[:512] or None
        )
        session.flush()
        info = _to_info(row)
        recorded_reason = row.lifecycle_reason or ""
    # #327 replaces this with an audit_events row; until it lands the log line
    # is the only durable record that an operator changed an agent's state.
    _log.info(
        "agent lifecycle change agent_id=%s tenant_id=%s from=%s to=%s actor=%s reason=%s",
        agent_id,
        info.tenant_id,
        previous,
        lifecycle_status,
        actor or "unknown",
        recorded_reason,
    )
    return info


def register_agent(
    *,
    agent_id: str | None = None,
    hostname: str = "",
    version: str = "",
    labels: dict[str, str] | None = None,
    tenant_id: str = "default",
    metrics: dict[str, Any] | None = None,
    capabilities: list[str] | None = None,
    provisioning_key_id: str | None = None,
) -> AgentInfo:
    settings = _require_settings()
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Agent, agent_id) if agent_id else None
        if row is not None:
            if row.tenant_id and row.tenant_id != tenant_id:
                raise PermissionError("agent_id belongs to a different tenant")
            previous_version = row.version or ""
            row.hostname = hostname or row.hostname or ""
            row.version = version or row.version or ""
            row.tenant_id = tenant_id
            if labels is not None:
                row.labels = dict(labels)
            row.last_seen_at = now
            # ``upgrade_requested`` is an operator marker, so re-registration must
            # neither drop it (a plain restart is not an upgrade) nor keep it
            # forever. A changed reported version is the only evidence the host
            # acted on it, so that is what clears it.
            _, prev_metrics, prev_caps, prev_upgrade = _extract_detail(row.detail)
            if prev_upgrade and row.version != previous_version:
                prev_upgrade = False
            row.detail = _pack_detail(
                metrics=metrics if metrics is not None else prev_metrics,
                capabilities=capabilities if capabilities is not None else prev_caps,
                upgrade_requested=prev_upgrade or None,
            )
            if row.status == "stale":
                row.status = "idle"
            # Re-registering does not launder a disabled or quarantined agent
            # back into service: without this, an agent refused on claim would
            # simply restart and come back as a fresh "active" row, which is
            # the pause that #308 is about. Only an operator moves it back.
            if (row.lifecycle_status or LIFECYCLE_ACTIVE) != LIFECYCLE_ACTIVE:
                raise PermissionError(
                    lifecycle_message(row.lifecycle_status, row.lifecycle_reason)
                )
            # Rewritten on every registration, so an agent that re-registers
            # with a newer key is deletable-with-revoke against *that* key
            # rather than one that is already gone.
            if provisioning_key_id:
                row.provisioning_key_id = provisioning_key_id
            session.flush()
            return _to_info(row)

        row = models.Agent(
            agent_id=(agent_id or "").strip() or uuid.uuid4().hex,
            tenant_id=tenant_id,
            hostname=hostname or "",
            version=version or "",
            labels=dict(labels or {}),
            status="idle",
            lifecycle_status=LIFECYCLE_ACTIVE,
            provisioning_key_id=provisioning_key_id,
            current_job_id=None,
            detail=_pack_detail(metrics=metrics, capabilities=capabilities),
            registered_at=now,
            last_seen_at=now,
        )
        session.add(row)
        session.flush()
        info = _to_info(row)
    # #327 replaces this with an audit_events row. Until then it is the only
    # record that a key was exchanged for a place in the fleet, which is the
    # event an operator reconstructs an intrusion from.
    _log.info(
        "agent registered agent_id=%s tenant_id=%s hostname=%s version=%s key_id=%s",
        info.agent_id,
        info.tenant_id,
        info.hostname,
        info.version,
        provisioning_key_id or "",
    )
    return info


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
    """One agent, or ``None`` — including when it belongs to another tenant.

    "Exists elsewhere" and "does not exist" are deliberately the same answer
    (#223). Distinguishing them turned this into an existence oracle: a caller
    walking agent ids learned which ones are real in some other tenant, which
    is the only thing the id itself is worth. docs/api-and-rbac.md has promised
    ``404`` for both since the tenancy work landed.
    """
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Agent, agent_id)
        if not row:
            return None
        if tenant_id and row.tenant_id != tenant_id:
            return None
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
        if not _is_online(r.last_seen_at):
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
        min_version=_min_version(),
        total_agents=total,
        online_agents=online,
        busy_agents=busy,
        stale_agents=stale,
        error_agents=error,
        outdated_agents=outdated,
        latest_version=LATEST_AGENT_VERSION,
        by_tenant=by_tenant,
    )


def delete_agent(
    agent_id: str,
    tenant_id: str | None = None,
    *,
    revoke_key: bool = False,
    actor: str = "",
) -> dict[str, Any] | None:
    """Delete the agent, optionally revoking the key it registered with.

    Returns ``None`` when there was nothing to delete — an agent in another
    tenant is reported as absent, for the reason in :func:`get_agent`.

    Deleting the row alone is not a revocation: the host still holds the
    provisioning key it registered with and a valid JWT minted from it, so it
    re-registers on its next poll and the "delete" was a pause (#308).
    ``revoke_key`` is what makes it permanent, and the answer says which of the
    two happened rather than implying the stronger one.

    ``key_revoked`` is ``False`` with ``provisioning_key_id`` ``None`` for an
    agent registered before this column existed, and for a legacy
    shared-token agent: neither has a key on record, and ``OCTO_AGENT_TOKEN``
    is not a per-agent credential this could revoke at all.
    """
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Agent, agent_id)
        if row is None:
            return None
        if tenant_id and row.tenant_id != tenant_id:
            return None
        key_id = row.provisioning_key_id
        agent_tenant_id = row.tenant_id
        session.delete(row)
        session.flush()

    key_revoked = False
    if revoke_key and key_id:
        # After the delete, and in its own session: revoking first would leave
        # a revoked key behind if the delete then failed, and the FK from
        # agents.provisioning_key_id has to be gone before the key row is
        # touched by anything that might remove it later.
        key_revoked = tenants_service.revoke_provisioning_key(key_id) is not None
    # #327 replaces this with an audit_events row.
    _log.info(
        "agent deleted agent_id=%s tenant_id=%s actor=%s key_id=%s key_revoked=%s",
        agent_id,
        agent_tenant_id,
        actor or "unknown",
        key_id or "",
        key_revoked,
    )
    return {
        "agent_id": agent_id,
        "provisioning_key_id": key_id,
        "key_revoked": key_revoked,
    }


def request_upgrade(agent_id: str, tenant_id: str | None = None) -> dict[str, Any]:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Agent, agent_id)
        if row is None or (tenant_id and row.tenant_id != tenant_id):
            # Same LookupError either way — see get_agent on the id oracle.
            raise LookupError("Agent not found")
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

    The container and Kubernetes forms pass the key in the environment and
    invoke ``python -m agent`` with no arguments, so it does not end up in the
    long-lived argv of the agent process, which every local user on that host
    can read. The variable names are the ones ``agent/worker.py`` reads.
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
        f"-e OCTO_API_URL={clean_server} -e OCTO_AGENT_PROVISIONING_KEY={provisioning_key} "
        f"-e OCTO_TENANT_ID={tenant_id} "
        f"ghcr.io/onixus/shapoclyack:latest python -m agent"
    )
    docker_compose = f"""version: '3.8'
services:
  shapoclyack-agent:
    image: ghcr.io/onixus/shapoclyack:latest
    container_name: shapoclyack-agent
    restart: always
    environment:
      - OCTO_API_URL={clean_server}
      - OCTO_AGENT_PROVISIONING_KEY={provisioning_key}
      - OCTO_TENANT_ID={tenant_id}
    command: python -m agent
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
        - name: OCTO_API_URL
          value: "{clean_server}"
        - name: OCTO_AGENT_PROVISIONING_KEY
          value: "{provisioning_key}"
        - name: OCTO_TENANT_ID
          value: "{tenant_id}"
        command: ["python", "-m", "agent"]
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
