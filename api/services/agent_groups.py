"""Agent groups — which of a tenant's agents may execute which of its jobs (#361).

``claim_job`` filtered by tenant and by "queued", and nothing else. Every agent
of a tenant could therefore take every job of that tenant: a provider running
one agent inside a customer's card-data segment and another in their office
network had no way to say that the card segment's scan must come *from* the
card segment, and no way to keep the office agent from being handed its target
list. Inside one tenant the queue was flat, and the first worker to poll won.

A group is a name inside one tenant (``pci-segment``, ``ops-eu``). Three places
refer to it by that name — the agent it was put on, the job it is addressed to,
and the scope entry that requires it — so the name is the identifier and there
is no rename: renaming would silently re-point a scope entry's restriction, and
the two things an operator does instead (create the new group, move the agents,
delete the old one) are each visible in the audit trail.

**Membership is an operator's decision, never the agent's.** An agent reports
``labels`` at registration and this module does not read them: a worker that
could put itself into a group would be a worker that grants itself the jobs of
a segment it does not sit in, which is the whole of what this control is for.
Assignment goes through ``PUT /api/agents/{agent_id}/group``, gated on
``agent.group.manage``.

**Deleting a group is refused while anything still names it.** There is no
foreign key to do it (the reference is by name, on purpose), and the failure a
cascade would produce is the wrong one: a scope entry restricted to a group
that no longer exists would fall back to "any agent", turning a deletion into a
silent widening of what a low-trust agent may reach.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select

from api.db import models
from api.db.engine import get_session
from api.services import audit as audit_service
from api.services import tenants as tenants_service
from api.settings import Settings

#: Group names are typed by operators, stored in three tables and rendered in
#: the scan form, so they are held to the same shape as a DNS label: lowercase
#: letters, digits and dashes. It keeps a name that differs from another only
#: by case or whitespace from being a second group nobody can tell apart.
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")

#: Job states in which a job still expects to be claimed by an agent. A group
#: that one of these names cannot be deleted — the job would become unclaimable
#: or, worse, claimable by anybody.
_PENDING_JOB_STATES = ("queued", "claimed", "running")


def _now() -> datetime:
    """Naive UTC, matching the other Postgres-backed services."""
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(dt: datetime | None) -> str | None:
    return dt.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z") if dt else None


def _to_dict(row: models.AgentGroup, *, agent_count: int = 0) -> dict[str, Any]:
    return {
        "group_id": row.group_id,
        "tenant_id": row.tenant_id,
        "name": row.name,
        "description": row.description or "",
        "created_at": _iso(row.created_at),
        "created_by": row.created_by,
        "agent_count": agent_count,
    }


def normalize_name(value: str) -> str:
    """One group name as it is stored. Raises ValueError on anything else."""
    name = str(value or "").strip().lower()
    if not _NAME_RE.match(name):
        raise ValueError(
            f"invalid agent group name {value!r}: lowercase letters, digits and "
            "dashes, starting with a letter or digit, at most 63 characters"
        )
    return name


def list_groups(settings: Settings, tenant_id: str) -> list[dict[str, Any]]:
    """Every group of one tenant, by name, each with how many agents are in it.

    The count is what an operator reads before restricting a scope entry to a
    group: a restriction to an empty group is a restriction to nobody.
    """
    with get_session(settings.postgres_url) as session:
        rows = list(
            session.execute(
                select(models.AgentGroup)
                .where(models.AgentGroup.tenant_id == tenant_id)
                .order_by(models.AgentGroup.name)
            )
            .scalars()
            .all()
        )
        counts = dict(
            session.execute(
                select(models.Agent.agent_group, func.count(models.Agent.agent_id))
                .where(
                    models.Agent.tenant_id == tenant_id,
                    models.Agent.agent_group.is_not(None),
                )
                .group_by(models.Agent.agent_group)
            ).all()
        )
        return [_to_dict(row, agent_count=int(counts.get(row.name, 0))) for row in rows]


def get_group(settings: Settings, *, tenant_id: str, name: str) -> dict[str, Any] | None:
    """One group of this tenant by name, or None. Never crosses a tenant edge."""
    with get_session(settings.postgres_url) as session:
        row = _row_by_name(session, tenant_id=tenant_id, name=name)
        return _to_dict(row) if row is not None else None


def _row_by_name(session, *, tenant_id: str, name: str) -> models.AgentGroup | None:
    return (
        session.execute(
            select(models.AgentGroup).where(
                models.AgentGroup.tenant_id == tenant_id,
                models.AgentGroup.name == name,
            )
        )
        .scalars()
        .first()
    )


def existing_names(settings: Settings, tenant_id: str) -> set[str]:
    """The tenant's group names, for validating a reference against them."""
    with get_session(settings.postgres_url) as session:
        return {
            name
            for (name,) in session.execute(
                select(models.AgentGroup.name).where(
                    models.AgentGroup.tenant_id == tenant_id
                )
            ).all()
        }


def create_group(
    settings: Settings,
    *,
    tenant_id: str,
    name: str,
    description: str = "",
    created_by: str | None = None,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any]:
    """Create one group. Raises ValueError for a bad or duplicate name."""
    if tenants_service.get_tenant(tenant_id) is None:
        raise LookupError(f"tenant not found: {tenant_id}")
    normalized = normalize_name(name)

    with get_session(settings.postgres_url) as session:
        if _row_by_name(session, tenant_id=tenant_id, name=normalized) is not None:
            raise ValueError(f"agent group already exists: {normalized}")
        row = models.AgentGroup(
            group_id=f"agp_{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id,
            name=normalized,
            description=str(description or "").strip()[:500],
            created_at=_now(),
            created_by=created_by,
        )
        session.add(row)
        session.flush()
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_AGENT_GROUP_CREATE,
            resource_type="agent_group",
            resource_id=row.group_id,
            tenant_id=tenant_id,
            after={"name": row.name, "description": row.description},
        )
        return _to_dict(row)


def delete_group(
    settings: Settings,
    *,
    tenant_id: str,
    name: str,
    audit: "audit_service.AuditContext | None" = None,
) -> None:
    """Delete one group, or refuse while something still refers to it.

    LookupError when there is no such group in this tenant; ValueError naming
    what still points at it — agents, pending jobs, or scope entries. See the
    module docstring for why this is not a cascade.
    """
    with get_session(settings.postgres_url) as session:
        row = _row_by_name(session, tenant_id=tenant_id, name=name)
        if row is None:
            raise LookupError(f"agent group not found: {name}")

        blockers: list[str] = []
        agents = int(
            session.query(func.count(models.Agent.agent_id))
            .filter(
                models.Agent.tenant_id == tenant_id,
                models.Agent.agent_group == row.name,
            )
            .scalar()
            or 0
        )
        if agents:
            blockers.append(f"{agents} agent(s) are in it")
        jobs = int(
            session.query(func.count(models.Job.job_id))
            .filter(
                models.Job.tenant_id == tenant_id,
                models.Job.agent_group == row.name,
                models.Job.status.in_(_PENDING_JOB_STATES),
            )
            .scalar()
            or 0
        )
        if jobs:
            blockers.append(f"{jobs} unfinished job(s) are addressed to it")
        entries = [
            entry.value
            for entry in session.execute(
                select(models.TenantScanScope).where(
                    models.TenantScanScope.tenant_id == tenant_id
                )
            )
            .scalars()
            .all()
            if row.name in (entry.agent_groups or [])
        ]
        if entries:
            blockers.append(f"{len(entries)} scan-scope entry(ies) require it")
        if blockers:
            raise ValueError(
                f"agent group {row.name} is still in use: {'; '.join(blockers)}"
            )

        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_AGENT_GROUP_DELETE,
            resource_type="agent_group",
            resource_id=row.group_id,
            tenant_id=tenant_id,
            before={"name": row.name, "description": row.description or ""},
        )
        session.delete(row)


def set_agent_group(
    settings: Settings,
    *,
    tenant_id: str,
    agent_id: str,
    name: str | None,
    audit: "audit_service.AuditContext | None" = None,
) -> str | None:
    """Put an agent into ``name``, or take it out of every group with None.

    Returns the stored group name. LookupError for an unknown agent or group,
    PermissionError when the agent belongs to another tenant — the same shape
    the rest of the agent service raises, so the routes translate it the way
    they already do.

    A job the agent is *currently* holding is left alone: it was claimed under
    the membership that applied when it was handed out, and taking it back here
    would abandon a scan that is already running on the customer's network. The
    move takes effect on the next claim.
    """
    normalized = normalize_name(name) if name else None
    with get_session(settings.postgres_url) as session:
        agent = session.get(models.Agent, agent_id)
        if agent is None:
            raise LookupError(f"agent not found: {agent_id}")
        if (agent.tenant_id or tenants_service.DEFAULT_TENANT_ID) != tenant_id:
            raise PermissionError("Cross-tenant agent access denied")
        if normalized is not None and _row_by_name(
            session, tenant_id=tenant_id, name=normalized
        ) is None:
            raise LookupError(f"agent group not found: {normalized}")

        before = agent.agent_group
        agent.agent_group = normalized
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_AGENT_GROUP_ASSIGN,
            resource_type="agent",
            resource_id=agent_id,
            tenant_id=tenant_id,
            before={"agent_group": before},
            after={"agent_group": normalized},
        )
        return normalized


def live_agent_count(settings: Settings, *, tenant_id: str, name: str) -> int:
    """Agents of ``name`` that could actually take a job right now.

    "Could" is deliberately generous: active lifecycle and a heartbeat inside
    ``OCTO_AGENT_STALE_SECONDS``. It is used to *warn* at scan start, not to
    refuse — an agent that is restarting comes back in seconds, and a scan
    refused because nobody was polling at that instant would be a worse failure
    than one that waits. See ``jobs.start_scan``.
    """
    cutoff = _now() - timedelta(seconds=settings.agent_stale_seconds)
    with get_session(settings.postgres_url) as session:
        return int(
            session.query(func.count(models.Agent.agent_id))
            .filter(
                models.Agent.tenant_id == tenant_id,
                models.Agent.agent_group == name,
                models.Agent.lifecycle_status == "active",
                models.Agent.last_seen_at >= cutoff,
            )
            .scalar()
            or 0
        )


def resolve_for_scan(
    settings: Settings,
    *,
    tenant_id: str,
    requested: str | None,
    required: frozenset[str] | None,
) -> str | None:
    """The group a scan must be executed by, from the request and the scope.

    ``requested`` is what the operator (or a schedule) asked for and is never
    taken on trust: it has to be a group of *this* tenant, and it has to be one
    the approved scope permits for these targets. ``required`` is what
    :func:`api.services.scan_scopes.required_agent_groups` derived from the
    scope entries covering the targets — ``None`` when no entry restricts them,
    which is every scope written before #361.

    Returns the group name to store on the job, or None for "any agent of the
    tenant" — the pre-#361 behaviour, and still the common case.

    Raises ValueError when the request names a group that does not exist or
    leaves an ambiguous restriction unresolved, and ScanScopeDenied (a
    PermissionError, answered 403) when the scope does not permit the group
    asked for. The distinction matters to the caller: one is a malformed
    request, the other is a refusal that belongs in the access journal.
    """
    # Imported here rather than at module scope: scan_scopes imports nothing
    # from this module, and keeping it that way is what makes the cycle
    # impossible rather than merely absent today.
    from api.services import scan_scopes

    name = normalize_name(requested) if requested else None
    if name is not None and name not in existing_names(settings, tenant_id):
        raise ValueError(f"Unknown agent_group for tenant {tenant_id}: {name}")

    if required is None:
        return name

    if not required:
        raise scan_scopes.ScanScopeDenied(
            f"the approved scan scope of tenant {tenant_id} restricts these targets "
            "to agent groups that have nothing in common: no single agent may scan "
            "them together, so they have to be split into separate scans",
            tenant_id=tenant_id,
        )
    if name is None:
        if len(required) == 1:
            # One permitted group and nobody chose otherwise: the scope has
            # already made the decision, and asking the operator to retype it
            # would only create a way to get it wrong.
            return next(iter(required))
        raise ValueError(
            "these targets are restricted by the approved scan scope to agent "
            f"groups {', '.join(sorted(required))}; name one in agent_group"
        )
    if name not in required:
        raise scan_scopes.ScanScopeDenied(
            f"agent group {name} is not permitted by the approved scan scope of "
            f"tenant {tenant_id} for these targets (permitted: "
            f"{', '.join(sorted(required))})",
            tenant_id=tenant_id,
        )
    return name


def reset_for_tests(settings: Settings) -> None:
    """Clear every tenant's groups (test isolation only)."""
    with get_session(settings.postgres_url) as session:
        session.query(models.AgentGroup).delete()
