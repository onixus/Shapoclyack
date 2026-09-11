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

**The name is normalised once, in :func:`normalize_name`, on every path that
takes one.** Creating a group normalised and reading one did not, so
``POST {"name": "PCI"}`` created ``pci`` and ``DELETE /api/agent-groups/PCI``
answered 404 for a group that was plainly there. Two spellings of one name is
the failure this module exists to prevent, so there is one spelling and every
entry point goes through it.

**References are validated inside the transaction that writes them**, holding
the group rows (:func:`lock_existing_names`). Validating on one connection and
writing on another leaves a window in which a concurrent deletion sees no
reference yet and the reference is committed against a row that is gone — the
same silent widening a cascade would produce, arrived at by a race.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

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


class GroupInUse(ValueError):
    """Deleting the group is refused because something still names it.

    A ValueError like the other refusals this module raises, so a caller that
    does not care why the name was rejected keeps working — but its own class,
    because the delete route answers "still in use" with 409 and a malformed
    name with 422, and without the distinction a mistyped name in the path
    would be reported as a group that is busy.
    """


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
    """One group of this tenant by name, or None. Never crosses a tenant edge.

    ``name`` arrives from a URL path, so it is put through
    :func:`normalize_name` here rather than matched raw: the name an operator
    sent to ``POST /api/agent-groups`` and the name that was stored are not
    necessarily the same string, and looking up the one they typed has to find
    the group they created. A name that cannot be normalised raises ValueError
    — that is a malformed request, not a missing group.
    """
    normalized = normalize_name(name)
    with get_session(settings.postgres_url) as session:
        row = _row_by_name(session, tenant_id=tenant_id, name=normalized)
        return _to_dict(row) if row is not None else None


def _row_by_name(
    session, *, tenant_id: str, name: str, for_update: bool = False
) -> models.AgentGroup | None:
    """The row, optionally held until the caller's transaction ends.

    ``for_update`` is what a writer whose decision depends on the group still
    existing takes — see :func:`lock_existing_names`. A no-op on the SQLite
    fallback, which has no row locks and no second writer either.
    """
    stmt = select(models.AgentGroup).where(
        models.AgentGroup.tenant_id == tenant_id,
        models.AgentGroup.name == name,
    )
    if for_update:
        stmt = stmt.with_for_update()
    return session.execute(stmt).scalars().first()


def lock_existing_names(session, *, tenant_id: str, names: set[str]) -> set[str]:
    """Which of ``names`` the tenant has, holding those rows until commit.

    :func:`existing_names` answers the same question on a connection of its
    own, which is enough to *report* an unknown group and not enough to write
    a reference to a known one: between that read and the write, a concurrent
    ``delete_group`` sees no reference yet, finds no blocker and removes the
    row. The reference then survives pointing at nothing — and because a scope
    entry restricted to a missing group cannot be satisfied by any agent, the
    jobs it covers are queued and never claimed.

    Taking the rows ``FOR UPDATE`` inside the writing transaction serialises
    the two: whichever gets there first makes the other see its result rather
    than the state that preceded it.
    """
    if not names:
        return set()
    return {
        name
        for (name,) in session.execute(
            select(models.AgentGroup.name)
            .where(
                models.AgentGroup.tenant_id == tenant_id,
                models.AgentGroup.name.in_(sorted(names)),
            )
            .with_for_update()
        ).all()
    }


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
        try:
            # The check above is the fast path, not the decision: two operators
            # posting the same name at once both find no row and both insert,
            # and the loser met uq_agent_groups_tenant_name as an unhandled
            # IntegrityError — a 500 for a request whose only fault is that it
            # arrived second. Inside a SAVEPOINT so the failure is scoped to
            # this insert instead of aborting the transaction the audit record
            # is written in.
            with session.begin_nested():
                session.add(row)
                session.flush()
        except IntegrityError as exc:
            raise ValueError(f"agent group already exists: {normalized}") from exc
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
) -> str:
    """Delete one group, or refuse while something still refers to it.

    Returns the name as it was stored, which is what the caller answers with:
    the spelling that came in is not necessarily the one that was there.

    LookupError when there is no such group in this tenant; GroupInUse naming
    what still points at it — agents, pending jobs, schedules, or scope
    entries. See the module docstring for why this is not a cascade.

    ``name`` comes from the URL path and is normalised the way the create path
    normalises it, so ``DELETE /api/agent-groups/PCI`` removes the group that
    ``POST {"name": "PCI"}`` created instead of reporting it missing.

    The row is taken ``FOR UPDATE`` before the blockers are counted: the
    references being counted are written by other transactions, and a
    ``replace_scope`` that has validated its group list but not yet committed
    its entries is invisible to that count. Both sides hold the same row, so
    one of them sees the other's result instead of the state before it.
    """
    normalized = normalize_name(name)
    with get_session(settings.postgres_url) as session:
        row = _row_by_name(
            session, tenant_id=tenant_id, name=normalized, for_update=True
        )
        if row is None:
            raise LookupError(f"agent group not found: {normalized}")

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
        # Read and filtered here rather than with a JSON predicate: ``JSON``
        # rather than ``JSONB`` on the SQLite fallback has no ``->>`` to index
        # anyway, and a tenant has a handful of schedules. A *disabled*
        # schedule counts too — enabling it is one click, and the failure it
        # would come back to is the one below.
        schedules = [
            row_.name
            for row_ in session.execute(
                select(models.ScanSchedule).where(
                    models.ScanSchedule.tenant_id == tenant_id
                )
            )
            .scalars()
            .all()
            if (row_.scan_options or {}).get("agent_group") == row.name
        ]
        if schedules:
            # Nothing else would catch it: the dispatcher builds its
            # StartScanRequest from options stored days ago, start_scan refuses
            # the unknown group with a ValueError, _tick swallows it into
            # stats["errors"] and leaves next_run_at where it was — so the
            # schedule retries and fails every poll, forever, and the only
            # symptom an operator sees is that the nightly scans stopped.
            blockers.append(f"{len(schedules)} schedule(s) dispatch to it")
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
            raise GroupInUse(
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
        return normalized


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


def live_groups(settings: Settings, tenant_ids: set[str]) -> set[tuple[str, str]]:
    """``(tenant_id, group)`` pairs that have an agent able to take a job now.

    The set form of :func:`live_agent_count`, for rendering a page of jobs: the
    queue view asks it once and answers "is anything listening to this job's
    group" for every row, instead of one count query per row. Keyed by tenant
    as well as name because group names are only unique inside a tenant, and
    the cross-tenant job list is one query for all of them.

    Computed where it is read, never stored: a job queued while the group's
    only agent was restarting would otherwise carry "nothing to execute it"
    for the rest of its life, minutes after the agent came back.
    """
    if not tenant_ids:
        return set()
    cutoff = _now() - timedelta(seconds=settings.agent_stale_seconds)
    with get_session(settings.postgres_url) as session:
        return {
            (tenant_id, name)
            for tenant_id, name in session.execute(
                select(models.Agent.tenant_id, models.Agent.agent_group).where(
                    models.Agent.tenant_id.in_(sorted(tenant_ids)),
                    models.Agent.agent_group.is_not(None),
                    models.Agent.lifecycle_status == "active",
                    models.Agent.last_seen_at >= cutoff,
                )
            ).all()
        }


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
    if name is None and required is None:
        # Nothing asked for and nothing required: the pre-#361 scan, and the
        # only path with no group to validate. Answered without a query.
        return None

    known = existing_names(settings, tenant_id)
    if name is not None and name not in known:
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
            only = next(iter(required))
            if only not in known:
                # The scope names a group the tenant no longer has. Queuing the
                # job would be the worst answer available: no agent can be put
                # into a group that does not exist, so nothing would ever claim
                # it and the scan would sit in ``queued`` with no error against
                # it. Refuse it here, where somebody is still looking.
                raise scan_scopes.ScanScopeDenied(
                    f"the approved scan scope of tenant {tenant_id} restricts these "
                    f"targets to agent group {only}, which this tenant no longer "
                    "has: no agent can be put into it, so the scan could never be "
                    "executed. Re-create the group or re-approve the scope.",
                    tenant_id=tenant_id,
                )
            return only
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
