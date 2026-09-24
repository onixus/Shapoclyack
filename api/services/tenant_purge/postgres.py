"""The Postgres half of a tenant purge (#325): which tables hold a tenant, in
what order they are emptied, and the transaction that deletes the tenant itself.

**Every table is named.** :data:`POSTGRES_TABLES` lists each table the tenant
has rows in, children before parents, and ``tests/test_tenant_purge.py`` walks
the live schema to prove the list is complete: a table that gains a
``tenant_id`` column — or a foreign key to one that has it — and is not listed
here, in :data:`OUTBOX_TABLES`, :data:`FINALIZE_TABLES` or :data:`RETAINED`
fails that test. The foreign keys would cascade most of it from the tenant row
anyway; they are not relied on, because one ``DELETE FROM tenants`` cascading
a million findings is exactly the long lock the purge exists to avoid.

**Batched.** Each ``DELETE`` removes at most ``OCTO_TENANT_PURGE_BATCH_SIZE``
rows by primary key, inside :meth:`PurgeContext.guard` — so every batch holds
the tenant row lock only for itself, re-checks the legal hold, and counts what
it removed in the same transaction that removed it.

**What stays.** ``audit_events`` is append-only (#329) and outlives the tenant
on purpose: the record of what was done in a tenant matters most after the
tenant is gone. Its rows are pruned by the audit retention job like any other
tenant's — the default window, since the tenant's own policy row goes with the
tenant (``audit_events_prune``, migration 0065). The deletion journal is kept
because it is the proof.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, func, select, tuple_
from sqlalchemy.orm import Session

from api.db import models
from api.services import audit as audit_service
from api.services import job_states
from api.services import legal_hold
from api.services import sessions as sessions_service
from api.services import tenant_lifecycle as lifecycle
from api.services import tenants as tenants_service
from api.services.tenant_purge.context import (
    PurgeContext,
    RerunSteps,
    StepWaiting,
    iso,
    now,
    system_session,
)

#: Rows owed a publication to NATS: removed before the JetStream step, so the
#: outbox relay cannot republish into subjects that were just purged.
OUTBOX_TABLES = ("nats_outbox", "run_publications")

#: Everything else the tenant owns, children before parents. Where a child
#: cascades from its parent it is still listed, and first: the cascade would
#: work, in one statement the size of the tenant.
POSTGRES_TABLES = (
    # Findings and their history.
    "vulnerability_events",
    "software_cve_matches",
    "vulnerabilities",
    # Endpoint inventory: items and changes before snapshots, all before devices.
    "endpoint_software_items",
    "endpoint_software_changes",
    "endpoint_inventory_snapshots",
    "endpoint_identifiers",
    "endpoint_devices",
    # Assets: asset_tags and asset_identifiers are NO ACTION keys to assets.
    "asset_context_events",
    "asset_tags",
    "asset_identifiers",
    "asset_services",
    "asset_os",
    "asset_identity_links",
    "assets",
    # Integrations.
    "webhook_deliveries",
    "webhook_subscriptions",
    "notification_channels",
    # Reports; the objects themselves went in the artifact step.
    "report_schedules",
    "generated_reports",
    "report_templates",
    # The fleet: agents are a NO ACTION key to provisioning_keys, below.
    "agent_deployments",
    "agent_ssh_host_keys",
    "agents",
    "agent_groups",
    # Scans.
    "jobs",
    "scan_schedules",
    "maintenance_windows",
    "risk_score_snapshots",
    "workflow_event_markers",
    "idempotency_records",
    "retro_match_state",
    # Configuration the tenant wrote.
    "wordlists",
    "sla_policies",
    "sla_escalation_policies",
    "endpoint_agent_policies",
    "tenant_scan_scopes",
    "tenant_scan_policies",
    "tenant_promoted_domains",
    "tenant_branding",
    "tenant_quotas",
    "tenant_retention_policies",
    # Custom roles, keyed by the tenant id (built-ins are keyed by '').
    "role_permissions",
    "roles",
    # Credentials last among the tenant's rows: already revoked, kept until now
    # so that nothing above could be re-created through them.
    "service_tokens",
    "provisioning_keys",
)

#: Deleted by :func:`finalize`, in the transaction that completes the deletion.
FINALIZE_TABLES = ("user_tenants", "tenants")

#: Tables that name a tenant and are deliberately not purged, with the reason.
RETAINED: dict[str, str] = {
    "audit_events": "append-only (#329); aged out by the audit retention window, never purged",
    "tenant_deletions": "the deletion journal: the tombstone that proves the purge",
    "tenant_deletion_steps": "the journal's per-store progress",
    "tenant_legal_holds": "must be empty for a purge to run; its RESTRICT key is the backstop",
}

#: Tables with no ``tenant_id`` of their own, and the parent that has one:
#: ``(own column, parent table, parent column)``.
_VIA: dict[str, tuple[str, str, str]] = {
    "asset_tags": ("asset_id", "assets", "asset_id"),
}


def _table(name: str):
    return models.Base.metadata.tables[name]


def _predicate(name: str, tenant_id: str, table=None):
    table = _table(name) if table is None else table
    via = _VIA.get(name)
    if via is not None:
        column, parent_name, parent_column = via
        parent = _table(parent_name)
        return table.c[column].in_(
            select(parent.c[parent_column]).where(parent.c.tenant_id == tenant_id)
        )
    return table.c.tenant_id == tenant_id


def delete_batch(session: Session, name: str, tenant_id: str, limit: int) -> int:
    """Delete up to ``limit`` of the tenant's rows from ``name``, by primary key."""
    table = _table(name)
    # The batch is chosen from an alias of the table: a subquery over the very
    # table the DELETE names would otherwise be correlated to it, and select
    # from nothing.
    inner = table.alias(f"purge_{name}")
    names = [column.name for column in table.primary_key.columns]
    chosen = (
        select(*(inner.c[column] for column in names))
        .where(_predicate(name, tenant_id, inner))
        .limit(limit)
    )
    keys = [table.c[column] for column in names]
    target = keys[0] if len(keys) == 1 else tuple_(*keys)
    result = session.execute(delete(table).where(target.in_(chosen)))
    return int(result.rowcount or 0)


def remaining(session: Session, names: tuple[str, ...], tenant_id: str) -> dict[str, int]:
    """``{table: rows}`` for every table in ``names`` that still holds the tenant."""
    left: dict[str, int] = {}
    for name in names:
        count = session.execute(
            select(func.count()).select_from(_table(name)).where(_predicate(name, tenant_id))
        ).scalar_one()
        if count:
            left[name] = int(count)
    return left


def purge_tables(ctx: PurgeContext, names: tuple[str, ...]) -> dict[str, int]:
    """Empty ``names`` of the tenant, batch by batch, each batch under the guard.

    Counts are recorded by each batch as it commits, so a crash loses nothing
    that was deleted; the return value only fills in the tables that held no
    rows, so the tombstone lists every table it looked at.
    """
    batch = max(1, int(ctx.settings.tenant_purge_batch_size))
    for name in names:
        while True:
            with ctx.guard() as session:
                removed = delete_batch(session, name, ctx.tenant_id, batch)
                if removed:
                    ctx.add_counts(session, {name: removed})
            if removed < batch:
                break
    with ctx.guard() as session:
        left = remaining(session, names, ctx.tenant_id)
        if left:
            # A writer that did not see the status got a row in after its
            # table was emptied. The next attempt deletes it.
            raise RuntimeError(f"rows remain after the purge: {left}")
        ctx.add_counts(session, {name: 0 for name in names})
    return {}


# -- the steps -------------------------------------------------------------------


def quiesce(ctx: PurgeContext) -> dict[str, Any]:
    """Wait until no job of the tenant can still write for it.

    A local scan cannot be stopped (``job_control.cancel_job``), and one that is
    running writes its run directory and its findings when it finishes; a job
    an agent was told to stop is closed by the grace-period reaper. The purge
    starts after both. A queued job left by a race with the suspension is
    cancelled here — no agent of a closed tenant can claim it.
    """
    with ctx.guard() as session:
        cancelled, stopping, _local = lifecycle.stop_jobs(
            session, ctx.tenant_id, actor="tenant-purge", why="being deleted"
        )
        active = session.execute(
            select(models.Job.job_id)
            .where(
                models.Job.tenant_id == ctx.tenant_id,
                models.Job.status.in_(job_states.ACTIVE),
            )
            .order_by(models.Job.job_id)
        ).scalars().all()
    if active:
        shown = ", ".join(active[:5]) + (" …" if len(active) > 5 else "")
        raise StepWaiting(
            f"waiting for {len(active)} job(s) to reach a final state: {shown}"
        )
    return {"jobs_cancelled": len(cancelled), "jobs_stopped": len(stopping)}


def outbox(ctx: PurgeContext) -> dict[str, Any]:
    return purge_tables(ctx, OUTBOX_TABLES)


def postgres(ctx: PurgeContext) -> dict[str, Any]:
    return purge_tables(ctx, POSTGRES_TABLES)


def _stranded_accounts(session: Session, tenant_id: str) -> list[str]:
    """Accounts whose only membership is this tenant, platform admins aside.

    Once their membership row is gone they have none, and an account with no
    memberships acts in ``default`` with its global role
    (``memberships.resolve_tenant``) — a purge that left them enabled would
    hand a deleted customer's users the platform's own tenant.
    """
    elsewhere = select(models.UserTenant.username).where(
        models.UserTenant.tenant_id != tenant_id
    )
    return list(
        session.execute(
            select(models.User.username)
            .join(models.UserTenant, models.UserTenant.username == models.User.username)
            .where(
                models.UserTenant.tenant_id == tenant_id,
                models.User.role != "admin",
                models.User.username.not_in(elsewhere),
            )
            .order_by(models.User.username)
        ).scalars()
    )


def _tombstone(session: Session, deletion: models.TenantDeletion) -> dict[str, Any]:
    """What the purge removed, store by store. Counts and ids of the platform's
    own records only: no names, no usernames, nothing the tenant wrote."""
    stores: dict[str, Any] = {}
    skipped: dict[str, str] = {}
    for step in session.execute(
        select(models.TenantDeletionStep)
        .where(models.TenantDeletionStep.deletion_id == deletion.deletion_id)
        .order_by(models.TenantDeletionStep.position)
    ).scalars():
        if step.step == "finalize":
            continue
        if step.state == lifecycle.STEP_SKIPPED:
            skipped[step.step] = step.last_error or "not configured"
            continue
        stores[step.step] = dict(step.counts or {})
    return {
        "tenant_id": deletion.tenant_id,
        "deletion_id": deletion.deletion_id,
        "requested_at": iso(deletion.requested_at),
        "approved_at": iso(deletion.approved_at),
        "stores": stores,
        "skipped": skipped,
        "retained": dict(RETAINED),
    }


def finalize(ctx: PurgeContext) -> dict[str, Any]:
    """Delete the tenant row and write the tombstone, in one transaction.

    The last check before it is the proof: every table the plan names is
    counted, and a row a late writer slipped in sends the Postgres steps round
    again rather than letting ``DELETE FROM tenants`` cascade it silently.
    """
    moment = now()
    with system_session(ctx.settings) as session:
        tenant = session.execute(
            select(models.Tenant)
            .where(models.Tenant.tenant_id == ctx.tenant_id)
            .with_for_update()
        ).scalar_one_or_none()
        ctx.renew(session)
        disabled: list[str] = []
        memberships = 0
        if tenant is not None:
            legal_hold.assert_not_on_hold(session, ctx.tenant_id, action="tenant.delete")
            left = remaining(session, OUTBOX_TABLES + POSTGRES_TABLES, ctx.tenant_id)
            if left:
                # Every store step, not only the Postgres ones: whatever wrote
                # the row (a job that finished late, an ingest) may have left
                # objects, analytics and subjects behind it too.
                raise RerunSteps(
                    ("quiesce", "outbox", "jetstream", "artifacts", "clickhouse", "postgres"),
                    f"rows written after their table was purged: {left}",
                )
            disabled = _stranded_accounts(session, ctx.tenant_id)
            for username in disabled:
                account = session.get(models.User, username)
                if account is not None and account.disabled_at is None:
                    account.disabled_at = moment
                sessions_service.revoke_all_in_session(
                    session, username, reason=sessions_service.END_TENANT_CLOSED
                )
            memberships = int(
                session.execute(
                    delete(models.UserTenant).where(models.UserTenant.tenant_id == ctx.tenant_id)
                ).rowcount
                or 0
            )
            # The RESTRICT key from tenant_legal_holds fires here if anything
            # above was talked past: the backstop, not the check.
            session.delete(tenant)
            session.flush()

        deletion = session.get(models.TenantDeletion, ctx.deletion_id, with_for_update=True)
        assert deletion is not None
        step = session.get(models.TenantDeletionStep, (ctx.deletion_id, "finalize"))
        counts = {"memberships": memberships, "accounts_disabled": len(disabled)}
        if step is not None:
            step.state = lifecycle.STEP_DONE
            step.finished_at = moment
            step.last_error = None
            step.counts = counts
        session.flush()
        tombstone = _tombstone(session, deletion)
        tombstone["stores"]["finalize"] = counts
        tombstone["completed_at"] = iso(moment)
        deletion.state = lifecycle.STATE_COMPLETED
        deletion.completed_at = moment
        deletion.outcome = tombstone
        deletion.last_error = None
        deletion.next_attempt_at = None
        deletion.lease_owner = None
        deletion.lease_until = None
        audit_service.record(
            session,
            audit_service.system_context("tenant-purge"),
            action=audit_service.ACTION_TENANT_DELETE_COMPLETE,
            resource_type="tenant",
            resource_id=ctx.tenant_id,
            before={"status": tenants_service.STATUS_DELETING},
            after={**tombstone, "accounts_disabled": disabled},
        )
    return counts
