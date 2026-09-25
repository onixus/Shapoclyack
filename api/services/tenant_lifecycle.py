"""Suspending, resuming and deleting a tenant (#325).

A tenant moves through four statuses, and only the first passes any gate
(:func:`api.services.tenants.check_active`)::

    active ──suspend──▶ suspended ──resume──▶ active
      │                    │
      └──request deletion──┴──▶ pending_deletion ──approve──▶ deleting ──▶ (gone)
                                   │
                                   └──cancel──▶ suspended

**Suspension cuts every path the tenant had in**, in the transaction that
changes its status, rather than leaving each one to notice on its own:

* console sessions of the accounts that can act in no *other* active tenant are
  ended (``token_version`` bumped, session families revoked) — an MSSP analyst
  who serves twenty customers is not signed out of nineteen because one was
  suspended; the per-request gate refuses them this tenant instead;
* the tenant's service tokens and provisioning keys are revoked — unless the
  platform admin asks to keep them for the resume, in which case they stay
  refused by the status gate on every request (service tokens:
  ``api.auth.resolve_tenant_principal``; agent JWTs: ``agents.check_credential``;
  key exchange: ``tenants.resolve_provisioning_key``);
* queued jobs are cancelled — nothing may claim them, and a resumed tenant
  should not find last month's scans starting. Jobs an agent is running go to
  ``cancelling`` through #360's channel, so the lease reaper cannot hand them to
  another agent and the grace-period reaper closes them. The sensor itself
  cannot be told: its heartbeat is refused with everything else it sends, so a
  scan already running on it finishes locally and its upload is refused. A
  *local* scan cannot be stopped at all (``job_control.cancel_job``) and runs to
  its end; the deletion's first step waits for it;
* scan and report schedules, SLA escalation, ticket sync, webhook deliveries,
  notification channels and the retro/software matchers skip every tenant that
  is not active (``tenants.active_tenant_ids``). Nothing is disabled row by row,
  so resuming restores exactly what the tenant had switched on.

**Resuming** restores what the status paused and nothing that was revoked:
credentials revoked at suspension stay revoked, because a key that left the
platform's control while the customer was suspended is not one to trust again
by flipping a status back. Overdue schedules are moved to their next occurrence
rather than all firing at once.

**Deletion is two steps and two people** (``OCTO_TENANT_DELETION_TWO_PERSON``,
#348's rule): a request, which suspends the tenant and starts a grace period
(``OCTO_TENANT_DELETION_GRACE_DAYS``) during which it can be cancelled with
nothing lost, and an approval after it, which marks the tenant ``deleting`` and
hands it to the purge worker (:mod:`api.services.tenant_purge`). Both take the
typed tenant id as confirmation. A tenant on legal hold cannot be requested for
deletion or approved for purge (``legal_hold.assert_not_on_hold``, under the
tenant row lock ``place_hold`` also takes); a hold placed *during* a purge stops
it at the next batch, and the journal says ``blocked`` until somebody retries
after the hold is released. The ``default`` tenant can be neither suspended nor
deleted: it is where accounts without a membership and legacy shared-token
agents act.

Every decision is one platform-level audit row (``tenant_id`` NULL,
``resource_id`` the tenant), like the legal hold's: why a customer was
suspended is the platform's record, and a deleted tenant has no trail of its
own left to put it in.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db import models
from api.db.engine import get_session
from api.services import audit as audit_service
from api.services import job_states
from api.services import job_store
from api.services import legal_hold
from api.services import metrics as metrics_service
from api.services import scan_schedules
from api.services import sessions as sessions_service
from api.services import tenants as tenants_service
from api.services.reports import store as report_store
# #348's comparison, imported rather than copied: the two-person rule for a
# purge and for a risk acceptance must not drift apart on what "the same
# person" means (case- and whitespace-insensitive).
from api.services.vulnerabilities import _same_person
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.tenant-lifecycle")

#: Long enough for a ticket number and a sentence, like a legal hold's.
MAX_REASON_LENGTH = 1000

# Deletion journal states (``tenant_deletions.state``, migration 0066).
STATE_PENDING = "pending"
STATE_CANCELLED = "cancelled"
STATE_PURGING = "purging"
STATE_BLOCKED = "blocked"
STATE_COMPLETED = "completed"
#: A deletion still in these has not reached an outcome. Mirrored by the partial
#: unique index in migration 0066: one open deletion per tenant.
OPEN_STATES = (STATE_PENDING, STATE_PURGING, STATE_BLOCKED)

#: The stores the purge walks, in order (:mod:`api.services.tenant_purge`). The
#: order is load-bearing: the job inputs and report objects are found through
#: the Postgres rows, so the artifact step runs before the Postgres step; the
#: outbox rows go before JetStream so the relay cannot publish into a stream
#: that was just purged; ``finalize`` deletes the tenant row last.
STEPS = ("quiesce", "outbox", "jetstream", "artifacts", "clickhouse", "postgres", "finalize")

# Step states (``tenant_deletion_steps.state``).
STEP_PENDING = "pending"
STEP_RUNNING = "running"
STEP_WAITING = "waiting"
STEP_FAILED = "failed"
STEP_DONE = "done"
STEP_SKIPPED = "skipped"

#: How many ids of each kind an audit row lists. The audit document is capped
#: at 16 KiB (``audit._MAX_DOCUMENT_BYTES``); a tenant with ten thousand queued
#: jobs should still get a row that says what was cut, not a truncation marker.
_AUDIT_SAMPLE = 50


class LifecycleConflict(RuntimeError):
    """The tenant is not in a state this act applies to. Routes answer 409."""


class SecondApproverRequired(PermissionError):
    """The approver is the requester and the installation requires two people.

    A ``PermissionError`` like #348's self-approval refusal, and answered 403
    like it: the act is well formed, this caller may not perform it.
    """


def _now() -> datetime:
    # Naive UTC, like every timestamp column in this schema.
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


def _reason(value: str | None) -> str:
    cleaned = " ".join(str(value or "").split())
    if not cleaned:
        raise ValueError("a reason is required")
    if len(cleaned) > MAX_REASON_LENGTH:
        raise ValueError(f"reason must be at most {MAX_REASON_LENGTH} characters")
    return cleaned


def _refuse_default(tenant_id: str) -> None:
    if tenant_id == tenants_service.DEFAULT_TENANT_ID:
        raise LifecycleConflict(
            "the default tenant cannot be suspended or deleted: accounts without a "
            "membership and legacy shared-token agents act in it"
        )


def _lock_tenant(session: Session, tenant_id: str) -> models.Tenant:
    """``SELECT … FOR UPDATE`` on the tenant row — the lock ``place_hold`` takes.

    Every change of status goes through it, so a legal hold and a deletion of
    the same tenant are serialised rather than interleaved
    (``legal_hold`` module docstring, step 1).
    """
    tenant = session.execute(
        select(models.Tenant).where(models.Tenant.tenant_id == tenant_id).with_for_update()
    ).scalar_one_or_none()
    if tenant is None:
        raise LookupError(f"tenant not found: {tenant_id}")
    return tenant


def _set_status(tenant: models.Tenant, status: str, *, reason: str | None, actor: str) -> None:
    moment = _now()
    if status == tenants_service.STATUS_ACTIVE:
        tenant.closed_at = None
    elif tenant.status == tenants_service.STATUS_ACTIVE or tenant.closed_at is None:
        # Leaving ``active``; a move between two closed states keeps the time
        # it closed. Set before the closure revokes anything, so what it revokes
        # carries ``revoked_at >= closed_at`` (agents.check_credential).
        tenant.closed_at = moment
    tenant.status = status
    tenant.status_reason = reason
    tenant.status_changed_at = moment
    tenant.status_changed_by = actor


def _sample(ids: list[str]) -> dict[str, Any]:
    return {"count": len(ids), "ids": sorted(ids)[:_AUDIT_SAMPLE]}


# -- cutting the tenant off ---------------------------------------------------


def _stranded_members(session: Session, tenant_id: str) -> list[str]:
    """Accounts that can act in no active tenant once this one has closed.

    Called after the tenant's status has been changed in this session, so
    "active" already excludes it. Platform admins are never stranded — they act
    everywhere — and an account with memberships in another active tenant keeps
    its session: the per-request gate refuses it this tenant, and signing it out
    of the others would punish the other customers for this one.
    """
    elsewhere = (
        select(models.UserTenant.username)
        .join(models.Tenant, models.Tenant.tenant_id == models.UserTenant.tenant_id)
        .where(
            models.UserTenant.tenant_id != tenant_id,
            models.Tenant.status == tenants_service.STATUS_ACTIVE,
        )
    )
    return list(
        session.execute(
            select(models.UserTenant.username)
            .join(models.User, models.User.username == models.UserTenant.username)
            .where(
                models.UserTenant.tenant_id == tenant_id,
                models.User.role != "admin",
                models.UserTenant.username.not_in(elsewhere),
            )
            .order_by(models.UserTenant.username)
        ).scalars()
    )


def _cut_access(
    session: Session,
    tenant_id: str,
    *,
    revoke_credentials: bool,
    actor: str,
    why: str,
) -> dict[str, Any]:
    """End every way into ``tenant_id`` that outlives a status check.

    In the caller's transaction, after the status change has been flushed: the
    suspension and its consequences commit together or not at all. Returns
    what was cut, for the audit row and the response.
    """
    now = _now()
    stranded = _stranded_members(session, tenant_id)
    for username in stranded:
        sessions_service.revoke_all_in_session(
            session, username, reason=sessions_service.END_TENANT_CLOSED
        )

    tokens: list[str] = []
    keys: list[str] = []
    if revoke_credentials:
        tokens, keys = _revoke_credentials(session, tenant_id, now=now)

    cancelled, stopping, local_running = stop_jobs(session, tenant_id, actor=actor, why=why)
    return {
        "sessions_ended": _sample(stranded),
        "service_tokens_revoked": _sample(tokens),
        "provisioning_keys_revoked": _sample(keys),
        "jobs_cancelled": _sample(cancelled),
        "jobs_stopping": _sample(stopping),
        "local_jobs_running": _sample(local_running),
    }


def _revoke_credentials(
    session: Session, tenant_id: str, *, now: datetime
) -> tuple[list[str], list[str]]:
    """Revoke the tenant's live service tokens and provisioning keys; return their ids."""
    tokens: list[str] = []
    keys: list[str] = []
    for token in session.execute(
        select(models.ServiceToken).where(
            models.ServiceToken.tenant_id == tenant_id,
            models.ServiceToken.revoked_at.is_(None),
        )
    ).scalars():
        token.revoked_at = now
        tokens.append(token.token_id)
    for key in session.execute(
        select(models.ProvisioningKey).where(
            models.ProvisioningKey.tenant_id == tenant_id,
            models.ProvisioningKey.revoked_at.is_(None),
        )
    ).scalars():
        key.revoked_at = now
        keys.append(key.key_id)
    session.flush()
    return tokens, keys


def stop_jobs(
    session: Session, tenant_id: str, *, actor: str, why: str
) -> tuple[list[str], list[str], list[str]]:
    """Cancel the tenant's queued jobs and ask its agents to put running ones down.

    Returns ``(cancelled, stopping, local_running)``. Also the purge's first
    step, which runs it again: a scan admitted in the instant before the
    suspension committed would otherwise sit ``queued`` for ever, since no
    agent of a closed tenant can claim it.

    Queued first, then in flight: an agent claiming at this moment holds the
    row with FOR UPDATE SKIP LOCKED, this waits for it, and Postgres then
    re-reads the row — a job claimed a millisecond ago no longer matches
    ``queued`` here and is caught by the second query instead.
    """
    now = _now()
    cancelled: list[str] = []
    for job in session.execute(
        select(models.Job)
        .where(models.Job.tenant_id == tenant_id, models.Job.status == job_states.QUEUED)
        .with_for_update()
    ).scalars():
        job_states.check_transition(job.job_id, job.status, job_states.CANCELLED)
        job.status = job_states.CANCELLED
        job.finished_at = now
        job.claimed_until = None
        job.error = f"Cancelled: tenant {tenant_id} {why} by {actor}"[:2000]
        cancelled.append(job.job_id)
    stopping: list[str] = []
    local_running: list[str] = []
    for job in session.execute(
        select(models.Job)
        .where(
            models.Job.tenant_id == tenant_id,
            models.Job.status.in_(job_states.IN_FLIGHT),
        )
        .with_for_update()
    ).scalars():
        if job.execution != "agent":
            # job_control.cancel_job's rule: the scanner is a subprocess of
            # one replica's thread, and no other replica can signal it.
            local_running.append(job.job_id)
            continue
        job_states.check_transition(job.job_id, job.status, job_states.CANCELLING)
        job.status = job_states.CANCELLING
        job.cancel_requested_at = now
        job.claimed_until = None
        job.error = f"Cancellation requested: tenant {tenant_id} {why} by {actor}"[:2000]
        stopping.append(job.job_id)
    if cancelled:
        metrics_service.JOB_CANCELLATIONS_TOTAL.labels(outcome="queued").inc(len(cancelled))
    session.flush()
    return cancelled, stopping, local_running


# -- suspension ----------------------------------------------------------------


def suspend(
    settings: Settings,
    tenant_id: str,
    *,
    reason: str,
    actor: str,
    revoke_credentials: bool = True,
    audit: audit_service.AuditContext | None = None,
) -> dict[str, Any]:
    """Suspend an active tenant and cut its access paths. See the module docstring.

    Suspending a tenant that is already suspended changes nothing and records
    nothing — a retried request is not a second decision — with one exception:
    a suspension that kept the credentials, followed by one that asks for them
    to go, revokes them. That is the ordinary way a short suspension becomes a
    long one ("the keys leaked after all"), and answering it with a 200 that
    revoked nothing would leave them working again after the resume. Raises
    LookupError, ValueError (no reason) and :class:`LifecycleConflict` (the
    default tenant, or one pending deletion).
    """
    cleaned = _reason(reason)
    _refuse_default(tenant_id)
    with get_session(settings.postgres_url) as session:
        tenant = _lock_tenant(session, tenant_id)
        if tenant.status == tenants_service.STATUS_SUSPENDED:
            described = _describe_in(settings, session, tenant_id)
            if not revoke_credentials:
                return described
            tokens, keys = _revoke_credentials(session, tenant_id, now=_now())
            if not tokens and not keys:
                return described
            revoked = {
                "service_tokens_revoked": _sample(tokens),
                "provisioning_keys_revoked": _sample(keys),
            }
            audit_service.record(
                session,
                audit,
                action=audit_service.ACTION_TENANT_SUSPEND,
                resource_type="tenant",
                resource_id=tenant_id,
                before={"status": tenants_service.STATUS_SUSPENDED},
                after={
                    "status": tenants_service.STATUS_SUSPENDED,
                    "reason": cleaned,
                    "revoke_credentials": True,
                    **revoked,
                },
            )
            described["cut"] = revoked
            LOG.warning("Credentials of suspended tenant %s revoked by %s", tenant_id, actor)
            return described
        if tenant.status != tenants_service.STATUS_ACTIVE:
            raise LifecycleConflict(f"tenant {tenant_id} is {tenant.status}")
        before = {"status": tenant.status}
        _set_status(tenant, tenants_service.STATUS_SUSPENDED, reason=cleaned, actor=actor)
        session.flush()
        cut = _cut_access(
            session,
            tenant_id,
            revoke_credentials=revoke_credentials,
            actor=actor,
            why="suspended",
        )
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_TENANT_SUSPEND,
            resource_type="tenant",
            resource_id=tenant_id,
            before=before,
            after={
                "status": tenants_service.STATUS_SUSPENDED,
                "reason": cleaned,
                "revoke_credentials": revoke_credentials,
                **cut,
            },
        )
        described = _describe_in(settings, session, tenant_id)
        described["cut"] = cut
    job_store.refresh_job_gauges(settings)
    LOG.warning("Tenant %s suspended by %s", tenant_id, actor)
    return described


def resume(
    settings: Settings,
    tenant_id: str,
    *,
    actor: str,
    audit: audit_service.AuditContext | None = None,
) -> dict[str, Any]:
    """Put a suspended tenant back into service.

    Restores what the status paused — schedules, workers, the tenant's people
    and its agents' *unrevoked* credentials — and moves overdue schedules to
    their next occurrence. Revoked credentials stay revoked: mint new
    provisioning keys and service tokens. Resuming an active tenant changes
    nothing. A tenant pending deletion is resumed by cancelling the deletion
    first; one being purged cannot be resumed at all.
    """
    now = _now()
    with get_session(settings.postgres_url) as session:
        tenant = _lock_tenant(session, tenant_id)
        if tenant.status == tenants_service.STATUS_ACTIVE:
            return _describe_in(settings, session, tenant_id)
        if tenant.status == tenants_service.STATUS_PENDING_DELETION:
            raise LifecycleConflict(
                f"tenant {tenant_id} is pending deletion; cancel the deletion first"
            )
        if tenant.status != tenants_service.STATUS_SUSPENDED:
            raise LifecycleConflict(f"tenant {tenant_id} is {tenant.status} and cannot be resumed")
        before = {"status": tenant.status, "reason": tenant.status_reason}
        _set_status(tenant, tenants_service.STATUS_ACTIVE, reason=None, actor=actor)
        # The schedulers compare against aware UTC; the columns are naive and
        # the database reads both as UTC.
        aware_now = now.replace(tzinfo=UTC)
        scans = scan_schedules.reanchor_overdue(session, tenant_id, now=aware_now)
        reports = report_store.reanchor_overdue(session, tenant_id, now=aware_now)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_TENANT_RESUME,
            resource_type="tenant",
            resource_id=tenant_id,
            before=before,
            after={
                "status": tenants_service.STATUS_ACTIVE,
                "scan_schedules_reanchored": scans,
                "report_schedules_reanchored": reports,
            },
        )
        described = _describe_in(settings, session, tenant_id)
    LOG.warning("Tenant %s resumed by %s", tenant_id, actor)
    return described


# -- deletion ------------------------------------------------------------------


def _open_deletion(
    session: Session, tenant_id: str, *, lock: bool = False
) -> models.TenantDeletion | None:
    query = select(models.TenantDeletion).where(
        models.TenantDeletion.tenant_id == tenant_id,
        models.TenantDeletion.state.in_(OPEN_STATES),
    )
    if lock:
        query = query.with_for_update()
    return session.execute(query).scalar_one_or_none()


def _confirm(tenant_id: str, confirm: str | None) -> None:
    # Exact, not case-folded: the point is that the operator read the id of
    # the tenant they are destroying, and ``Acme`` is not what they read.
    if (confirm or "") != tenant_id:
        raise ValueError("confirm must be the tenant id, typed exactly")


def request_deletion(
    settings: Settings,
    tenant_id: str,
    *,
    confirm: str,
    reason: str,
    actor: str,
    audit: audit_service.AuditContext | None = None,
) -> dict[str, Any]:
    """Step one: suspend the tenant and open a deletion with a grace period.

    Refused with :class:`legal_hold.LegalHoldActive` for a tenant on hold, and
    with :class:`LifecycleConflict` for the default tenant, one already being
    deleted, or one with a deletion open. Nothing is deleted here; the tenant's
    credentials are revoked whatever the suspension had kept, since a tenant on
    its way out has no resume to keep them for.
    """
    cleaned = _reason(reason)
    _confirm(tenant_id, confirm)
    _refuse_default(tenant_id)
    now = _now()
    with get_session(settings.postgres_url) as session:
        tenant = _lock_tenant(session, tenant_id)
        legal_hold.assert_not_on_hold(session, tenant_id, action="tenant.delete")
        if _open_deletion(session, tenant_id) is not None:
            raise LifecycleConflict(f"tenant {tenant_id} already has a deletion in progress")
        if tenant.status not in (
            tenants_service.STATUS_ACTIVE,
            tenants_service.STATUS_SUSPENDED,
        ):
            raise LifecycleConflict(f"tenant {tenant_id} is {tenant.status}")
        before = {"status": tenant.status}
        _set_status(
            tenant, tenants_service.STATUS_PENDING_DELETION, reason=cleaned, actor=actor
        )
        session.flush()
        cut = _cut_access(
            session,
            tenant_id,
            revoke_credentials=True,
            actor=actor,
            why="marked for deletion",
        )
        grace = timedelta(days=max(0, settings.tenant_deletion_grace_days))
        deletion = models.TenantDeletion(
            deletion_id=f"del_{uuid.uuid4().hex[:16]}",
            tenant_id=tenant_id,
            state=STATE_PENDING,
            reason=cleaned,
            requested_by=actor,
            requested_at=now,
            purge_after=now + grace,
        )
        session.add(deletion)
        for position, step in enumerate(STEPS):
            session.add(
                models.TenantDeletionStep(
                    deletion_id=deletion.deletion_id,
                    step=step,
                    position=position,
                    state=STEP_PENDING,
                    counts={},
                )
            )
        session.flush()
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_TENANT_DELETE_REQUEST,
            resource_type="tenant",
            resource_id=tenant_id,
            before=before,
            after={
                "status": tenants_service.STATUS_PENDING_DELETION,
                "deletion_id": deletion.deletion_id,
                "reason": cleaned,
                "purge_after": _iso(deletion.purge_after),
                **cut,
            },
        )
        described = _describe_in(settings, session, tenant_id)
        described["cut"] = cut
    job_store.refresh_job_gauges(settings)
    LOG.warning(
        "Deletion of tenant %s requested by %s; purge possible after %s",
        tenant_id,
        actor,
        _iso(now + grace),
    )
    return described


def cancel_deletion(
    settings: Settings,
    tenant_id: str,
    *,
    actor: str,
    audit: audit_service.AuditContext | None = None,
) -> dict[str, Any]:
    """Withdraw a deletion still in its grace period. The tenant stays suspended.

    Suspended rather than active: whoever cancels a deletion has not thereby
    decided to let the customer back in, and the credentials the request
    revoked are gone either way. Resuming is its own, audited, step. A purge
    that has started cannot be cancelled — what it deleted is not coming back.
    """
    with get_session(settings.postgres_url) as session:
        tenant = _lock_tenant(session, tenant_id)
        deletion = _open_deletion(session, tenant_id, lock=True)
        if deletion is None:
            raise LookupError(f"tenant {tenant_id} has no deletion in progress")
        if deletion.state != STATE_PENDING:
            raise LifecycleConflict(
                f"the purge of tenant {tenant_id} has started and cannot be cancelled"
            )
        now = _now()
        deletion.state = STATE_CANCELLED
        deletion.cancelled_by = actor
        deletion.cancelled_at = now
        _set_status(
            tenant,
            tenants_service.STATUS_SUSPENDED,
            reason=f"deletion {deletion.deletion_id} cancelled",
            actor=actor,
        )
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_TENANT_DELETE_CANCEL,
            resource_type="tenant",
            resource_id=tenant_id,
            before={
                "status": tenants_service.STATUS_PENDING_DELETION,
                "deletion_id": deletion.deletion_id,
            },
            after={"status": tenants_service.STATUS_SUSPENDED, "deletion": STATE_CANCELLED},
        )
        described = _describe_in(settings, session, tenant_id)
    LOG.warning("Deletion of tenant %s cancelled by %s", tenant_id, actor)
    return described


def unconfigured_stores(settings: Settings) -> list[str]:
    """What this replica's purge would fail on for want of configuration alone.

    The ClickHouse and JetStream steps fail on a replica where the store's URL
    is unset and the installation has not declared the store unused
    (``OCTO_TENANT_PURGE_UNUSED_STORES``): the tenant's data may be in a store
    this replica cannot reach, and recording it as holding nothing would be a
    guess. Checked by :func:`approve_deletion`, so that the misconfiguration
    stops the approval — before the point of no return — rather than leaving a
    tenant ``deleting`` behind a step that can never succeed.
    """
    unused = set(settings.tenant_purge_unused_stores)
    missing: list[str] = []
    for store, variable, url in (
        ("clickhouse", "OCTO_CLICKHOUSE_URL", settings.clickhouse_url),
        ("jetstream", "OCTO_NATS_URL", settings.nats_url),
    ):
        if not (url or "").strip() and store not in unused:
            missing.append(f"{variable} (or '{store}' in OCTO_TENANT_PURGE_UNUSED_STORES)")
    return missing


def approve_deletion(
    settings: Settings,
    tenant_id: str,
    *,
    confirm: str,
    actor: str,
    audit: audit_service.AuditContext | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Step two: start the purge, after the grace period, by a second person.

    The legal-hold contract, in this order and in this transaction: lock the
    tenant row, refuse a held tenant, and only then mark it ``deleting``. From
    the commit on, the purge worker owns it; every batch it deletes re-checks
    the hold under the same lock.

    Refused with :class:`LifecycleConflict` on a replica whose configuration
    would fail a store's step (:func:`unconfigured_stores`): an approved purge
    cannot be taken back, and one that cannot finish leaves the tenant
    ``deleting`` until someone fixes the configuration.
    """
    _confirm(tenant_id, confirm)
    missing = unconfigured_stores(settings)
    if missing:
        raise LifecycleConflict(
            "this installation's purge could not finish: set "
            + " and ".join(missing)
            + " on the API replicas before approving it — the purge runs on "
            "every replica, and a store none of them can reach is not one it "
            "may record as empty"
        )
    moment = now or _now()
    with get_session(settings.postgres_url) as session:
        tenant = _lock_tenant(session, tenant_id)
        deletion = _open_deletion(session, tenant_id, lock=True)
        if deletion is None:
            raise LookupError(f"tenant {tenant_id} has no deletion in progress")
        if deletion.state != STATE_PENDING:
            raise LifecycleConflict(f"the deletion of tenant {tenant_id} is {deletion.state}")
        if moment < deletion.purge_after:
            raise LifecycleConflict(
                f"the grace period for tenant {tenant_id} ends at {_iso(deletion.purge_after)}; "
                "the purge can be approved after it"
            )
        if settings.tenant_deletion_two_person and _same_person(deletion.requested_by, actor):
            raise SecondApproverRequired(
                "the platform admin who requested a tenant's deletion cannot approve its "
                "purge; this decision needs a second person (OCTO_TENANT_DELETION_TWO_PERSON)"
            )
        legal_hold.assert_not_on_hold(session, tenant_id, action="tenant.delete")
        _set_status(tenant, tenants_service.STATUS_DELETING, reason=deletion.reason, actor=actor)
        deletion.state = STATE_PURGING
        deletion.approved_by = actor
        deletion.approved_at = moment
        deletion.next_attempt_at = moment
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_TENANT_DELETE_APPROVE,
            resource_type="tenant",
            resource_id=tenant_id,
            before={
                "status": tenants_service.STATUS_PENDING_DELETION,
                "deletion_id": deletion.deletion_id,
                "requested_by": deletion.requested_by,
            },
            after={"status": tenants_service.STATUS_DELETING, "deletion": STATE_PURGING},
        )
        described = _describe_in(settings, session, tenant_id)
    LOG.warning("Purge of tenant %s approved by %s", tenant_id, actor)
    return described


def retry_deletion(
    settings: Settings,
    tenant_id: str,
    *,
    actor: str,
    audit: audit_service.AuditContext | None = None,
) -> dict[str, Any]:
    """Make a failing or blocked purge due now, instead of at its backoff.

    A ``blocked`` purge — stopped by a legal hold — is resumed only through
    here, and only once the hold is gone: releasing a hold is one decision and
    destroying what it preserved is another, so the second is not implied by
    the first.
    """
    with get_session(settings.postgres_url) as session:
        _lock_tenant(session, tenant_id)
        deletion = _open_deletion(session, tenant_id, lock=True)
        if deletion is None:
            raise LookupError(f"tenant {tenant_id} has no deletion in progress")
        if deletion.state not in (STATE_PURGING, STATE_BLOCKED):
            raise LifecycleConflict(f"the deletion of tenant {tenant_id} is {deletion.state}")
        legal_hold.assert_not_on_hold(session, tenant_id, action="tenant.delete")
        before = {"state": deletion.state, "last_error": deletion.last_error}
        now = _now()
        deletion.state = STATE_PURGING
        deletion.next_attempt_at = now
        for step in session.execute(
            select(models.TenantDeletionStep).where(
                models.TenantDeletionStep.deletion_id == deletion.deletion_id,
                models.TenantDeletionStep.state.in_((STEP_FAILED, STEP_WAITING)),
            )
        ).scalars():
            step.state = STEP_PENDING
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_TENANT_DELETE_RETRY,
            resource_type="tenant",
            resource_id=tenant_id,
            before=before,
            after={"state": STATE_PURGING, "deletion_id": deletion.deletion_id},
        )
        described = _describe_in(settings, session, tenant_id)
    LOG.warning("Purge of tenant %s retried by %s", tenant_id, actor)
    return described


# -- reading -------------------------------------------------------------------


def _step_dict(row: models.TenantDeletionStep) -> dict[str, Any]:
    return {
        "step": row.step,
        "position": row.position,
        "state": row.state,
        "attempts": row.attempts,
        "started_at": _iso(row.started_at),
        "finished_at": _iso(row.finished_at),
        "last_error": row.last_error,
        "counts": dict(row.counts or {}),
    }


def deletion_dict(
    session: Session,
    row: models.TenantDeletion,
    steps: list[models.TenantDeletionStep] | None = None,
) -> dict[str, Any]:
    """One journal row. ``steps`` when the caller loaded them already, in order."""
    if steps is None:
        steps = list(
            session.execute(
                select(models.TenantDeletionStep)
                .where(models.TenantDeletionStep.deletion_id == row.deletion_id)
                .order_by(models.TenantDeletionStep.position)
            ).scalars()
        )
    return {
        "deletion_id": row.deletion_id,
        "tenant_id": row.tenant_id,
        "state": row.state,
        "reason": row.reason,
        "requested_by": row.requested_by,
        "requested_at": _iso(row.requested_at),
        "purge_after": _iso(row.purge_after),
        "approved_by": row.approved_by,
        "approved_at": _iso(row.approved_at),
        "cancelled_by": row.cancelled_by,
        "cancelled_at": _iso(row.cancelled_at),
        "completed_at": _iso(row.completed_at),
        "attempts": row.attempts,
        "last_error": row.last_error,
        "next_attempt_at": _iso(row.next_attempt_at),
        "outcome": row.outcome,
        "steps": [_step_dict(step) for step in steps],
    }


def _describe_in(settings: Settings, session: Session, tenant_id: str) -> dict[str, Any]:
    tenant = session.get(models.Tenant, tenant_id)
    deletions = session.execute(
        select(models.TenantDeletion)
        .where(models.TenantDeletion.tenant_id == tenant_id)
        .order_by(models.TenantDeletion.requested_at.desc())
    ).scalars().all()
    if tenant is None and not deletions:
        raise LookupError(f"tenant not found: {tenant_id}")
    hold = session.get(models.TenantLegalHold, tenant_id)
    current = next((row for row in deletions if row.state in OPEN_STATES), None)
    return {
        "tenant_id": tenant_id,
        "name": tenant.name if tenant is not None else None,
        # ``deleted`` is not a status a row can hold — there is no row — but it
        # is the honest answer for an id whose journal says it was purged.
        "status": tenant.status if tenant is not None else "deleted",
        "status_reason": tenant.status_reason if tenant is not None else None,
        "status_changed_at": _iso(tenant.status_changed_at) if tenant is not None else None,
        "status_changed_by": tenant.status_changed_by if tenant is not None else None,
        "legal_hold": (
            {
                "tenant_id": hold.tenant_id,
                "reason": hold.reason,
                "set_by": hold.set_by,
                "set_at": _iso(hold.set_at),
            }
            if hold is not None
            else None
        ),
        "deletion": deletion_dict(session, current) if current is not None else None,
        "history": [deletion_dict(session, row) for row in deletions if row is not current],
        "grace_days": max(0, settings.tenant_deletion_grace_days),
        "two_person": settings.tenant_deletion_two_person,
    }


def describe(settings: Settings, tenant_id: str) -> dict[str, Any]:
    """The platform admin's view of one tenant's lifecycle. LookupError when unknown."""
    with get_session(settings.postgres_url) as session:
        return _describe_in(settings, session, tenant_id)


#: The most journal rows one listing returns. The journal only grows — a row
#: per deletion ever requested — so the listing pages rather than reading it
#: whole.
MAX_LIST_LIMIT = 500


def list_deletions(
    settings: Settings,
    *,
    state: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Deletions, newest first — the tombstones included. Paged: ``limit``
    (at most :data:`MAX_LIST_LIMIT`) from ``offset``.

    What an operator re-applies after restoring a backup: the ``completed``
    rows are the tenants that must not come back (docs/tenant-lifecycle.md).
    Two queries whatever the page size: the rows, then all their steps.
    """
    limit = max(1, min(int(limit), MAX_LIST_LIMIT))
    with get_session(settings.postgres_url) as session:
        query = (
            select(models.TenantDeletion)
            .order_by(
                models.TenantDeletion.requested_at.desc(),
                models.TenantDeletion.deletion_id.desc(),
            )
            .offset(max(0, int(offset)))
            .limit(limit)
        )
        if state:
            query = query.where(models.TenantDeletion.state == state)
        rows = session.execute(query).scalars().all()
        steps: dict[str, list[models.TenantDeletionStep]] = {row.deletion_id: [] for row in rows}
        if rows:
            for step in session.execute(
                select(models.TenantDeletionStep)
                .where(models.TenantDeletionStep.deletion_id.in_(list(steps)))
                .order_by(models.TenantDeletionStep.deletion_id, models.TenantDeletionStep.position)
            ).scalars():
                steps[step.deletion_id].append(step)
        return [deletion_dict(session, row, steps[row.deletion_id]) for row in rows]
