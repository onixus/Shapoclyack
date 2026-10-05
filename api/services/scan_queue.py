"""Scan queue policy: priority, per-tenant concurrency and admission (#365).

Before this the queue was one FIFO per tenant with no ceiling. A tenant could
queue as many scans as it liked and have every one of them out with a sensor
at once, and an urgent re-scan of a finding waited behind the nightly sweep of
the whole estate. Three controls, each enforced where it can actually hold:

**Priority** orders the claim. ``jobs.priority`` (higher first, then
``queued_at``) is the ``ORDER BY`` of every hand-out — the HTTP claim, the
NATS claim of a named job falls outside it (see below), and a local scan held
back by its ceiling waits behind the better ones of its tenant on this
replica. 0 is the default and what every row before migration 0074 reads, so
a queue nobody prioritised is exactly the FIFO it was. Raising a scan above 0
is ``scan.priority.raise``; see :func:`check_priority`.

**Concurrency** is a claim-time ceiling: ``tenants.max_concurrent_scans`` jobs
of the tenant may be out with an executor at once — ``claimed``, ``running``
or ``cancelling``, because a scan being stopped is still on the wire until its
agent confirms. It is enforced inside the claim's own transaction under a
per-tenant advisory lock (:func:`hold_slot`), so two replicas claiming for the
same tenant at the same moment are decided one after the other: the second
one's count is taken after the first one's claim committed. Counting first and
claiming after, without the lock, lets both read "one slot free" and both
take it — the race the multi-replica test in ``tests/test_scan_queue.py``
reproduces against the pre-lock code.

The lock is advisory and per tenant on purpose. ``SELECT … FOR UPDATE`` on the
tenant row was the obvious alternative and is the one that hurt last time: it
also fences every foreign-key check against the tenant — every job insert,
every ingest write — and it deadlocked with ingest. An advisory lock fences
claims of one tenant and nothing else, and is released at commit or with the
backend. It is taken only for a tenant that *has* a ceiling, so an installation
that never sets one pays nothing.

**Admission** refuses a new scan with 429 and ``Retry-After`` while the
tenant's queue (``tenants.max_queued_scans``) or the installation's
(``OCTO_SCAN_QUEUE_MAX_DEPTH``) is full. A soft bound: the count is read
before the insert, outside any lock, so N simultaneous starts can overshoot by
N-1. Admission is back-pressure on a queue that drains by itself, not an
isolation boundary — the concurrency ceiling above is the one that must hold.

What none of this does: the NATS offer for a job is published at submission
and is FIFO; a sensor that claims a named offered job is subject to the
concurrency ceiling but not to the priority order. A burned offer — one a
sensor was refused because its tenant was at its ceiling — is picked up by the
sensor's periodic HTTP fallback claim, which *is* priority-ordered.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy import and_, func, or_, select, text

from api.db import models
from api.db import tenant_scope
from api.db.engine import get_session
from api.services import audit as audit_service
from api.services import job_states
from api.services import job_store
from api.services import metrics as metrics_service
from api.services import quotas
from api.services import tenants as tenants_service
from api.settings import Settings

if TYPE_CHECKING:
    from api.schemas import JobInfo
    from api.services.audit import AuditContext

_log = logging.getLogger(__name__)

#: Bounds of ``jobs.priority``. Wide enough that "a bit ahead" and "ahead of
#: everything" can both be said, narrow enough that nobody types 2**31.
PRIORITY_MIN = -100
PRIORITY_MAX = 100
PRIORITY_DEFAULT = 0

#: Upper bound on either ceiling — a typo guard, not a capacity statement.
LIMIT_MAX = 10_000

#: What occupies one of the tenant's concurrent slots: everything out with an
#: executor. ``cancelling`` included — the agent is still scanning until it
#: confirms the stop.
OCCUPYING = (job_states.CLAIMED, job_states.RUNNING, job_states.CANCELLING)

#: Advisory-lock class of the per-tenant claim lock, ``(class, hash of the
#: tenant)``. Not ``leader_lock.LOCK_CLASS_ID``: its object ids are session
#: locks a replica holds for its lifetime, and a tenant whose hash landed on one
#: would wait for a rollout to claim. Not ``asset_import``'s class either, so a
#: CMDB import does not hold a tenant's claims. "SHAQ" in ASCII.
CLAIM_LOCK_CLASS_ID = 0x53484151

#: Counter reasons, also the vocabulary of the docs.
REASON_TENANT_QUEUE_FULL = "tenant_queue_full"
REASON_GLOBAL_QUEUE_FULL = "global_queue_full"
REASON_CONCURRENCY = "concurrency_limit"

RESOURCE_QUEUE = "queue"


class QueueFull(quotas.QuotaExceeded):
    """A scan refused because too many scans are already waiting.

    A :class:`~api.services.quotas.QuotaExceeded` so the route's 429 with
    ``Retry-After`` handles it without learning a new exception. The schedule
    dispatcher catches it first, on purpose: a spent quota skips the tick, a
    full queue only defers it by ``retry_after_seconds``. ``limit`` and
    ``used`` are the queue ceiling and its depth; ``used`` of the
    installation's ceiling is every tenant's queue, so nothing may put it in
    front of a tenant.
    """


class PriorityNotPermitted(PermissionError):
    """Raising a scan above the default priority without ``scan.priority.raise``."""


class JobNotQueued(ValueError):
    """The job has left the queue, so its place in it is no longer a thing to set."""


@dataclass(frozen=True)
class QueueLimits:
    """One tenant's queue ceilings. ``None`` is unlimited."""

    tenant_id: str
    max_concurrent_scans: int | None
    max_queued_scans: int | None


def _normalise_limit(value: int | None) -> int | None:
    """0 and negatives mean unlimited, as for the quotas."""
    if value is None or value <= 0:
        return None
    return int(value)


def claim_order() -> tuple:
    """The ``ORDER BY`` of every hand-out: priority, then age, then id.

    ``job_id`` last so two jobs queued in the same microsecond are still handed
    out in one order on every replica.
    """
    return (models.Job.priority.desc(), models.Job.queued_at, models.Job.job_id)


def check_priority(priority: int, *, may_raise: bool, current: int = PRIORITY_DEFAULT) -> int:
    """Validate a requested priority against its bounds and the caller's authority.

    Above the default needs ``scan.priority.raise``, and so does moving a job
    that someone who held it already put above the default: otherwise an
    operator could undo the admin's decision by setting it back to 0, which is
    the same decision about everybody else's scans in the other direction.
    Anything at or below 0 on a job at or below 0 is the operator's own
    business — making room for somebody else's scan is not jumping the queue.
    """
    if not PRIORITY_MIN <= priority <= PRIORITY_MAX:
        raise ValueError(
            f"priority must be between {PRIORITY_MIN} and {PRIORITY_MAX}, got {priority}"
        )
    if (priority > PRIORITY_DEFAULT or current > PRIORITY_DEFAULT) and not may_raise:
        raise PriorityNotPermitted(
            "raising a scan above the default priority, or moving one that was "
            "raised, needs the scan.priority.raise permission in this tenant"
        )
    return priority


def get_limits(settings: Settings, tenant_id: str) -> QueueLimits | None:
    """This tenant's ceilings, or ``None`` for a tenant that does not exist."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Tenant, tenant_id)
        if row is None:
            return None
        return QueueLimits(
            tenant_id=tenant_id,
            max_concurrent_scans=_normalise_limit(row.max_concurrent_scans),
            max_queued_scans=_normalise_limit(row.max_queued_scans),
        )


def set_limits(
    settings: Settings,
    tenant_id: str,
    *,
    max_concurrent_scans: int | None,
    max_queued_scans: int | None,
    audit: AuditContext | None = None,
) -> QueueLimits:
    """Write both ceilings at once. ``None`` (or 0) stores unlimited.

    A lowered concurrency ceiling does not touch scans already out: they run
    to completion, and the tenant simply gets no new claim until it is below
    the new number. Pulling a running scan off its sensor is ``cancel``.
    """
    concurrent = _normalise_limit(max_concurrent_scans)
    queued = _normalise_limit(max_queued_scans)
    for name, value in (("max_concurrent_scans", concurrent), ("max_queued_scans", queued)):
        if value is not None and value > LIMIT_MAX:
            raise ValueError(f"{name} must be at most {LIMIT_MAX}")
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Tenant, tenant_id)
        if row is None:
            raise LookupError(f"Unknown tenant_id: {tenant_id}")
        before = {
            "max_concurrent_scans": _normalise_limit(row.max_concurrent_scans),
            "max_queued_scans": _normalise_limit(row.max_queued_scans),
        }
        row.max_concurrent_scans = concurrent
        row.max_queued_scans = queued
        after = {"max_concurrent_scans": concurrent, "max_queued_scans": queued}
        if before != after:
            audit_service.record(
                session,
                audit,
                action=audit_service.ACTION_TENANT_QUEUE_LIMITS,
                resource_type="tenant",
                resource_id=tenant_id,
                tenant_id=tenant_id,
                before=before,
                after=after,
            )
    return QueueLimits(
        tenant_id=tenant_id, max_concurrent_scans=concurrent, max_queued_scans=queued
    )


def _queued_count(session, tenant_id: str | None) -> int:
    filters = [models.Job.status == job_states.QUEUED]
    if tenant_id is not None:
        filters.append(models.Job.tenant_id == tenant_id)
    return int(
        session.execute(select(func.count()).select_from(models.Job).where(*filters)).scalar_one()
    )


def assert_admitted(settings: Settings, *, tenant_id: str, exempt: bool = False) -> None:
    """Refuse a new scan while the tenant's or the installation's queue is full.

    Called from ``scan_admission.admit_scan`` beside the monthly quota, for the
    reason that one is there: the schedule dispatcher reaches it too, and a
    ceiling the nightly sweep walks past is not a ceiling.

    ``exempt`` is the quota's exemption, for the same reason: a verification
    re-scan the platform dispatches to close a finding must not be refused, or
    the finding sits in ``VERIFYING`` because the queue was busy. It still
    waits its turn for a slot — exemption is from admission, not from the
    concurrency ceiling.
    """
    if exempt:
        return
    with get_session(settings.postgres_url) as session:
        tenant_limit = _normalise_limit(
            session.execute(
                select(models.Tenant.max_queued_scans).where(models.Tenant.tenant_id == tenant_id)
            ).scalar_one_or_none()
        )
        if tenant_limit is not None:
            depth = _queued_count(session, tenant_id)
            if depth >= tenant_limit:
                metrics_service.SCAN_QUEUE_THROTTLED_TOTAL.labels(REASON_TENANT_QUEUE_FULL).inc()
                raise QueueFull(
                    f"Scan queue full for tenant {tenant_id}: {depth}/{tenant_limit} scans "
                    "already waiting; retry once some have started",
                    tenant_id=tenant_id,
                    resource=RESOURCE_QUEUE,
                    limit=tenant_limit,
                    used=depth,
                    retry_after_seconds=settings.scan_queue_retry_after_seconds,
                )
    global_limit = _normalise_limit(settings.scan_queue_max_depth)
    if global_limit is None:
        return
    # A session of its own, opened in the system scope: the request's session
    # is a tenant's under row-level security, and an unfiltered count in it
    # sees that tenant's queue only — every tenant would get a ceiling of its
    # own instead of sharing one. The scope is fixed when a transaction
    # begins, so widening it for a statement inside the request's session
    # would not take.
    with tenant_scope.system("scan admission: installation-wide queue depth"):
        with get_session(settings.postgres_url) as session:
            depth = _queued_count(session, None)
    if depth >= global_limit:
        metrics_service.SCAN_QUEUE_THROTTLED_TOTAL.labels(REASON_GLOBAL_QUEUE_FULL).inc()
        # The installation's depth is not the tenant's business, so the
        # message names the ceiling and not the numbers behind it.
        raise QueueFull(
            "The installation's scan queue is full; retry once some scans have started",
            tenant_id=tenant_id,
            resource=RESOURCE_QUEUE,
            limit=global_limit,
            used=depth,
            retry_after_seconds=settings.scan_queue_retry_after_seconds,
        )


_CLAIM_LOCK = text("SELECT pg_advisory_xact_lock(:class_id, :object_id)")
_CLAIM_LOCK_TRY = text("SELECT pg_try_advisory_xact_lock(:class_id, :object_id)")


def _lock_claims(session, tenant_id: str, *, wait: bool = True) -> bool:
    """Hold this tenant's claim lock until the transaction ends. ``False`` if busy.

    ``wait=False`` asks once and answers ``False`` while another transaction
    holds the lock, instead of queueing behind it with a pooled connection in
    hand; see :func:`hold_slot`.

    SQLite (dev and the test fallback) has no advisory locks and one writer at
    a time anyway.
    """
    if session.get_bind().dialect.name != "postgresql":
        return True
    digest = hashlib.blake2b(tenant_id.encode("utf-8"), digest_size=4).digest()
    result = session.execute(
        _CLAIM_LOCK if wait else _CLAIM_LOCK_TRY,
        {
            "class_id": CLAIM_LOCK_CLASS_ID,
            "object_id": int.from_bytes(digest, "big", signed=True),
        },
    ).scalar()
    # pg_advisory_xact_lock returns void (None) once it has the lock.
    return wait or bool(result)


def concurrency_limit(session, tenant_id: str) -> int | None:
    return _normalise_limit(
        session.execute(
            select(models.Tenant.max_concurrent_scans).where(models.Tenant.tenant_id == tenant_id)
        ).scalar_one_or_none()
    )


def hold_slot(session, tenant_id: str, *, wait: bool = True) -> bool:
    """Whether the tenant may have one more scan out, deciding it for this transaction.

    Call inside the transaction that then claims the job, *before* selecting
    the row. With a ceiling set, the tenant's claim lock is taken first and
    held to commit, so the count below already includes every claim that
    committed before this one — and none that commits after it can have read
    a count that excludes this one. Under READ COMMITTED each statement takes
    a fresh snapshot, which is what makes the count after the lock current.

    ``wait=False`` is for a caller that will ask again anyway — a local scan
    polling for its slot. While another claim of the tenant holds the lock it
    is answered ``False`` at once rather than waiting its turn: a claim can
    hold the lock for as long as it takes to read a job's inputs from the
    object store, and every waiting local scan queued behind it would hold a
    pooled connection meanwhile. ``False`` then means "not now", not "at the
    ceiling", and is not counted as a throttle.

    ``True`` without a ceiling, without a lock and without a count: the
    pre-#365 claim, unchanged.
    """
    limit = concurrency_limit(session, tenant_id)
    if limit is None:
        return True
    if not _lock_claims(session, tenant_id, wait=wait):
        return False
    out = int(
        session.execute(
            select(func.count())
            .select_from(models.Job)
            .where(models.Job.tenant_id == tenant_id, models.Job.status.in_(OCCUPYING))
        ).scalar_one()
    )
    if out < limit:
        return True
    metrics_service.SCAN_QUEUE_THROTTLED_TOTAL.labels(REASON_CONCURRENCY).inc()
    _log.debug(
        "Tenant %s has %d/%d scans out; nothing is handed out until one ends",
        tenant_id,
        out,
        limit,
    )
    return False


def local_job_ahead(session, row: models.Job) -> bool:
    """Whether a better queued local job of the same tenant waits on this replica.

    A local scan held back by its tenant's ceiling waits in its own thread and
    asks again; without this, whichever thread asked first after a slot freed
    would take it, and priority would mean nothing for local scans. Confined to
    this replica's jobs (``owner_id``): another replica's queued local job can
    only be started by that replica, and one that has gone away would
    otherwise block this one forever.
    """
    better = or_(
        models.Job.priority > row.priority,
        and_(models.Job.priority == row.priority, models.Job.queued_at < row.queued_at),
        and_(
            models.Job.priority == row.priority,
            models.Job.queued_at == row.queued_at,
            models.Job.job_id < row.job_id,
        ),
    )
    return (
        session.execute(
            select(models.Job.job_id)
            .where(
                models.Job.execution == "local",
                models.Job.status == job_states.QUEUED,
                models.Job.tenant_id == row.tenant_id,
                models.Job.owner_id == row.owner_id,
                models.Job.job_id != row.job_id,
                better,
            )
            .limit(1)
        ).first()
        is not None
    )


def set_priority(
    settings: Settings,
    job_id: str,
    priority: int,
    *,
    tenant_id: str | None,
    may_raise: bool,
    username: str,
    audit: AuditContext | None = None,
) -> JobInfo:
    """Move a queued job within its tenant's queue.

    ``tenant_id`` of ``None`` is a platform admin acting across tenants; any
    other value pins the job to that tenant and a mismatch is reported like a
    missing job (:class:`LookupError`), so the id is not confirmed to someone
    with no right to know it exists. Only a ``queued`` job may move: once it is
    out with an executor its place in the queue is history.
    """
    with get_session(settings.postgres_url) as session:
        # Locked so a claim taking the row at this moment either sees the old
        # priority and claims it, or waits and finds it already moved — never
        # half of each.
        row = session.get(models.Job, job_id, with_for_update=True)
        job_tenant = (row.tenant_id or tenants_service.DEFAULT_TENANT_ID) if row else None
        if row is None or (tenant_id is not None and job_tenant != tenant_id):
            raise LookupError("Job not found")
        if row.status != job_states.QUEUED:
            raise JobNotQueued(
                f"Job {job_id} is {row.status}; only a queued job can change its priority"
            )
        before = row.priority or PRIORITY_DEFAULT
        check_priority(priority, may_raise=may_raise, current=before)
        if before != priority:
            row.priority = priority
            audit_service.record(
                session,
                audit,
                action=audit_service.ACTION_SCAN_PRIORITY,
                resource_type="job",
                resource_id=job_id,
                tenant_id=job_tenant,
                before={"priority": before},
                after={"priority": priority, "requested_by": username},
            )
        session.flush()
        return job_store.to_info(row)
