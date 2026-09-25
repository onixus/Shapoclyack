"""The tenant purge: an approved deletion, carried out one store at a time (#325).

A deletion approved in :mod:`api.services.tenant_lifecycle` is ``purging`` in
the journal (``tenant_deletions``) and ``deleting`` in ``tenants``. This worker
takes it from there, through the steps in
:data:`api.services.tenant_lifecycle.STEPS`::

    quiesce → outbox → jetstream → artifacts → clickhouse → postgres → finalize

**Durable and resumable.** Each step has a row of its own
(``tenant_deletion_steps``) with a state, attempts, the last error and what it
removed. Every step is idempotent — it deletes what is still there and verifies
nothing is left — so an attempt that died half way, with its replica, is
simply run again from the step it was on. A completed step is never repeated.

**Claimed, not elected.** Every replica runs the worker. A deletion is taken
with ``FOR UPDATE SKIP LOCKED`` and held on a lease that every batch renews
(:mod:`.context`); a replica whose lease lapsed finds out at its next batch and
stops, and the replica that took the row over carries on from the same step.
The steps being idempotent is what makes the brief overlap harmless — the same
discipline as the run publisher's.

**Failures are visible and retried.** A step that fails records its error,
the deletion is due again after a backoff (the purge interval, doubled per
attempt of that step, capped at an hour), and the first failure of each step
is written to the audit trail — once, not once per retry. A platform admin can
make it due now (``POST …/deletion/retry``). The tenant stays ``deleting`` the
whole time: there is no way back from a purge that has started.

**A legal hold stops it.** Checked under the tenant row lock before every
batch; a hold that appears mid-purge leaves the journal ``blocked`` with the
rest of the data intact, and only a retry after the hold is released resumes.

The worker is off with ``OCTO_TENANT_PURGE_ENABLED=false``; approved deletions
then wait in the journal.
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import timedelta
from typing import Any, Callable

from sqlalchemy import or_, select

from api.db import models
from api.services import audit as audit_service
from api.services import legal_hold
from api.services import tenant_lifecycle as lifecycle
from api.services.tenant_purge import artifacts, clickhouse, jetstream, postgres
from api.services.tenant_purge.context import (
    LEASE_SECONDS,
    LeaseLost,
    PurgeContext,
    RerunSteps,
    StepSkipped,
    StepWaiting,
    now,
    system_session,
)
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.tenant-purge")

#: The longest a failing step waits before its next attempt.
MAX_BACKOFF_SECONDS = 3600

STEP_FUNCTIONS: dict[str, Callable[[PurgeContext], dict[str, Any]]] = {
    "quiesce": postgres.quiesce,
    "outbox": postgres.outbox,
    "jetstream": jetstream.run,
    "artifacts": artifacts.run,
    "clickhouse": clickhouse.run,
    "postgres": postgres.postgres,
    "finalize": postgres.finalize,
}
assert tuple(STEP_FUNCTIONS) == lifecycle.STEPS, "every journal step needs a function, in order"

_worker: TenantPurgeWorker | None = None


def _describe_error(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:1000]


def backoff_seconds(settings: Settings, attempts: int) -> int:
    base = max(1, int(settings.tenant_purge_interval_seconds))
    return int(min(MAX_BACKOFF_SECONDS, base * 2 ** max(0, attempts - 1)))


def _owned(session, deletion_id: str, owner: str) -> models.TenantDeletion | None:
    """The journal row, locked, if this worker still holds it; None if not."""
    row = session.get(models.TenantDeletion, deletion_id, with_for_update=True)
    if row is None or row.lease_owner != owner or row.state != lifecycle.STATE_PURGING:
        return None
    return row


def _release(row: models.TenantDeletion) -> None:
    row.lease_owner = None
    row.lease_until = None


def _claim(settings: Settings, owner: str) -> str | None:
    moment = now()
    with system_session(settings) as session:
        row = session.execute(
            select(models.TenantDeletion)
            .where(
                models.TenantDeletion.state == lifecycle.STATE_PURGING,
                or_(
                    models.TenantDeletion.next_attempt_at.is_(None),
                    models.TenantDeletion.next_attempt_at <= moment,
                ),
                or_(
                    models.TenantDeletion.lease_until.is_(None),
                    models.TenantDeletion.lease_until < moment,
                ),
            )
            .order_by(models.TenantDeletion.next_attempt_at, models.TenantDeletion.deletion_id)
            .limit(1)
            .with_for_update(skip_locked=True)
        ).scalar_one_or_none()
        if row is None:
            return None
        row.lease_owner = owner
        row.lease_until = moment + timedelta(seconds=LEASE_SECONDS)
        return row.deletion_id


def _start_step(settings: Settings, deletion_id: str, step: str, owner: str) -> bool:
    with system_session(settings) as session:
        if _owned(session, deletion_id, owner) is None:
            return False
        row = session.get(models.TenantDeletionStep, (deletion_id, step))
        assert row is not None
        row.state = lifecycle.STEP_RUNNING
        row.attempts = int(row.attempts or 0) + 1
        if row.started_at is None:
            row.started_at = now()
        return True


def _finish_step(
    settings: Settings,
    deletion_id: str,
    step: str,
    owner: str,
    *,
    state: str,
    counts: dict[str, Any] | None = None,
    note: str | None = None,
) -> bool:
    """Record the step's outcome; False when the lease is no longer ``owner``'s.

    A step can return without another checkpoint after its lease went to a
    second replica, which is running the same step now: the bookkeeping is
    that replica's to write, and this one stops.
    """
    with system_session(settings) as session:
        row = session.get(models.TenantDeletionStep, (deletion_id, step))
        if row is None or row.state == lifecycle.STEP_DONE:
            return True
        if _owned(session, deletion_id, owner) is None:
            return False
        merged: dict[str, Any] = dict(row.counts or {})
        for key, value in (counts or {}).items():
            merged[key] = int(merged.get(key) or 0) + int(value)
        row.counts = merged
        row.state = state
        row.finished_at = now()
        row.last_error = note
        return True


def _wait(settings: Settings, deletion_id: str, step: str, owner: str, reason: str) -> None:
    with system_session(settings) as session:
        deletion = _owned(session, deletion_id, owner)
        if deletion is None:
            return
        row = session.get(models.TenantDeletionStep, (deletion_id, step))
        assert row is not None
        row.state = lifecycle.STEP_WAITING
        row.last_error = reason
        deletion.last_error = f"{step}: {reason}"
        deletion.next_attempt_at = now() + timedelta(
            seconds=max(1, int(settings.tenant_purge_interval_seconds))
        )
        _release(deletion)


def _block(
    settings: Settings,
    deletion_id: str,
    step: str,
    owner: str,
    held: legal_hold.LegalHoldActive,
) -> None:
    with system_session(settings) as session:
        deletion = _owned(session, deletion_id, owner)
        if deletion is None:
            return
        row = session.get(models.TenantDeletionStep, (deletion_id, step))
        assert row is not None
        row.state = lifecycle.STEP_FAILED
        row.last_error = str(held)
        deletion.state = lifecycle.STATE_BLOCKED
        deletion.last_error = f"{step}: {held}"
        deletion.next_attempt_at = None
        _release(deletion)
        audit_service.record(
            session,
            audit_service.system_context("tenant-purge"),
            action=audit_service.ACTION_TENANT_DELETE_BLOCK,
            resource_type="tenant",
            resource_id=deletion.tenant_id,
            after={"deletion_id": deletion_id, "step": step, "legal_hold_by": held.set_by},
        )
    LOG.warning("Purge of tenant deletion %s stopped by a legal hold at %s", deletion_id, step)


def _fail(
    settings: Settings,
    deletion_id: str,
    step: str,
    owner: str,
    exc: BaseException,
    *,
    rerun: tuple[str, ...] = (),
) -> None:
    message = _describe_error(exc)
    with system_session(settings) as session:
        deletion = _owned(session, deletion_id, owner)
        if deletion is None:
            return
        row = session.get(models.TenantDeletionStep, (deletion_id, step))
        assert row is not None
        row.state = lifecycle.STEP_FAILED
        row.last_error = message
        for name in rerun:
            earlier = session.get(models.TenantDeletionStep, (deletion_id, name))
            if earlier is not None:
                earlier.state = lifecycle.STEP_PENDING
                earlier.finished_at = None
        deletion.attempts = int(deletion.attempts or 0) + 1
        deletion.last_error = f"{step}: {message}"
        deletion.next_attempt_at = now() + timedelta(
            seconds=backoff_seconds(settings, int(row.attempts or 1))
        )
        _release(deletion)
        if int(row.attempts or 0) <= 1:
            # Once per step, not per retry: a store down for a day would
            # otherwise write forty-eight rows saying the same thing.
            audit_service.record(
                session,
                audit_service.system_context("tenant-purge"),
                action=audit_service.ACTION_TENANT_DELETE_FAIL,
                resource_type="tenant",
                resource_id=deletion.tenant_id,
                after={"deletion_id": deletion_id, "step": step, "error": message},
            )


def _plan(settings: Settings, deletion_id: str) -> tuple[str, list[tuple[str, str]]]:
    with system_session(settings) as session:
        deletion = session.get(models.TenantDeletion, deletion_id)
        assert deletion is not None
        steps = session.execute(
            select(models.TenantDeletionStep.step, models.TenantDeletionStep.state)
            .where(models.TenantDeletionStep.deletion_id == deletion_id)
            .order_by(models.TenantDeletionStep.position)
        ).all()
        return deletion.tenant_id, [(step, state) for step, state in steps]


def drive(settings: Settings, deletion_id: str, owner: str) -> str:
    """Run the claimed deletion's remaining steps. Returns how it stopped.

    ``completed``, ``waiting`` (a step is not ready), ``failed`` (a step raised;
    due again after its backoff), ``blocked`` (a legal hold) or ``lease_lost``.
    """
    tenant_id, steps = _plan(settings, deletion_id)
    for step, state in steps:
        if state in (lifecycle.STEP_DONE, lifecycle.STEP_SKIPPED):
            continue
        if not _start_step(settings, deletion_id, step, owner):
            return "lease_lost"
        ctx = PurgeContext(
            settings, deletion_id=deletion_id, tenant_id=tenant_id, owner=owner, step=step
        )
        try:
            counts = STEP_FUNCTIONS[step](ctx)
        except StepSkipped as skipped:
            if not _finish_step(
                settings, deletion_id, step, owner, state=lifecycle.STEP_SKIPPED, note=str(skipped)
            ):
                return "lease_lost"
            continue
        except StepWaiting as waiting:
            _wait(settings, deletion_id, step, owner, str(waiting))
            return "waiting"
        except legal_hold.LegalHoldActive as held:
            _block(settings, deletion_id, step, owner, held)
            return "blocked"
        except LeaseLost:
            LOG.warning("Lost the lease on deletion %s during %s", deletion_id, step)
            return "lease_lost"
        except RerunSteps as rerun:
            LOG.warning("Deletion %s: %s", deletion_id, rerun)
            _fail(settings, deletion_id, step, owner, rerun, rerun=rerun.steps)
            return "failed"
        except Exception as exc:  # noqa: BLE001 - recorded on the journal and retried
            LOG.exception("Deletion %s failed at %s", deletion_id, step)
            _fail(settings, deletion_id, step, owner, exc)
            return "failed"
        if not _finish_step(
            settings, deletion_id, step, owner, state=lifecycle.STEP_DONE, counts=counts
        ):
            LOG.warning("Lost the lease on deletion %s as %s finished", deletion_id, step)
            return "lease_lost"
    LOG.warning("Tenant %s purged (deletion %s)", tenant_id, deletion_id)
    return "completed"


def run_once(settings: Settings, *, owner: str | None = None) -> dict[str, Any]:
    """Claim one due deletion and drive it. Public so tests drive the worker."""
    owner = owner or f"{settings.instance_id or 'api'}:{uuid.uuid4().hex[:8]}"
    deletion_id = _claim(settings, owner)
    if deletion_id is None:
        return {"deletion_id": None, "outcome": "idle"}
    return {"deletion_id": deletion_id, "outcome": drive(settings, deletion_id, owner)}


class TenantPurgeWorker:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._owner = f"{settings.instance_id or 'api'}:{uuid.uuid4().hex[:8]}"
        self._stats: dict[str, Any] = {"runs": 0, "last": None, "errors": 0}

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="octo-tenant-purge", daemon=True)
        self._thread.start()
        LOG.info(
            "Tenant purge worker started (interval=%ds)",
            self._settings.tenant_purge_interval_seconds,
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        LOG.info("Tenant purge worker stopped stats=%s", self._stats)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                # Drain what is due, one deletion at a time, then sleep.
                while not self._stop.is_set():
                    result = run_once(self._settings, owner=self._owner)
                    self._stats["runs"] += 1
                    self._stats["last"] = result
                    if result["outcome"] == "idle":
                        break
            except Exception:  # noqa: BLE001
                self._stats["errors"] += 1
                LOG.exception("Tenant purge tick failed")
            self._stop.wait(max(5, int(self._settings.tenant_purge_interval_seconds)))

    def stats(self) -> dict[str, Any]:
        return dict(self._stats)


def start_worker(settings: Settings) -> None:
    global _worker
    if not settings.tenant_purge_enabled:
        return
    if _worker is None:
        _worker = TenantPurgeWorker(settings)
        _worker.start()


def stop_worker() -> None:
    global _worker
    if _worker is not None:
        _worker.stop()
        _worker = None


def worker_stats() -> dict[str, Any] | None:
    return None if _worker is None else _worker.stats()
