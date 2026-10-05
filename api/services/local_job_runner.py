"""Execution wrapper for scans run inside the API process.

The process mechanics live in local_scan_executor. This module owns the job
state transitions around that process and hands the run it produced to
run_publisher, as a durable publication written with the outcome. What the
run then feeds — assets, findings, services, events, notifications, the
scope-denial journal — is decided by run_completion for local and sensor runs
alike (#454); nothing here calls those hooks.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from api.db import models
from api.db.engine import get_session
from api.services import job_inputs
from api.services import job_leases
from api.services import job_repository
from api.services import job_states
from api.services import job_store
from api.services import local_scan_executor
from api.services import run_completion
from api.services import run_publisher
from api.services import runs as runs_service
from api.services import scan_queue
from api.services import tenants as tenants_service
from api.services.artifact_store import workspace as artifact_workspace
from api.settings import Settings

_log = logging.getLogger(__name__)


def _now() -> datetime:
    """Naive UTC, matching the other Postgres-backed services."""
    return datetime.now(UTC).replace(tzinfo=None)


def _publication(
    settings: Settings,
    job_id: str,
    *,
    run_id: str | None,
    status: str,
    exit_code: int,
    error: str | None,
) -> models.RunPublication | None:
    """The publication this scan's terminal write owes, or ``None``.

    ``None`` when there is nothing to publish — no run id, or a scanner that
    exited before it created its directory — and when the directory is not
    this scan's to take: a flat ``runs/<run_id>`` that already names an owner
    is an older run the scanner wrote into, and staging it would write this
    job's tenant over another tenant's marker (#427). That one stays where it
    is, as ``adopt_local_run`` always left it, and the job says so.
    """
    if not run_id:
        return None
    source = Path(settings.output_dir) / "runs" / str(run_id)
    if not source.is_dir():
        return None
    if (source / artifact_workspace.RUN_MARKER).exists():
        _log.warning("Run %s is an existing flat run; leaving %s in place", run_id, source)
        return None
    job = job_repository.get_job(settings, job_id)
    return run_publisher.new_local_publication(
        settings,
        job_id=job_id,
        run_id=str(run_id),
        tenant_id=(
            job.tenant_id
            if job
            else tenants_service.DEFAULT_TENANT_ID
        ),
        job_status=status,
        exit_code=exit_code,
        scan_error=error,
        surface=(
            (job.scan_options or {}).get("surface")
            if job
            else None
        ),
        source=source,
    )


def _keep_refused_run(
    settings: Settings, job_id: str, publication: models.RunPublication
) -> None:
    """Tag the run of a job that was written off while its scanner ran.

    The terminal write was refused, so there is no publication and nothing
    will move ``runs/<run_id>`` under its tenant. Left as it is, a flat run
    with no ``tenant.json`` reads as the *default* tenant's
    (``runs.read_run_tenant``): one tenant's scan in another's run list. So
    the job's tenant is written into it, as staging would have, and it stays
    a flat run that only its owner sees; the job says where it is.

    A sensor's refused upload is a staging tree nobody can see. This is the
    local counterpart, and it has to be made so.
    """
    source = Path(publication.staging_path)
    try:
        runs_service.stage_run_tenant(
            source,
            publication.tenant_id,
            job_id=job_id,
            surface=publication.surface,
        )
    except OSError:
        # Logged loudly rather than raised: the job is already terminal, and
        # the outer handler would only overwrite how it ended.
        _log.error(
            "Run %s of written-off job %s could not be tagged with tenant %s; "
            "it reads as the default tenant's until removed",
            publication.run_id,
            job_id,
            publication.tenant_id,
            exc_info=True,
        )
        return
    run_completion.note_adoption_failed(
        settings,
        job_id,
        f"runs/{publication.run_id} was left in place: the job had already ended "
        "when its scan finished",
    )


def _start(settings: Settings, job_id: str) -> bool:
    """Move this local job queued → running, or answer that it must wait.

    A local job has no claim step — this process is its worker — so this is
    its claim, and it is held to the same ceiling a sensor's claim is (#365):
    with the tenant at ``max_concurrent_scans`` the answer is ``False`` and
    the job stays queued. It also waits while a better job of its tenant is
    queued on this replica, so a slot that frees goes to the highest priority
    rather than to whichever thread asked first. Both are decided in the
    transaction that makes the move, under the tenant's claim lock, so two
    replicas cannot both take the last slot. The lock is only tried: while
    another claim holds it the answer is ``False`` and the thread asks again
    at its next poll (:func:`scan_queue.hold_slot`).

    Every ``False`` renews the job's waiting mark
    (:func:`job_leases.waiting_deadline`): it is how the reaper on any replica
    tells a scan that is still waiting from one whose replica went away.

    Raises :class:`job_states.InvalidJobTransition` for a job that is no
    longer queued — cancelled while it waited, typically.
    """
    with get_session(settings.postgres_url) as session:
        tenant_id = session.execute(
            select(models.Job.tenant_id).where(models.Job.job_id == job_id)
        ).scalar_one_or_none()
        if tenant_id is None:
            raise job_states.InvalidJobTransition(f"Job {job_id} no longer exists")
        # The slot first, the row second: the same order as the sensor claim,
        # so the two never wait on each other in opposite orders.
        slot = scan_queue.hold_slot(session, tenant_id, wait=False)
        # Locked, as ``job_store.update_job`` locks it: an operator cancelling
        # while this thread starts it must see one outcome or the other.
        row = session.get(models.Job, job_id, with_for_update=True)
        if row is None:
            raise job_states.InvalidJobTransition(f"Job {job_id} no longer exists")
        job_states.check_transition(job_id, row.status, job_states.RUNNING)
        if not slot or (
            scan_queue.concurrency_limit(session, tenant_id) is not None
            and scan_queue.local_job_ahead(session, row)
        ):
            row.claimed_until = job_leases.waiting_deadline(settings)
            return False
        row.status = job_states.RUNNING
        row.started_at = _now()
        row.claimed_until = job_leases.lease_deadline(settings)
        row.attempts = 1
    job_store.refresh_job_gauges(settings)
    return True


def _wait_for_slot(settings: Settings, job_id: str) -> bool:
    """Start this job, waiting for its tenant's slot. ``False`` if it never will here.

    A database error while asking is retried at the next poll rather than
    ending the thread. Ending it would leave the job ``queued`` with nobody to
    start it, and — since a waiting job holds back the lower ones of its
    tenant on this replica (``scan_queue.local_job_ahead``) — every job behind
    it too, until its waiting mark lapsed and the reaper failed it.
    """
    waited = False
    while True:
        try:
            if _start(settings, job_id):
                return True
            if not waited:
                _log.info(
                    "Job %s waits for a slot: its tenant is at max_concurrent_scans",
                    job_id,
                )
                waited = True
        except SQLAlchemyError:
            _log.warning(
                "Job %s: could not ask for a slot; retrying in %ss",
                job_id,
                settings.scan_queue_local_poll_seconds,
                exc_info=True,
            )
        if local_scan_executor.wait_unless_draining(settings.scan_queue_local_poll_seconds):
            # The process is stopping its local scans; one that has not
            # started stays queued. Nobody renews its waiting mark after
            # this, so the job reaper fails it once the mark lapses.
            _log.info("Job %s did not start: local scans are being stopped", job_id)
            return False


def run_job(
    settings: Settings, job_id: str, command: list[str]
) -> None:
    """Execute one local scan and account for its terminal outcome."""
    try:
        # A local job goes queued → running with no claim step: this process
        # is the worker. If it was cancelled while the thread was still
        # starting — or while it waited for a slot — the transition is
        # rejected and the scan never launches.
        if not _wait_for_slot(settings, job_id):
            return
    except job_states.InvalidJobTransition as exc:
        _log.info("Not starting job %s: %s", job_id, exc)
        # Cancelled between the insert and this thread getting scheduled: the
        # scan never launches, so nothing will ever read the wordlist copy or
        # the input files.
        job_inputs.discard_wordlist(settings, job_id)
        job_inputs.discard(settings, job_id)
        return

    try:
        with job_leases.renewing_lease(settings, job_id):
            completed = local_scan_executor.run_scanner(
                job_id, command
            )

        # Best-effort: read latest_run.json after completion.
        run_id = None
        pointer = settings.state_dir / "latest_run.json"
        if pointer.exists():
            try:
                run_id = json.loads(
                    pointer.read_text(encoding="utf-8")
                ).get("run_id")
            except json.JSONDecodeError:
                run_id = None

        status = (
            job_states.SUCCEEDED
            if completed.returncode == 0
            else job_states.FAILED
        )
        error = None
        if completed.returncode != 0:
            error = (
                completed.stderr
                or completed.stdout
                or f"exit {completed.returncode}"
            )[:2000]

        publication = _publication(
            settings,
            job_id,
            run_id=run_id,
            status=status,
            exit_code=completed.returncode,
            error=error,
        )
        # The outcome and the publication it owes are one write, as for a
        # sensor's upload (#454): a job the reaper or a restart already wrote
        # off refuses the transition here and leaves no publication behind,
        # and an outcome that is written cannot lose its run to a store
        # outage or to this replica dying before the run was published.
        try:
            job_store.update_job(
                settings,
                job_id,
                publication=publication,
                status=status,
                finished_at=_now(),
                exit_code=completed.returncode,
                run_id=str(run_id) if run_id else None,
                error=error,
            )
        except job_states.InvalidJobTransition as exc:
            # Handled here, not by the handler below: that one would write
            # this refusal over the ``error`` the write-off recorded.
            _log.warning("Job %s ended before its scan did: %s", job_id, exc)
            if publication is not None:
                _keep_refused_run(settings, job_id, publication)
            return

        if (
            publication is None
            and run_id
            and (
                Path(settings.output_dir) / "runs" / str(run_id) / artifact_workspace.RUN_MARKER
            ).exists()
        ):
            # After the terminal write, which sets ``error`` and would erase it.
            run_completion.note_adoption_failed(
                settings,
                job_id,
                f"runs/{run_id} is an existing run with an owner of its own; left in place",
            )
        if publication is not None:
            # In this thread, so the ordinary local scan is published and fed
            # to its derived state before the executor returns. A failure is
            # not raised: what is left undone is a row the reconciler owns.
            run_publisher.publish_now(settings, publication.publication_id)

    except Exception as exc:  # noqa: BLE001
        _log.exception("Scan job %s failed", job_id)
        try:
            job_store.update_job(
                settings,
                job_id,
                status=job_states.FAILED,
                finished_at=_now(),
                error=str(exc)[:2000],
            )
        except job_states.InvalidJobTransition:
            # The scan itself finished and the job is already terminal: the
            # bookkeeping after the terminal write blew up. Record it without
            # rewriting the outcome the job has.
            job_store.update_job(
                settings, job_id, error=str(exc)[:2000]
            )
    finally:
        # The scanner has exited either way, so its copy of the wordlist and
        # its input files have been read for the last time.
        job_inputs.discard_wordlist(settings, job_id)
        job_inputs.discard(settings, job_id)
