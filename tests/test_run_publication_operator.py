"""The operator's side of an accepted run that is not published (#425, #426).

``test_run_publication_replicas`` proves what the reconciler does with a row on
its own. This file is the part a person does: read what a job still owes,
requeue a ``dead`` publication once whatever refused it is fixed, discard one
that is not coming back — and the two things that make those buttons
dangerous in a deployment of more than one pod:

* ``dead`` is *one* attempt giving up, not every attempt having stopped. A
  second attempt that took the row while the first one's hold lapsed may still
  be uploading, and a requeue beside it is a second live publication of the
  same keys; a discard deletes the row that attempt reads its rollback fence
  from. So both are refused while any attempt still proves it is alive;
* an attempt that stopped proving it — a paused process, not a dead one — must
  not wake up after the requeue and take the requeued attempt's keys back off.
  ``claims`` could not fence that: it starts over on every recorded outcome,
  and the requeue resets it too, so the stale attempt read its own number
  again.

And #426: the renewal that keeps a running publication's hold is counted when
it fails or lands late, and marked on the row, because that lapse is the
precondition of every race above.
"""

from __future__ import annotations

import threading
from datetime import timedelta
from pathlib import Path

import pytest

from api.db import models
from api.db.engine import get_session
from api.schemas import StartScanRequest
from api.services import agents as agents_service
from api.services import artifact_store
from api.services import audit as audit_service
from api.services import jobs as jobs_service
from api.services import metrics as metrics_service
from api.services import run_completion
from api.services import run_publisher
from api.services.artifact_store import keys
from api.services.artifact_store import s3 as s3_store
from api.services.artifact_store import workspace as artifact_workspace
from tests.conftest import auth_headers, configured_client, login, make_settings, requires_postgres
from tests.fake_s3 import FakeS3Client
from tests.test_run_publication_replicas import (
    _leave_it_to_a_pod_that_is_gone,
    _remote_replica,
    _replica,
    _serve,
    _upload,
    _wait_until,
)

pytestmark = requires_postgres


@pytest.fixture(autouse=True)
def _clean_store_cache():
    artifact_store.reset_cache()
    artifact_workspace.reset_marker_cache()
    yield
    artifact_store.reset_cache()
    artifact_workspace.reset_marker_cache()


def _renewals(outcome: str) -> float:
    return (
        metrics_service.REGISTRY.get_sample_value(
            "octo_run_publication_lease_renewal_total", {"outcome": outcome}
        )
        or 0.0
    )


def _row(settings, publication_id: str) -> models.RunPublication | None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication_id)
        if row is not None:
            session.expunge(row)
        return row


def _store_refuses(*_args, **_kwargs):
    raise artifact_store.ArtifactStoreError("bucket unreachable")


def _dead_run(settings, monkeypatch) -> tuple[str, str, str]:
    """An accepted upload whose publication is ``dead``: (job, run, publication).

    The store refuses every attempt and ``run_publication_max_attempts`` is 1,
    so the accepting request's own attempt is the last one — the state the
    runbook starts from. No attempt is running any more.
    """
    settings.run_publication_max_attempts = 1
    with monkeypatch.context() as patch:
        patch.setattr(artifact_workspace, "promote_staging", _store_refuses)
        job = jobs_service.start_scan(
            settings, StartScanRequest(mode="balanced"), username="admin"
        )
        claim = jobs_service.claim_job(settings, "agent-1")
        run_id = str(jobs_service.get_job(settings, job.job_id).run_id)
        _upload(settings, job.job_id, claim.attempt, run_id)
    owed = run_publisher.pending_publications(settings, job.job_id)
    assert [row.status for row in owed] == ["dead"]
    _expire_lease(settings, owed[0].publication_id)
    return job.job_id, run_id, owed[0].publication_id


def _expire_lease(settings, publication_id: str) -> None:
    """Age the proof of life out, as one horizon of silence would."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication_id)
        row.leased_until = jobs_service._now() - timedelta(seconds=300)  # noqa: SLF001


def _peer_gives_up(settings, publication_id: str, reason: str = "peer: bucket unreachable"):
    """End the row ``dead`` the way a peer's last failed attempt does.

    Through ``_record_failure`` itself rather than a column write, so the row
    comes out exactly as a peer leaves it — ``claims`` reset and all.
    """
    with get_session(settings.postgres_url) as session:
        snapshot = run_publisher._snapshot(  # noqa: SLF001
            session.get(models.RunPublication, publication_id)
        )
    run_publisher._record_failure(settings, snapshot, reason, final=True)  # noqa: SLF001


# --------------------------------------------------------------------------
# Requeue and discard against the fence
# --------------------------------------------------------------------------


def test_a_dead_publication_is_requeued_and_published_and_the_job_stops_saying_otherwise(
    tmp_path, monkeypatch
):
    """The runbook's first way out, end to end, with the store still down once.

    A requeue gives the row a full set of attempts again — the ones it spent
    were spent against the outage the operator has just fixed, or thinks they
    have. The first tick after it here still meets a refusing store, which must
    count as attempt 1 of a fresh budget and not end the row on the old one.
    When the publication then lands, the "run not published" note it left on
    the job goes too: it sits in the field the console paints red on a job that
    says ``succeeded``, and it is no longer true.
    """
    settings = _replica(tmp_path, "pod-a")
    _serve(settings)
    job_id, run_id, publication_id = _dead_run(settings, monkeypatch)
    settings.run_publication_max_attempts = 3
    assert "run not published" in (jobs_service.get_job(settings, job_id).error or "")
    fence_before = _row(settings, publication_id).fence

    requeued = run_publisher.requeue_publication(settings, publication_id, job_id=job_id)

    assert requeued is not None
    assert requeued["status"] == "pending"
    assert requeued["attempts"] == 0
    row = _row(settings, publication_id)
    assert row.fence == fence_before + 1
    # The budget starts over; the counter a previous release fences on does not.
    assert row.claims - row.claims_base == 0
    assert row.claims >= 1
    assert not run_publisher.is_backlogged(settings)

    # The store is still refusing on the first tick: one attempt of three.
    with monkeypatch.context() as patch:
        patch.setattr(artifact_workspace, "promote_staging", _store_refuses)
        assert run_publisher.reconcile_once(settings, now=jobs_service._now())["failed"] == 1  # noqa: SLF001
    row = _row(settings, publication_id)
    assert (row.status, row.attempts) == ("pending", 1)

    # And fixed on the next.
    monkeypatch.setattr(run_completion, "notify_channels_best_effort", lambda *_a, **_k: None)
    later = jobs_service._now() + timedelta(hours=1)  # noqa: SLF001
    assert run_publisher.reconcile_once(settings, now=later)["published"] == 1
    assert run_publisher.pending_publications(settings, job_id) == []
    assert artifact_workspace.run_exists(settings, run_id)
    assert "run not published" not in (jobs_service.get_job(settings, job_id).error or "")


def test_a_note_that_cannot_be_cleared_does_not_cost_the_run_its_projections(
    tmp_path, monkeypatch
):
    """The note is cosmetic; the close-out and the projections after it are not.

    The note is cleared in the transaction that deletes the row. An exception
    out of it must neither roll that delete back (the run would be published
    again on every tick, forever, if the job row itself is what fails) nor
    reach the projections, which nothing retries once the row is gone.
    """
    settings = _replica(tmp_path, "pod-a")
    _serve(settings)
    job_id, run_id, publication_id = _dead_run(settings, monkeypatch)
    settings.run_publication_max_attempts = 3
    assert run_publisher.requeue_publication(settings, publication_id) is not None
    projected: list[str] = []

    def _database_hiccup(*_a, **_k):
        raise RuntimeError("connection reset")

    monkeypatch.setattr(run_completion, "clear_publication_notes", _database_hiccup)
    monkeypatch.setattr(
        run_completion,
        "on_run_published",
        lambda _settings, _job_id, **kwargs: projected.append(kwargs["run_id"]),
    )

    assert run_publisher.reconcile_once(settings)["published"] == 1
    assert projected == [run_id]
    assert run_publisher.pending_publications(settings, job_id) == []


def test_a_requeue_is_refused_while_an_attempt_at_the_dead_row_is_still_running(
    tmp_path, monkeypatch
):
    """Two replicas, one row: the button must not start a third attempt.

    The accepting request is mid-publication — parked in the bus hop, the last
    step — when a peer that took the row while the request's hold lapsed
    records its last failure and ends the row ``dead``. That is what the
    console shows. The request is still running, and a requeue beside it would
    let the next tick upload the same keys alongside it.

    Before #425 the running attempt stopped renewing the moment the row said
    ``dead``, so nothing on the row could tell the two cases apart. Its renewal
    now stamps ``leased_until`` whatever the status, the requeue and the
    discard both refuse while it is in the future — and once the request has
    finished (and published: its success closes the row), there is nothing
    left to requeue.
    """
    settings = _replica(tmp_path, "pod-a")
    settings.nats_url = "nats://stub:4222"
    _serve(settings)
    monkeypatch.setattr(run_publisher, "_LEASE_RENEW_SECONDS", 0.05)
    monkeypatch.setattr(run_completion, "notify_channels_best_effort", lambda *_a, **_k: None)

    parked = threading.Event()
    go_on = threading.Event()

    def _slow_bus(_settings, _publication):
        parked.set()
        assert go_on.wait(60), "the test never released the bus hop"

    monkeypatch.setattr(run_publisher, "_publish_to_bus", _slow_bus)
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(settings, "agent-1")
    run_id = str(jobs_service.get_job(settings, job.job_id).run_id)
    accepted: dict[str, object] = {}

    def _accept() -> None:
        try:
            accepted["job"] = _upload(settings, job.job_id, claim.attempt, run_id)
        except Exception as exc:  # noqa: BLE001 - reported by the assertions below
            accepted["error"] = exc

    request = threading.Thread(target=_accept, name="accepting-request")
    request.start()
    try:
        assert parked.wait(30), "the request never reached the bus hop"
        publication_id = run_publisher.pending_publications(settings, job.job_id)[0].publication_id
        _peer_gives_up(settings, publication_id)
        dead = _row(settings, publication_id)
        assert dead.status == "dead"

        # Still renewed while dead: that is the running attempt's proof of life.
        stamped = dead.leased_until
        assert stamped is not None
        assert _wait_until(lambda: _row(settings, publication_id).leased_until > stamped)

        with pytest.raises(run_publisher.PublicationInFlight) as refused:
            run_publisher.requeue_publication(settings, publication_id, job_id=job.job_id)
        assert refused.value.retry_after_seconds >= 1
        with pytest.raises(run_publisher.PublicationInFlight):
            run_publisher.discard_publication(settings, publication_id, job_id=job.job_id)
        # Refused means untouched: still dead, same fence, nothing claimable.
        after = _row(settings, publication_id)
        assert (after.status, after.fence) == ("dead", dead.fence)
        assert run_publisher.reconcile_once(settings)["published"] == 0
    finally:
        go_on.set()
        request.join(60)
    assert "error" not in accepted, accepted.get("error")

    # The attempt the operator would have raced finished the job itself.
    assert run_publisher.pending_publications(settings, job.job_id) == []
    assert run_publisher.requeue_publication(settings, publication_id) is None
    assert artifact_workspace.run_exists(settings, run_id)
    # And the job says so. The peer's ``dead`` left a "not published" note on
    # it, and the attempt that then published the run had taken its snapshot
    # before the row died — with no error on it. Deciding from that snapshot
    # left a published run whose job said it was not, with no row and no
    # button left to explain or clear it.
    assert "run not published" not in (jobs_service.get_job(settings, job.job_id).error or "")


def test_an_attempt_that_slept_through_a_requeue_does_not_take_back_the_new_upload(
    tmp_path, monkeypatch
):
    """The requeue moves the fence; a stale attempt reads the row as not its own.

    The refusal above stops a requeue beside an attempt that proves it is
    alive. It cannot see one that stopped proving it — a process paused for
    longer than a horizon is indistinguishable from a dead one until it wakes.
    Here the accepting request writes one key and freezes; its hold lapses; a
    peer ends the row ``dead``; the operator requeues; the next tick starts
    uploading the same tree. Then the stale request wakes to a store refusing
    it and rolls back "the keys it wrote" — which are the same names the
    requeued attempt is writing.

    Fenced on ``claims`` alone that rollback went ahead: the peer's failure
    reset ``claims`` to 0, the requeue left it there and the new claim made it
    1 — the stale attempt's own number. ``fence`` never goes back, so the stale
    attempt leaves the keys where they are and the requeued upload comes out
    whole.
    """
    shared = FakeS3Client()
    writer = _remote_replica(tmp_path, "pod-a", shared)
    reader = _remote_replica(tmp_path, "pod-b", shared)
    _serve(writer)
    monkeypatch.setattr(s3_store, "_TREE_CONCURRENCY", 1)
    monkeypatch.setattr(run_completion, "notify_channels_best_effort", lambda *_a, **_k: None)
    # A paused process renews nothing after its first stamp.
    monkeypatch.setattr(run_publisher, "_LEASE_RENEW_SECONDS", 3600.0)

    store = artifact_store.get_store(writer)
    real_put = store.put_bytes
    stale_wrote_one = threading.Event()
    requeued_mid_tree = threading.Event()
    stale_done = threading.Event()
    requeued_keys = {"n": 0}

    def _interleaves(key, data, **kwargs):
        if not key.startswith(f"{keys.RUNS}/"):
            return real_put(key, data, **kwargs)
        if requeued_mid_tree.is_set() and not stale_done.is_set():
            raise artifact_store.ArtifactStoreError("bucket started refusing")
        if not stale_wrote_one.is_set():
            written = real_put(key, data, **kwargs)
            stale_wrote_one.set()
            assert requeued_mid_tree.wait(30), "the requeued attempt never got mid-tree"
            return written
        written = real_put(key, data, **kwargs)
        requeued_keys["n"] += 1
        if requeued_keys["n"] == 2:
            requeued_mid_tree.set()
            assert stale_done.wait(30), "the stale attempt never finished"
        return written

    monkeypatch.setattr(store, "put_bytes", _interleaves)

    job = jobs_service.start_scan(writer, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(writer, "agent-1")
    run_id = str(jobs_service.get_job(writer, job.job_id).run_id)
    accepted: dict[str, object] = {}

    def _accept() -> None:
        try:
            accepted["job"] = _upload(writer, job.job_id, claim.attempt, run_id)
        except Exception as exc:  # noqa: BLE001 - reported by the assertions below
            accepted["error"] = exc
        finally:
            stale_done.set()

    request = threading.Thread(target=_accept, name="accepting-request")
    request.start()
    try:
        assert stale_wrote_one.wait(30), "the request never wrote a key"
        publication_id = run_publisher.pending_publications(writer, job.job_id)[0].publication_id
        _peer_gives_up(writer, publication_id)
        _expire_lease(writer, publication_id)
        assert run_publisher.requeue_publication(writer, publication_id) is not None
        # Same number the stale attempt holds: the row it claimed once, and
        # the requeued attempt's first claim.
        assert run_publisher.reconcile_once(writer)["published"] == 1
    finally:
        requeued_mid_tree.set()
        stale_done.set()
        request.join(60)
    assert "error" not in accepted, accepted.get("error")

    artifact_workspace.reset_marker_cache()
    landed = sorted(
        entry.key.rsplit("/", 1)[-1] for entry in store.list_prefix(keys.run_prefix(run_id))
    )
    assert landed == ["fresh.json", "summary.json", "tenant.json"]
    assert artifact_workspace.run_ids(reader) == [run_id]
    assert run_publisher.pending_publications(writer, job.job_id) == []


def test_a_claim_counter_that_came_back_round_is_not_mistaken_for_ones_own(
    tmp_path, monkeypatch
):
    """The same fence without an operator: a peer's failure, then a new claim.

    ``_record_failure`` reset ``claims`` so the claim budget counted claims
    since the last outcome. A stale attempt that snapshotted the row at its
    first claim therefore saw ``1`` again after one failure and one fresh
    claim, and read the row as still its own. This release no longer resets
    it, but a replica on the previous one still does — so the failure here is
    recorded the way that replica records it, and ``fence`` is what has to
    hold.
    """
    settings = _replica(tmp_path, "pod-a")
    _serve(settings)
    job_id, _run_id, publication_id = _dead_run(settings, monkeypatch)
    settings.run_publication_max_attempts = 5
    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication_id)
        row.status = "pending"
        row.attempts = 0
        row.claims = 0
        # Nobody has finished the upload: on the local backend the refused
        # promotion comes after the stamp, which would fence this on its own.
        row.stored_at = None
        row.next_attempt_at = jobs_service._now()  # noqa: SLF001
    with get_session(settings.postgres_url) as session:
        stale = run_publisher._snapshot(  # noqa: SLF001
            run_publisher._claim_due(  # noqa: SLF001
                session, now=jobs_service._now(), limit=10, settings=settings  # noqa: SLF001
            )[0]
        )
    assert stale.claims == 1
    assert run_publisher._may_take_back(settings, stale)  # noqa: SLF001

    # Its hold lapses; a peer claims, fails, and the row is claimed again.
    later = jobs_service._now() + timedelta(hours=1)  # noqa: SLF001
    with get_session(settings.postgres_url) as session:
        peer = run_publisher._snapshot(  # noqa: SLF001
            run_publisher._claim_due(session, now=later, limit=10, settings=settings)[0]  # noqa: SLF001
        )
    run_publisher._record_failure(settings, peer, "peer: bucket unreachable")  # noqa: SLF001
    with get_session(settings.postgres_url) as session:
        # What the previous release's ``_record_failure`` writes on top.
        session.get(models.RunPublication, publication_id).claims = 0
    with get_session(settings.postgres_url) as session:
        again = run_publisher._claim_due(  # noqa: SLF001
            session, now=later + timedelta(hours=1), limit=10, settings=settings
        )
        assert [row.claims for row in again] == [1]

    assert not run_publisher._may_take_back(settings, stale)  # noqa: SLF001


def test_a_discard_is_audited_clears_the_backlog_and_keeps_the_tree(tmp_path, monkeypatch):
    """The second way out: the row goes, the evidence stays.

    Only ``dead`` rows — a pending one is still the reconciler's, and deleting
    it is the silent loss this whole mechanism exists to prevent — and one
    audit row, written in the same transaction as the delete, carrying what the
    operator was looking at when they decided.
    """
    settings = _replica(tmp_path, "pod-a")
    _serve(settings)
    audit_service.configure(settings)
    audit_service.reset_for_tests()
    job_id, _run_id, publication_id = _dead_run(settings, monkeypatch)
    staging = Path(_row(settings, publication_id).staging_path)
    assert run_publisher.is_backlogged(settings)

    assert not run_publisher.discard_publication(settings, publication_id, job_id="another-job")
    assert not run_publisher.discard_publication(settings, publication_id, tenant_id="ten_b")
    assert run_publisher.discard_publication(settings, publication_id, job_id=job_id)

    assert run_publisher.pending_publications(settings, job_id) == []
    assert not run_publisher.is_backlogged(settings)
    assert staging.is_dir()
    events, _total = audit_service.list_events(action="run_publication.discard")
    assert [event["resource_id"] for event in events] == [publication_id]
    assert events[0]["before"]["status"] == "dead"
    assert "bucket unreachable" in events[0]["before"]["last_error"]


def test_a_pending_publication_is_neither_requeued_nor_discarded(tmp_path, monkeypatch):
    """Pending is the reconciler's. A double-click on requeue is not a second decision."""
    settings = _replica(tmp_path, "pod-a")
    _serve(settings)
    job_id, _run_id, publication_id = _dead_run(settings, monkeypatch)
    first = run_publisher.requeue_publication(settings, publication_id, job_id=job_id)
    fence = _row(settings, publication_id).fence

    again = run_publisher.requeue_publication(settings, publication_id, job_id=job_id)

    assert again == first
    assert _row(settings, publication_id).fence == fence
    with pytest.raises(ValueError, match="only a dead publication"):
        run_publisher.discard_publication(settings, publication_id, job_id=job_id)
    assert _row(settings, publication_id).status == "pending"


# --------------------------------------------------------------------------
# What the console reads
# --------------------------------------------------------------------------


def test_a_row_from_a_pod_that_is_gone_is_shown_as_silent_and_then_as_a_rescan(
    tmp_path, monkeypatch
):
    """The HA overlay's orphan, visible before its deadline and named after it.

    On an ``emptyDir`` cache a row from a pod the autoscaler removed can only
    be finished by a re-scan, and the reconciler takes an hour to conclude so.
    For that hour the row is ``pending`` like any retry, so the view says it
    has gone quiet and when it will be declared dead; after it, that requeue is
    not the answer.
    """
    settings = _replica(tmp_path, "pod-a")
    settings.run_publication_orphan_deadline_seconds = 3600
    _serve(settings)
    job_id, _run_id, publication_id = _dead_run(settings, monkeypatch)
    with get_session(settings.postgres_url) as session:
        session.get(models.RunPublication, publication_id).status = "pending"
    _leave_it_to_a_pod_that_is_gone(settings, job_id, age_seconds=1200)

    [view] = run_publisher.publications_for_job(settings, job_id, tenant_id="default")
    assert (view["state"], view["resolution"], view["silent"]) == ("retrying", "wait", True)
    assert view["orphan_deadline_at"] is not None
    assert view["actionable"] is False
    # Pods and paths are the platform admin's.
    assert view["staging_path"] is None and view["replica"] is None

    _leave_it_to_a_pod_that_is_gone(settings, job_id, age_seconds=7200)
    assert run_publisher.reconcile_once(settings)["failed"] == 1
    [view] = run_publisher.publications_for_job(
        settings, job_id, tenant_id=None, show_paths=True
    )
    assert (view["state"], view["resolution"], view["actionable"]) == ("dead", "rescan", True)
    assert view["replica"] == "shapoclyack-api-7d9f-evicted"
    assert view["staging_path"].endswith(".ingest-gone")
    # And nothing of it is visible to another tenant.
    assert run_publisher.publications_for_job(settings, job_id, tenant_id="ten_b") == []


def test_a_bus_hop_with_no_archive_left_says_the_run_is_published(tmp_path, monkeypatch):
    """The dead row whose run is readable must not be reported as needing a re-scan.

    ``_TreeIsGone`` is raised for two different losses and was recorded with
    one message — "needs a re-scan or a manual load" — including for the one
    where every step but the bus hop had landed. An operator would re-scan a
    run they already have; the console's resolution for it is ``discard``.
    """
    settings = _replica(tmp_path, "pod-a")
    settings.nats_url = "nats://stub:4222"
    _serve(settings)
    monkeypatch.setattr(run_completion, "notify_channels_best_effort", lambda *_a, **_k: None)
    real_bus = run_publisher._publish_to_bus  # noqa: SLF001

    def _archive_swept(settings, publication):
        Path(publication.archive_path).unlink(missing_ok=True)
        return real_bus(settings, publication)

    monkeypatch.setattr(run_publisher, "_publish_to_bus", _archive_swept)
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(settings, "agent-1")
    run_id = str(jobs_service.get_job(settings, job.job_id).run_id)
    _upload(settings, job.job_id, claim.attempt, run_id)

    [view] = run_publisher.publications_for_job(settings, job.job_id, tenant_id="default")
    assert view["status"] == "dead"
    assert "the run itself is published" in view["last_error"]
    assert view["resolution"] == "discard"


# --------------------------------------------------------------------------
# #426: the lease renewal, counted and marked
# --------------------------------------------------------------------------


def test_a_lost_or_late_renewal_is_counted_and_marked_on_the_row(tmp_path, monkeypatch):
    """The precondition of every race in this file, no longer a log line only.

    A renewal that raises is counted ``failed`` and marked on the row by the
    next renewal that reaches the database — the failed one could not write
    anything. One that lands after its own previous hold ran out is ``late``:
    a peer could have claimed meanwhile. One that finds the row claimed or
    requeued since is ``superseded``.
    """
    settings = _replica(tmp_path, "pod-a")
    _serve(settings)
    clock = {"at": jobs_service._now()}  # noqa: SLF001
    monkeypatch.setattr(run_publisher, "_now", lambda: clock["at"])
    job_id, _run_id, publication_id = _dead_run(settings, monkeypatch)
    lapses = _row(settings, publication_id).lease_lapses
    with get_session(settings.postgres_url) as session:
        lease = run_publisher._Lease(  # noqa: SLF001
            settings, run_publisher._snapshot(session.get(models.RunPublication, publication_id))  # noqa: SLF001
        )
    counts = {k: _renewals(k) for k in ("renewed", "late", "superseded", "failed")}

    lease._renew()  # noqa: SLF001
    assert _renewals("renewed") == counts["renewed"] + 1

    def _database_is_away(*_a, **_k):
        raise RuntimeError("connection refused")

    with monkeypatch.context() as patch:
        # The owning module's name: ``_renew`` looks ``get_session`` up there.
        patch.setattr(run_publisher, "get_session", _database_is_away)
        lease._renew()  # noqa: SLF001
    assert _renewals("failed") == counts["failed"] + 1
    assert _row(settings, publication_id).lease_lapses == lapses

    # The next one lands, past the hold the first one set: late, and it writes
    # down the failure before it as well.
    clock["at"] += timedelta(seconds=3600)
    lease._renew()  # noqa: SLF001
    assert _renewals("late") == counts["late"] + 1
    assert _row(settings, publication_id).lease_lapses == lapses + 2

    with get_session(settings.postgres_url) as session:
        session.get(models.RunPublication, publication_id).fence += 1
    lease._renew()  # noqa: SLF001
    lease._renew()  # noqa: SLF001
    assert _renewals("superseded") == counts["superseded"] + 2
    # Marked once: it is one event, however long the attempt runs on.
    assert _row(settings, publication_id).lease_lapses == lapses + 3
    [view] = run_publisher.publications_for_job(settings, job_id, tenant_id=None)
    assert view["lease_lapses"] == lapses + 3


# --------------------------------------------------------------------------
# Review of #435: the edges the first version got wrong
# --------------------------------------------------------------------------


def test_a_row_whose_tree_has_been_swept_is_not_offered_as_a_requeue(tmp_path, monkeypatch):
    """The tree is kept a day from the *acceptance*, not from the last attempt.

    ``_sweep_abandoned`` reads the staging directory's ``st_mtime``, which only
    the first ``tenant.json`` moves — so a row that died two days after its
    upload has no tree left on any disk. Suggesting a requeue for it walked the
    row to ``_TreeIsGone`` and a second "not published" note.
    """
    settings = _replica(tmp_path, "pod-a")
    _serve(settings)
    job_id, _run_id, publication_id = _dead_run(settings, monkeypatch)
    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication_id)
        row.stored_at = None
    [fresh] = run_publisher.publications_for_job(settings, job_id, tenant_id=None)
    assert fresh["resolution"] == "requeue"

    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication_id)
        row.created_at = jobs_service._now() - timedelta(hours=25)  # noqa: SLF001
    [old] = run_publisher.publications_for_job(settings, job_id, tenant_id=None)
    assert old["resolution"] == "rescan"


def test_clearing_a_note_leaves_every_other_note_on_the_job(tmp_path, monkeypatch):
    """Only this publication's note goes — not the text around it.

    Reasons carry ``;`` of their own (every named one does), so the note has no
    end the text can mark, and a note appended after it by something else — a
    late partial archive — was eaten along with it.
    """
    settings = _replica(tmp_path, "pod-a")
    _serve(settings)
    monkeypatch.setattr(run_completion, "notify_channels_best_effort", lambda *_a, **_k: None)
    job_id, _run_id, publication_id = _dead_run(settings, monkeypatch)
    reason = _row(settings, publication_id).last_error
    before = "Cancellation requested by op"
    after = "; partial results uploaded late by agent agent-1"
    other = "; run not published (publication 0ther): the replica that accepted this upload is gone"
    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication_id)
        row.last_error = "the store said no; twice; then gave up"
        job = session.get(models.Job, job_id)
        job.error = (
            f"{before}; run not published (publication {publication_id}): {reason}"
            f"{after}"
            f"; run not published (publication {publication_id}): "
            "the store said no; twice; then gave up"
            f"{other}"
        )
    settings.run_publication_max_attempts = 3
    assert run_publisher.requeue_publication(settings, publication_id) is not None
    assert run_publisher.reconcile_once(settings)["published"] == 1

    assert jobs_service.get_job(settings, job_id).error == f"{before}{after}{other}"


def test_a_note_whose_reason_has_changed_since_still_ends_where_it_should(
    tmp_path, monkeypatch
):
    """A requeued row dies again with a new reason; the old note is cleared too.

    Only the latest reason is on the row, so the older note is found by its
    prefix alone — which needs the note to end at the next ``;``, i.e. no
    ``;`` of its own. ``note_publication_failed`` writes them as ``,``.
    """
    settings = _replica(tmp_path, "pod-a")
    _serve(settings)
    job_id, _run_id, publication_id = _dead_run(settings, monkeypatch)
    after = "; partial results uploaded late by agent agent-1"
    with get_session(settings.postgres_url) as session:
        session.get(models.Job, job_id).error = None
    with get_session(settings.postgres_url) as session:
        run_completion.note_publication_failed(
            session, job_id, publication_id=publication_id, reason="first; then; this"
        )
    with get_session(settings.postgres_url) as session:
        job = session.get(models.Job, job_id)
        job.error = f"{job.error}{after}"
    with get_session(settings.postgres_url) as session:
        run_completion.clear_publication_notes(
            session, job_id, publication_id=publication_id, reasons=["a later reason"]
        )
    assert jobs_service.get_job(settings, job_id).error == after


def test_a_tenant_reads_the_reason_but_not_the_pods_paths(tmp_path, monkeypatch):
    """Paths on the pod's disk are the platform admin's, in the reason as well.

    A failure is recorded as ``f"{type}: {exc}"`` and an ``OSError`` carries the
    full path of the staging tree. The route withheld ``staging_path`` from a
    tenant and then printed it in ``last_error`` and in the job's note.
    """
    client, settings = _api(tmp_path, monkeypatch)
    settings.run_publication_max_attempts = 1
    secret = "/var/lib/shapoclyack/cache/.ingest-20260923T080001Z-1a2b3c-abcdef/tenant.json"

    def _disk_refuses(*_a, **_k):
        raise FileNotFoundError(2, "No such file or directory", secret)

    with monkeypatch.context() as patch:
        patch.setattr(artifact_workspace, "promote_staging", _disk_refuses)
        job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
        claim = jobs_service.claim_job(settings, "agent-1")
        _upload(settings, job.job_id, claim.attempt, str(jobs_service.get_job(settings, job.job_id).run_id))

    operator = auth_headers(client, "operator")
    [row] = client.get(f"/api/jobs/{job.job_id}/publications", headers=operator).json()
    assert "FileNotFoundError" in row["last_error"]
    assert "/var/lib/shapoclyack" not in row["last_error"]
    assert "tenant.json" in row["last_error"]
    assert "/var/lib/shapoclyack" not in client.get(f"/api/jobs/{job.job_id}", headers=operator).json()["error"]
    admin = auth_headers(client, "admin")
    [full] = client.get(f"/api/jobs/{job.job_id}/publications", headers=admin).json()
    assert secret in full["last_error"]


def test_the_lease_is_read_on_the_database_clock_not_the_pods(tmp_path, monkeypatch):
    """A pod whose clock runs an hour slow must still hold its row.

    ``leased_until`` is written by the pod running the attempt and compared by
    whichever pod serves the button. Stamped from each one's own clock, a skew
    past one horizon read a live attempt as a lease long expired.
    """
    settings = _replica(tmp_path, "pod-a")
    _serve(settings)
    job_id, _run_id, publication_id = _dead_run(settings, monkeypatch)
    with get_session(settings.postgres_url) as session:
        lease = run_publisher._Lease(  # noqa: SLF001
            settings, run_publisher._snapshot(session.get(models.RunPublication, publication_id))  # noqa: SLF001
        )
    slow = jobs_service._now() - timedelta(hours=1)  # noqa: SLF001
    with monkeypatch.context() as patch:
        patch.setattr(run_publisher, "_now", lambda: slow)
        lease._renew()  # noqa: SLF001

    with pytest.raises(run_publisher.PublicationInFlight):
        run_publisher.requeue_publication(settings, publication_id, job_id=job_id)
    # And the other side: the pod serving the button runs an hour fast.
    fast = jobs_service._now() + timedelta(hours=1)  # noqa: SLF001
    with monkeypatch.context() as patch:
        patch.setattr(run_publisher, "_now", lambda: fast)
        with pytest.raises(run_publisher.PublicationInFlight):
            run_publisher.discard_publication(settings, publication_id, job_id=job_id)
        [view] = run_publisher.publications_for_job(settings, job_id, tenant_id=None)
        assert view["actionable"] is False


def test_a_requeue_does_not_hand_a_previous_release_its_own_claim_number_back(
    tmp_path, monkeypatch
):
    """Mixed fleet: a replica on the previous release fences on ``claims`` alone.

    ``claims`` was reset by every recorded outcome and again by the requeue, so
    the requeued attempt's first claim wrote back the very number an older
    attempt holds — which, on the previous release, is all its rollback asks.
    ``claims`` now only grows; the budget counts from the base the last outcome
    left, so a requeued row still gets its full set of claims.
    """
    settings = _replica(tmp_path, "pod-a")
    _serve(settings)
    job_id, _run_id, publication_id = _dead_run(settings, monkeypatch)
    settings.run_publication_max_attempts = 3
    assert run_publisher.requeue_publication(settings, publication_id) is not None
    with get_session(settings.postgres_url) as session:
        stale = run_publisher._snapshot(  # noqa: SLF001
            run_publisher._claim_due(  # noqa: SLF001
                session, now=jobs_service._now(), limit=10, settings=settings  # noqa: SLF001
            )[0]
        )
    _peer_gives_up(settings, publication_id)
    _expire_lease(settings, publication_id)
    assert run_publisher.requeue_publication(settings, publication_id) is not None
    with get_session(settings.postgres_url) as session:
        fresh = run_publisher._snapshot(  # noqa: SLF001
            run_publisher._claim_due(  # noqa: SLF001
                session, now=jobs_service._now(), limit=10, settings=settings  # noqa: SLF001
            )[0]
        )

    # What the previous release's ``_may_take_back`` compares.
    assert fresh.claims != stale.claims
    # And the budget is per outcome, not per life of the row.
    assert not run_publisher._claims_spent(settings, fresh)  # noqa: SLF001
    [view] = run_publisher.publications_for_job(settings, job_id, tenant_id=None)
    assert view["claims"] == 1


# --------------------------------------------------------------------------
# The routes
# --------------------------------------------------------------------------


def _api(tmp_path: Path, monkeypatch):
    settings = make_settings(tmp_path, job_execution_mode="agent", instance_id="pod-a")
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    return client, settings


def _tenant_admin_elsewhere(client) -> dict[str, str]:
    """``operator``, made admin of ``ten_b`` and of nothing else."""
    admin = auth_headers(client, "admin")
    created = client.post(
        "/api/tenants", headers=admin, json={"name": "ten_b", "tenant_id": "ten_b"}
    )
    assert created.status_code == 201, created.text
    granted = client.put(
        "/api/tenants/ten_b/members/operator", headers=admin, json={"role": "admin"}
    )
    assert granted.status_code == 200, granted.text
    return {"Authorization": f"Bearer {login(client, 'operator')}"}


def test_the_job_card_reads_what_a_job_still_owes(tmp_path, monkeypatch):
    client, settings = _api(tmp_path, monkeypatch)
    job_id, _run_id, publication_id = _dead_run(settings, monkeypatch)

    operator = client.get(f"/api/jobs/{job_id}/publications", headers=auth_headers(client, "operator"))
    assert operator.status_code == 200, operator.text
    [row] = operator.json()
    assert row["publication_id"] == publication_id
    assert (row["status"], row["state"], row["resolution"]) == ("dead", "dead", "requeue")
    assert row["attempts"] == 1 and row["max_attempts"] == 1
    assert "bucket unreachable" in row["last_error"]
    assert row["actionable"] is True
    assert row["staging_path"] is None

    platform = client.get(f"/api/jobs/{job_id}/publications", headers=auth_headers(client, "admin"))
    assert platform.json()[0]["staging_path"] == _row(settings, publication_id).staging_path
    assert platform.json()[0]["replica"] == "pod-a"

    viewer = client.get(f"/api/jobs/{job_id}/publications", headers=auth_headers(client, "viewer"))
    assert viewer.status_code == 403


def test_another_tenant_cannot_read_or_act_on_a_publication(tmp_path, monkeypatch):
    """404 rather than 403, for the job and for the row: ids are not confirmed.

    The job check in the route and the tenant predicate in the service are two
    layers; the second is asserted in the service tests above
    (``tenant_id="ten_b"`` finds nothing), this one through the route.
    """
    client, settings = _api(tmp_path, monkeypatch)
    job_id, _run_id, publication_id = _dead_run(settings, monkeypatch)
    intruder = _tenant_admin_elsewhere(client)

    in_b = {"tenant_id": "ten_b"}
    base = f"/api/jobs/{job_id}/publications"

    assert client.get(base, headers=intruder, params=in_b).status_code == 404
    assert (
        client.post(f"{base}/{publication_id}/requeue", headers=intruder, params=in_b).status_code
        == 404
    )
    assert client.delete(f"{base}/{publication_id}", headers=intruder, params=in_b).status_code == 404
    assert _row(settings, publication_id).status == "dead"


def test_requeue_and_discard_through_the_api_are_admin_audited_and_fenced(tmp_path, monkeypatch):
    client, settings = _api(tmp_path, monkeypatch)
    job_id, _run_id, publication_id = _dead_run(settings, monkeypatch)
    admin = auth_headers(client, "admin")
    base = f"/api/jobs/{job_id}/publications/{publication_id}"

    # An operator reads the card but does not decide about the run.
    assert client.post(f"{base}/requeue", headers=auth_headers(client, "operator")).status_code == 403
    # Another job's path does not reach this row.
    other = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    assert (
        client.post(
            f"/api/jobs/{other.job_id}/publications/{publication_id}/requeue", headers=admin
        ).status_code
        == 404
    )

    # A running attempt is waited out, and the answer says how long.
    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication_id)
        row.leased_until = jobs_service._now() + timedelta(seconds=45)  # noqa: SLF001
    refused = client.post(f"{base}/requeue", headers=admin)
    assert refused.status_code == 409, refused.text
    assert 1 <= int(refused.headers["Retry-After"]) <= 50
    assert client.delete(base, headers=admin).status_code == 409
    _expire_lease(settings, publication_id)

    requeued = client.post(f"{base}/requeue", headers=admin)
    assert requeued.status_code == 200, requeued.text
    assert requeued.json()["status"] == "pending"
    # Pending is the reconciler's: no discard.
    assert client.delete(base, headers=admin).status_code == 409

    _peer_gives_up(settings, publication_id)
    _expire_lease(settings, publication_id)
    assert client.delete(base, headers=admin).status_code == 204
    assert client.delete(base, headers=admin).status_code == 404
    assert client.get(f"/api/jobs/{job_id}/publications", headers=admin).json() == []

    for action in ("run_publication.requeue", "run_publication.discard"):
        events = client.get("/api/audit", headers=admin, params={"action": action})
        assert events.status_code == 200, events.text
        [event] = events.json()["items"]
        assert event["resource_id"] == publication_id
        assert event["actor"] == "admin"
        assert event["before"]["status"] == "dead"
