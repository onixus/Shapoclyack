"""What happens to an accepted run's publication *after* its row exists.

The fencing tests next door prove the row itself: one per accepted upload,
written with the outcome, none for an upload the fence refuses. They all run on
the local backend and in one replica, where ``publish_run`` is a no-op and the
row is always finished by the process that wrote it. This file is the other
half — the part that only exists because the API runs as more than one pod
against one bucket:

* a row whose staging tree died with its replica (the HA overlay keeps the
  artifact cache in an ``emptyDir``, so that is the *ordinary* case, not an
  exotic one) has to end somewhere an operator can see;
* the accepting request and a reconciler tick must not publish the same row at
  once — two bus messages, two projections, two notifications for one scan, and
  an ``upload_tree`` racing the ``rmtree`` that promotes the tree. Not for the
  first minute: for as long as the publication actually takes, which is why the
  race tests below drive the clock rather than trusting a constant;
* and when that race happens anyway, the side that loses must not take the
  published run with it: a rollback removes the keys *it* wrote, and only
  while the run is still owed;
* a store that starts refusing halfway through a tree must not leave a run that
  every other replica lists and opens with files missing from it — and when the
  same outage refuses the cleanup too, the operator has to be told.

Each test therefore reads through a second ``Settings`` sharing the bucket and
nothing else, the way ``test_runs_on_object_storage`` does.
"""

from __future__ import annotations

import io
import re
import tarfile
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest

from api.db import models
from api.db.engine import get_session
from api.schemas import StartScanRequest
from api.services import agents as agents_service
from api.services import artifact_store
from api.services import jobs as jobs_service
from api.services import results_ingest
from api.services import run_completion
from api.services import run_publisher
from api.services import tenants as tenants_service
from api.services.artifact_store import keys
from api.services.artifact_store import s3 as s3_store
from api.services.artifact_store import workspace as artifact_workspace
from tests.conftest import approve_scan_scope, make_settings, requires_postgres
from tests.fake_s3 import FakeS3Client

pytestmark = requires_postgres


@pytest.fixture(autouse=True)
def _clean_store_cache():
    artifact_store.reset_cache()
    artifact_workspace.reset_marker_cache()
    yield
    artifact_store.reset_cache()
    artifact_workspace.reset_marker_cache()


def _publish_result(*, published: bool) -> dict[str, object]:
    """What ``results_ingest.publish_raw_results`` answers, in full.

    The bus hop reads more of it than ``published``: a refusal is written to
    the outbox under the message's own ``subject`` and ``msg_id``
    (``nats_outbox``), so a stub that leaves them out is answering a different
    contract and fails the caller rather than the broker.
    """
    return {
        "published": published,
        "msg_id": "m",
        "archive_sha256": "d",
        "tenant_id": "default",
        "subject": "ingest.results.default",
    }


def _replica(tmp_path: Path, name: str, shared: FakeS3Client | None = None, **overrides):
    """One API pod: its own disk and cache, the same database and bucket."""
    root = tmp_path / name
    settings = make_settings(
        root,
        state_dir=root / "state",
        output_dir=root / "output",
        job_execution_mode="agent",
        instance_id=name,
        **overrides,
    )
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    if shared is not None:
        artifact_store.get_store(settings)._client = shared  # noqa: SLF001
    return settings


def _remote_replica(tmp_path: Path, name: str, shared: FakeS3Client, **overrides):
    root = tmp_path / name
    return _replica(
        tmp_path,
        name,
        shared,
        artifact_backend="s3",
        artifact_s3_bucket="artifacts",
        artifact_cache_dir=str(root / "cache"),
        artifact_cache_ttl_seconds=0,
        **overrides,
    )


def _serve(settings) -> None:
    """Point the shared services at this replica, as its lifespan would."""
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(settings)
    approve_scan_scope(settings)
    agents_service.configure(settings)
    agents_service.reset_for_tests()
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    jobs_service.reset_for_tests(settings)
    run_publisher.reset_for_tests(settings)


def _archive(marker: str) -> bytes:
    payload = f'{{"attempt": "{marker}"}}\n'.encode("utf-8")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name in (f"{marker}.json", "summary.json"):
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _later():
    return jobs_service._now() + timedelta(hours=1)  # noqa: SLF001


def _upload(settings, job_id: str, attempt: int, run_id: str, marker: str = "fresh"):
    return jobs_service.complete_job(
        settings,
        job_id,
        agent_id="agent-1",
        exit_code=0,
        run_id=run_id,
        archive_bytes=_archive(marker),
        attempt=attempt,
        idempotency_key=f"upload-{marker}",
    )


def _owed_run(settings, monkeypatch) -> tuple[str, str]:
    """An accepted upload whose publication failed. Returns (job id, run id)."""

    def _store_is_down(*_args, **_kwargs):
        raise artifact_store.ArtifactStoreError("bucket unreachable")

    monkeypatch.setattr(artifact_workspace, "promote_staging", _store_is_down)
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(settings, "agent-1")
    run_id = str(jobs_service.get_job(settings, job.job_id).run_id)
    _upload(settings, job.job_id, claim.attempt, run_id)
    monkeypatch.undo()
    return job.job_id, run_id


def _leave_it_to_a_pod_that_is_gone(settings, job_id: str, *, age_seconds: int) -> str:
    """Rewrite the owed row the way a scaled-down pod would leave it behind.

    The row is the only thing that outlives the pod: its staging tree was in
    that pod's ``emptyDir`` and went with it, and its ``replica`` names a pod
    the deployment no longer has.
    """
    owed = run_publisher.pending_publications(settings, job_id)
    assert [row.status for row in owed] == ["pending"]
    publication_id = owed[0].publication_id
    now = jobs_service._now()  # noqa: SLF001
    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication_id)
        row.replica = "shapoclyack-api-7d9f-evicted"
        row.staging_path = str(Path(settings.output_dir) / "runs" / ".ingest-gone")
        row.archive_path = str(Path(settings.output_dir) / "runs" / ".ingest-gone.upload")
        row.created_at = now - timedelta(seconds=age_seconds)
        # And nothing has touched it since, which is what a pod that is gone
        # looks like: a publication in flight renews ``updated_at`` every few
        # seconds, and that — not the age of the upload — is what the orphan
        # deadline runs from.
        row.updated_at = now - timedelta(seconds=age_seconds)
        # Its lease went quiet at the same moment (#425): the proof of life
        # is renewed by the same work that stamps ``updated_at``.
        row.leased_until = now - timedelta(seconds=age_seconds)
        row.next_attempt_at = now
    return publication_id


class _Clock:
    """A clock the test moves, shared by the publisher and its lease.

    A publication that outlives its hold cannot be staged by handing
    ``reconcile_once`` a ``now`` from the future alone: the lease renewing the
    hold reads the same clock, and a test that moves one side only is testing
    the constant rather than the mechanism. So both sides read this.
    """

    def __init__(self) -> None:
        self._at = jobs_service._now()  # noqa: SLF001
        self._lock = threading.Lock()

    def now(self):
        with self._lock:
            return self._at

    def advance(self, seconds: int) -> None:
        with self._lock:
            self._at = self._at + timedelta(seconds=seconds)


def _wait_until(predicate, *, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_a_row_whose_replica_is_gone_is_given_back_while_adoption_can_still_work(
    tmp_path, monkeypatch
):
    """A peer that cannot see the tree neither publishes nor condemns the run.

    This is the behaviour the deadline below must not break: the pod may be
    slow rather than dead, and on a shared volume a peer that *can* see the
    tree is the run's best outcome. A claim is not an attempt either — a
    replica the OOM killer takes down between claiming a batch and publishing
    it used to write off one attempt per row per restart, so five restarts left
    a batch ``dead`` without the store having refused once.
    """
    settings = _replica(tmp_path, "pod-a")
    _serve(settings)
    job_id, _ = _owed_run(settings, monkeypatch)
    publication_id = _leave_it_to_a_pod_that_is_gone(settings, job_id, age_seconds=600)
    before = run_publisher.pending_publications(settings, job_id)[0].attempts

    assert run_publisher.reconcile_once(settings) == {
        "published": 0,
        "failed": 0,
        "skipped": 1,
    }

    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication_id)
        assert row.status == "pending"
        assert row.attempts == before
        # Offered again after an adoption window, not on the next tick.
        assert row.next_attempt_at > jobs_service._now()  # noqa: SLF001
    assert not run_publisher.is_backlogged(settings)


def test_a_claim_a_replica_never_acted_on_does_not_spend_an_attempt(tmp_path, monkeypatch):
    """Five restarts are not five refusals from the store.

    A tick claims up to ten rows in one transaction and publishes them after
    it commits. Counting the attempt at the claim meant a replica the OOM
    killer takes down on a large run wrote off one attempt for every row it
    was holding, on every restart — so a batch reached ``dead``, and told the
    operator the store would not take it, without the store having been asked.
    An attempt is something that was tried and refused.
    """
    settings = _replica(tmp_path, "pod-a")
    _serve(settings)
    job_id, _ = _owed_run(settings, monkeypatch)
    before = run_publisher.pending_publications(settings, job_id)[0]
    assert before.attempts == 1  # the accepting request's, which did fail

    # The tick claims the row and the pod dies before it publishes anything.
    with get_session(settings.postgres_url) as session:
        claimed = run_publisher._claim_due(  # noqa: SLF001
            session, now=_later(), limit=10, settings=settings
        )
        assert len(claimed) == 1

    after = run_publisher.pending_publications(settings, job_id)[0]
    assert after.attempts == before.attempts
    assert after.status == "pending"
    # Held for the length of the batch, so a peer does not take it from under
    # a tick that is still publishing.
    assert after.next_attempt_at > _later()


def test_a_row_no_replica_can_ever_publish_ends_dead_instead_of_circulating(
    tmp_path, monkeypatch
):
    """The bound on adoption, and the failure it exists to end.

    The HA overlay keeps the artifact cache in an ``emptyDir``, so a staging
    tree dies with its pod and a row left by one the autoscaler removed is one
    *no* peer can ever see. Giving it back unconditionally meant it was claimed
    and handed back every adoption window forever: the job went on saying
    ``succeeded`` with no artifacts behind it, ``/api/health`` stayed green
    because only ``dead`` counts, and nothing on the job said why — the exact
    state this module was written to end, made permanent and silent.

    Past ``run_publication_orphan_deadline_seconds`` the row is ``dead``, with
    the same three-way visibility a store outage gets.
    """
    settings = _replica(tmp_path, "pod-a")
    settings.run_publication_orphan_deadline_seconds = 3600
    _serve(settings)
    job_id, _ = _owed_run(settings, monkeypatch)
    publication_id = _leave_it_to_a_pod_that_is_gone(settings, job_id, age_seconds=7200)

    assert run_publisher.reconcile_once(settings) == {
        "published": 0,
        "failed": 1,
        "skipped": 0,
    }

    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication_id)
        assert row.status == "dead"
        assert "replica that accepted this upload is gone" in (row.last_error or "")
    assert run_publisher.backlog(settings) == {"pending": 0, "dead": 1}
    assert run_publisher.is_backlogged(settings)
    # And on the job, which is where the operator looking at a scan with no
    # artifacts starts.
    assert "run not published" in (jobs_service.get_job(settings, job_id).error or "")
    # A dead row is not offered around again.
    assert run_publisher.reconcile_once(settings, now=_later())["failed"] == 0
    # And the operator's way out of it, which is the one the runbook prints.
    assert run_publisher.discard_publication(settings, publication_id)
    assert not run_publisher.discard_publication(settings, publication_id)
    assert run_publisher.backlog(settings) == {"pending": 0, "dead": 0}


@pytest.mark.parametrize("tick_after_seconds", [0, 61, 600])
def test_the_accepting_request_and_a_reconciler_tick_do_not_both_publish(
    tmp_path, monkeypatch, tick_after_seconds
):
    """One accepted upload is one publication, not one per replica that looks.

    The row is inserted due immediately so a request that dies leaves work the
    next tick picks up. Publishing it is minutes of store and broker work, so
    the accepting request has to hold the row for that long — exactly as a
    reconciler tick holds the batch it claimed. Without that hold a tick
    anywhere in the deployment republished the run underneath the request: two
    messages on ``ingest.results``, two projections, two notifications for one
    scan, and an ``upload_tree`` racing the ``rmtree`` that promotes the tree,
    with whichever side lost swallowed silently.

    Parametrised by *when* that tick lands, because the first version of this
    test only ever ticked at the moment of the claim: the hold was a 60-second
    constant, and a tick one second past it published the run a second time
    while the request was still uploading it — which is the case the docstring
    ("minutes") describes and the constant did not cover. The hold is renewed
    while the work runs, so a publication that takes ten minutes is held for
    ten minutes; the clock below is shared by the renewal and the tick,
    because moving only one of them would test the constant again.
    """
    settings = _replica(tmp_path, "pod-a")
    settings.nats_url = "nats://stub:4222"
    _serve(settings)
    clock = _Clock()
    monkeypatch.setattr(run_publisher, "_now", clock.now)
    # Renewed far more often than in production, so the test does not wait out
    # a real horizon to observe one.
    monkeypatch.setattr(run_publisher, "_LEASE_RENEW_SECONDS", 0.05)

    on_the_bus: list[str] = []
    notified: list[str] = []
    publishing = threading.Event()
    release = threading.Event()

    def _slow_broker(**kwargs):
        on_the_bus.append(kwargs["run_id"])
        publishing.set()
        release.wait(30)
        return _publish_result(published=True)

    monkeypatch.setattr(results_ingest, "publish_raw_results", _slow_broker)
    monkeypatch.setattr(
        run_completion,
        "notify_channels_best_effort",
        lambda *_a, **kwargs: notified.append(kwargs["run_id"]),
    )

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
        assert publishing.wait(30)

        # The publication is still running this far into it, and has said so by
        # renewing its hold — which is what the tick below must see.
        clock.advance(tick_after_seconds)
        assert _wait_until(
            lambda: run_publisher.pending_publications(settings, job.job_id)[0].next_attempt_at
            > clock.now()
        ), "the running publication never renewed its hold"

        # A tick in any replica, while the accepting request is still mid-publication.
        assert run_publisher.reconcile_once(settings) == {
            "published": 0,
            "failed": 0,
            "skipped": 0,
        }
    finally:
        # Always, including on a failed assertion: an accepting request left
        # blocked in the broker stub finishes its publication after pytest has
        # undone the monkeypatches, i.e. against the real notification
        # channels, and the run hangs rather than failing.
        release.set()
        request.join(30)
    assert "error" not in accepted, accepted.get("error")
    assert on_the_bus == [run_id]
    assert notified == [run_id]
    assert run_publisher.pending_publications(settings, job.job_id) == []


def test_a_deferred_publication_puts_the_whole_run_in_the_bucket(tmp_path, monkeypatch):
    """The retry path, on the backend it was written for.

    Every other publication test runs on the local backend, where
    ``publish_run`` returns 0 without doing anything — so the store half of
    this module was exercised by nothing at all. Here the bucket refuses, the
    run is owed, and the reconciler finishes it: the second replica, which
    shares only the bucket, then sees the whole run and its tenant marker.
    """
    shared = FakeS3Client()
    writer = _remote_replica(tmp_path, "pod-a", shared)
    reader = _remote_replica(tmp_path, "pod-b", shared)
    _serve(writer)

    store = artifact_store.get_store(writer)
    real_put = store.put_bytes
    bucket = {"up": False}

    def _flaky(key, data, **kwargs):
        # Runs only: the scan's own inputs go up before it is handed out, and
        # refusing those would fail the scan rather than its publication.
        if not bucket["up"] and key.startswith(f"{keys.RUNS}/"):
            raise artifact_store.ArtifactStoreError("bucket unreachable")
        return real_put(key, data, **kwargs)

    monkeypatch.setattr(store, "put_bytes", _flaky)
    job = jobs_service.start_scan(writer, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(writer, "agent-1")
    run_id = str(jobs_service.get_job(writer, job.job_id).run_id)
    done = _upload(writer, job.job_id, claim.attempt, run_id)

    # Accepted, owed, and invisible to everyone — including the replica that
    # accepted it, which must not serve a run the bucket does not have.
    assert done.status == "succeeded"
    assert [row.status for row in run_publisher.pending_publications(writer, job.job_id)] == [
        "pending"
    ]
    artifact_workspace.reset_marker_cache()
    assert artifact_workspace.run_ids(reader) == []

    bucket["up"] = True
    assert run_publisher.reconcile_once(writer, now=_later())["published"] == 1

    artifact_workspace.reset_marker_cache()
    assert artifact_workspace.run_ids(reader) == [run_id]
    landed = sorted(
        entry.key.rsplit("/", 1)[-1] for entry in store.list_prefix(keys.run_prefix(run_id))
    )
    assert landed == ["fresh.json", "summary.json", "tenant.json"]
    assert run_publisher.pending_publications(writer, job.job_id) == []
    assert not run_publisher.is_backlogged(writer)


def test_a_tree_that_went_up_by_halves_is_not_left_in_the_bucket(tmp_path, monkeypatch):
    """A dead publication costs the run its visibility, not half of one.

    ``upload_tree`` writes a key at a time and a run listing is the children of
    ``runs/``, so a bucket that starts refusing in the middle of a tree used to
    leave a run every replica could list and open — with ``summary.json``, or
    whatever else did not make it, simply absent. An operator reading it has no
    way to tell it apart from a scan that found nothing, while the job says the
    run was not published.
    """
    shared = FakeS3Client()
    writer = _remote_replica(tmp_path, "pod-a", shared)
    reader = _remote_replica(tmp_path, "pod-b", shared)
    writer.run_publication_max_attempts = 1
    _serve(writer)

    store = artifact_store.get_store(writer)
    real_put = store.put_bytes

    def _refuses_halfway(key, data, **kwargs):
        if key.endswith("summary.json"):
            raise artifact_store.ArtifactStoreError("bucket started refusing")
        return real_put(key, data, **kwargs)

    monkeypatch.setattr(store, "put_bytes", _refuses_halfway)
    job = jobs_service.start_scan(writer, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(writer, "agent-1")
    run_id = str(jobs_service.get_job(writer, job.job_id).run_id)
    done = _upload(writer, job.job_id, claim.attempt, run_id)

    assert done.status == "succeeded"
    assert [row.status for row in run_publisher.pending_publications(writer, job.job_id)] == [
        "dead"
    ]
    # Nothing of the run is in the bucket, so nothing lists it.
    assert list(store.list_prefix(keys.run_prefix(run_id))) == []
    artifact_workspace.reset_marker_cache()
    assert artifact_workspace.run_ids(reader) == []
    # The scan is not gone, though: the extracted tree is still on the
    # accepting replica's disk for whoever decides between a manual load and a
    # re-scan, and the job says so.
    owed = run_publisher.pending_publications(writer, job.job_id)[0]
    assert (Path(owed.staging_path) / "summary.json").is_file()
    assert "run not published" in (jobs_service.get_job(writer, job.job_id).error or "")


def test_the_loser_of_a_publication_race_does_not_delete_the_published_run(
    tmp_path, monkeypatch
):
    """A rollback takes back this attempt's upload, never a finished one.

    The hold above makes this race rare; it cannot make it impossible, because
    a hold is renewed by a process that may stop renewing. So the losing side
    has to be harmless. It was not: ``unpublish_run`` removed the run's whole
    prefix, so a second attempt that failed after a first one had published the
    whole run deleted it — every key, for every replica — while the job stayed
    ``succeeded`` with an empty ``error``, the row was gone (the winner had
    deleted it) and ``/api/health`` stayed green. Nothing said anything.

    Here the tick publishes the run and promotes the staging tree out from
    under the request, whose own upload then fails on a file that is no longer
    on disk — and it does so in the order production runs in: the request finds
    out the moment the tree is moved, which is while the winner is still
    shipping the archive to the broker, several seconds before the row that
    owes the publication is deleted. Releasing the loser only after the whole
    tick has returned tests the one order in which a rollback fenced on the row
    alone would also have been harmless.
    """
    shared = FakeS3Client()
    writer = _remote_replica(tmp_path, "pod-a", shared)
    reader = _remote_replica(tmp_path, "pod-b", shared)
    _serve(writer)
    # One key at a time, so "halfway through the tree" is a place the test can
    # stand rather than a race between eight threads.
    monkeypatch.setattr(s3_store, "_TREE_CONCURRENCY", 1)
    monkeypatch.setattr(run_completion, "notify_channels_best_effort", lambda *_a, **_k: None)

    store = artifact_store.get_store(writer)
    real_put = store.put_bytes
    at_the_store = threading.Event()
    go_on = threading.Event()
    first = {"key": True}

    def _stalls_on_the_first_key(key, data, **kwargs):
        if first["key"] and key.startswith(f"{keys.RUNS}/"):
            first["key"] = False
            at_the_store.set()
            go_on.wait(60)
        return real_put(key, data, **kwargs)

    monkeypatch.setattr(store, "put_bytes", _stalls_on_the_first_key)

    # The winner's bus publish: megabytes of archive, and the seconds during
    # which the loser finds its staging tree gone and decides what to do about
    # the keys it wrote. The row it would read is still there throughout.
    real_bus = run_publisher._publish_to_bus  # noqa: SLF001
    loser_done = threading.Event()

    def _ships_the_archive_while_the_loser_wakes_up(settings, publication):
        go_on.set()
        assert loser_done.wait(60), "the losing attempt never finished"
        return real_bus(settings, publication)

    monkeypatch.setattr(
        run_publisher, "_publish_to_bus", _ships_the_archive_while_the_loser_wakes_up
    )
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
            loser_done.set()

    request = threading.Thread(target=_accept, name="accepting-request")
    request.start()
    try:
        assert at_the_store.wait(30), "the request never reached the store"

        # A tick that finds the row due anyway — a renewal that never landed, a
        # clock the pods do not share — and publishes the whole run.
        winner = run_publisher.reconcile_once(
            writer, now=jobs_service._now() + timedelta(seconds=61)  # noqa: SLF001
        )
        assert winner["published"] == 1
        artifact_workspace.reset_marker_cache()
        assert artifact_workspace.run_ids(reader) == [run_id]
    finally:
        # Always: a request left blocked in the store stub would finish its
        # publication after pytest undid the monkeypatches around it, and a
        # tick left waiting on it would never return.
        go_on.set()
        loser_done.set()
        request.join(60)
    assert "error" not in accepted, accepted.get("error")

    # The run the winner published is still there, whole, for every replica.
    artifact_workspace.reset_marker_cache()
    assert artifact_workspace.run_ids(reader) == [run_id]
    landed = sorted(
        entry.key.rsplit("/", 1)[-1] for entry in store.list_prefix(keys.run_prefix(run_id))
    )
    assert landed == ["fresh.json", "summary.json", "tenant.json"]
    assert run_publisher.pending_publications(writer, job.job_id) == []
    assert not run_publisher.is_backlogged(writer)


def test_a_loser_does_not_take_keys_back_out_of_a_tree_that_is_still_going_up(
    tmp_path, monkeypatch
):
    """The winner's upload is fenced from the first key, not from the last.

    The fence above is ``stored_at``, and it is stamped when the winner's
    *whole* tree is in the store — so for the length of that upload it is
    honestly NULL, while the keys already written carry the same names the
    loser wrote. "Only what this attempt wrote" is therefore no defence at
    all: a loser whose own store refused it halfway — the very failure the
    rollback exists for, and one two attempts hammering one bucket make more
    likely, not less — deleted files out of the run the winner was in the
    middle of publishing, and the run came out short with the job
    ``succeeded``, no row owing it and the backlog gauge empty.

    So the rollback also asks whether the row has been claimed since: every
    attempt claims before it touches the store, which makes the other attempt
    visible from its first key rather than from its last.
    """
    shared = FakeS3Client()
    writer = _remote_replica(tmp_path, "pod-a", shared)
    reader = _remote_replica(tmp_path, "pod-b", shared)
    _serve(writer)
    # One key at a time, so the two uploads interleave where the test puts
    # them rather than across eight threads.
    monkeypatch.setattr(s3_store, "_TREE_CONCURRENCY", 1)
    monkeypatch.setattr(run_completion, "notify_channels_best_effort", lambda *_a, **_k: None)

    store = artifact_store.get_store(writer)
    real_put = store.put_bytes
    loser_wrote_one = threading.Event()
    winner_mid_tree = threading.Event()
    loser_done = threading.Event()
    winner_keys = {"n": 0}

    def _refuses_the_loser_mid_tree(key, data, **kwargs):
        if not key.startswith(f"{keys.RUNS}/"):
            return real_put(key, data, **kwargs)
        # Told apart by the interleaving rather than by thread name:
        # ``upload_tree`` runs in a pool, so the caller here is not the
        # accepting request's own thread.
        if winner_mid_tree.is_set() and not loser_done.is_set():
            raise artifact_store.ArtifactStoreError("bucket started refusing")
        if not loser_wrote_one.is_set():
            written = real_put(key, data, **kwargs)
            loser_wrote_one.set()
            assert winner_mid_tree.wait(30), "the winner never got mid-tree"
            return written
        written = real_put(key, data, **kwargs)
        winner_keys["n"] += 1
        if winner_keys["n"] == 2:
            # Half a tree up, nothing stamped, and the loser wakes to a store
            # that has started refusing it.
            winner_mid_tree.set()
            assert loser_done.wait(30), "the losing attempt never finished"
        return written

    monkeypatch.setattr(store, "put_bytes", _refuses_the_loser_mid_tree)

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
            loser_done.set()

    request = threading.Thread(target=_accept, name="accepting-request")
    request.start()
    try:
        assert loser_wrote_one.wait(30), "the request never wrote a key"
        # A tick that finds the row due anyway, and uploads the same tree.
        winner = run_publisher.reconcile_once(
            writer, now=jobs_service._now() + timedelta(seconds=61)  # noqa: SLF001
        )
        assert winner["published"] == 1
    finally:
        # Always: a request left blocked in the store stub finishes after
        # pytest has undone the monkeypatches around it.
        winner_mid_tree.set()
        loser_done.set()
        request.join(60)
    assert "error" not in accepted, accepted.get("error")

    artifact_workspace.reset_marker_cache()
    landed = sorted(
        entry.key.rsplit("/", 1)[-1] for entry in store.list_prefix(keys.run_prefix(run_id))
    )
    assert landed == ["fresh.json", "summary.json", "tenant.json"]
    assert artifact_workspace.run_ids(reader) == [run_id]
    assert run_publisher.pending_publications(writer, job.job_id) == []
    assert not run_publisher.is_backlogged(writer)


def test_a_peer_does_not_call_a_run_published_while_its_owner_is_still_uploading(
    tmp_path, monkeypatch
):
    """"The tree is in the store" is the stamp, not one key under the prefix.

    A row a peer adopts is one whose staging tree it cannot see, so the peer
    has nothing to upload and the only question left is whether somebody
    already did. Asked of the store — any key under ``runs/<run_id>/`` — the
    answer is yes from the *first* key of an upload that is still running. A
    peer adopting the row of a pod that had merely stopped renewing therefore
    skipped the upload of a half-written tree, put the run on the bus and
    deleted the row: every replica listed a run with most of it missing, and
    nothing owed it any more, so the owner's own failure a moment later had
    nowhere left to be recorded.

    ``stored_at`` is stamped for the whole tree, so the peer sees the
    publication for what it is — unfinished, and not its own — and hands the
    row back to the replica that is working on it.
    """
    shared = FakeS3Client()
    owner = _remote_replica(tmp_path, "pod-a", shared)
    peer = _remote_replica(tmp_path, "pod-b", shared)
    _serve(owner)
    monkeypatch.setattr(s3_store, "_TREE_CONCURRENCY", 1)
    monkeypatch.setattr(run_completion, "notify_channels_best_effort", lambda *_a, **_k: None)

    store = artifact_store.get_store(owner)
    real_put = store.put_bytes
    parked = threading.Event()
    go_on = threading.Event()
    first = {"key": True}

    def _parks_after_the_first_key(key, data, **kwargs):
        written = real_put(key, data, **kwargs)
        if first["key"] and key.startswith(f"{keys.RUNS}/"):
            first["key"] = False
            parked.set()
            go_on.wait(60)
        return written

    monkeypatch.setattr(store, "put_bytes", _parks_after_the_first_key)

    job = jobs_service.start_scan(owner, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(owner, "agent-1")
    run_id = str(jobs_service.get_job(owner, job.job_id).run_id)
    accepted: dict[str, object] = {}

    def _accept() -> None:
        try:
            accepted["job"] = _upload(owner, job.job_id, claim.attempt, run_id)
        except Exception as exc:  # noqa: BLE001 - reported by the assertions below
            accepted["error"] = exc

    request = threading.Thread(target=_accept, name="accepting-request")
    request.start()
    try:
        assert parked.wait(30), "the owner never reached the store"
        # What the peer finds: a row whose replica has stopped renewing and
        # whose staging tree is in that pod's ``emptyDir``, i.e. not on this
        # disk. The owner goes on publishing from the snapshot it took.
        owed = run_publisher.pending_publications(owner, job.job_id)[0]
        publication_id = owed.publication_id
        before = owed.attempts
        now = jobs_service._now()  # noqa: SLF001
        with get_session(owner.postgres_url) as session:
            row = session.get(models.RunPublication, publication_id)
            row.replica = "shapoclyack-api-7d9f-unreachable"
            row.staging_path = str(Path(peer.output_dir) / "runs" / ".ingest-gone")
            row.archive_path = str(Path(peer.output_dir) / "runs" / ".ingest-gone.upload")
            row.created_at = now - timedelta(seconds=600)
            row.updated_at = now - timedelta(seconds=600)
            row.next_attempt_at = now
        artifact_workspace.reset_marker_cache()

        assert run_publisher.reconcile_once(peer) == {
            "published": 0,
            "failed": 0,
            "skipped": 1,
        }
        with get_session(owner.postgres_url) as session:
            row = session.get(models.RunPublication, publication_id)
            assert row.status == "pending"
            assert row.attempts == before
            assert row.stored_at is None
    finally:
        go_on.set()
        request.join(60)
    assert "error" not in accepted, accepted.get("error")

    # And the owner, left to it, puts the whole tree up and closes the row.
    artifact_workspace.reset_marker_cache()
    landed = sorted(
        entry.key.rsplit("/", 1)[-1] for entry in store.list_prefix(keys.run_prefix(run_id))
    )
    assert landed == ["fresh.json", "summary.json", "tenant.json"]
    assert artifact_workspace.run_ids(peer) == [run_id]
    assert run_publisher.pending_publications(owner, job.job_id) == []
    assert not run_publisher.is_backlogged(owner)


def test_a_rollback_removes_the_keys_this_attempt_wrote_and_no_others(
    tmp_path, monkeypatch
):
    """Only this upload's keys, and the operator is told when a half is left.

    Run ids are minted per second, and until this release two jobs claimed in
    the same one shared a prefix — so "delete everything under
    ``runs/<run_id>``" was a cross-tenant delete waiting for a bad second. The
    rollback now removes the keys this transfer actually wrote, which is also
    the only set it can know: the return value of ``upload_tree`` is gone with
    the exception that raised, and the staging tree describes the keys it
    *would* have written, not the ones it did.

    The stranger's key left behind is the other half of the bargain: the run is
    still listable, so ``a dead row never leaves a half of a run`` is not
    something this can promise, and the job says so instead of pretending.
    """
    shared = FakeS3Client()
    writer = _remote_replica(tmp_path, "pod-a", shared)
    writer.run_publication_max_attempts = 1
    _serve(writer)

    job = jobs_service.start_scan(writer, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(writer, "agent-1")
    run_id = str(jobs_service.get_job(writer, job.job_id).run_id)

    store = artifact_store.get_store(writer)
    # Somebody else's key under this prefix: the run of a job that shared the
    # run id, or a hand-loaded artifact an operator put there.
    store.put_bytes(keys.run_artifact(run_id, "not-ours.json"), b"{}\n")
    real_put = store.put_bytes

    def _refuses_halfway(key, data, **kwargs):
        if key.endswith("summary.json"):
            raise artifact_store.ArtifactStoreError("bucket started refusing")
        return real_put(key, data, **kwargs)

    monkeypatch.setattr(store, "put_bytes", _refuses_halfway)
    done = _upload(writer, job.job_id, claim.attempt, run_id)

    assert done.status == "succeeded"
    left = sorted(entry.key.rsplit("/", 1)[-1] for entry in store.list_prefix(
        keys.run_prefix(run_id)
    ))
    assert left == ["not-ours.json"]
    owed = run_publisher.pending_publications(writer, job.job_id)[0]
    assert owed.status == "dead"
    assert "listed by every replica with files missing" in (owed.last_error or "")
    assert "run not published" in (jobs_service.get_job(writer, job.job_id).error or "")


def test_a_store_that_refuses_the_cleanup_too_says_so_on_the_job(tmp_path, monkeypatch):
    """The outage that refused the upload refuses the rollback as well.

    Taking the half back off is best-effort by construction — the store is
    already refusing — so ``dead`` can leave a run other replicas list and open
    with files missing from it. That is not a promise this module can keep, and
    the honest version of keeping it is telling the operator: the reason on the
    row, and the note on the job, both say the run may be listed short.
    """
    shared = FakeS3Client()
    writer = _remote_replica(tmp_path, "pod-a", shared)
    reader = _remote_replica(tmp_path, "pod-b", shared)
    writer.run_publication_max_attempts = 1
    _serve(writer)

    store = artifact_store.get_store(writer)
    real_put = store.put_bytes

    def _refuses_halfway(key, data, **kwargs):
        if key.endswith("summary.json"):
            raise artifact_store.ArtifactStoreError("bucket started refusing")
        return real_put(key, data, **kwargs)

    monkeypatch.setattr(store, "put_bytes", _refuses_halfway)
    shared.fail_deletes_with = RuntimeError("bucket started refusing")

    job = jobs_service.start_scan(writer, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(writer, "agent-1")
    run_id = str(jobs_service.get_job(writer, job.job_id).run_id)
    _upload(writer, job.job_id, claim.attempt, run_id)

    owed = run_publisher.pending_publications(writer, job.job_id)[0]
    assert owed.status == "dead"
    assert "could not be taken back" in (owed.last_error or "")
    # And it is a half — said out loud rather than asserted away.
    artifact_workspace.reset_marker_cache()
    assert artifact_workspace.run_ids(reader) == [run_id]
    assert run_publisher.is_backlogged(writer)


def test_a_publisher_that_dies_before_it_records_anything_does_not_loop_forever(
    tmp_path, monkeypatch
):
    """The bound on the other end of "a claim is not an attempt".

    Counting an attempt at the claim was wrong (five OOM restarts must not
    condemn a batch the store never refused), and removing it left the
    symmetric hole: a tree large enough to kill the replica publishing it — the
    example that motivated the change — is claimed, kills the replica before
    anything is recorded, and is claimed again one horizon later. Nothing
    counted it: ``attempts`` stayed where it was, ``_is_orphaned`` only ever
    looks at another replica's rows, and ``is_backlogged`` counts only ``dead``.
    Fifty such cycles left ``attempts=1``, a green ``/api/health`` and an empty
    ``jobs.error``.

    Claims are counted now, given back when a peer hands a row back untouched,
    and reset by any attempt that reaches an outcome.
    """
    settings = _replica(tmp_path, "pod-a")
    _serve(settings)
    job_id, _ = _owed_run(settings, monkeypatch)
    budget = run_publisher._claim_budget(settings)  # noqa: SLF001
    now = jobs_service._now()  # noqa: SLF001

    for _ in range(budget):
        now = now + timedelta(seconds=300)
        with get_session(settings.postgres_url) as session:
            assert len(
                run_publisher._claim_due(  # noqa: SLF001
                    session, now=now, limit=10, settings=settings
                )
            ) == 1
    row = run_publisher.pending_publications(settings, job_id)[0]
    assert (row.status, row.attempts) == ("pending", 1), "written off too early"

    outcome = run_publisher.reconcile_once(settings, now=now + timedelta(seconds=300))
    assert outcome["failed"] == 1
    row = run_publisher.pending_publications(settings, job_id)[0]
    assert row.status == "dead"
    assert "dying mid-publication" in (row.last_error or "")
    assert run_publisher.is_backlogged(settings)
    assert "run not published" in (jobs_service.get_job(settings, job_id).error or "")


def test_a_peer_does_not_condemn_a_row_its_owner_is_still_working_on(tmp_path, monkeypatch):
    """The orphan deadline runs from the last sign of life, not from the upload.

    It was measured from ``created_at``, i.e. from the moment the upload was
    accepted — so an installation that raised
    ``OCTO_RUN_PUBLICATION_MAX_ATTEMPTS`` to ride out a long store outage had
    its rows declared *dead, the replica is gone* by a peer that cannot see
    the tree, while the owner was retrying and had touched the row
    milliseconds earlier. The extracted tree was on a running pod's disk and
    the runbook told the operator to re-scan.
    """
    owner = _replica(tmp_path, "pod-a")
    _serve(owner)
    owner.run_publication_max_attempts = 50
    job_id, _ = _owed_run(owner, monkeypatch)
    owed = run_publisher.pending_publications(owner, job_id)[0]
    now = jobs_service._now()  # noqa: SLF001
    with get_session(owner.postgres_url) as session:
        row = session.get(models.RunPublication, owed.publication_id)
        row.replica = "pod-a"
        row.created_at = now - timedelta(hours=2)  # accepted two hours ago
        row.updated_at = now  # ...and being published right now
        row.next_attempt_at = now
        row.staging_path = str(tmp_path / "pod-a" / "not-visible-from-pod-b")

    peer = _replica(tmp_path, "pod-b")
    assert run_publisher.reconcile_once(peer) == {"published": 0, "failed": 0, "skipped": 1}

    with get_session(owner.postgres_url) as session:
        row = session.get(models.RunPublication, owed.publication_id)
        assert row.status == "pending"
    assert not run_publisher.is_backlogged(peer)


def test_two_jobs_claimed_in_the_same_second_get_different_run_ids(tmp_path):
    """A run id is a prefix, and a shared prefix is a shared run.

    ``%Y%m%dT%H%M%SZ`` is not unique, and two agents claiming inside one second
    got the same id: two scans merged into one run directory and one key
    prefix — across tenants, since the prefix carries no owner yet (#311) — and
    the loser of a publication took the winner's keys with it. The clock still
    leads, so the listing's ordering is unchanged.
    """
    settings = _replica(tmp_path, "pod-a")
    _serve(settings)
    agents_service.register_agent(agent_id="agent-2", tenant_id="default")
    jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")

    first = jobs_service.claim_job(settings, "agent-1")
    second = jobs_service.claim_job(settings, "agent-2")
    assert first.run_id != second.run_id
    # The shape, not the two stamps being equal: the gap between the claims is
    # milliseconds, so a pair that straddles a second boundary would fail an
    # equality assertion without anything being wrong. What matters is that
    # both ids carry the suffix and that the clock still leads.
    shape = re.compile(r"\d{8}T\d{6}Z-[0-9a-f]{6}")
    assert shape.fullmatch(first.run_id) and shape.fullmatch(second.run_id)
    assert first.run_id.split("-")[0] <= second.run_id.split("-")[0]
