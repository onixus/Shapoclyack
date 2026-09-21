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
  an ``upload_tree`` racing the ``rmtree`` that promotes the tree;
* a store that starts refusing halfway through a tree must not leave a run that
  every other replica lists and opens with files missing from it.

Each test therefore reads through a second ``Settings`` sharing the bucket and
nothing else, the way ``test_runs_on_object_storage`` does.
"""

from __future__ import annotations

import io
import tarfile
import threading
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
from api.services import run_publisher
from api.services import tenants as tenants_service
from api.services.artifact_store import keys
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
        row.next_attempt_at = now
    return publication_id


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


def test_the_accepting_request_and_a_reconciler_tick_do_not_both_publish(
    tmp_path, monkeypatch
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
    """
    settings = _replica(tmp_path, "pod-a")
    settings.nats_url = "nats://stub:4222"
    _serve(settings)

    on_the_bus: list[str] = []
    notified: list[str] = []
    publishing = threading.Event()
    release = threading.Event()

    def _slow_broker(**kwargs):
        on_the_bus.append(kwargs["run_id"])
        publishing.set()
        release.wait(30)
        return {"published": True, "msg_id": "m", "archive_sha256": "d"}

    monkeypatch.setattr(results_ingest, "publish_raw_results", _slow_broker)
    monkeypatch.setattr(
        jobs_service,
        "_notify_channels_best_effort",
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
    assert publishing.wait(30)

    # A tick in any replica, while the accepting request is still mid-publication.
    assert run_publisher.reconcile_once(settings) == {
        "published": 0,
        "failed": 0,
        "skipped": 0,
    }

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
