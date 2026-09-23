"""Fencing at the *final write*, not only at the door (architecture review P1).

``complete_job`` checked the claim's attempt in its first transaction and then
spent minutes on the archive: a NATS publish, extraction, artifact writes over
the network, projections. The lease could lapse inside that window, the reaper
could hand the job to a second attempt, and the first one's terminal write —
which re-took the row lock but compared nothing — would finish somebody else's
attempt and publish its own archive over the run the new attempt was producing.

The scenario is the one the review asks for: stall the first completion after
its first transaction, expire the lease, hand the job out again, then let the
first one run to the end.
"""

from __future__ import annotations

import io
import json
import tarfile
from datetime import timedelta
from pathlib import Path

import pytest

from api.db import models
from api.db.engine import get_session
from api.schemas import StartScanRequest
from api.services import agents as agents_service
from api.services import jobs as jobs_service
from api.services import nats_outbox
from api.services import results_ingest
from api.services import run_completion
from api.services import run_publisher
from api.services import artifact_store
from api.services import runs as runs_service
from api.services import tenants as tenants_service
from api.services.artifact_store import keys as artifact_keys
from api.services.artifact_store import workspace as artifact_workspace
from api.services.jobs import get_job
from tests.conftest import approve_scan_scope, make_settings, requires_postgres

pytestmark = requires_postgres


@pytest.fixture()
def settings(tmp_path: Path):
    base = make_settings(
        tmp_path,
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "output",
        job_execution_mode="agent",
    )
    base.state_dir.mkdir(parents=True, exist_ok=True)
    base.output_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(base)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(base)
    approve_scan_scope(base)
    agents_service.configure(base)
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    # Publications are counted installation-wide by ``backlog``, so a run owed
    # by an earlier test would be read here as this one's.
    jobs_service.reset_for_tests(base)
    run_publisher.reset_for_tests(base)
    return base



def _ref(run_id, tenant: str = "default") -> artifact_keys.RunRef:
    """Where an agent's run lands: under the job's tenant (#427)."""
    return artifact_keys.run_ref(str(run_id), tenant)


def _archive(marker: str) -> bytes:
    """A run archive whose one distinctive file names the attempt that made it."""
    payload = f'{{"attempt": "{marker}"}}\n'.encode("utf-8")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name in (f"{marker}.json", "summary.json"):
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _outbox_rows(settings) -> list[models.NatsOutboxEntry]:
    """Messages the broker refused and the outbox is holding for it."""
    with get_session(settings.postgres_url) as session:
        rows = session.query(models.NatsOutboxEntry).all()
        session.expunge_all()
        return rows


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


def _later():
    """A moment past any backoff a failed publication can have earned."""
    return jobs_service._now() + timedelta(hours=1)  # noqa: SLF001


def _ingest_leftovers(settings) -> list[str]:
    """Whatever an ingest left beside the runs: staging trees and archives."""
    root = Path(settings.output_dir) / "runs"
    if not root.is_dir():
        return []
    # Beside the run, which since #427 is under the tenant: a helper that only
    # looked at ``runs/`` itself would now answer "nothing left" for ever.
    return sorted(child.name for child in root.rglob(".ingest-*"))


def _expire_lease(settings, job_id: str) -> None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        row.claimed_until = jobs_service._now() - timedelta(seconds=1)  # noqa: SLF001


def _reissue_to_a_second_attempt(settings, job_id: str) -> int:
    """What the reaper does while the first completion is still ingesting."""
    _expire_lease(settings, job_id)
    jobs_service.reap_expired_leases(settings)
    claim = jobs_service.claim_job(settings, "agent-1")
    assert claim is not None and claim.job_id == job_id
    return claim.attempt


def test_a_stalled_ingest_cannot_finish_the_attempt_that_replaced_it(settings, monkeypatch):
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    first = jobs_service.claim_job(settings, "agent-1")
    run_id = get_job(settings, job.job_id).run_id
    reissued: dict[str, int] = {}

    real_extract = results_ingest.extract_run_archive

    def _stall_then_extract(archive_bytes: bytes, dest: Path, **kwargs):
        # Mid-ingest: the first transaction is committed and the terminal write
        # has not happened yet. This is the window the reaper used to win.
        if not reissued:
            reissued["attempt"] = _reissue_to_a_second_attempt(settings, job.job_id)
        return real_extract(archive_bytes, dest, **kwargs)

    monkeypatch.setattr(results_ingest, "extract_run_archive", _stall_then_extract)

    with pytest.raises(jobs_service.StaleAttempt):
        jobs_service.complete_job(
            settings,
            job.job_id,
            agent_id="agent-1",
            exit_code=0,
            run_id=run_id,
            archive_bytes=_archive("stale"),
            attempt=first.attempt,
            idempotency_key="upload-stale",
        )

    assert reissued["attempt"] == 2
    row = get_job(settings, job.job_id)
    # The outcome belongs to the attempt that is still out there.
    assert row.status == "claimed"
    assert row.exit_code is None
    assert row.finished_at is None
    # And nothing the rejected ingest extracted may be visible as this run's
    # artifacts: the staging directory is bound to the attempt, not to the run.
    run_dir = artifact_workspace.run_dir(settings, _ref(run_id), refresh=False)
    assert not (run_dir / "stale.json").exists()


def test_the_reissued_attempt_still_completes_after_the_stale_one_is_rejected(
    settings, monkeypatch
):
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    first = jobs_service.claim_job(settings, "agent-1")
    run_id = get_job(settings, job.job_id).run_id
    reissued: dict[str, int] = {}

    real_extract = results_ingest.extract_run_archive

    def _stall_then_extract(archive_bytes: bytes, dest: Path, **kwargs):
        if not reissued:
            reissued["attempt"] = _reissue_to_a_second_attempt(settings, job.job_id)
        return real_extract(archive_bytes, dest, **kwargs)

    monkeypatch.setattr(results_ingest, "extract_run_archive", _stall_then_extract)
    with pytest.raises(jobs_service.StaleAttempt):
        jobs_service.complete_job(
            settings,
            job.job_id,
            agent_id="agent-1",
            exit_code=0,
            run_id=run_id,
            archive_bytes=_archive("stale"),
            attempt=first.attempt,
            idempotency_key="upload-stale",
        )
    monkeypatch.setattr(results_ingest, "extract_run_archive", real_extract)

    done = jobs_service.complete_job(
        settings,
        job.job_id,
        agent_id="agent-1",
        exit_code=0,
        run_id=run_id,
        archive_bytes=_archive("fresh"),
        attempt=reissued["attempt"],
        idempotency_key="upload-fresh",
    )
    assert done.status == "succeeded"

    run_dir = artifact_workspace.run_dir(settings, _ref(run_id), refresh=False)
    assert (run_dir / "fresh.json").exists()
    assert not (run_dir / "stale.json").exists()


def test_a_rejected_ingest_gives_its_reservation_back(settings, monkeypatch):
    """The key it held names an upload that landed nowhere. Left behind, the
    agent's next upload would meet its own abandoned reservation."""
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    first = jobs_service.claim_job(settings, "agent-1")
    run_id = get_job(settings, job.job_id).run_id

    real_extract = results_ingest.extract_run_archive
    done: dict[str, int] = {}

    def _stall_then_extract(archive_bytes: bytes, dest: Path, **kwargs):
        if not done:
            done["attempt"] = _reissue_to_a_second_attempt(settings, job.job_id)
        return real_extract(archive_bytes, dest, **kwargs)

    monkeypatch.setattr(results_ingest, "extract_run_archive", _stall_then_extract)
    with pytest.raises(jobs_service.StaleAttempt):
        jobs_service.complete_job(
            settings,
            job.job_id,
            agent_id="agent-1",
            exit_code=0,
            run_id=run_id,
            archive_bytes=_archive("stale"),
            attempt=first.attempt,
            idempotency_key="upload-stale",
        )

    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job.job_id)
        assert row.results_idempotency_key is None
        # The ingest lease is the rejected attempt's, and it is gone with it.
        assert row.ingest_token is None


def test_an_ingest_in_flight_holds_the_lease_open(settings, monkeypatch):
    """The upload *is* proof of life. Without a lease covering the transfer and
    the processing, an ingest longer than the remaining lease makes the reaper
    requeue a job whose result is at that moment being written."""
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(settings, "agent-1")
    run_id = get_job(settings, job.job_id).run_id
    seen: dict[str, object] = {}

    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job.job_id)
        # One second of lease left: an ordinary ingest outlives it.
        row.claimed_until = jobs_service._now() + timedelta(seconds=1)  # noqa: SLF001
        before = row.claimed_until

    real_extract = results_ingest.extract_run_archive

    def _observe_then_extract(archive_bytes: bytes, dest: Path, **kwargs):
        with get_session(settings.postgres_url) as session:
            row = session.get(models.Job, job.job_id)
            seen["claimed_until"] = row.claimed_until
            seen["token"] = row.ingest_token
            seen["attempt"] = row.ingest_attempt
        return real_extract(archive_bytes, dest, **kwargs)

    monkeypatch.setattr(results_ingest, "extract_run_archive", _observe_then_extract)
    jobs_service.complete_job(
        settings,
        job.job_id,
        agent_id="agent-1",
        exit_code=0,
        run_id=run_id,
        archive_bytes=_archive("fresh"),
        attempt=claim.attempt,
        idempotency_key="upload-fresh",
    )

    assert seen["claimed_until"] > before
    assert seen["token"]
    assert seen["attempt"] == claim.attempt
    # Cleared with the terminal write: a finished job holds no ingest lease.
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Job, job.job_id).ingest_token is None


def test_a_store_failure_leaves_the_run_owed_rather_than_lost(settings, monkeypatch):
    """A store that refuses does not make the scan disappear, and does not lie.

    Both orders that were tried before got this wrong in opposite directions:
    publishing after the outcome left the job ``succeeded`` with nothing behind
    it and the agent's retry answered as a replay, and publishing before it
    cost the upload its outcome, so the whole scan was run again. The
    publication is recorded with the outcome instead — the sensor is answered,
    the extracted run stays on disk, and the reconciler finishes it when the
    store is back.
    """
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(settings, "agent-1")
    run_id = get_job(settings, job.job_id).run_id
    down = {"store": True}

    real_promote = artifact_workspace.promote_staging

    def _store_is_down(settings_, run_id_, staging, *args, **kwargs):
        if down["store"]:
            raise artifact_store.ArtifactStoreError("bucket unreachable")
        return real_promote(settings_, run_id_, staging, *args, **kwargs)

    monkeypatch.setattr(artifact_workspace, "promote_staging", _store_is_down)

    done = jobs_service.complete_job(
        settings,
        job.job_id,
        agent_id="agent-1",
        exit_code=0,
        run_id=run_id,
        archive_bytes=_archive("fresh"),
        attempt=claim.attempt,
        idempotency_key="upload-fresh",
    )

    # The upload is accepted: the sensor is not asked for these bytes again.
    assert done.status == "succeeded"
    # The run is not visible yet, and the installation says so rather than
    # offering an empty scan.
    assert not artifact_workspace.run_dir(settings, _ref(run_id), refresh=False).is_dir()
    owed = run_publisher.pending_publications(settings, job.job_id)
    assert [row.status for row in owed] == ["pending"]
    assert "bucket unreachable" in (owed[0].last_error or "")
    assert run_publisher.backlog(settings) == {"pending": 1, "dead": 0}
    # And the only copy of the scan on this side is still on disk, with the
    # archive the ingest bus is still owed beside it.
    staging = Path(owed[0].staging_path)
    assert (staging / "fresh.json").is_file()
    assert Path(owed[0].archive_path).is_file()

    # Past the backoff the failed attempt earned, which is what keeps a
    # refusing store from being retried in a tight loop.
    assert owed[0].next_attempt_at > jobs_service._now()  # noqa: SLF001
    down["store"] = False
    assert run_publisher.reconcile_once(settings, now=_later())["published"] == 1

    run_dir = artifact_workspace.run_dir(settings, _ref(run_id), refresh=False)
    assert (run_dir / "fresh.json").is_file()
    assert run_publisher.pending_publications(settings, job.job_id) == []
    assert not staging.exists()


def test_a_publication_nobody_can_finish_ends_visibly_instead_of_retrying_forever(
    settings, monkeypatch
):
    """The bound on the retries, and what an operator is left holding.

    A reconciler that never gives up is a queue that grows while every health
    check stays green. Past ``run_publication_max_attempts`` the row is
    ``dead``: the job that claims to have succeeded says why, ``/api/health``
    stops being green, and the extracted run is still on disk for whoever
    decides between publishing it by hand and re-scanning.
    """
    settings.run_publication_max_attempts = 2
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(settings, "agent-1")
    run_id = get_job(settings, job.job_id).run_id

    def _store_is_down(*_args, **_kwargs):
        raise artifact_store.ArtifactStoreError("bucket unreachable")

    monkeypatch.setattr(artifact_workspace, "promote_staging", _store_is_down)
    jobs_service.complete_job(
        settings,
        job.job_id,
        agent_id="agent-1",
        exit_code=0,
        run_id=run_id,
        archive_bytes=_archive("fresh"),
        attempt=claim.attempt,
        idempotency_key="upload-fresh",
    )
    # The first attempt was the request's; this one spends the last of them.
    assert run_publisher.reconcile_once(settings, now=_later()) == {
        "published": 0,
        "failed": 1,
        "skipped": 0,
    }

    owed = run_publisher.pending_publications(settings, job.job_id)
    assert [row.status for row in owed] == ["dead"]
    assert run_publisher.backlog(settings) == {"pending": 0, "dead": 1}
    assert run_publisher.is_backlogged(settings)
    # Said on the job itself, which is where an operator looks first.
    assert "run not published" in (get_job(settings, job.job_id).error or "")
    # A dead row is not retried again by the next tick.
    assert run_publisher.reconcile_once(settings, now=_later())["failed"] == 0
    assert Path(owed[0].staging_path).is_dir()


def test_a_deferred_publication_does_not_send_a_second_ingest_message(settings, monkeypatch):
    """A retried publication is the same message, not a second run.

    ``ingest.results.{tenant}`` feeds ClickHouse under the run id, so a
    republish that produced a second message would insert the same scan twice.
    What is asserted here is that exactly one message reaches the broker across
    the whole deferral, and that nothing is left owing it afterwards. (The
    other half — a retry carrying the *same* ``Msg-Id``, for the broker to drop
    — is the archive kept beside the staging tree, and it is JetStream's
    duplicate window that acts on it; see ``nats_bus``.)

    The deferral is the outbox's, not this module's: the bus hop is the last
    step of the publication and hands a refused message to ``nats_outbox``
    rather than failing the row, so the run's artifacts and its Postgres
    projections do not wait for the broker. What stays owed is the message.
    """
    settings.nats_url = "nats://127.0.0.1:4222"
    published: list[dict] = []
    broker = {"up": False}

    def _publish(**kwargs):
        if not broker["up"]:
            return _publish_result(published=False)
        published.append(kwargs)
        return _publish_result(published=True)

    monkeypatch.setattr(results_ingest, "publish_raw_results", _publish)
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(settings, "agent-1")
    run_id = get_job(settings, job.job_id).run_id

    done = jobs_service.complete_job(
        settings,
        job.job_id,
        agent_id="agent-1",
        exit_code=0,
        run_id=run_id,
        archive_bytes=_archive("fresh"),
        attempt=claim.attempt,
        idempotency_key="upload-fresh",
    )

    # The broker is down, so the run is published on disk and in the store and
    # only the message is owed. The scan is not failed over a projection, and
    # the publication itself is not held open by the broker either.
    assert done.status == "succeeded"
    assert (
        artifact_workspace.run_dir(settings, _ref(run_id), refresh=False) / "fresh.json"
    ).is_file()
    assert published == []
    assert run_publisher.pending_publications(settings, job.job_id) == []
    assert run_publisher.reconcile_once(settings, now=_later())["published"] == 0
    owed = _outbox_rows(settings)
    assert [(row.status, row.run_id) for row in owed] == [("pending", str(run_id))]

    # The broker is back. The reconciler talks to it directly rather than
    # through ``publish_raw_results``, so the recovered publish is recorded on
    # the same list by the bus itself.
    broker["up"] = True

    class _Broker:
        def publish_ingest(self, payload, *, msg_id):
            published.append({"run_id": str(payload.get("run_id"))})
            return True

    monkeypatch.setattr(nats_outbox.nats_bus, "get_bus", lambda url: _Broker())
    assert nats_outbox.reconcile_once(settings, now=_later())["republished"] == 1
    assert [p["run_id"] for p in published] == [str(run_id)]
    # Nothing is owed any more, so no later tick can publish it a second time.
    assert _outbox_rows(settings) == []
    assert nats_outbox.reconcile_once(settings, now=_later())["republished"] == 0
    assert [p["run_id"] for p in published] == [str(run_id)]


def test_a_run_is_never_visible_without_its_tenant_marker(settings, monkeypatch):
    """A run with no ``tenant.json`` reads back as the *default* tenant — i.e.
    as one tenant's scan in every tenant's run list.

    Deliberately scanned for a tenant that is **not** the default: the marker
    and its absence are indistinguishable for a ``default`` run, so a test on
    one proves nothing about the leak it is named after. The marker is written
    into staging, which is what makes it travel into the store copy and the
    run directory at the moment either becomes readable — written after the
    publication, a failure between the two would leave this run in every
    tenant's list for good.
    """
    tenant = tenants_service.create_tenant(tenant_id="ten_acme", name="Acme")["tenant_id"]
    approve_scan_scope(settings, tenant_id=tenant)
    agents_service.register_agent(agent_id="agent-acme", tenant_id=tenant)
    job = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced", tenant_id=tenant), username="admin"
    )
    claim = jobs_service.claim_job(settings, "agent-acme")
    run_id = get_job(settings, job.job_id).run_id
    seen: dict[str, bool] = {}

    real_promote = artifact_workspace.promote_staging

    def _check_then_promote(settings_, run_id_, staging, *args, **kwargs):
        seen["marked_before_promotion"] = (Path(staging) / "tenant.json").is_file()
        return real_promote(settings_, run_id_, staging, *args, **kwargs)

    monkeypatch.setattr(artifact_workspace, "promote_staging", _check_then_promote)
    jobs_service.complete_job(
        settings,
        job.job_id,
        agent_id="agent-acme",
        exit_code=0,
        run_id=run_id,
        archive_bytes=_archive("fresh"),
        attempt=claim.attempt,
        idempotency_key="upload-fresh",
        tenant_id=tenant,
    )

    assert seen["marked_before_promotion"]
    run_dir = artifact_workspace.run_dir(settings, _ref(run_id, tenant), refresh=False)
    marker = json.loads((run_dir / "tenant.json").read_text(encoding="utf-8"))
    assert marker["tenant_id"] == tenant
    assert marker["job_id"] == job.job_id
    # The listing's own reader, which is what puts a run in a tenant's drawer.
    assert runs_service.run_tenant_of(settings, _ref(run_id, tenant)) == tenant
    assert runs_service.read_run_tenant(run_dir) == tenant


def test_a_rejected_result_reaches_neither_the_run_nor_the_ingest_bus(settings, monkeypatch):
    """Everything a refused straggler carried stays where nobody can see it.

    ``ingest.results.{tenant}`` is the run's other publication: the ClickHouse
    worker inserts it under the run id the *new* attempt owns, and the Msg-Id
    dedup cannot catch it because two attempts produce two different archives.
    The run directory and the store are the same statement in the other two
    places a scan is visible from.

    The reap fires inside ``extract_run_archive`` — before the terminal write,
    which is the only place a straggler can still be refused.
    """
    settings.nats_url = "nats://127.0.0.1:4222"
    published: list[dict] = []
    monkeypatch.setattr(
        results_ingest,
        "publish_raw_results",
        lambda **kwargs: published.append(kwargs) or _publish_result(published=True),
    )
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    first = jobs_service.claim_job(settings, "agent-1")
    run_id = get_job(settings, job.job_id).run_id

    real_extract = results_ingest.extract_run_archive
    reissued: dict[str, int] = {}

    def _stall_then_extract(archive_bytes: bytes, dest: Path, **kwargs):
        if not reissued:
            reissued["attempt"] = _reissue_to_a_second_attempt(settings, job.job_id)
        return real_extract(archive_bytes, dest, **kwargs)

    monkeypatch.setattr(results_ingest, "extract_run_archive", _stall_then_extract)
    with pytest.raises(jobs_service.StaleAttempt):
        jobs_service.complete_job(
            settings,
            job.job_id,
            agent_id="agent-1",
            exit_code=0,
            run_id=run_id,
            archive_bytes=_archive("stale"),
            attempt=first.attempt,
            idempotency_key="upload-stale",
        )

    assert published == []
    # Not in the run directory, not in the store's listing, and not owed a
    # publication that would put it in either later.
    assert not artifact_workspace.run_dir(settings, _ref(run_id), refresh=False).is_dir()
    assert artifact_workspace.run_ids(settings) == []
    assert run_publisher.pending_publications(settings, job.job_id) == []
    # And nothing of it is left on disk to be swept, promoted or found.
    assert _ingest_leftovers(settings) == []

    # The attempt that owns the job does reach all of it, with its own archive.
    jobs_service.complete_job(
        settings,
        job.job_id,
        agent_id="agent-1",
        exit_code=0,
        run_id=run_id,
        archive_bytes=_archive("fresh"),
        attempt=reissued["attempt"],
        idempotency_key="upload-fresh",
    )
    assert [p["run_id"] for p in published] == [str(run_id)]
    run_dir = artifact_workspace.run_dir(settings, _ref(run_id), refresh=False)
    assert sorted(p.name for p in run_dir.iterdir()) == [
        "fresh.json",
        "summary.json",
        "tenant.json",
    ]


def test_a_reap_during_the_publication_cannot_mix_two_attempts(settings, monkeypatch):
    """The window the previous fix opened, in the place it opened it.

    Publishing *before* the terminal write left the whole publication —
    ``upload_tree`` into the store, ``promote_staging`` into the run
    directory, the pointer, the bus — outside the fence. A lease that lapsed
    inside it (an archive of a large scan is minutes of store writes) got the
    job requeued, the terminal write refused, and nothing rolled back: the run
    directory held the files of *both* attempts, because ``promote_staging``
    merges, and the bus held two messages under one run id.

    So the reap is fired from inside ``promote_staging``, which is the latest
    moment it can do damage. The publication is downstream of the outcome now,
    and a reaper cannot take a job that is already terminal.
    """
    settings.nats_url = "nats://127.0.0.1:4222"
    published: list[dict] = []
    monkeypatch.setattr(
        results_ingest,
        "publish_raw_results",
        lambda **kwargs: published.append(kwargs) or _publish_result(published=True),
    )
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    first = jobs_service.claim_job(settings, "agent-1")
    run_id = get_job(settings, job.job_id).run_id

    real_promote = artifact_workspace.promote_staging
    reaped: dict[str, int] = {}

    def _reap_then_promote(settings_, run_id_, staging, *args, **kwargs):
        if not reaped:
            # What the reaper does to a job whose lease lapsed mid-publication.
            _expire_lease(settings, job.job_id)
            reaped["requeued"] = jobs_service.reap_expired_leases(settings)["requeued"]
        return real_promote(settings_, run_id_, staging, *args, **kwargs)

    monkeypatch.setattr(artifact_workspace, "promote_staging", _reap_then_promote)
    done = jobs_service.complete_job(
        settings,
        job.job_id,
        agent_id="agent-1",
        exit_code=0,
        run_id=run_id,
        archive_bytes=_archive("first"),
        attempt=first.attempt,
        idempotency_key="upload-first",
    )

    # The outcome was written before the publication began, so there was no
    # in-flight job left for the reaper to hand out.
    assert reaped["requeued"] == 0
    assert done.status == "succeeded"
    assert jobs_service.claim_job(settings, "agent-1") is None

    run_dir = artifact_workspace.run_dir(settings, _ref(run_id), refresh=False)
    assert sorted(p.name for p in run_dir.iterdir()) == [
        "first.json",
        "summary.json",
        "tenant.json",
    ]
    assert [p["run_id"] for p in published] == [str(run_id)]


def test_a_replica_killed_after_the_outcome_still_publishes_the_run(settings, monkeypatch):
    """The crash the two previous orders could not survive either way.

    A process that dies between the terminal write and the publication used to
    leave a job ``succeeded`` with no run anywhere, an agent retry answered as
    a replay of that outcome, and nothing that remembered the difference. The
    publication is a row written in the same transaction as the outcome, so
    the death is a retry: another replica — or this one, after its restart —
    finds the run owed and finishes it.
    """
    monkeypatch.setattr(run_publisher, "publish_now", lambda *_a, **_k: False)
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(settings, "agent-1")
    run_id = get_job(settings, job.job_id).run_id

    done = jobs_service.complete_job(
        settings,
        job.job_id,
        agent_id="agent-1",
        exit_code=0,
        run_id=run_id,
        archive_bytes=_archive("fresh"),
        attempt=claim.attempt,
        idempotency_key="upload-fresh",
    )
    assert done.status == "succeeded"
    assert not artifact_workspace.run_dir(settings, _ref(run_id), refresh=False).is_dir()
    assert [row.status for row in run_publisher.pending_publications(settings, job.job_id)] == [
        "pending"
    ]

    # The reconciler in this or any other replica that can see the tree.
    assert run_publisher.reconcile_once(settings, now=_later())["published"] == 1
    run_dir = artifact_workspace.run_dir(settings, _ref(run_id), refresh=False)
    assert (run_dir / "fresh.json").is_file()
    assert (run_dir / "tenant.json").is_file()
    assert run_publisher.pending_publications(settings, job.job_id) == []
    assert _ingest_leftovers(settings) == []


def test_a_projection_that_throws_cannot_undo_a_finished_job(settings, monkeypatch):
    """Everything after the terminal write is best-effort by construction.

    The outcome is committed and the agent's retry is answered as a replay, so
    an exception escaping here would report a failure for a result the API
    kept — and would skip the lines below it, leaving the agent marked busy on
    a job that is finished and its job inputs on disk."""
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(settings, "agent-1")
    run_id = get_job(settings, job.job_id).run_id

    def _boom(*_args, **_kwargs):
        raise RuntimeError("the asset table is gone")

    # Patched on run_completion, which owns the projection and is what
    # on_run_published calls. The jobs facade still carries a wrapper of the
    # same name, but nothing routes through it: patching there would leave the
    # real upsert running and this test green without ever throwing.
    monkeypatch.setattr(run_completion, "upsert_assets_best_effort", _boom)

    done = jobs_service.complete_job(
        settings,
        job.job_id,
        agent_id="agent-1",
        exit_code=0,
        run_id=run_id,
        archive_bytes=_archive("fresh"),
        attempt=claim.attempt,
        idempotency_key="upload-fresh",
    )
    assert done.status == "succeeded"
    assert "run projections did not complete" in (get_job(settings, job.job_id).error or "")
    assert agents_service.get_agent("agent-1").current_job_id is None


def test_a_failed_ingest_gives_the_job_back_on_the_ordinary_lease(settings, monkeypatch):
    """The ingest lease is worth 900s *while an ingest is running*. Left on the
    row afterwards it is 900s of a job nobody is working on: the agent does not
    resend a refused upload, so the reaper is the only thing that moves the job
    on, and it waits out the whole reserved window before it may."""
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(settings, "agent-1")
    run_id = get_job(settings, job.job_id).run_id

    def _corrupt(*_args, **_kwargs):
        raise results_ingest.IngestError("not a gzip stream")

    monkeypatch.setattr(results_ingest, "extract_run_archive", _corrupt)
    with pytest.raises(ValueError):
        jobs_service.complete_job(
            settings,
            job.job_id,
            agent_id="agent-1",
            exit_code=0,
            run_id=run_id,
            archive_bytes=_archive("fresh"),
            attempt=claim.attempt,
            idempotency_key="upload-broken",
        )

    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job.job_id)
        assert row.ingest_token is None
        ordinary = jobs_service._now() + timedelta(  # noqa: SLF001
            seconds=settings.job_lease_seconds
        )
        assert row.claimed_until <= ordinary + timedelta(seconds=5)


def test_the_agents_heartbeat_does_not_shorten_the_ingest_lease(settings, monkeypatch):
    """The agent keeps beating while its upload is ingested, and a heartbeat is
    worth one ordinary lease — shorter than the ingest one. Assigning it would
    let those beats pull the deadline back into the window the ingest reserved."""
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(settings, "agent-1")
    run_id = get_job(settings, job.job_id).run_id
    seen: dict[str, object] = {}

    real_extract = results_ingest.extract_run_archive

    def _beat_then_extract(archive_bytes: bytes, dest: Path, **kwargs):
        with get_session(settings.postgres_url) as session:
            reserved = session.get(models.Job, job.job_id).claimed_until
        jobs_service.mark_running(settings, job.job_id, agent_id="agent-1")
        assert jobs_service.renew_lease(settings, job.job_id, agent_id="agent-1")
        with get_session(settings.postgres_url) as session:
            seen["after_beat"] = session.get(models.Job, job.job_id).claimed_until
        seen["reserved"] = reserved
        return real_extract(archive_bytes, dest, **kwargs)

    monkeypatch.setattr(results_ingest, "extract_run_archive", _beat_then_extract)
    jobs_service.complete_job(
        settings,
        job.job_id,
        agent_id="agent-1",
        exit_code=0,
        run_id=run_id,
        archive_bytes=_archive("fresh"),
        attempt=claim.attempt,
        idempotency_key="upload-fresh",
    )

    assert seen["after_beat"] == seen["reserved"]
