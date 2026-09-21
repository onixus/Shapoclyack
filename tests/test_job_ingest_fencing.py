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
import tarfile
from datetime import timedelta
from pathlib import Path

import pytest

from api.db import models
from api.db.engine import get_session
from api.schemas import StartScanRequest
from api.services import agents as agents_service
from api.services import jobs as jobs_service
from api.services import results_ingest
from api.services import artifact_store
from api.services import runs as runs_service
from api.services import tenants as tenants_service
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
    return base


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
    run_dir = artifact_workspace.run_dir(settings, str(run_id), refresh=False)
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

    run_dir = artifact_workspace.run_dir(settings, str(run_id), refresh=False)
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


def test_a_store_failure_does_not_report_a_scan_the_installation_does_not_have(
    settings, monkeypatch
):
    """The job may not go terminal on a run the store refused to take.

    Publishing after the terminal write made a store outage permanent: the job
    read ``succeeded``, the artifacts were nowhere, and the agent's retry was
    answered as a replay of that outcome, so nothing would ever fetch the scan
    again. Ahead of it, the same outage costs the upload its terminal write —
    the job stays claimed, the reaper requeues it, and the scan is redone.
    """
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(settings, "agent-1")
    run_id = get_job(settings, job.job_id).run_id

    def _store_is_down(*_args, **_kwargs):
        raise artifact_store.ArtifactStoreError("bucket unreachable")

    monkeypatch.setattr(artifact_workspace, "publish_run", _store_is_down)

    with pytest.raises(artifact_store.ArtifactStoreError):
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

    row = get_job(settings, job.job_id)
    assert row.status == "claimed"
    assert row.finished_at is None
    # And the extracted upload is still on disk: it is the only copy this side
    # of the sensor, and a full disk must not turn into a deleted scan.
    leftovers = sorted(p.name for p in (Path(settings.output_dir) / "runs").iterdir())
    assert any(name.startswith(".ingest-") for name in leftovers), leftovers


def test_a_promote_failure_keeps_the_extracted_upload(settings, monkeypatch):
    """The disk filling up mid-promotion is the other half of the same rule.

    ``promote_staging`` raising used to be caught beside the store errors and
    a ``finally`` then removed the staging tree — an ENOSPC deleted the one
    copy of the scan and the job still reported ``succeeded``."""
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(settings, "agent-1")
    run_id = get_job(settings, job.job_id).run_id

    def _disk_is_full(*_args, **_kwargs):
        raise OSError("No space left on device")

    monkeypatch.setattr(artifact_workspace, "promote_staging", _disk_is_full)

    with pytest.raises(OSError, match="No space left"):
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

    assert get_job(settings, job.job_id).status == "claimed"
    staged = [
        child
        for child in (Path(settings.output_dir) / "runs").iterdir()
        if child.name.startswith(".ingest-")
    ]
    assert staged and (staged[0] / "fresh.json").exists()


def test_a_run_is_never_visible_without_its_tenant_marker(settings, monkeypatch):
    """A run with no ``tenant.json`` reads back as the *default* tenant — i.e.
    as one tenant's scan in every tenant's run list. Written after the run was
    published, a failed marker left that state behind for good; written into
    staging, it travels with the run into both copies at once."""
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    claim = jobs_service.claim_job(settings, "agent-1")
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
        agent_id="agent-1",
        exit_code=0,
        run_id=run_id,
        archive_bytes=_archive("fresh"),
        attempt=claim.attempt,
        idempotency_key="upload-fresh",
    )

    assert seen["marked_before_promotion"]
    run_dir = artifact_workspace.run_dir(settings, str(run_id), refresh=False)
    assert (run_dir / "tenant.json").is_file()
    assert runs_service.run_tenant_of(settings, str(run_id)) == "default"


def test_a_rejected_result_reaches_neither_the_run_nor_the_ingest_bus(settings, monkeypatch):
    """``ingest.results.{tenant}`` is the run's other publication.

    The gateway publish used to run at the top of the ingest, before anything
    had asked whether this upload was still the current one: a straggler's
    archive went to the bus, the ClickHouse worker inserted it under the run id
    the *new* attempt owns, and the Msg-Id dedup cannot catch it because two
    attempts produce two different archives.
    """
    settings.nats_url = "nats://127.0.0.1:4222"
    published: list[dict] = []
    monkeypatch.setattr(
        results_ingest,
        "publish_raw_results",
        lambda **kwargs: published.append(kwargs) or {"published": True},
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

    # The attempt that owns the job does reach it, with its own archive.
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

    monkeypatch.setattr(jobs_service, "_upsert_assets_best_effort", _boom)

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
