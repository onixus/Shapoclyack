"""What a finished run feeds, by how it finished and where it ran (#454).

A run reaches the derived state — the asset registry, the vulnerability
tracker, service fingerprints, asset events, the notification channels and the
scope-denial journal — from two places: the local executor, once its scanner
has exited, and the sensor upload, once ``run_publisher`` has made the run
visible. These tests drive both through their real entry points and record
which of those derived updates ran, in which order, for each outcome.

The recorders sit on the owning services (``assets.upsert_assets_from_run``
and its neighbours), not on the ``run_completion`` helpers in between, so the
table below says what the installation *did* and survives the helpers being
moved around.

``partial`` is not a job status of its own. It is a run whose scan did not
finish and whose artifacts are on disk anyway: for a sensor, the archive a
slow but obedient agent uploads after the reaper already wrote its
cancellation off (#360); locally, a scanner killed mid-run that leaves its
directory behind.
"""

from __future__ import annotations

import io
import json
import tarfile
import types
from datetime import timedelta
from pathlib import Path

import pytest

from api.db import models
from api.db.engine import get_session
from api.schemas import StartScanRequest
from api.services import agents as agents_service
from api.services import artifact_store
from api.services import asset_events
from api.services import asset_services
from api.services import assets as assets_service
from api.services import auth_audit
from api.services import jobs as jobs_service
from api.services import local_scan_executor
from api.services import nats_outbox
from api.services import run_completion
from api.services import run_publisher
from api.services import tenants as tenants_service
from api.services import vulnerabilities as vulns_service
from api.services import workflow_events
from api.services.artifact_store import workspace as artifact_workspace
from api.services.integrations import channels as channels_service
from tests.conftest import approve_scan_scope, make_settings, requires_postgres
from tests.fake_s3 import FakeS3Client

pytestmark = requires_postgres

RUN_ID = "20261004T101500Z-i454"
DENIED = "10.9.9.9"

#: Characterization of ``main`` before #454: the two paths disagree. The
#: sensor path upserts assets whatever the outcome — before it looks at the
#: status — while the local path upserts only a succeeded run; the local path
#: journals scope denials first, the sensor path after the asset upsert.
CURRENT = {
    ("local", "succeeded"): ["scope_denials", "assets", "findings", "services", "events", "notify"],
    ("local", "failed"): ["scope_denials"],
    ("local", "cancelled"): [],
    ("local", "partial"): ["scope_denials"],
    ("sensor", "succeeded"): ["assets", "scope_denials", "findings", "services", "events", "notify"],
    ("sensor", "failed"): ["assets", "scope_denials"],
    ("sensor", "cancelled"): ["assets", "scope_denials"],
    ("sensor", "partial"): ["assets", "scope_denials"],
}

#: The job status each case ends on, which the derived updates are keyed by.
STATUS = {
    ("local", "succeeded"): "succeeded",
    ("local", "failed"): "failed",
    ("local", "cancelled"): "cancelled",
    ("local", "partial"): "failed",
    ("sensor", "succeeded"): "succeeded",
    ("sensor", "failed"): "failed",
    ("sensor", "cancelled"): "cancelled",
    ("sensor", "partial"): "cancelled",
}


class _Derived:
    """Every derived update a published run triggered, in order."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None, str | None]] = []

    def names(self) -> list[str]:
        return [name for name, _run, _tenant in self.calls]

    def record(self, name: str, result=None):
        def _recorder(*_args, **kwargs):
            self.calls.append((name, kwargs.get("run_id"), kwargs.get("tenant_id")))
            return result

        return _recorder


@pytest.fixture()
def derived(monkeypatch) -> _Derived:
    spy = _Derived()
    monkeypatch.setattr(assets_service, "upsert_assets_from_run", spy.record("assets"))
    monkeypatch.setattr(vulns_service, "register_findings_from_run", spy.record("findings"))
    monkeypatch.setattr(asset_services, "record_run", spy.record("services", {}))
    monkeypatch.setattr(asset_events, "publish_run_events", spy.record("events", 0))
    monkeypatch.setattr(channels_service, "notify_run_complete_async", spy.record("notify"))

    real_denied = auth_audit.record_denied

    def _denied(*, username: str, reason: str, detail: str | None = None, client_ip: str = ""):
        if reason == auth_audit.REASON_SCAN_SCOPE and "dropped by the scanner" in (detail or ""):
            spy.calls.append(("scope_denials", RUN_ID, username))
            return None
        return real_denied(username=username, reason=reason, detail=detail, client_ip=client_ip)

    monkeypatch.setattr(auth_audit, "record_denied", _denied)
    # The events hop needs a broker URL to be attempted at all, and so does
    # the run's own bus message; neither may leave the test.
    monkeypatch.setattr(workflow_events, "emit", lambda *_a, **_k: None)
    monkeypatch.setattr(
        nats_outbox,
        "publish_ingest_or_record",
        lambda *_a, **_k: {"published": True, "msg_id": "m"},
    )
    return spy


@pytest.fixture(autouse=True)
def _clean_store_cache():
    artifact_store.reset_cache()
    artifact_workspace.reset_marker_cache()
    yield
    artifact_store.reset_cache()
    artifact_workspace.reset_marker_cache()


def _pod(tmp_path: Path, mode: str, name: str = "pod-a", bucket: FakeS3Client | None = None):
    """One API replica: its own disk, the shared database and, given one, bucket."""
    root = tmp_path / name
    remote = (
        {
            "artifact_backend": "s3",
            "artifact_s3_bucket": "artifacts",
            "artifact_cache_dir": str(root / "cache"),
            "artifact_cache_ttl_seconds": 0,
        }
        if bucket is not None
        else {}
    )
    settings = make_settings(
        root,
        state_dir=root / "state",
        output_dir=root / "output",
        job_execution_mode="agent" if mode == "sensor" else "local",
        instance_id=name,
        asset_events_enabled=True,
        notification_channels_enabled=True,
        **remote,
    )
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    if bucket is not None:
        artifact_store.get_store(settings)._client = bucket  # noqa: SLF001
    return settings


def _settings(tmp_path: Path, mode: str, bucket: FakeS3Client | None = None):
    settings = _pod(tmp_path, mode, bucket=bucket)
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(settings)
    approve_scan_scope(settings)
    agents_service.configure(settings)
    agents_service.reset_for_tests()
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    jobs_service.reset_for_tests(settings)
    run_publisher.reset_for_tests(settings)
    return settings


class _NoopThread:
    """start_scan would run a local job on a thread; the test drives it."""

    def __init__(self, *args, **kwargs) -> None:
        pass

    def start(self) -> None:
        pass

    def join(self, timeout: float | None = None) -> None:
        pass

    def is_alive(self) -> bool:
        return False


def _run_files() -> dict[str, bytes]:
    return {
        "summary.json": b'{"hosts": 1}\n',
        "scan_scope_denied.json": json.dumps({"denied": [DENIED]}).encode("utf-8"),
    }


def _archive() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, payload in _run_files().items():
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _enable_broker(settings) -> None:
    """Turned on after the job is queued: the offer hint is not under test."""
    settings.nats_url = "nats://broker.invalid:4222"


def _local(settings, monkeypatch, case: str) -> str:
    # Only the facade's executor thread: the store's upload pool and the lease
    # renewal are real threads and must stay that way.
    monkeypatch.setattr(jobs_service, "threading", types.SimpleNamespace(Thread=_NoopThread))
    job = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced", run_id=RUN_ID), username="analyst"
    )
    run_dir = Path(settings.output_dir) / "runs" / RUN_ID
    run_dir.mkdir(parents=True, exist_ok=True)
    for name, payload in _run_files().items():
        (run_dir / name).write_bytes(payload)
    (Path(settings.state_dir) / "latest_run.json").write_text(
        json.dumps({"run_id": RUN_ID}), encoding="utf-8"
    )
    _enable_broker(settings)
    if case == "cancelled":
        # A local scan can only be stopped before it starts (architecture.md).
        jobs_service.cancel_job(settings, job.job_id, username="operator")
    command = {
        "succeeded": ["true"],
        "failed": ["false"],
        "cancelled": ["true"],
        # Killed mid-run, its directory left behind.
        "partial": ["sh", "-c", "kill -TERM $$"],
    }[case]
    jobs_service._run_job(settings, job.job_id, command)  # noqa: SLF001
    return job.job_id


def _sensor(settings, case: str) -> str:
    job = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced", run_id=RUN_ID), username="analyst"
    )
    claim = jobs_service.claim_job(settings, "agent-1")
    assert claim is not None and claim.job_id == job.job_id
    _enable_broker(settings)
    upload = {
        "agent_id": "agent-1",
        "run_id": RUN_ID,
        "archive_bytes": _archive(),
        "attempt": claim.attempt,
        "idempotency_key": f"agent-1:{job.job_id}:{case}",
    }
    if case == "succeeded":
        jobs_service.complete_job(settings, job.job_id, exit_code=0, **upload)
    elif case == "failed":
        jobs_service.complete_job(settings, job.job_id, exit_code=1, **upload)
    elif case == "cancelled":
        jobs_service.cancel_job(settings, job.job_id, username="operator")
        jobs_service.complete_job(settings, job.job_id, exit_code=143, cancelled=True, **upload)
    else:
        # The reaper wrote the stop off before the archive arrived (#360).
        jobs_service.cancel_job(settings, job.job_id, username="operator")
        with get_session(settings.postgres_url) as session:
            row = session.get(models.Job, job.job_id)
            row.cancel_requested_at = row.cancel_requested_at - timedelta(seconds=300)
        settings.job_cancel_grace_seconds = 60
        assert jobs_service.reap_stale_cancellations(settings) == 1
        jobs_service.complete_job(settings, job.job_id, exit_code=143, cancelled=True, **upload)
    return job.job_id


def _finish(settings, monkeypatch, mode: str, case: str) -> str:
    if mode == "local":
        return _local(settings, monkeypatch, case)
    return _sensor(settings, case)


@pytest.mark.parametrize("case", ["succeeded", "failed", "cancelled", "partial"])
@pytest.mark.parametrize("mode", ["local", "sensor"])
def test_derived_updates_by_outcome(tmp_path, monkeypatch, derived, mode, case):
    settings = _settings(tmp_path, mode)

    job_id = _finish(settings, monkeypatch, mode, case)

    assert jobs_service.get_job(settings, job_id).status == STATUS[(mode, case)]
    assert derived.names() == CURRENT[(mode, case)]
    # Whatever ran, ran for this run and under the job's tenant.
    for name, run_id, who in derived.calls:
        assert run_id == RUN_ID, name
        assert who == ("analyst" if name == "scope_denials" else "default"), name


def _later():
    """A moment past any backoff a failed publication can have earned."""
    return jobs_service._now() + timedelta(hours=1)  # noqa: SLF001


def _store_is_down(*_args, **_kwargs):
    raise artifact_store.ArtifactStoreError("bucket unreachable")


_LOCAL_IS_NOT_DURABLE = pytest.mark.xfail(
    strict=True,
    reason="#454: a local run is adopted inline, with no run_publications row, and its "
    "derived updates run whether or not the store took it",
)


@pytest.mark.parametrize(
    "mode", [pytest.param("local", marks=_LOCAL_IS_NOT_DURABLE), "sensor"]
)
def test_a_store_outage_defers_derived_updates_until_the_run_is_published(
    tmp_path, monkeypatch, derived, mode
):
    """Nothing derived before the publication, and nothing lost after it.

    The store refuses while the scan finishes; the outcome is still the
    scan's, the run is owed rather than forgotten, and the derived updates
    wait for it. A restarted replica — a fresh process on the same disk —
    then publishes it, and they run exactly once.
    """
    bucket = FakeS3Client()
    settings = _settings(tmp_path, mode, bucket)
    real_publish_run = artifact_workspace.publish_run
    monkeypatch.setattr(artifact_workspace, "publish_run", _store_is_down)

    job_id = _finish(settings, monkeypatch, mode, "succeeded")

    assert jobs_service.get_job(settings, job_id).status == "succeeded"
    assert derived.names() == []
    assert len(run_publisher.pending_publications(settings, job_id)) == 1

    monkeypatch.setattr(artifact_workspace, "publish_run", real_publish_run)
    restarted = _pod(tmp_path, mode, bucket=bucket)
    restarted.nats_url = settings.nats_url
    assert run_publisher.reconcile_once(restarted, now=_later())["published"] == 1

    assert derived.names() == CURRENT[("sensor", "succeeded")]
    assert run_publisher.pending_publications(settings, job_id) == []
    run_publisher.reconcile_once(restarted, now=_later())
    assert len(derived.names()) == len(CURRENT[("sensor", "succeeded")])


@pytest.mark.parametrize(
    "mode", [pytest.param("local", marks=_LOCAL_IS_NOT_DURABLE), "sensor"]
)
def test_a_replica_that_cannot_see_the_run_leaves_it_to_the_one_that_can(
    tmp_path, monkeypatch, derived, mode
):
    """Two API replicas, one bucket: the run's tree is on the disk of the pod
    that accepted it. The other pod neither publishes it nor derives anything
    from it, and the owner does both once."""
    bucket = FakeS3Client()
    settings = _settings(tmp_path, mode, bucket)
    peer = _pod(tmp_path, mode, name="pod-b", bucket=bucket)
    real_publish_run = artifact_workspace.publish_run
    monkeypatch.setattr(artifact_workspace, "publish_run", _store_is_down)
    job_id = _finish(settings, monkeypatch, mode, "succeeded")
    monkeypatch.setattr(artifact_workspace, "publish_run", real_publish_run)
    peer.nats_url = settings.nats_url

    # The tree is on pod-a's disk, which pod-b does not mount. Both pods are
    # one filesystem here, so it is put out of sight for pod-b's tick.
    staging = Path(run_publisher.pending_publications(settings, job_id)[0].staging_path)
    hidden = staging.with_name(staging.name + ".on-pod-a")
    staging.rename(hidden)
    try:
        tick = run_publisher.reconcile_once(peer, now=_later())
    finally:
        hidden.rename(staging)
    assert tick == {"published": 0, "failed": 0, "skipped": 1}
    assert derived.names() == []
    assert [row.status for row in run_publisher.pending_publications(settings, job_id)] == [
        "pending"
    ]

    # The give-back holds the row for an adoption window; past it, the owner.
    assert run_publisher.reconcile_once(settings, now=_later() + timedelta(hours=1)) == {
        "published": 1,
        "failed": 0,
        "skipped": 0,
    }
    assert derived.names() == CURRENT[("sensor", "succeeded")]


def test_a_replayed_upload_derives_nothing_twice(tmp_path, monkeypatch, derived):
    """The sensor's retry of an upload whose answer it never got."""
    settings = _settings(tmp_path, "sensor")
    job = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced", run_id=RUN_ID), username="analyst"
    )
    claim = jobs_service.claim_job(settings, "agent-1")
    _enable_broker(settings)
    upload = {
        "agent_id": "agent-1",
        "exit_code": 0,
        "run_id": RUN_ID,
        "archive_bytes": _archive(),
        "attempt": claim.attempt,
        "idempotency_key": "agent-1:upload",
    }
    jobs_service.complete_job(settings, job.job_id, **upload)
    first = derived.names()

    jobs_service.complete_job(settings, job.job_id, **upload)

    assert derived.names() == first
    assert run_publisher.pending_publications(settings, job.job_id) == []


def test_a_stale_attempt_derives_nothing_and_the_current_one_derives_once(
    tmp_path, monkeypatch, derived
):
    settings = _settings(tmp_path, "sensor")
    job = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced", run_id=RUN_ID), username="analyst"
    )
    stale = jobs_service.claim_job(settings, "agent-1")
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job.job_id)
        row.claimed_until = jobs_service._now() - timedelta(seconds=1)  # noqa: SLF001
    jobs_service.reap_expired_leases(settings)
    current = jobs_service.claim_job(settings, "agent-1")
    assert current.attempt > stale.attempt
    _enable_broker(settings)

    with pytest.raises(jobs_service.StaleAttempt):
        jobs_service.complete_job(
            settings,
            job.job_id,
            agent_id="agent-1",
            exit_code=0,
            run_id=RUN_ID,
            archive_bytes=_archive(),
            attempt=stale.attempt,
        )
    assert derived.names() == []
    assert run_publisher.pending_publications(settings, job.job_id) == []

    jobs_service.complete_job(
        settings,
        job.job_id,
        agent_id="agent-1",
        exit_code=0,
        run_id=RUN_ID,
        archive_bytes=_archive(),
        attempt=current.attempt,
    )
    assert derived.names() == CURRENT[("sensor", "succeeded")]


def test_a_local_result_for_a_job_already_written_off_is_refused(
    tmp_path, monkeypatch, derived
):
    """The local counterpart of a stale attempt: the job was terminalized —
    by restart reconciliation, say — while its scanner was still running.
    The scanner's own exit must not finish it a second time or publish."""
    settings = _settings(tmp_path, "local")
    real_run_scanner = local_scan_executor.run_scanner

    def _written_off_meanwhile(job_id, command):
        jobs_service._update_job(  # noqa: SLF001
            settings,
            job_id,
            status="failed",
            finished_at=jobs_service._now(),  # noqa: SLF001
            error="orphaned by a restart",
        )
        return real_run_scanner(job_id, command)

    monkeypatch.setattr(local_scan_executor, "run_scanner", _written_off_meanwhile)
    job_id = _local(settings, monkeypatch, "succeeded")

    job = jobs_service.get_job(settings, job_id)
    assert job.status == "failed"
    assert job.exit_code is None
    assert derived.names() == []
    assert run_publisher.pending_publications(settings, job_id) == []


def _seed_findings_run(settings) -> None:
    run_dir = Path(settings.output_dir) / "runs" / RUN_ID
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "alive_hosts.json").write_text(
        json.dumps([{"host": "10.0.0.5", "hostname": "app.example.com"}]), encoding="utf-8"
    )
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps(
            [{"host": "10.0.0.5", "port": "443", "cve": "CVE-2024-0001", "severity": "critical"}]
        ),
        encoding="utf-8",
    )


@pytest.mark.xfail(
    strict=True,
    reason="#454: replaying a published run's derived updates counts the same "
    "observation again",
)
def test_replaying_a_published_run_does_not_count_its_observations_twice(tmp_path):
    """A publication whose derived updates ran and whose row was not closed —
    a replica killed between the two — is published again. The findings it
    folds are the same facts, not a second sighting of them."""
    settings = _settings(tmp_path, "sensor")
    _seed_findings_run(settings)
    with get_session(settings.postgres_url) as session:
        session.query(models.VulnerabilityEvent).delete()
        session.query(models.Vulnerability).delete()

    for _ in range(2):
        run_completion.on_run_published(
            settings, "job-replayed", run_id=RUN_ID, tenant_id="default", status="succeeded"
        )

    with get_session(settings.postgres_url) as session:
        row = session.query(models.Vulnerability).one()
        assert row.observation_count == 1
        observed = (
            session.query(models.VulnerabilityEvent)
            .filter_by(vuln_id=row.vuln_id, kind="observed")
            .count()
        )
    assert observed == 1
