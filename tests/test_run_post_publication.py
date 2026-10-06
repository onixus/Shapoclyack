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
from api.services import vuln_states
from api.services import vulnerabilities as vulns_service
from api.services import workflow_events
from api.services.artifact_store import workspace as artifact_workspace
from api.services.integrations import channels as channels_service
from tests.conftest import approve_scan_scope, make_settings, requires_postgres
from tests.fake_s3 import FakeS3Client

pytestmark = requires_postgres

RUN_ID = "20261004T101500Z-i454"
DENIED = "10.9.9.9"

#: Characterization of ``main`` before #454, kept as the record of what the
#: unification changed: the two paths disagreed. The sensor path upserted
#: assets whatever the outcome — before it looked at the status — while the
#: local path upserted only a succeeded run; the local path journalled scope
#: denials first, the sensor path after the asset upsert.
BEFORE_454 = {
    ("local", "succeeded"): ["scope_denials", "assets", "findings", "services", "events", "notify"],
    ("local", "failed"): ["scope_denials"],
    ("local", "cancelled"): [],
    ("local", "partial"): ["scope_denials"],
    ("sensor", "succeeded"): ["assets", "scope_denials", "findings", "services", "events", "notify"],
    ("sensor", "failed"): ["assets", "scope_denials"],
    ("sensor", "cancelled"): ["assets", "scope_denials"],
    ("sensor", "partial"): ["assets", "scope_denials"],
}

#: One matrix for both paths, keyed by outcome alone (``run_completion.
#: POST_PUBLICATION``). A local job cancelled before it started has no run
#: and so no publication at all. ``verification`` (#451) came after #454: a
#: run that did not succeed gives back the finding its job was verifying.
MATRIX = {
    "succeeded": ["scope_denials", "assets", "findings", "services", "events", "notify"],
    "failed": ["scope_denials", "verification"],
    "cancelled": ["scope_denials", "verification"],
    "partial": ["scope_denials", "verification"],
}

#: Steps added to the matrix after #454, left out of its before/after record.
AFTER_454 = {"verification"}


def _expected(mode: str, case: str) -> list[str]:
    if (mode, case) == ("local", "cancelled"):
        return []
    return MATRIX[case]


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
    monkeypatch.setattr(
        vulns_service, "release_unfinished_verification", spy.record("verification", 0)
    )
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
    assert derived.names() == _expected(mode, case)
    # Whatever ran, ran for this run and under the job's tenant.
    for name, run_id, who in derived.calls:
        assert run_id == RUN_ID, name
        assert who == ("analyst" if name == "scope_denials" else "default"), name
    # Fed from the publication, so nothing is owed once it has landed.
    assert run_publisher.pending_publications(settings, job_id) == []


@pytest.mark.parametrize("case", ["failed", "partial"])
def test_an_unfinished_local_run_is_still_published_under_its_tenant(
    tmp_path, monkeypatch, derived, case
):
    """It feeds nothing derived, but it is the tenant's run: filed under its
    owner and marked, which a failed local run used not to be."""
    from api.services import runs as runs_service

    settings = _settings(tmp_path, "local")
    _local(settings, monkeypatch, case)

    run_dir = runs_service.get_run_dir(settings, RUN_ID, tenant_id="default")
    assert run_dir is not None and (run_dir / "summary.json").is_file()
    assert runs_service.read_run_tenant(run_dir) == "default"
    assert not (Path(settings.output_dir) / "runs" / RUN_ID).exists()


def test_the_matrix_is_the_service_table():
    """The tests' table and the code's table say the same thing."""
    for case, status in (("succeeded", "succeeded"), ("failed", "failed"), ("cancelled", "cancelled")):
        assert list(run_completion.actions_for(status)) == MATRIX[case]
    # An outcome nobody classified feeds the journal and nothing derived.
    assert run_completion.actions_for("cancelling") == (run_completion.SCOPE_DENIALS,)


def test_the_recorded_change_against_main_is_the_documented_one():
    """What #454 changed beyond moving code, and nothing else: a sensor's
    failed, cancelled or partial run no longer feeds the asset registry, and
    the sensor path journals scope denials before the asset upsert.

    A record, not a check of the code: both tables are literals in this file
    and no code runs here. ``BEFORE_454`` was made true by running this
    module's matrix against ``main`` before the change (commit c7d882e7, as a
    strict xfail); this only keeps the two tables saying what the CHANGELOG
    says. ``test_derived_updates_by_outcome`` is the test of the code."""
    def _at_454(mode: str, case: str) -> list[str]:
        return [n for n in _expected(mode, case) if n not in AFTER_454]

    changed = {key for key, before in BEFORE_454.items() if before != _at_454(*key)}
    assert changed == {
        ("sensor", "succeeded"),
        ("sensor", "failed"),
        ("sensor", "cancelled"),
        ("sensor", "partial"),
    }
    assert sorted(BEFORE_454[("sensor", "succeeded")]) == sorted(MATRIX["succeeded"])
    for case in ("failed", "cancelled", "partial"):
        assert [n for n in BEFORE_454[("sensor", case)] if n != "assets"] == [
            n for n in MATRIX[case] if n not in AFTER_454
        ]


@pytest.mark.parametrize("mode", ["local", "sensor"])
def test_a_failing_notification_does_not_touch_the_scan_outcome(
    tmp_path, monkeypatch, derived, mode
):
    settings = _settings(tmp_path, mode)

    def _slack_is_down(**_kwargs):
        raise RuntimeError("could not start the sender thread")

    monkeypatch.setattr(channels_service, "notify_run_complete_async", _slack_is_down)

    job_id = _finish(settings, monkeypatch, mode, "succeeded")

    job = jobs_service.get_job(settings, job_id)
    assert job.status == "succeeded"
    assert job.exit_code == 0
    assert not job.error
    assert derived.names() == MATRIX["succeeded"][:-1]
    assert run_publisher.pending_publications(settings, job_id) == []


class _Killed(BaseException):
    """The replica dying: not an ``Exception`` any handler on the way catches."""


@pytest.mark.parametrize("mode", ["local", "sensor"])
def test_a_replica_killed_after_the_derived_updates_replays_them_on_the_owed_row(
    tmp_path, monkeypatch, derived, mode
):
    """The derived updates are owed with the publication, not after it.

    The replica dies between feeding the run and closing its row. The row is
    still there, so the run is published and fed again — which is why each
    derived update must take a second pass over one run as the same facts
    (see the replay test below) — and then the row closes.
    """
    settings = _settings(tmp_path, mode)
    real_record_success = run_publisher._record_success  # noqa: SLF001

    def _dies(*_args, **_kwargs):
        raise _Killed()

    monkeypatch.setattr(run_publisher, "_record_success", _dies)
    with pytest.raises(_Killed):
        _finish(settings, monkeypatch, mode, "succeeded")
    with get_session(settings.postgres_url) as session:
        owed = session.query(models.RunPublication).one()
        job_id = owed.job_id
    assert derived.names() == MATRIX["succeeded"]
    assert jobs_service.get_job(settings, job_id).status == "succeeded"

    monkeypatch.setattr(run_publisher, "_record_success", real_record_success)
    assert run_publisher.reconcile_once(settings, now=_later())["published"] == 1

    assert derived.names() == MATRIX["succeeded"] * 2
    assert run_publisher.pending_publications(settings, job_id) == []


def _later():
    """A moment past any backoff a failed publication can have earned."""
    return jobs_service._now() + timedelta(hours=1)  # noqa: SLF001


def _store_is_down(*_args, **_kwargs):
    raise artifact_store.ArtifactStoreError("bucket unreachable")


@pytest.mark.parametrize("mode", ["local", "sensor"])
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

    assert derived.names() == MATRIX["succeeded"]
    assert run_publisher.pending_publications(settings, job_id) == []
    run_publisher.reconcile_once(restarted, now=_later())
    assert len(derived.names()) == len(MATRIX["succeeded"])


@pytest.mark.parametrize("mode", ["local", "sensor"])
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
    assert derived.names() == MATRIX["succeeded"]


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
    assert derived.names() == MATRIX["succeeded"]


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


def _seed_findings_run(settings, run_id: str = RUN_ID, findings: int = 1) -> None:
    run_dir = Path(settings.output_dir) / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "alive_hosts.json").write_text(
        json.dumps([{"host": "10.0.0.5", "hostname": "app.example.com"}]), encoding="utf-8"
    )
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps(
            [{"host": "10.0.0.5", "port": "443", "cve": "CVE-2024-0001", "severity": "critical"}]
            * findings
        ),
        encoding="utf-8",
    )


def _clean_tracker(settings) -> None:
    with get_session(settings.postgres_url) as session:
        session.query(models.VulnerabilityEvent).delete()
        session.query(models.Vulnerability).delete()


def _owed(settings, job_id: str, run_id: str = RUN_ID) -> str:
    """The row ``job_id``'s terminal write leaves for its run, still owed."""
    publication = run_publisher.new_local_publication(
        settings,
        job_id=job_id,
        run_id=run_id,
        tenant_id="default",
        job_status="succeeded",
        exit_code=0,
        scan_error=None,
        surface=None,
        source=Path(settings.output_dir) / "runs" / run_id,
    )
    with get_session(settings.postgres_url) as session:
        session.add(publication)
    return publication.publication_id


def _feed(settings, publication_id: str, run_id: str = RUN_ID) -> None:
    """What ``run_publisher._project`` does for that row, once."""
    with get_session(settings.postgres_url) as session:
        job_id = session.get(models.RunPublication, publication_id).job_id
    run_completion.on_run_published(
        settings,
        job_id,
        run_id=run_id,
        tenant_id="default",
        status="succeeded",
        publication_id=publication_id,
    )


def _finding(settings):
    with get_session(settings.postgres_url) as session:
        row = session.query(models.Vulnerability).one()
        events = [
            event.kind
            for event in session.query(models.VulnerabilityEvent)
            .filter_by(vuln_id=row.vuln_id)
            .order_by(models.VulnerabilityEvent.id)
        ]
        return types.SimpleNamespace(
            count=row.observation_count,
            last_run=row.last_seen_run_id,
            state=row.state,
            reopens=row.reopen_count,
            events=events,
        )


def _close_finding(settings) -> None:
    with get_session(settings.postgres_url) as session:
        session.query(models.Vulnerability).one().state = vuln_states.CLOSED


def test_replaying_a_published_run_does_not_count_its_observations_twice(tmp_path):
    """A publication whose derived updates ran and whose row was not closed —
    a replica killed between the two — is published again. The findings it
    folds are the same facts, not a second sighting of them."""
    settings = _settings(tmp_path, "sensor")
    _seed_findings_run(settings)
    _clean_tracker(settings)
    publication_id = _owed(settings, "job-replayed")

    for _ in range(2):
        _feed(settings, publication_id)

    finding = _finding(settings)
    assert finding.count == 1
    assert finding.events == ["observed"]


def test_the_next_job_under_a_reused_run_id_reopens_a_closed_finding(tmp_path):
    """A nightly integration submits ``run_id="nightly"`` every night. The
    finding was closed in between and came back: the second job is a new
    sighting, not a replay of the first, whatever its run is called."""
    settings = _settings(tmp_path, "sensor")
    _seed_findings_run(settings, "nightly")
    _clean_tracker(settings)

    _feed(settings, _owed(settings, "job-monday", "nightly"), "nightly")
    _close_finding(settings)
    _feed(settings, _owed(settings, "job-tuesday", "nightly"), "nightly")

    finding = _finding(settings)
    assert finding.state == vuln_states.OPEN
    assert finding.count == 2
    assert finding.reopens == 1
    assert finding.events == ["observed", "reopened"]


def test_a_replay_after_a_later_run_counts_nothing_and_winds_nothing_back(tmp_path):
    """Run A is fed and its replica dies before closing the row; run B, another
    job over the same host, is fed; A's row falls due and is fed again."""
    settings = _settings(tmp_path, "sensor")
    _seed_findings_run(settings, "run-a")
    _seed_findings_run(settings, "run-b")
    _clean_tracker(settings)
    run_a = _owed(settings, "job-a", "run-a")

    _feed(settings, run_a, "run-a")
    _feed(settings, _owed(settings, "job-b", "run-b"), "run-b")
    _close_finding(settings)
    _feed(settings, run_a, "run-a")

    finding = _finding(settings)
    assert finding.count == 2
    assert finding.last_run == "run-b"
    # Closed after B, and A is older than the closure: not a regression.
    assert finding.state == vuln_states.CLOSED
    assert finding.events == ["observed", "observed"]


def test_a_replayed_asset_upsert_neither_revives_nor_winds_back(tmp_path):
    """The same replay, on the registry: A's second pass must not point the
    asset back at A, nor bring back an asset retired after B."""
    settings = _settings(tmp_path, "sensor")
    _seed_findings_run(settings, "run-a")
    _seed_findings_run(settings, "run-b")
    _clean_tracker(settings)
    run_a = _owed(settings, "job-a", "run-a")

    _feed(settings, run_a, "run-a")
    _feed(settings, _owed(settings, "job-b", "run-b"), "run-b")
    with get_session(settings.postgres_url) as session:
        asset_id = (
            session.query(models.AssetIdentifier.asset_id)
            .filter_by(tenant_id="default", identifier_value="10.0.0.5")
            .scalar()
        )
        session.get(models.Asset, asset_id).status = "decommissioned"
    _feed(settings, run_a, "run-a")

    with get_session(settings.postgres_url) as session:
        asset = session.get(models.Asset, asset_id)
        assert asset.status == "decommissioned"
        assert asset.last_scan_run_id == "run-b"


def test_two_attempts_folding_one_publication_at_once_count_it_once(tmp_path, monkeypatch):
    """Two attempts on one row after its lease lapsed, folding side by side.
    The second waits for the first's transaction and then reads its mark;
    neither may read "not folded yet" while the other is folding."""
    import threading
    import time

    from sqlalchemy import text

    settings = _settings(tmp_path, "sensor")
    _seed_findings_run(settings)
    _clean_tracker(settings)
    publication_id = _owed(settings, "job-raced")
    # The registry first, as the sequence has it: a finding needs its asset.
    assets_service.upsert_assets_from_run(settings, tenant_id="default", run_id=RUN_ID)
    real = vulns_service._declared_surface_for_run  # noqa: SLF001
    first_inside = threading.Event()
    release = threading.Event()
    callers: list[str] = []

    def _hold_the_first(session, **kwargs):
        callers.append(threading.current_thread().name)
        if threading.current_thread().name == "first":
            first_inside.set()
            release.wait(10)
        return real(session, **kwargs)

    monkeypatch.setattr(vulns_service, "_declared_surface_for_run", _hold_the_first)

    def _fold():
        vulns_service.register_findings_from_run(
            settings, tenant_id="default", run_id=RUN_ID, publication_id=publication_id
        )

    first = threading.Thread(target=_fold, name="first")
    second = threading.Thread(target=_fold, name="second")
    first.start()
    assert first_inside.wait(10)
    second.start()
    # Until the second attempt is blocked on a lock, or has given up waiting.
    deadline = time.monotonic() + 5
    while second.is_alive() and time.monotonic() < deadline:
        with get_session(settings.postgres_url) as session:
            waiting = session.execute(
                text("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock'")
            ).scalar_one()
        if waiting:
            break
        time.sleep(0.05)
    release.set()
    first.join(10)
    second.join(10)

    assert _finding(settings).count == 1
    assert callers == ["first"]


def test_two_entries_of_one_pass_on_one_key_are_two_observations(tmp_path):
    """What a run reports twice it observed twice, as it always did; the mark
    stops a second *pass*, not a second entry."""
    settings = _settings(tmp_path, "sensor")
    _seed_findings_run(settings, "run-once")
    _seed_findings_run(settings, "run-twice", findings=2)
    _clean_tracker(settings)

    # Twice for a key the pass creates, and twice for one it finds.
    _feed(settings, _owed(settings, "job-twice-new", "run-twice"), "run-twice")
    assert _finding(settings).count == 2
    _feed(settings, _owed(settings, "job-once", "run-once"), "run-once")
    _feed(settings, _owed(settings, "job-twice-known", "run-twice"), "run-twice")

    finding = _finding(settings)
    assert finding.count == 5
    assert finding.events == ["observed"] * 5


@pytest.mark.parametrize("mode", ["local", "sensor"])
def test_a_row_a_peer_closed_meanwhile_is_not_fed_again(
    tmp_path, monkeypatch, derived, mode
):
    """Two attempts on one row: the peer published, fed and closed it while
    this one was publishing. This one finds it gone and feeds nothing."""
    bucket = FakeS3Client()
    settings = _settings(tmp_path, mode, bucket)
    real_publish_run = artifact_workspace.publish_run
    monkeypatch.setattr(artifact_workspace, "publish_run", _store_is_down)
    job_id = _finish(settings, monkeypatch, mode, "succeeded")
    monkeypatch.setattr(artifact_workspace, "publish_run", real_publish_run)
    real_publish = run_publisher._publish  # noqa: SLF001

    def _peer_closes_it(settings_, publication):
        real_publish(settings_, publication)
        with get_session(settings_.postgres_url) as session:
            session.query(models.RunPublication).filter_by(
                publication_id=publication.publication_id
            ).delete()

    monkeypatch.setattr(run_publisher, "_publish", _peer_closes_it)
    run_publisher.reconcile_once(settings, now=_later())

    assert derived.names() == []
    assert run_publisher.pending_publications(settings, job_id) == []


def test_a_retried_local_row_leaves_the_latest_run_pointer_alone(
    tmp_path, monkeypatch, derived
):
    """The scanner wrote ``latest_run.json`` as it finished. By the time a
    retry publishes this run a newer scan has written it again, and a retry
    that rewrote it would point it back at the older run."""
    bucket = FakeS3Client()
    settings = _settings(tmp_path, "local", bucket)
    real_publish_run = artifact_workspace.publish_run
    monkeypatch.setattr(artifact_workspace, "publish_run", _store_is_down)
    job_id = _local(settings, monkeypatch, "succeeded")
    monkeypatch.setattr(artifact_workspace, "publish_run", real_publish_run)
    pointer = Path(settings.state_dir) / "latest_run.json"
    pointer.write_text(json.dumps({"run_id": "20261004T120000Z-newer"}), encoding="utf-8")

    assert run_publisher.reconcile_once(settings, now=_later())["published"] == 1

    assert json.loads(pointer.read_text(encoding="utf-8"))["run_id"] == "20261004T120000Z-newer"
    assert derived.names() == MATRIX["succeeded"]
    assert run_publisher.pending_publications(settings, job_id) == []


def test_a_local_row_an_old_replica_ended_for_want_of_an_archive_is_requeued(
    tmp_path, monkeypatch, derived
):
    """Mid-rollout, a replica on the previous release adopts a local row: it
    publishes the run, then asks for the archive a local row never has and
    ends it ``dead``, unfed. A requeue on this release feeds it, so the
    console must say requeue — a discard would drop the feed for good."""
    settings = _settings(tmp_path, "local")

    def _old_replica(*_args, **_kwargs):
        raise run_publisher._TreeIsGone(run_publisher._ARCHIVE_IS_GONE)  # noqa: SLF001

    real_project = run_publisher._project  # noqa: SLF001
    monkeypatch.setattr(run_publisher, "_project", _old_replica)
    job_id = _local(settings, monkeypatch, "succeeded")
    monkeypatch.setattr(run_publisher, "_project", real_project)
    [row] = run_publisher.publications_for_job(settings, job_id, tenant_id=None)
    assert row["status"] == "dead"
    assert row["resolution"] == "requeue"
    assert row["tree_kept_until"] is None

    with get_session(settings.postgres_url) as session:
        # The rollout is over and the old replica's attempt with it.
        session.get(models.RunPublication, row["publication_id"]).leased_until = None
    run_publisher.requeue_publication(settings, row["publication_id"], job_id=job_id)
    assert run_publisher.reconcile_once(settings, now=_later())["published"] == 1

    assert derived.names() == MATRIX["succeeded"]
    assert run_publisher.pending_publications(settings, job_id) == []


def test_a_dead_local_row_is_not_a_rescan_after_a_day(tmp_path):
    """The staging sweep that makes a day-old sensor tree a re-scan never
    takes a local run's directory, so a requeue still has something to send."""
    settings = _settings(tmp_path, "local")
    row = run_publisher.new_local_publication(
        settings,
        job_id="job-old",
        run_id=RUN_ID,
        tenant_id="default",
        job_status="succeeded",
        exit_code=0,
        scan_error=None,
        surface=None,
        source=Path(settings.output_dir) / "runs" / RUN_ID,
    )
    row.status = run_publisher.STATUS_DEAD
    row.last_error = "ArtifactStoreError: bucket unreachable"

    later = row.created_at + timedelta(days=3)
    assert run_publisher._resolution(row, now=later) == "requeue"  # noqa: SLF001


def test_a_refused_local_result_leaves_its_run_tagged_with_the_job(
    tmp_path, monkeypatch, derived
):
    """The job was written off while its scanner ran, so the terminal write is
    refused and nothing publishes the run. Its flat directory must still not
    read as the default tenant's, and the write-off's reason must survive."""
    from api.services import runs as runs_service

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

    flat = Path(settings.output_dir) / "runs" / RUN_ID
    marker = json.loads((flat / artifact_workspace.RUN_MARKER).read_text(encoding="utf-8"))
    assert marker["tenant_id"] == "default"
    assert marker["job_id"] == job_id
    assert runs_service.read_run_tenant(flat) == "default"
    job = jobs_service.get_job(settings, job_id)
    assert job.status == "failed"
    assert job.error.startswith("orphaned by a restart")
    assert f"runs/{RUN_ID} was left in place" in job.error
    assert derived.names() == []
