"""The scan queue's priority, concurrency ceiling and admission (#365).

Before this a tenant's queue was a FIFO with no ceiling: every queued scan
could be out with a sensor at once, an urgent re-scan waited behind the
nightly sweep, and nothing refused the thousandth queued scan. The tests below
are written against the three promises the issue makes and against the one
that matters most under load — that the concurrency ceiling holds when two API
replicas claim for the same tenant at the same moment.
"""

from __future__ import annotations

import concurrent.futures
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.db import models
from api.db import tenant_scope
from api.db.engine import get_session
from api.schemas import StartScanRequest
from api.services import agents as agents_service
from api.services import job_reaper
from api.services import job_states
from api.services import jobs as jobs_service
from api.services import local_job_runner
from api.services import local_scan_executor
from api.services import metrics_sources
from api.services import scan_queue
from api.services import scan_schedules
from api.services import schedule_dispatcher
from api.services import tenants as tenants_service
from api.settings import Settings
from tests.conftest import (
    approve_scan_scope,
    auth_headers,
    bearer,
    configured_client,
    login,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres

DEFAULT = tenants_service.DEFAULT_TENANT_ID


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


@pytest.fixture()
def svc(tmp_path: Path) -> Settings:
    """Service-level settings over a freshly reset database, one replica's view."""
    settings = make_settings(tmp_path, instance_id="replica-a", job_execution_mode="agent")
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(settings)
    approve_scan_scope(settings)
    agents_service.configure(settings)
    return settings


def _queue(
    settings: Settings,
    job_id: str,
    *,
    priority: int = 0,
    age_seconds: float = 0.0,
    execution: str = "agent",
    status: str = job_states.QUEUED,
    owner_id: str | None = None,
    tenant_id: str = DEFAULT,
) -> None:
    with get_session(settings.postgres_url) as session:
        session.add(
            models.Job(
                job_id=job_id,
                tenant_id=tenant_id,
                execution=execution,
                status=status,
                command=["true"],
                requested_by="test",
                priority=priority,
                owner_id=owner_id,
                queued_at=_now() - timedelta(seconds=age_seconds),
            )
        )


def _status(settings: Settings, job_id: str) -> str:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        assert row is not None
        return row.status


def _limit(settings: Settings, *, concurrent: int | None = None, queued: int | None = None) -> None:
    scan_queue.set_limits(
        settings, DEFAULT, max_concurrent_scans=concurrent, max_queued_scans=queued
    )


def _agent(agent_id: str) -> None:
    agents_service.register_agent(agent_id=agent_id, tenant_id=DEFAULT)


def _claim(settings: Settings, agent_id: str, job_id: str | None = None) -> str | None:
    claimed = jobs_service.claim_job(settings, agent_id, tenant_id=DEFAULT, job_id=job_id)
    return claimed.job_id if claimed else None


# --- Priority ---------------------------------------------------------------


def test_the_claim_hands_out_the_highest_priority_first_then_the_oldest(svc):
    _agent("agent-prio")
    _queue(svc, "old-default", age_seconds=300)
    _queue(svc, "new-urgent", priority=50, age_seconds=1)
    _queue(svc, "older-urgent", priority=50, age_seconds=10)
    _queue(svc, "bulk", priority=-10, age_seconds=600)

    order = [_claim(svc, "agent-prio") for _ in range(4)]

    assert order == ["older-urgent", "new-urgent", "old-default", "bulk"]


def test_a_queue_nobody_prioritised_is_still_the_fifo_it_was(svc):
    """Post-upgrade state: every row reads priority 0, so the order is age."""
    _agent("agent-fifo")
    for index, age in enumerate((30, 10, 20)):
        _queue(svc, f"fifo-{index}", age_seconds=age)
    with get_session(svc.postgres_url) as session:
        # What migration 0074 leaves on rows that existed before it.
        assert {row.priority for row in session.execute(select(models.Job)).scalars()} == {0}

    assert [_claim(svc, "agent-fifo") for _ in range(3)] == ["fifo-0", "fifo-2", "fifo-1"]


# --- Concurrency ceiling: sensor claims --------------------------------------


def test_a_tenant_at_its_ceiling_is_handed_nothing_until_a_scan_ends(svc):
    _agent("agent-c1")
    _agent("agent-c2")
    for index in range(3):
        _queue(svc, f"ceil-{index}", age_seconds=10 - index)
    _limit(svc, concurrent=1)

    assert _claim(svc, "agent-c1") == "ceil-0"
    # A second sensor of the same tenant, a queue with work in it: nothing.
    assert _claim(svc, "agent-c2") is None
    assert _status(svc, "ceil-1") == job_states.QUEUED

    # Being stopped still occupies the slot: the agent is scanning until it
    # confirms (#360).
    jobs_service.mark_running(svc, "ceil-0", agent_id="agent-c1")
    jobs_service.cancel_job(svc, "ceil-0", username="op", tenant_id=DEFAULT)
    assert _status(svc, "ceil-0") == job_states.CANCELLING
    assert _claim(svc, "agent-c2") is None

    jobs_service.force_status(svc, "ceil-0", job_states.CANCELLED)
    assert _claim(svc, "agent-c2") == "ceil-1"


def test_the_nats_path_naming_a_job_is_held_to_the_ceiling_too(svc):
    _agent("agent-n1")
    _queue(svc, "nats-a", age_seconds=5)
    _queue(svc, "nats-b", age_seconds=1)
    _limit(svc, concurrent=1)
    assert _claim(svc, "agent-n1", job_id="nats-a") == "nats-a"

    assert _claim(svc, "agent-n1", job_id="nats-b") is None
    assert _status(svc, "nats-b") == job_states.QUEUED


def test_a_tenant_without_a_ceiling_claims_as_before(svc):
    _agent("agent-free")
    for index in range(5):
        _queue(svc, f"free-{index}", age_seconds=10 - index)
    _limit(svc, concurrent=None)
    assert [_claim(svc, "agent-free") for _ in range(5)] == [f"free-{i}" for i in range(5)]


def _slow_slot(monkeypatch, delay: float) -> None:
    """Widen the window between deciding a slot and committing the claim.

    The claim's decision and its write are one transaction; what keeps two of
    them apart is the tenant's claim lock, which is held until commit. Sleeping
    after the decision — still inside the transaction — gives a second replica
    every chance to decide on the same count. Without the lock it does.
    """
    original = scan_queue.hold_slot

    def slow(session, tenant_id, **kwargs):
        granted = original(session, tenant_id, **kwargs)
        time.sleep(delay)
        return granted

    monkeypatch.setattr(scan_queue, "hold_slot", slow)


def test_two_replicas_claiming_at_once_never_exceed_the_ceiling(svc, tmp_path, monkeypatch):
    """The ceiling is decided under a lock, not read in Python and then written.

    Six sensors on two "replicas" (settings objects with their own instance id,
    one shared database, a connection each), released together against a
    tenant allowed two scans. Before the claim lock every one of them counted
    zero scans out and claimed — six out against a ceiling of two.
    """
    replicas = [
        svc,
        make_settings(tmp_path / "b", instance_id="replica-b", job_execution_mode="agent"),
    ]
    for index in range(10):
        _queue(svc, f"race-{index}", age_seconds=100 - index)
    agents = [f"agent-race-{index}" for index in range(6)]
    for agent_id in agents:
        _agent(agent_id)
    _limit(svc, concurrent=2)
    _slow_slot(monkeypatch, 0.3)
    start = threading.Barrier(len(agents))

    def claim(index: int) -> str | None:
        start.wait(timeout=10)
        return _claim(replicas[index % 2], agents[index])

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(agents)) as pool:
        claimed = [job for job in pool.map(claim, range(len(agents))) if job]

    assert len(claimed) == 2, claimed
    with get_session(svc.postgres_url) as session:
        out = session.execute(
            select(models.Job.job_id).where(models.Job.status.in_(scan_queue.OCCUPYING))
        ).scalars().all()
    assert sorted(out) == sorted(claimed)


# --- Concurrency ceiling: local scans ---------------------------------------


def test_a_local_scan_waits_for_its_tenants_slot_and_then_for_its_turn(svc):
    owner = svc.instance_id
    _queue(svc, "local-running", execution="local", status=job_states.RUNNING, owner_id=owner)
    _queue(svc, "local-low", execution="local", owner_id=owner, age_seconds=60)
    _queue(svc, "local-high", execution="local", owner_id=owner, priority=10, age_seconds=1)
    _limit(svc, concurrent=1)

    assert local_job_runner._start(svc, "local-high") is False
    assert local_job_runner._start(svc, "local-low") is False

    jobs_service.force_status(svc, "local-running", job_states.SUCCEEDED)
    # The slot is free, and the older job asking first does not get it: the
    # higher priority one is still waiting on this replica.
    assert local_job_runner._start(svc, "local-low") is False
    assert local_job_runner._start(svc, "local-high") is True
    assert _status(svc, "local-high") == job_states.RUNNING

    jobs_service.force_status(svc, "local-high", job_states.SUCCEEDED)
    assert local_job_runner._start(svc, "local-low") is True


def test_a_local_scan_counts_against_the_same_ceiling_as_a_sensors(svc):
    _agent("agent-mixed")
    _queue(svc, "mixed-agent", age_seconds=10)
    _queue(svc, "mixed-local", execution="local", owner_id=svc.instance_id)
    _limit(svc, concurrent=1)

    assert local_job_runner._start(svc, "mixed-local") is True
    assert _claim(svc, "agent-mixed") is None


def test_two_replicas_starting_local_scans_at_once_take_one_slot(svc, tmp_path, monkeypatch):
    replica_b = make_settings(tmp_path / "b", instance_id="replica-b")
    _queue(svc, "lrace-a", execution="local", owner_id=svc.instance_id)
    _queue(svc, "lrace-b", execution="local", owner_id=replica_b.instance_id)
    _limit(svc, concurrent=1)
    _slow_slot(monkeypatch, 0.3)
    start = threading.Barrier(2)

    def begin(pair: tuple[Settings, str]) -> bool:
        start.wait(timeout=10)
        return local_job_runner._start(*pair)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        started = list(pool.map(begin, [(svc, "lrace-a"), (replica_b, "lrace-b")]))

    assert sorted(started) == [False, True]


def test_a_waiting_local_scan_that_is_cancelled_never_launches(svc, monkeypatch):
    _queue(svc, "wait-running", execution="local", status=job_states.RUNNING, owner_id=svc.instance_id)
    _queue(svc, "wait-me", execution="local", owner_id=svc.instance_id)
    _limit(svc, concurrent=1)
    waits: list[float] = []

    def cancel_while_waiting(seconds: float) -> bool:
        waits.append(seconds)
        jobs_service.cancel_job(svc, "wait-me", username="op", tenant_id=DEFAULT)
        return False

    def never(*_args, **_kwargs):
        raise AssertionError("a cancelled job must not launch its scanner")

    monkeypatch.setattr(local_scan_executor, "wait_unless_draining", cancel_while_waiting)
    monkeypatch.setattr(local_scan_executor, "run_scanner", never)

    local_job_runner.run_job(svc, "wait-me", ["true"])

    assert waits == [svc.scan_queue_local_poll_seconds]
    assert _status(svc, "wait-me") == job_states.CANCELLED


def test_a_waiting_local_scan_starts_when_the_slot_frees(svc, monkeypatch):
    import subprocess

    _queue(svc, "free-running", execution="local", status=job_states.RUNNING, owner_id=svc.instance_id)
    _queue(svc, "free-next", execution="local", owner_id=svc.instance_id)
    _limit(svc, concurrent=1)

    def finish_the_other(_seconds: float) -> bool:
        jobs_service.force_status(svc, "free-running", job_states.SUCCEEDED)
        return False

    launched: list[str] = []

    def scanner(job_id: str, command: list[str]):
        launched.append(job_id)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(local_scan_executor, "wait_unless_draining", finish_the_other)
    monkeypatch.setattr(local_scan_executor, "run_scanner", scanner)

    local_job_runner.run_job(svc, "free-next", ["true"])

    assert launched == ["free-next"]
    assert _status(svc, "free-next") == job_states.SUCCEEDED


def test_a_database_error_while_waiting_is_retried_not_fatal(svc, monkeypatch):
    """A thread that died here would strand its job — and the ones behind it."""
    import subprocess

    from sqlalchemy.exc import OperationalError

    _queue(svc, "retry-me", execution="local", owner_id=svc.instance_id)
    real_start = local_job_runner._start
    calls: list[str] = []

    def flaky(settings, job_id):
        calls.append(job_id)
        if len(calls) == 1:
            raise OperationalError("SELECT 1", {}, Exception("connection reset"))
        return real_start(settings, job_id)

    monkeypatch.setattr(local_job_runner, "_start", flaky)
    monkeypatch.setattr(local_scan_executor, "wait_unless_draining", lambda _seconds: False)
    monkeypatch.setattr(
        local_scan_executor,
        "run_scanner",
        lambda job_id, command: subprocess.CompletedProcess(command, 0, "", ""),
    )

    local_job_runner.run_job(svc, "retry-me", ["true"])

    assert calls == ["retry-me", "retry-me"]
    assert _status(svc, "retry-me") == job_states.SUCCEEDED


def test_local_scans_of_equal_priority_start_oldest_first(svc):
    _queue(svc, "eq-new", execution="local", owner_id=svc.instance_id, age_seconds=1)
    _queue(svc, "eq-old", execution="local", owner_id=svc.instance_id, age_seconds=60)
    _limit(svc, concurrent=1)

    assert local_job_runner._start(svc, "eq-new") is False
    assert local_job_runner._start(svc, "eq-old") is True


def test_a_better_job_of_another_replica_does_not_hold_this_ones_back(svc):
    """Only the replica that accepted a local scan can start it. A better one
    queued on another replica — or left by a pod that is gone — is not this
    replica's to wait for, or one orphan would stop the tenant's local scans."""
    _queue(
        svc, "foreign-urgent", execution="local", owner_id="replica-gone",
        priority=50, age_seconds=60,
    )
    _queue(svc, "mine", execution="local", owner_id=svc.instance_id)
    _limit(svc, concurrent=1)

    assert local_job_runner._start(svc, "mine") is True


def test_a_waiting_local_scan_gives_up_when_local_scans_are_stopped(svc, monkeypatch):
    _queue(svc, "drain-running", execution="local", status=job_states.RUNNING, owner_id=svc.instance_id)
    _queue(svc, "drain-waiting", execution="local", owner_id=svc.instance_id)
    _limit(svc, concurrent=1)
    waits: list[float] = []

    def draining(seconds: float) -> bool:
        waits.append(seconds)
        if len(waits) > 3:
            raise AssertionError("the thread kept waiting after stop_all began")
        return True

    def never(*_args, **_kwargs):
        raise AssertionError("a scan that never got its slot must not launch")

    monkeypatch.setattr(local_scan_executor, "wait_unless_draining", draining)
    monkeypatch.setattr(local_scan_executor, "run_scanner", never)

    local_job_runner.run_job(svc, "drain-waiting", ["true"])

    assert waits == [svc.scan_queue_local_poll_seconds]
    # Left queued: its waiting mark lapses and the reaper writes it off.
    assert _status(svc, "drain-waiting") == job_states.QUEUED


# --- Local scans whose replica went away --------------------------------------


def _lapse_wait(settings: Settings, job_id: str) -> None:
    """Move a waiting scan's mark into the past instead of waiting one out."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        row.claimed_until = _now() - timedelta(seconds=1)


def test_a_local_scan_left_waiting_by_a_replaced_pod_is_failed_and_frees_the_queue(
    svc, tmp_path
):
    """A Deployment's pod gets a new name, and so a new ``instance_id``, on
    every rollout. Startup reconciliation only fails the rows of its own id, so
    a scan the old pod was holding back for a slot stayed ``queued`` for good:
    nobody would start it, and it went on counting against
    ``max_queued_scans`` and the installation's depth until the tenant was
    refused every new scan."""
    old_pod = make_settings(tmp_path / "old", instance_id="api-7f9c4-old")
    _queue(svc, "slot-holder", status=job_states.RUNNING)
    _queue(svc, "orphan-waiting", execution="local", owner_id=old_pod.instance_id)
    _limit(svc, concurrent=1, queued=1)
    svc.scan_queue_max_depth = 1
    # The old pod's thread asked, was told to wait, and then the pod was replaced.
    assert local_job_runner._start(old_pod, "orphan-waiting") is False
    _lapse_wait(svc, "orphan-waiting")
    # The new pod starts under its own name: the row is not its to reconcile.
    jobs_service.load_jobs(svc)
    assert _status(svc, "orphan-waiting") == job_states.QUEUED
    with pytest.raises(scan_queue.QueueFull):
        scan_queue.assert_admitted(svc, tenant_id=DEFAULT)

    assert job_reaper.reap_expired_leases(svc) == {"requeued": 0, "failed": 1}

    assert _status(svc, "orphan-waiting") == job_states.FAILED
    with get_session(svc.postgres_url) as session:
        error = session.get(models.Job, "orphan-waiting").error
    assert old_pod.instance_id in error
    scan_queue.assert_admitted(svc, tenant_id=DEFAULT)
    assert _status(svc, "slot-holder") == job_states.RUNNING


def test_a_local_scan_whose_pod_died_before_it_ever_asked_is_failed_too(svc):
    """Accepted, and the pod gone before its thread first asked for a slot:
    no mark at all. Its age is the only evidence, and a lease of it is enough."""
    _queue(
        svc, "never-asked", execution="local", owner_id="api-gone",
        age_seconds=svc.job_lease_seconds + 60,
    )
    _queue(svc, "just-accepted", execution="local", owner_id="replica-b", age_seconds=1)

    assert job_reaper.reap_expired_leases(svc) == {"requeued": 0, "failed": 1}

    assert _status(svc, "never-asked") == job_states.FAILED
    assert _status(svc, "just-accepted") == job_states.QUEUED


def test_a_live_replicas_waiting_scan_is_not_reaped_by_another(svc, tmp_path):
    """Two replicas: B holds a scan back for a slot, A runs the reaper. However
    long the scan has waited, B asking again is what keeps it alive."""
    replica_b = make_settings(tmp_path / "b", instance_id="replica-b")
    _queue(svc, "slot-holder", status=job_states.RUNNING)
    _queue(
        svc, "patient", execution="local", owner_id=replica_b.instance_id,
        age_seconds=svc.job_lease_seconds * 4,
    )
    _limit(svc, concurrent=1)

    assert local_job_runner._start(replica_b, "patient") is False
    assert job_reaper.reap_expired_leases(svc) == {"requeued": 0, "failed": 0}

    # A mark that lapsed is renewed by the next ask, not only by the first.
    _lapse_wait(svc, "patient")
    assert local_job_runner._start(replica_b, "patient") is False
    assert job_reaper.reap_expired_leases(svc) == {"requeued": 0, "failed": 0}
    assert _status(svc, "patient") == job_states.QUEUED

    jobs_service.force_status(svc, "slot-holder", job_states.SUCCEEDED)
    assert local_job_runner._start(replica_b, "patient") is True


def test_a_waiting_local_scan_does_not_queue_on_the_tenants_claim_lock(svc):
    """A waiter that blocked on the claim lock would hold a pooled connection
    for as long as the claim in front of it — which may be reading a job's
    inputs from the object store. Hundreds of waiting scans would then starve
    the request handlers of connections. It asks again at the next poll."""
    _queue(svc, "lock-waiting", execution="local", owner_id=svc.instance_id)
    _limit(svc, concurrent=1)
    held = threading.Event()
    release = threading.Event()

    def hold_the_lock() -> None:
        with get_session(svc.postgres_url) as session:
            scan_queue._lock_claims(session, DEFAULT)
            held.set()
            release.wait(timeout=30)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        holder = pool.submit(hold_the_lock)
        assert held.wait(timeout=10)
        try:
            asked = pool.submit(local_job_runner._start, svc, "lock-waiting")
            assert asked.result(timeout=5) is False
        finally:
            release.set()
        holder.result(timeout=10)

    with get_session(svc.postgres_url) as session:
        mark = session.get(models.Job, "lock-waiting").claimed_until
    # It still said it is alive while it was turned away.
    assert mark is not None and mark > _now()
    assert local_job_runner._start(svc, "lock-waiting") is True


# --- Admission ---------------------------------------------------------------


def _client(tmp_path: Path, monkeypatch, **overrides) -> TestClient:
    return configured_client(tmp_path, monkeypatch, job_execution_mode="agent", **overrides)


def test_a_full_tenant_queue_refuses_a_new_scan_with_429_and_retry_after(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, scan_queue_retry_after_seconds=45)
    admin = auth_headers(client, "admin")
    operator = auth_headers(client, "operator")
    limits = client.put(
        f"/api/tenants/{DEFAULT}/queue-limits",
        headers=admin,
        json={"max_concurrent_scans": None, "max_queued_scans": 2},
    )
    assert limits.status_code == 200, limits.text

    for _ in range(2):
        assert client.post("/api/jobs", headers=operator, json={"mode": "safe"}).status_code == 202
    refused = client.post("/api/jobs", headers=operator, json={"mode": "safe"})

    assert refused.status_code == 429, refused.text
    assert refused.headers["Retry-After"] == "45"
    assert "2/2" in refused.json()["detail"]


def test_the_installation_wide_queue_ceiling_counts_every_tenants_queue(tmp_path, monkeypatch):
    """The backstop is installation-wide, so it has to see past the caller's tenant.

    Under row-level security (``enforce``, the default) a request of a tenant
    user or a tenant's service token runs as that tenant, and an unfiltered
    count in its session sees only its own rows: the queue another tenant
    filled was invisible and the "global" ceiling became one per tenant.
    """
    client = _client(tmp_path, monkeypatch, scan_queue_max_depth=1)
    assert tenant_scope.enforcing()
    admin = auth_headers(client, "admin")
    created = client.post("/api/tenants", headers=admin, json={"tenant_id": "acme", "name": "Acme"})
    assert created.status_code in (200, 201), created.text
    # The whole installation's queue is one scan of another tenant.
    _queue(make_settings(tmp_path), "acme-waiting", tenant_id="acme")
    token = client.post(
        f"/api/tenants/{DEFAULT}/service-tokens",
        headers=admin,
        json={"name": "ci", "scopes": ["*"], "role": "operator"},
    ).json()["token"]

    for caller in (auth_headers(client, "operator"), bearer(token)):
        refused = client.post("/api/jobs", headers=caller, json={"mode": "safe"})

        assert refused.status_code == 429, refused.text
        assert refused.headers["Retry-After"] == "60"
        detail = refused.json()["detail"]
        assert "installation" in detail
        # The other tenants' numbers are not this caller's business.
        assert "1/1" not in detail and "acme" not in detail


def test_a_verification_rescan_is_admitted_into_a_full_queue(svc):
    _limit(svc, queued=1)
    _queue(svc, "already-waiting")
    request = StartScanRequest(mode="safe", tenant_id=DEFAULT)
    with pytest.raises(scan_queue.QueueFull):
        jobs_service.start_scan(svc, request, username="op")

    job = jobs_service.start_scan(svc, request, username="verifier", quota_exempt=True)

    assert job.status == job_states.QUEUED


def test_queue_limits_are_the_platforms_to_set_and_the_tenant_admins_to_read(
    tmp_path, monkeypatch
):
    client = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    tenant_admin = _member(client, admin, "queue-tenant-admin", "admin")
    url = f"/api/tenants/{DEFAULT}/queue-limits"

    assert client.get(url, headers=tenant_admin).json()["max_concurrent_scans"] is None
    refused = client.put(url, headers=tenant_admin, json={"max_concurrent_scans": 50})
    assert refused.status_code == 403

    written = client.put(
        url, headers=admin, json={"max_concurrent_scans": 3, "max_queued_scans": 0}
    )
    assert written.status_code == 200, written.text
    assert written.json() == {
        "tenant_id": DEFAULT,
        "max_concurrent_scans": 3,
        # 0 is stored as unlimited, as the quota does.
        "max_queued_scans": None,
        "global_max_queued_scans": None,
    }
    assert client.get(url, headers=tenant_admin).json()["max_concurrent_scans"] == 3
    trail = _trail("tenant.queue_limits")
    assert [(row.actor, row.after) for row in trail] == [
        ("admin", {"max_concurrent_scans": 3, "max_queued_scans": None})
    ]


def _trail(action: str) -> list[models.AuditEvent]:
    from tests.conftest import POSTGRES_URL

    with get_session(POSTGRES_URL) as session:
        rows = session.execute(
            select(models.AuditEvent)
            .where(models.AuditEvent.action == action)
            .order_by(models.AuditEvent.id)
        ).scalars().all()
        session.expunge_all()
        return list(rows)


# --- Who may raise a priority --------------------------------------------------


def _member(client: TestClient, admin: dict[str, str], username: str, role: str) -> dict[str, str]:
    password = f"{username}-password-1234"
    created = client.post(
        "/api/users",
        headers=admin,
        json={"username": username, "password": password, "role": "viewer"},
    )
    assert created.status_code == 201, created.text
    granted = client.put(
        f"/api/tenants/{DEFAULT}/members/{username}", headers=admin, json={"role": role}
    )
    assert granted.status_code == 200, granted.text
    return {"Authorization": f"Bearer {login(client, username, password)}"}


def test_raising_a_scan_above_the_default_needs_the_named_permission(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    operator = auth_headers(client, "operator")
    # A global viewer who administers this tenant: the permission, not the
    # global role, is what lets them jump the queue.
    tenant_admin = _member(client, admin, "queue-prio-admin", "admin")

    refused = client.post("/api/jobs", headers=operator, json={"mode": "safe", "priority": 5})
    assert refused.status_code == 403
    assert "scan.priority.raise" in refused.json()["detail"]

    lowered = client.post("/api/jobs", headers=operator, json={"mode": "safe", "priority": -5})
    assert lowered.status_code == 202 and lowered.json()["priority"] == -5

    raised = client.post(
        "/api/jobs", headers=tenant_admin, json={"mode": "safe", "priority": 40}
    )
    assert raised.status_code == 202, raised.text
    assert raised.json()["priority"] == 40

    out_of_bounds = client.post(
        "/api/jobs", headers=tenant_admin, json={"mode": "safe", "priority": 101}
    )
    assert out_of_bounds.status_code == 422


def test_moving_a_queued_scan(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    operator = auth_headers(client, "operator")
    tenant_admin = _member(client, admin, "queue-move-admin", "admin")
    mine = client.post("/api/jobs", headers=operator, json={"mode": "safe"}).json()["job_id"]
    url = f"/api/jobs/{mine}/priority"

    # Making room is the operator's own business.
    assert client.put(url, headers=operator, json={"priority": -3}).json()["priority"] == -3
    refused = client.put(url, headers=operator, json={"priority": 3})
    assert refused.status_code == 403

    assert client.put(url, headers=tenant_admin, json={"priority": 30}).json()["priority"] == 30
    # Undoing the admin's decision is the same decision the other way round.
    assert client.put(url, headers=operator, json={"priority": 0}).status_code == 403
    assert client.get(f"/api/jobs/{mine}", headers=operator).json()["priority"] == 30

    assert [
        (row.actor, row.before["priority"], row.after["priority"])
        for row in _trail("scan.priority")
    ] == [("operator", 0, -3), ("queue-move-admin", -3, 30)]

    assert client.put(url, headers=operator, json={"priority": 200}).status_code == 422
    assert (
        client.put("/api/jobs/no-such-job/priority", headers=operator, json={"priority": 0})
        .status_code
        == 404
    )

    cancelled = client.post(f"/api/jobs/{mine}/cancel", headers=operator)
    assert cancelled.status_code == 200
    gone = client.put(url, headers=tenant_admin, json={"priority": 1})
    assert gone.status_code == 409


@pytest.mark.parametrize("tenant_rls", ["enforce", "off"])
def test_another_tenants_job_cannot_be_moved(tmp_path, monkeypatch, tenant_rls):
    """With ``OCTO_TENANT_RLS=off`` the database shows every tenant's row, and
    the tenant check in ``scan_queue.set_priority`` is all that is left."""
    client = _client(tmp_path, monkeypatch, tenant_rls=tenant_rls)
    admin = auth_headers(client, "admin")
    created = client.post("/api/tenants", headers=admin, json={"tenant_id": "acme", "name": "Acme"})
    assert created.status_code in (200, 201), created.text
    settings = make_settings(tmp_path)
    approve_scan_scope(settings, tenant_id="acme")
    theirs = client.post(
        "/api/jobs", headers=admin, json={"mode": "safe", "tenant_id": "acme"}
    ).json()["job_id"]
    operator = auth_headers(client, "operator")

    moved = client.put(f"/api/jobs/{theirs}/priority", headers=operator, json={"priority": -1})

    assert moved.status_code == 404
    assert client.get(f"/api/jobs/{theirs}", headers=admin).json()["priority"] == 0


# --- The per-tenant queue depth metric ---------------------------------------


def test_the_tenant_snapshot_reports_each_tenants_queue_depth(svc):
    svc.metrics_tenant_top_n = 5
    metrics_sources.configure(svc)
    try:
        _queue(svc, "depth-1")
        _queue(svc, "depth-2")
        _queue(svc, "depth-running", status=job_states.RUNNING)
        snapshot = metrics_sources.tenant_snapshot()
    finally:
        metrics_sources.configure(None)  # type: ignore[arg-type]
    assert snapshot is not None
    assert snapshot.jobs_queued[DEFAULT] == 2
    assert snapshot.jobs_queued[metrics_sources.TENANT_OTHER] == 0


# --- The schedule dispatcher and a full queue -----------------------------------


def test_a_full_queue_defers_a_scheduled_scan_instead_of_dropping_its_tick(svc, monkeypatch):
    """A full queue drains by itself within ``Retry-After``; a spent monthly
    quota does not. Treated like the quota, a nightly scan that met a busy
    minute was skipped until the next night, and counted as a billing refusal."""
    scan_schedules.configure(svc)
    sched = scan_schedules.create_schedule(
        tenant_id=DEFAULT,
        name="nightly",
        cron=None,
        interval_seconds=86400,
        scan_options={"mode": "safe"},
        targets={},
        created_by=None,
    )
    scan_schedules.record_dispatch(
        sched["schedule_id"], job_id="prior", ran_at=datetime.now(UTC) - timedelta(days=2)
    )
    _limit(svc, queued=1)
    _queue(svc, "already-waiting")
    monkeypatch.setattr(jobs_service, "get_job", lambda settings, job_id: None)
    dispatcher = schedule_dispatcher.ScheduleDispatcher(settings=svc)
    asked_at = datetime.now(UTC)

    dispatcher._tick()  # noqa: SLF001

    stats = dispatcher.stats
    assert stats["deferred_queue_full"] == 1
    assert stats["skipped_quota"] == 0
    assert stats["dispatched"] == 0
    assert stats["errors"] == 0
    updated = scan_schedules.get_schedule(sched["schedule_id"])
    next_run = datetime.fromisoformat(updated["next_run_at"].replace("Z", "+00:00")).replace(
        tzinfo=UTC
    )
    retry = timedelta(seconds=svc.scan_queue_retry_after_seconds)
    # Retried after the back-off, not at the next cadence tick a day away.
    assert asked_at + retry - timedelta(seconds=5) <= next_run <= datetime.now(UTC) + retry
    assert updated["last_job_id"] == "prior"
