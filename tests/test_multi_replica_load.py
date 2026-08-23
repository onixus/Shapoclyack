"""ROADMAP #188: Multi-replica concurrent load and race condition tests.

Exercises the concurrency guarantees introduced in P1 and #159 under load
across simulated multiple API replicas connected to the same database:
- Concurrent job claims via ``SELECT ... FOR UPDATE SKIP LOCKED`` (no double claims)
- Concurrent job submissions with identical idempotency keys (single job created)
- Concurrent scheduler dispatcher leader election (single dispatch per tick)
- Concurrent job reaper lease sweeps across replicas (idempotent, safe)
"""

from __future__ import annotations

import concurrent.futures
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from api.db.engine import get_session_factory
from api.db.models import Job, ScanSchedule, Tenant
from api.schemas import StartScanRequest
from api.services import agents as agents_service
from api.services import job_reaper
from api.services import jobs as jobs_service
from api.services import scan_schedules
from api.services import schedule_dispatcher
from api.services import tenants as tenants_service
from tests.conftest import make_settings, requires_postgres

pytestmark = requires_postgres


@pytest.fixture()
def multi_settings(tmp_path: Path):
    """Generate base settings for multi-replica tests."""
    s = make_settings(
        tmp_path,
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "output",
        instance_id="replica-0",
    )
    s.state_dir.mkdir(parents=True, exist_ok=True)
    s.output_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(s)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(s)
    agents_service.configure(s)
    scan_schedules.configure(s)
    scan_schedules.reset_for_tests()
    return s


def test_concurrent_job_claims_no_double_claim(multi_settings):
    """N concurrent workers claiming M jobs must never double-claim any job."""
    session_factory = get_session_factory(multi_settings.postgres_url)
    total_jobs = 20
    num_workers = 6

    # 1. Seed jobs in queued state
    job_ids: list[str] = []
    with session_factory() as session:
        tenant = session.scalar(select(Tenant).where(Tenant.tenant_id == "default"))
        assert tenant is not None
        for i in range(total_jobs):
            j_id = f"job-concurrent-{i}"
            job = Job(
                job_id=j_id,
                tenant_id="default",
                execution="agent",
                status="queued",
                command=["python", "-m", "scanner.main"],
                requested_by="admin",
                queued_at=datetime.now(UTC),
            )
            session.add(job)
            job_ids.append(j_id)
        session.commit()

    # 2. Concurrently claim jobs across worker threads (simulating multiple agent workers)
    claimed_jobs: list[str] = []
    errors: list[Exception] = []

    def worker_claim(agent_idx: int) -> list[str]:
        agent_id = f"agent-load-{agent_idx}"
        claimed: list[str] = []
        for _ in range(total_jobs):
            try:
                job_info = jobs_service.claim_job(
                    multi_settings,
                    agent_id=agent_id,
                    tenant_id="default",
                )
                if job_info is not None:
                    claimed.append(job_info.job_id)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
        return claimed

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [executor.submit(worker_claim, i) for i in range(num_workers)]
        for fut in concurrent.futures.as_completed(futures):
            claimed_jobs.extend(fut.result())

    assert not errors, f"Errors encountered during concurrent claim: {errors}"
    assert len(claimed_jobs) == total_jobs
    # Every job claimed exactly once — zero duplicates
    assert len(set(claimed_jobs)) == total_jobs
    assert set(claimed_jobs) == set(job_ids)


def test_concurrent_idempotent_job_creation(multi_settings):
    """Submitting the same idempotency key concurrently across replicas yields exactly one job."""
    idempotency_key = "idem-key-load-12345"
    num_callers = 10
    results: list[Any] = []
    errors: list[Exception] = []

    def create_job_attempt(replica_idx: int):
        try:
            settings_replica = make_settings(
                multi_settings.output_dir.parent / f"replica-{replica_idx}",
                instance_id=f"api-replica-{replica_idx}",
                job_execution_mode="agent",
            )
            req = StartScanRequest(
                targets=["192.168.1.1"],
                mode="quick",
                tenant_id="default",
            )
            job_info = jobs_service.start_scan(
                settings_replica,
                req,
                username="admin",
                idempotency_key=idempotency_key,
            )
            return job_info.job_id, True
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
            return None, False

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_callers) as executor:
        futures = [executor.submit(create_job_attempt, i) for i in range(num_callers)]
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res[0] is not None:
                results.append(res)

    assert not errors, f"Errors during concurrent idempotent creation: {errors}"
    assert len(results) == num_callers

    # All callers must receive the exact same job_id
    job_ids = [r[0] for r in results]
    assert len(set(job_ids)) == 1


def test_concurrent_scheduler_dispatch_leader_election(multi_settings):
    """Concurrent scheduler ticks across replicas result in single dispatch due to leader election."""
    session_factory = get_session_factory(multi_settings.postgres_url)
    due_time = datetime.now(UTC) - timedelta(minutes=5)

    # 1. Create a due schedule
    with session_factory() as session:
        sched = ScanSchedule(
            schedule_id="sched-concurrent-1",
            tenant_id="default",
            name="Concurrent Test Schedule",
            cron="* * * * *",
            targets={"include": ["10.0.0.1"]},
            scan_options={"mode": "balanced", "execution": "agent"},
            enabled=True,
            next_run_at=due_time,
            created_at=datetime.now(UTC),
        )
        session.add(sched)
        session.commit()

    num_replicas = 4
    dispatched_counts: list[int] = []
    errors: list[Exception] = []

    def run_replica_tick(replica_idx: int) -> int:
        replica_settings = make_settings(
            multi_settings.output_dir.parent / f"sched-replica-{replica_idx}",
            instance_id=f"api-sched-replica-{replica_idx}",
        )
        try:
            return schedule_dispatcher.tick(replica_settings)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
            return 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_replicas) as executor:
        futures = [executor.submit(run_replica_tick, i) for i in range(num_replicas)]
        for fut in concurrent.futures.as_completed(futures):
            dispatched_counts.append(fut.result())

    assert not errors, f"Errors in concurrent scheduler tick: {errors}"
    # Exactly one replica acquired the lock and dispatched 1 schedule
    assert sum(dispatched_counts) == 1


def test_concurrent_job_reaper_sweeps(multi_settings):
    """Multiple replicas running job reaper sweeps simultaneously handle expired jobs cleanly."""
    session_factory = get_session_factory(multi_settings.postgres_url)
    expired_time = datetime.now(UTC) - timedelta(minutes=10)

    with session_factory() as session:
        for i in range(10):
            job = Job(
                job_id=f"job-expired-{i}",
                tenant_id="default",
                execution="agent",
                status="claimed",
                claimed_until=expired_time,
                attempts=1,
                command=["python", "-m", "scanner.main"],
                requested_by="admin",
                queued_at=datetime.now(UTC),
            )
            session.add(job)
        session.commit()

    num_replicas = 4
    sweep_results: list[dict[str, int]] = []
    errors: list[Exception] = []

    def run_reaper_sweep(replica_idx: int):
        replica_settings = make_settings(
            multi_settings.output_dir.parent / f"reaper-replica-{replica_idx}",
            instance_id=f"api-reaper-replica-{replica_idx}",
        )
        try:
            return job_reaper.sweep(replica_settings)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
            return {"requeued": 0, "failed": 0}

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_replicas) as executor:
        futures = [executor.submit(run_reaper_sweep, i) for i in range(num_replicas)]
        for fut in concurrent.futures.as_completed(futures):
            sweep_results.append(fut.result())

    assert not errors, f"Errors during concurrent reaper sweep: {errors}"
    total_requeued = sum(r.get("requeued", 0) for r in sweep_results)
    # Total 10 expired jobs must be requeued across the concurrent sweeps without race errors
    assert total_requeued == 10
