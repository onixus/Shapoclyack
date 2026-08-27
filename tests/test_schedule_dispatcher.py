"""Phase 8.5: schedule dispatcher tick logic (dispatch-once, overlap-skip, cadence advance)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from api.schemas import JobInfo
from api.services import jobs as jobs_service
from api.services import scan_schedules
from api.services import schedule_dispatcher
from api.services import tenants as tenants_service
from api.settings import Settings
from tests.conftest import approve_scan_scope, make_settings, requires_postgres

pytestmark = requires_postgres


def _settings(tmp_path: Path) -> Settings:
    return make_settings(tmp_path)


@pytest.fixture()
def settings(tmp_path):
    s = _settings(tmp_path)
    tenants_service.configure(s)
    tenants_service.load_tenants(s)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(s)
    scan_schedules.configure(s)
    scan_schedules.reset_for_tests()
    # Writing a schedule needs an approved scan scope since #244, the way
    # starting a scan has since #226; see tests/conftest.py.
    approve_scan_scope(s)
    return s


def _fake_job(job_id: str, *, status: str = "queued") -> JobInfo:
    return JobInfo(
        job_id=job_id,
        status=status,
        run_id=None,
        mode="balanced",
        command=["python", "-m", "scanner.main"],
        requested_by="scheduler",
        execution="local",
        tenant_id="default",
    )


def test_tick_dispatches_due_schedule_once(settings, monkeypatch):
    sched = scan_schedules.create_schedule(
        tenant_id="default", name="s", cron=None, interval_seconds=60,
        scan_options={"mode": "fast"}, targets={}, created_by=None,
    )
    scan_schedules.record_dispatch(
        sched["schedule_id"], job_id="prior", ran_at=datetime.now(UTC) - timedelta(hours=1)
    )

    started: list[str] = []
    keys: list[str | None] = []

    def fake_start_scan(_settings, request, *, username, idempotency_key=None):
        job_id = f"job_{len(started)}"
        started.append(job_id)
        keys.append(idempotency_key)
        return _fake_job(job_id, status="succeeded")

    monkeypatch.setattr(jobs_service, "start_scan", fake_start_scan)
    monkeypatch.setattr(jobs_service, "get_job", lambda settings, job_id: None)

    due_at = scan_schedules.get_schedule(sched["schedule_id"])["next_run_at"]

    dispatcher = schedule_dispatcher.ScheduleDispatcher(settings=settings)
    dispatcher._tick()  # noqa: SLF001

    assert started == ["job_0"]
    updated = scan_schedules.get_schedule(sched["schedule_id"])
    assert updated["last_job_id"] == "job_0"
    # Keyed on the schedule's due time, not this replica's clock (P1.5), so a
    # second replica dispatching the same tick computes the same key and the
    # idempotent start hands back the job instead of scanning twice.
    assert keys == [f"schedule:{sched['schedule_id']}:{due_at}"]


def test_tick_skips_when_previous_job_still_running(settings, monkeypatch):
    sched = scan_schedules.create_schedule(
        tenant_id="default", name="s", cron=None, interval_seconds=60,
        scan_options={}, targets={}, created_by=None,
    )
    scan_schedules.record_dispatch(
        sched["schedule_id"], job_id="running_job", ran_at=datetime.now(UTC) - timedelta(hours=1)
    )

    monkeypatch.setattr(jobs_service, "get_job", lambda settings, job_id: _fake_job(job_id, status="running"))
    started = []
    monkeypatch.setattr(
        jobs_service, "start_scan", lambda *a, **k: started.append(1) or _fake_job("x")
    )

    dispatcher = schedule_dispatcher.ScheduleDispatcher(settings=settings)
    dispatcher._tick()  # noqa: SLF001

    assert started == []
    assert dispatcher.stats["skipped_overlap"] == 1


def test_tick_ignores_not_yet_due_schedule(settings, monkeypatch):
    scan_schedules.create_schedule(
        tenant_id="default", name="s", cron=None, interval_seconds=3600,
        scan_options={}, targets={}, created_by=None,
    )
    started = []
    monkeypatch.setattr(
        jobs_service, "start_scan", lambda *a, **k: started.append(1) or _fake_job("x")
    )
    monkeypatch.setattr(jobs_service, "get_job", lambda settings, job_id: None)

    dispatcher = schedule_dispatcher.ScheduleDispatcher(settings=settings)
    dispatcher._tick()  # noqa: SLF001

    assert started == []
