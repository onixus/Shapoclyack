"""Phase 8.5: per-tenant recurring scan schedules (CRUD + due-schedule dispatch window)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from api.services import scan_schedules
from api.services import tenants as tenants_service
from api.settings import Settings
from tests.conftest import POSTGRES_URL, requires_postgres

pytestmark = requires_postgres


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        output_dir=tmp_path / "output",
        state_dir=tmp_path / "state",
        config_path=Path("scanner/config/default.yaml"),
        postgres_url=POSTGRES_URL,
    )


@pytest.fixture()
def settings(tmp_path):
    s = _settings(tmp_path)
    tenants_service.configure(s)
    tenants_service.load_tenants(s)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(s)
    scan_schedules.configure(s)
    scan_schedules.reset_for_tests()
    return s


def test_create_schedule_with_cron(settings):
    sched = scan_schedules.create_schedule(
        tenant_id="default",
        name="weekly",
        cron="0 2 * * 0",
        interval_seconds=None,
        scan_options={"mode": "balanced", "delta": True},
        targets={"ranges": "10.0.0.0/24"},
        created_by="admin",
    )
    assert sched["schedule_id"].startswith("sch_")
    assert sched["enabled"] is True
    assert sched["next_run_at"] is not None
    assert sched["scan_options"] == {"mode": "balanced", "delta": True}


def test_create_schedule_with_interval(settings):
    sched = scan_schedules.create_schedule(
        tenant_id="default",
        name="hourly",
        cron=None,
        interval_seconds=3600,
        scan_options={"mode": "fast"},
        targets={},
        created_by="admin",
    )
    next_run = datetime.fromisoformat(sched["next_run_at"].replace("Z", "+00:00"))
    assert next_run > datetime.now(UTC)


def test_create_schedule_rejects_both_or_neither_cadence(settings):
    with pytest.raises(ValueError, match="exactly one"):
        scan_schedules.create_schedule(
            tenant_id="default", name="bad", cron="0 2 * * 0", interval_seconds=60,
            scan_options={}, targets={}, created_by=None,
        )
    with pytest.raises(ValueError, match="exactly one"):
        scan_schedules.create_schedule(
            tenant_id="default", name="bad", cron=None, interval_seconds=None,
            scan_options={}, targets={}, created_by=None,
        )


def test_create_schedule_rejects_bad_cron(settings):
    with pytest.raises(ValueError):
        scan_schedules.create_schedule(
            tenant_id="default", name="bad", cron="not a cron", interval_seconds=None,
            scan_options={}, targets={}, created_by=None,
        )


def test_create_schedule_rejects_unknown_tenant(settings):
    with pytest.raises(ValueError, match="Unknown tenant_id"):
        scan_schedules.create_schedule(
            tenant_id="ten_missing", name="x", cron=None, interval_seconds=60,
            scan_options={}, targets={}, created_by=None,
        )


def test_update_schedule_merges_scan_options_and_targets(settings):
    sched = scan_schedules.create_schedule(
        tenant_id="default", name="s", cron=None, interval_seconds=3600,
        scan_options={"mode": "balanced", "delta": True}, targets={"ranges": "10.0.0.0/24"},
        created_by=None,
    )
    updated = scan_schedules.update_schedule(sched["schedule_id"], scan_options={"delta": False})
    assert updated["scan_options"] == {"mode": "balanced", "delta": False}
    assert updated["targets"] == {"ranges": "10.0.0.0/24"}


def test_update_schedule_enable_disable(settings):
    sched = scan_schedules.create_schedule(
        tenant_id="default", name="s", cron=None, interval_seconds=3600,
        scan_options={}, targets={}, created_by=None,
    )
    disabled = scan_schedules.update_schedule(sched["schedule_id"], enabled=False)
    assert disabled["enabled"] is False


def test_update_schedule_missing_returns_none(settings):
    assert scan_schedules.update_schedule("sch_missing", enabled=False) is None


def test_delete_schedule(settings):
    sched = scan_schedules.create_schedule(
        tenant_id="default", name="s", cron=None, interval_seconds=3600,
        scan_options={}, targets={}, created_by=None,
    )
    assert scan_schedules.delete_schedule(sched["schedule_id"]) is True
    assert scan_schedules.get_schedule(sched["schedule_id"]) is None
    assert scan_schedules.delete_schedule(sched["schedule_id"]) is False


def test_due_schedules_filters_by_next_run_at_and_enabled(settings):
    due_now = scan_schedules.create_schedule(
        tenant_id="default", name="due", cron=None, interval_seconds=60,
        scan_options={}, targets={}, created_by=None,
    )
    scan_schedules.update_schedule(due_now["schedule_id"], enabled=True)
    # Force next_run_at into the past by recording a dispatch far enough back
    # that the recomputed next_run_at (ran_at + 60s) is already due.
    scan_schedules.record_dispatch(
        due_now["schedule_id"], job_id="job1", ran_at=datetime.now(UTC) - timedelta(hours=1)
    )

    not_due = scan_schedules.create_schedule(
        tenant_id="default", name="not_due", cron=None, interval_seconds=3600,
        scan_options={}, targets={}, created_by=None,
    )

    disabled = scan_schedules.create_schedule(
        tenant_id="default", name="disabled", cron=None, interval_seconds=60,
        scan_options={}, targets={}, created_by=None,
    )
    scan_schedules.update_schedule(disabled["schedule_id"], enabled=False)
    scan_schedules.record_dispatch(
        disabled["schedule_id"], job_id="job2", ran_at=datetime.now(UTC) - timedelta(hours=1)
    )

    due_ids = {s["schedule_id"] for s in scan_schedules.due_schedules(datetime.now(UTC))}
    assert due_now["schedule_id"] in due_ids
    assert not_due["schedule_id"] not in due_ids
    assert disabled["schedule_id"] not in due_ids


def test_record_dispatch_advances_next_run_at(settings):
    sched = scan_schedules.create_schedule(
        tenant_id="default", name="s", cron=None, interval_seconds=60,
        scan_options={}, targets={}, created_by=None,
    )
    ran_at = datetime.now(UTC)
    updated = scan_schedules.record_dispatch(sched["schedule_id"], job_id="job1", ran_at=ran_at)
    assert updated["last_job_id"] == "job1"
    next_run = datetime.fromisoformat(updated["next_run_at"].replace("Z", "+00:00"))
    assert next_run == ran_at + timedelta(seconds=60)
