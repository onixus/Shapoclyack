"""Phase 8.5: per-tenant recurring scan schedules (CRUD + due-schedule dispatch window)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from api.services import auth_audit
from api.services import scan_schedules
from api.services import scan_scopes
from api.services import tenants as tenants_service
from api.settings import Settings
from tests.conftest import (
    approve_scan_scope,
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

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
    auth_audit.configure(s)
    auth_audit.reset_for_tests()
    # Writing a schedule needs an approved scan scope since #244, the way
    # starting a scan has since #226; see tests/conftest.py.
    approve_scan_scope(s)
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


# --- the approved scan scope (#244) -----------------------------------------


def test_a_schedule_outside_the_approved_scope_is_refused_when_it_is_written(settings):
    """The refusal moves to the moment the operator can act on it.

    Dispatch already refused this schedule — silently, hours later, by simply
    not starting a scan. The operator's evidence was an absence.
    """
    scan_scopes.replace_scope(
        settings,
        tenant_id="default",
        entries=[{"effect": "allow", "kind": "cidr", "value": "10.0.0.0/8"}],
        approved_by="admin",
    )

    with pytest.raises(scan_scopes.ScanScopeDenied, match="outside the approved scan scope"):
        scan_schedules.create_schedule(
            tenant_id="default",
            name="nightly",
            cron=None,
            interval_seconds=3600,
            scan_options={"mode": "fast"},
            targets={"ranges": "192.168.0.0/24"},
            created_by="operator",
        )

    assert scan_schedules.list_schedules(tenant_id="default")[1] == 0


def test_a_tenant_with_no_approved_scope_writes_no_schedule(settings):
    """Fail-closed here too, including a schedule on the default target files."""
    scan_scopes.replace_scope(
        settings, tenant_id="default", entries=[], approved_by="admin"
    )

    with pytest.raises(scan_scopes.ScanScopeDenied, match="no approved scan scope"):
        scan_schedules.create_schedule(
            tenant_id="default",
            name="nightly",
            cron=None,
            interval_seconds=3600,
            scan_options={"mode": "fast"},
            targets={},
            created_by="operator",
        )


def test_editing_a_schedule_into_an_out_of_scope_target_is_refused(settings):
    """The check is on the merged result, which is what would be stored."""
    scan_scopes.replace_scope(
        settings,
        tenant_id="default",
        entries=[{"effect": "allow", "kind": "cidr", "value": "10.0.0.0/8"}],
        approved_by="admin",
    )
    sched = scan_schedules.create_schedule(
        tenant_id="default",
        name="nightly",
        cron=None,
        interval_seconds=3600,
        scan_options={"mode": "fast"},
        targets={"ranges": "10.1.0.0/24"},
        created_by="operator",
    )

    with pytest.raises(scan_scopes.ScanScopeDenied, match="outside the approved scan scope"):
        scan_schedules.update_schedule(
            sched["schedule_id"], targets={"ranges": "192.168.0.0/24"}
        )

    assert scan_schedules.get_schedule(sched["schedule_id"])["targets"] == {
        "ranges": "10.1.0.0/24"
    }


def test_writing_a_schedule_does_not_resolve_its_names(settings, monkeypatch):
    """A record hours before the run is not evidence about the run.

    The resolution check belongs to dispatch and to the scanner's own filter;
    refusing a schedule over an answer with no shelf life would be a verdict
    about a moment nobody is scanning in.
    """
    scan_scopes.replace_scope(
        settings,
        tenant_id="default",
        entries=[
            {"effect": "allow", "kind": "domain", "value": "example.com"},
            {"effect": "deny", "kind": "cidr", "value": "169.254.0.0/16"},
        ],
        approved_by="admin",
    )
    monkeypatch.setattr(
        scan_scopes, "_resolve", lambda host: pytest.fail(f"resolved {host} at write time")
    )

    sched = scan_schedules.create_schedule(
        tenant_id="default",
        name="nightly",
        cron=None,
        interval_seconds=3600,
        scan_options={"mode": "fast"},
        targets={"domains": "metadata.example.com"},
        created_by="operator",
    )

    assert sched["targets"] == {"domains": "metadata.example.com"}


def test_an_out_of_scope_schedule_over_the_api_is_403(tmp_path, monkeypatch):
    """403, not 422: the cadence and the targets are both well-formed."""
    client = configured_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    # configured_client() approves an allow-all scope; narrow it first.
    client.put(
        "/api/tenants/default/scan-scope",
        headers=admin,
        json={"entries": [{"effect": "allow", "kind": "cidr", "value": "10.0.0.0/8"}]},
    )

    refused = client.post(
        "/api/schedules",
        headers=auth_headers(client, "operator"),
        json={"name": "nightly", "interval_seconds": 3600, "ranges": "192.168.0.0/24"},
    )

    assert refused.status_code == 403
    assert "outside the approved scan scope" in refused.json()["detail"]

    events, total = auth_audit.list_events(outcome=auth_audit.OUTCOME_DENIED)
    assert total == 1
    assert events[0]["username"] == "operator"
    assert events[0]["reason"] == auth_audit.REASON_SCAN_SCOPE
