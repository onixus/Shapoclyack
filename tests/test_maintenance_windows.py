"""Maintenance windows, the change freeze and scan admission (#352).

The calendar half of the feature is unit-tested in
``tests/test_maintenance_rrule.py`` (no database). This file is about what the
platform *does* with it: the routes, the refusal a scan gets, the audit row it
leaves, and the deferral the recurring dispatcher performs instead of losing a
tick.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from api.services import audit as audit_service
from api.services import jobs as jobs_service
from api.services import maintenance
from api.services import promoted_domains
from api.services import scan_schedules
from api.services import schedule_dispatcher
from api.settings import Settings
from tests.conftest import (
    approve_scan_scope,
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres

DEFAULT = "default"


def _settings(tmp_path: Path) -> Settings:
    # agent execution mode: POST /api/jobs queues a job for a remote worker
    # instead of running a scan in the test process (as tests/test_quotas.py).
    return make_settings(tmp_path, job_execution_mode="agent")


def _local(at: datetime) -> str:
    """A wall clock string for ``dtstart_local`` (UTC zone in these tests)."""
    return at.astimezone(UTC).replace(tzinfo=None).isoformat(timespec="minutes")


def _window_fields(*, open_now: bool, **overrides) -> dict:
    """A daily window that is either open right now or opens in two hours.

    Derived from the clock rather than a fixed date so the test cannot become
    "passes except between 00:00 and 00:30 UTC".
    """
    now = datetime.now(UTC)
    start = now - timedelta(hours=1) if open_now else now + timedelta(hours=2)
    fields = {
        "name": "nightly freeze" if open_now else "tonight",
        "kind": maintenance.KIND_BLACKOUT,
        "timezone": "UTC",
        "rrule": "FREQ=DAILY",
        "dtstart_local": _local(start),
        "duration_minutes": 120,
    }
    fields.update(overrides)
    return fields


@pytest.fixture()
def client(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    test_client = configured_client(tmp_path, monkeypatch, settings=settings)
    test_client.settings = settings  # type: ignore[attr-defined]
    return test_client


# --------------------------------------------------------------------------
# 1. Admission: a manual scan
# --------------------------------------------------------------------------


def test_no_windows_and_no_freeze_admits_everything(client):
    """The upgrade path: an installation that has written no calendar behaves
    exactly as it did on 0043."""
    auth = auth_headers(client, "operator")
    assert client.post("/api/jobs", headers=auth, json={"mode": "safe"}).status_code == 202


def test_an_open_blackout_refuses_a_scan_with_409_and_retry_after(client):
    settings = client.settings
    window = maintenance.create_window(
        settings, tenant_id=DEFAULT, fields=_window_fields(open_now=True), created_by="admin"
    )
    auth = auth_headers(client, "operator")

    refused = client.post("/api/jobs", headers=auth, json={"mode": "safe"})
    # 409, not 403: the operator is entitled to this scan, the tenant's
    # calendar is simply in a state that forbids it — and that state expires.
    assert refused.status_code == 409
    detail = refused.json()["detail"]
    assert window["name"] in detail
    assert 0 < int(refused.headers["Retry-After"]) <= 3600 + 60

    # And nothing was queued: a refused scan is not a scan.
    assert client.get("/api/jobs", headers=auth).json()["total"] == 0


def test_a_window_that_is_not_open_yet_admits_the_scan(client):
    maintenance.create_window(
        client.settings,
        tenant_id=DEFAULT,
        fields=_window_fields(open_now=False),
        created_by="admin",
    )
    auth = auth_headers(client, "operator")
    assert client.post("/api/jobs", headers=auth, json={"mode": "safe"}).status_code == 202


def test_a_change_freeze_refuses_every_scan_and_offers_no_retry_time(client):
    settings = client.settings
    maintenance.set_change_freeze(
        settings, DEFAULT, frozen=True, note="quarter close", actor="admin"
    )
    auth = auth_headers(client, "operator")

    refused = client.post("/api/jobs", headers=auth, json={"mode": "safe"})
    assert refused.status_code == 409
    assert "change freeze" in refused.json()["detail"]
    assert "quarter close" in refused.json()["detail"]
    # No Retry-After: a freeze has no end until somebody lifts it, and a
    # retry time here would be an invention an integration would believe.
    assert "Retry-After" not in refused.headers

    maintenance.set_change_freeze(settings, DEFAULT, frozen=False, actor="admin")
    assert client.post("/api/jobs", headers=auth, json={"mode": "safe"}).status_code == 202


def test_an_allowed_window_makes_the_tenant_opt_in(client):
    """One ``allowed`` window and scanning is forbidden outside it — the
    inverse polarity, which is a different customer's ask than a blackout."""
    settings = client.settings
    maintenance.create_window(
        settings,
        tenant_id=DEFAULT,
        fields=_window_fields(open_now=False, kind=maintenance.KIND_ALLOWED),
        created_by="admin",
    )
    auth = auth_headers(client, "operator")

    refused = client.post("/api/jobs", headers=auth, json={"mode": "safe"})
    assert refused.status_code == 409
    assert "may only scan inside" in refused.json()["detail"]
    assert int(refused.headers["Retry-After"]) > 0

    # Open the window (it starts an hour ago now) and the same scan is admitted.
    maintenance.create_window(
        settings,
        tenant_id=DEFAULT,
        fields=_window_fields(open_now=True, kind=maintenance.KIND_ALLOWED, name="now"),
        created_by="admin",
    )
    assert client.post("/api/jobs", headers=auth, json={"mode": "safe"}).status_code == 202


def test_a_blackout_beats_an_open_allowed_window(client):
    settings = client.settings
    maintenance.create_window(
        settings,
        tenant_id=DEFAULT,
        fields=_window_fields(open_now=True, kind=maintenance.KIND_ALLOWED, name="business hours"),
        created_by="admin",
    )
    maintenance.create_window(
        settings, tenant_id=DEFAULT, fields=_window_fields(open_now=True), created_by="admin"
    )
    auth = auth_headers(client, "operator")
    refused = client.post("/api/jobs", headers=auth, json={"mode": "safe"})
    assert refused.status_code == 409
    assert "blackout" in refused.json()["detail"]


def test_a_disabled_window_stops_nothing(client):
    maintenance.create_window(
        client.settings,
        tenant_id=DEFAULT,
        fields=_window_fields(open_now=True, enabled=False),
        created_by="admin",
    )
    auth = auth_headers(client, "operator")
    assert client.post("/api/jobs", headers=auth, json={"mode": "safe"}).status_code == 202


def test_an_asset_group_blackout_only_stops_the_scans_that_touch_it(client):
    settings = client.settings
    maintenance.create_window(
        settings,
        tenant_id=DEFAULT,
        fields=_window_fields(
            open_now=True,
            name="payments",
            scope_kind=maintenance.SCOPE_ASSET_GROUP,
            asset_group="payments",
            scope_targets=["10.0.5.0/24"],
        ),
        created_by="admin",
    )
    auth = auth_headers(client, "operator")

    inside = client.post(
        "/api/jobs", headers=auth, json={"mode": "safe", "ranges": "10.0.0.0/16"}
    )
    assert inside.status_code == 409, inside.text
    assert "payments" in inside.json()["detail"]

    elsewhere = client.post(
        "/api/jobs", headers=auth, json={"mode": "safe", "ranges": "192.168.7.0/24"}
    )
    assert elsewhere.status_code == 202, elsewhere.text


def test_a_promoted_domain_cannot_carry_a_scan_into_a_blacked_out_group(client):
    """A promoted related domain rides along with *every* scan the tenant
    starts (org_profile M4), so a group blackout has to see it — otherwise
    scanning an unrelated domain is a way into the group the window protects."""
    settings = client.settings
    promoted_domains.promote(
        settings,
        tenant_id=DEFAULT,
        domain="shop.example.com",
        source_run_id="run_1",
        promoted_by="operator",
    )
    maintenance.create_window(
        settings,
        tenant_id=DEFAULT,
        fields=_window_fields(
            open_now=True,
            name="payments",
            scope_kind=maintenance.SCOPE_ASSET_GROUP,
            asset_group="payments",
            scope_targets=["shop.example.com"],
        ),
        created_by="admin",
    )
    auth = auth_headers(client, "operator")

    refused = client.post(
        "/api/jobs", headers=auth, json={"mode": "safe", "domains": "corp.example.net"}
    )
    assert refused.status_code == 409, refused.text
    assert "payments" in refused.json()["detail"]


def test_the_refusal_is_recorded_in_the_audit_trail(client):
    maintenance.create_window(
        client.settings,
        tenant_id=DEFAULT,
        fields=_window_fields(open_now=True),
        created_by="admin",
    )
    auth = auth_headers(client, "operator")
    assert client.post("/api/jobs", headers=auth, json={"mode": "safe"}).status_code == 409

    events, total = audit_service.list_events(
        action=audit_service.ACTION_SCAN_MAINTENANCE_BLOCK
    )
    assert total == 1
    event = events[0]
    assert event["tenant_id"] == DEFAULT
    assert event["actor"] == "operator"
    assert event["after"]["reason"] == maintenance.REASON_BLACKOUT
    assert event["after"]["retry_at"]


# --------------------------------------------------------------------------
# 2. The routes
# --------------------------------------------------------------------------


def test_window_crud_over_http_and_the_calendar_view(client):
    admin = auth_headers(client, "admin")
    created = client.post("/api/maintenance-windows", headers=admin, json=_window_fields(open_now=True))
    assert created.status_code == 201, created.text
    window_id = created.json()["window_id"]

    calendar = client.get("/api/maintenance-windows", headers=auth_headers(client, "operator"))
    assert calendar.status_code == 200
    body = calendar.json()
    assert body["change_freeze"] is False
    assert body["admission"]["allowed"] is False
    assert body["admission"]["reason"] == maintenance.REASON_BLACKOUT
    assert [w["window_id"] for w in body["windows"]] == [window_id]
    assert body["windows"][0]["open_now"] is True
    assert body["windows"][0]["open_until"]

    patched = client.patch(
        f"/api/maintenance-windows/{window_id}",
        headers=admin,
        json={"enabled": False, "note": "paused for now"},
    )
    assert patched.status_code == 200
    assert patched.json()["enabled"] is False
    assert patched.json()["updated_by"] == "admin"

    assert client.delete(f"/api/maintenance-windows/{window_id}", headers=admin).status_code == 204
    assert client.get("/api/maintenance-windows", headers=admin).json()["windows"] == []


def test_writing_the_calendar_is_admin_only_and_reading_it_is_not(client):
    operator = auth_headers(client, "operator")
    viewer = auth_headers(client, "viewer")
    assert client.post(
        "/api/maintenance-windows", headers=operator, json=_window_fields(open_now=True)
    ).status_code == 403
    # An operator about to press "start scan" has to be able to see why it
    # will be refused; a viewer has no business with the queue at all.
    assert client.get("/api/maintenance-windows", headers=operator).status_code == 200
    assert client.get("/api/maintenance-windows", headers=viewer).status_code == 403


def test_a_window_of_another_tenant_is_a_404_not_a_403(client):
    """A tenant admin must not learn that somebody else's window id exists —
    the same rule GET /schedules/{id} follows."""
    admin = auth_headers(client, "admin")
    created = client.post(
        "/api/tenants", headers=admin, json={"tenant_id": "acme", "name": "Acme"}
    )
    assert created.status_code in (200, 201), created.text
    approve_scan_scope(client.settings, "acme")
    # The seeded `operator` account becomes an admin *inside acme only*, which
    # is what a customer's own administrator is.
    granted = client.put(
        "/api/tenants/acme/members/operator", headers=admin, json={"role": "admin"}
    )
    assert granted.status_code in (200, 201, 204), granted.text
    acme_admin = auth_headers(client, "operator")

    ours = maintenance.create_window(
        client.settings, tenant_id=DEFAULT, fields=_window_fields(open_now=True), created_by="admin"
    )

    calendar = client.get("/api/maintenance-windows", headers=acme_admin)
    assert calendar.json()["tenant_id"] == "acme"
    assert calendar.json()["windows"] == []
    refused = client.patch(
        f"/api/maintenance-windows/{ours['window_id']}",
        headers=acme_admin,
        json={"enabled": False},
    )
    assert refused.status_code == 404
    # …and a platform admin still reaches every tenant's calendar.
    assert client.patch(
        f"/api/maintenance-windows/{ours['window_id']}", headers=admin, json={"enabled": False}
    ).status_code == 200


def test_malformed_windows_are_refused_with_the_reason(client):
    admin = auth_headers(client, "admin")

    bad_rule = client.post(
        "/api/maintenance-windows",
        headers=admin,
        json=_window_fields(open_now=True, rrule="FREQ=WEEKLY;COUNT=4"),
    )
    assert bad_rule.status_code == 422
    assert "COUNT" in bad_rule.json()["detail"]

    bad_zone = client.post(
        "/api/maintenance-windows",
        headers=admin,
        json=_window_fields(open_now=True, timezone="Mars/Olympus"),
    )
    assert bad_zone.status_code == 422

    offset_dtstart = client.post(
        "/api/maintenance-windows",
        headers=admin,
        json=_window_fields(open_now=True, dtstart_local="2027-01-01T22:00+02:00"),
    )
    assert offset_dtstart.status_code == 422
    assert "wall clock" in offset_dtstart.json()["detail"]

    # An asset-group window with no selector would silently protect nobody.
    undefined_group = client.post(
        "/api/maintenance-windows",
        headers=admin,
        json=_window_fields(open_now=True, scope_kind="asset_group", asset_group="payments"),
    )
    assert undefined_group.status_code == 422
    assert "scope_targets" in undefined_group.json()["detail"]


def test_a_null_in_a_patch_leaves_the_field_alone(client):
    """Every field on the patch model is optional, so `{"enabled": null}` is a
    well-formed request. Read as `false` it would switch a blackout off — a
    fail-open edit in the one control whose entire job is to forbid."""
    admin = auth_headers(client, "admin")
    window_id = client.post(
        "/api/maintenance-windows", headers=admin, json=_window_fields(open_now=True)
    ).json()["window_id"]

    patched = client.patch(
        f"/api/maintenance-windows/{window_id}",
        headers=admin,
        json={"enabled": None, "note": "still on"},
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["enabled"] is True
    assert patched.json()["note"] == "still on"
    # …and the window is still the reason a scan is refused.
    assert client.post(
        "/api/jobs", headers=auth_headers(client, "operator"), json={"mode": "safe"}
    ).status_code == 409


def test_change_freeze_round_trips_and_is_audited(client):
    admin = auth_headers(client, "admin")
    frozen = client.put(
        "/api/change-freeze",
        headers=admin,
        json={"change_freeze": True, "note": "migration weekend"},
    )
    assert frozen.status_code == 200, frozen.text
    assert frozen.json()["change_freeze"] is True
    assert frozen.json()["change_freeze_by"] == "admin"

    read = client.get("/api/change-freeze", headers=auth_headers(client, "operator"))
    assert read.json()["change_freeze_note"] == "migration weekend"

    events, total = audit_service.list_events(action=audit_service.ACTION_TENANT_CHANGE_FREEZE)
    assert total == 1
    assert events[0]["before"]["change_freeze"] is False
    assert events[0]["after"]["change_freeze"] is True

    # Freezing is an admin act; an operator may read the state and no more.
    assert client.put(
        "/api/change-freeze",
        headers=auth_headers(client, "operator"),
        json={"change_freeze": False},
    ).status_code == 403
    # And a tenant the caller has no membership in is refused before the body.
    assert client.put(
        "/api/change-freeze",
        headers=admin,
        params={"tenant_id": "nope"},
        json={"change_freeze": True},
    ).status_code in (403, 404)


def test_a_platform_admin_can_read_one_tenants_calendar(client):
    admin = auth_headers(client, "admin")
    created = client.post(
        "/api/tenants", headers=admin, json={"tenant_id": "acme", "name": "Acme"}
    )
    assert created.status_code in (200, 201), created.text
    maintenance.create_window(
        client.settings, tenant_id="acme", fields=_window_fields(open_now=True), created_by="admin"
    )
    calendar = client.get("/api/tenants/acme/maintenance-windows", headers=admin)
    assert calendar.status_code == 200
    assert len(calendar.json()["windows"]) == 1
    assert client.get("/api/tenants/nope/maintenance-windows", headers=admin).status_code == 404
    assert client.get(
        "/api/tenants/acme/maintenance-windows", headers=auth_headers(client, "operator")
    ).status_code == 403


def test_window_writes_are_audited(client):
    admin = auth_headers(client, "admin")
    window_id = client.post(
        "/api/maintenance-windows", headers=admin, json=_window_fields(open_now=True)
    ).json()["window_id"]
    client.patch(
        f"/api/maintenance-windows/{window_id}", headers=admin, json={"duration_minutes": 30}
    )
    client.delete(f"/api/maintenance-windows/{window_id}", headers=admin)

    actions = [
        event["action"]
        for event in audit_service.list_events(resource_type="maintenance_window")[0]
    ]
    assert sorted(actions) == [
        audit_service.ACTION_MAINTENANCE_WINDOW_CREATE,
        audit_service.ACTION_MAINTENANCE_WINDOW_DELETE,
        audit_service.ACTION_MAINTENANCE_WINDOW_UPDATE,
    ]


# --------------------------------------------------------------------------
# 3. The recurring dispatcher defers rather than losing the tick
# --------------------------------------------------------------------------


def test_a_blacked_out_tick_is_deferred_to_the_end_of_the_window(client, monkeypatch):
    """The point of the feature that is easiest to get wrong: a schedule that
    fires during a blackout must run when the window closes, not vanish."""
    settings = client.settings
    scan_schedules.configure(settings)
    sched = scan_schedules.create_schedule(
        tenant_id=DEFAULT,
        name="nightly",
        cron=None,
        interval_seconds=86400,
        scan_options={"mode": "fast"},
        targets={},
        created_by=None,
    )
    scan_schedules.record_dispatch(
        sched["schedule_id"], job_id="prior", ran_at=datetime.now(UTC) - timedelta(days=2)
    )
    window = maintenance.create_window(
        settings, tenant_id=DEFAULT, fields=_window_fields(open_now=True), created_by="admin"
    )
    ends_at = maintenance.open_at(window, datetime.now(UTC))[1]

    monkeypatch.setattr(
        jobs_service, "get_job", lambda settings, job_id: None
    )
    dispatcher = schedule_dispatcher.ScheduleDispatcher(settings=settings)
    dispatcher._tick()  # noqa: SLF001

    assert dispatcher.stats["deferred_maintenance"] == 1
    assert dispatcher.stats["dispatched"] == 0
    updated = scan_schedules.get_schedule(sched["schedule_id"])
    # ``scan_schedules`` keeps next_run_at in a naive-UTC column, so the
    # comparison is against the naive form of the window's end.
    assert updated["next_run_at"] == ends_at.replace(tzinfo=None).isoformat()
    # Nothing ran, so the schedule's history says nothing ran.
    assert updated["last_job_id"] == "prior"


def test_a_frozen_tenants_tick_advances_by_its_own_cadence(client, monkeypatch):
    """A freeze has no end, so there is nothing to defer *to*: the schedule
    moves on by its cadence instead of being re-refused every 30 seconds."""
    settings = client.settings
    scan_schedules.configure(settings)
    sched = scan_schedules.create_schedule(
        tenant_id=DEFAULT,
        name="hourly",
        cron=None,
        interval_seconds=3600,
        scan_options={"mode": "fast"},
        targets={},
        created_by=None,
    )
    scan_schedules.record_dispatch(
        sched["schedule_id"], job_id="prior", ran_at=datetime.now(UTC) - timedelta(hours=2)
    )
    maintenance.set_change_freeze(settings, DEFAULT, frozen=True, actor="admin")

    monkeypatch.setattr(jobs_service, "get_job", lambda settings, job_id: None)
    dispatcher = schedule_dispatcher.ScheduleDispatcher(settings=settings)
    dispatcher._tick()  # noqa: SLF001

    assert dispatcher.stats["deferred_maintenance"] == 1
    next_run = datetime.fromisoformat(
        scan_schedules.get_schedule(sched["schedule_id"])["next_run_at"].replace("Z", "+00:00")
    ).replace(tzinfo=UTC)
    assert next_run > datetime.now(UTC) + timedelta(minutes=50)


def test_a_tick_outside_any_window_still_dispatches(client, monkeypatch):
    settings = client.settings
    scan_schedules.configure(settings)
    sched = scan_schedules.create_schedule(
        tenant_id=DEFAULT,
        name="hourly",
        cron=None,
        interval_seconds=3600,
        scan_options={"mode": "fast"},
        targets={},
        created_by=None,
    )
    scan_schedules.record_dispatch(
        sched["schedule_id"], job_id="prior", ran_at=datetime.now(UTC) - timedelta(hours=2)
    )
    maintenance.create_window(
        settings, tenant_id=DEFAULT, fields=_window_fields(open_now=False), created_by="admin"
    )

    # `start_scan` is deliberately *not* mocked: the admission check lives
    # inside it, so a test that replaced it would assert that a stub was
    # called and would pass just as happily with the window open.
    dispatcher = schedule_dispatcher.ScheduleDispatcher(settings=settings)
    dispatcher._tick()  # noqa: SLF001

    assert dispatcher.stats["deferred_maintenance"] == 0
    assert dispatcher.stats["dispatched"] == 1
    updated = scan_schedules.get_schedule(sched["schedule_id"])
    assert updated["last_job_id"] != "prior"
    # …and the job the dispatcher created is real and queued for an agent.
    job = jobs_service.get_job(settings, updated["last_job_id"])
    assert job is not None and job.status == "queued"
