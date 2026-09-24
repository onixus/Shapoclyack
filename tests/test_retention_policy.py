"""Per-tenant retention windows and legal hold, reaper by reaper (#332).

Every reaper used to read one window from ``Settings``. Each test below puts
three tenants side by side — one on the platform default, one with a window of
its own, one on legal hold — ages their data past the default, sweeps, and
asserts that each lost exactly what its own policy says. A reaper that still
read the global window fails the "own window" half; one that forgot the hold
fails the other.

Postgres-gated: the plan is read from ``tenant_retention_policies`` and
``tenant_legal_holds``, and the audit half runs through the SECURITY DEFINER
functions migration 0065 installs.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from api.db import models
from api.db.engine import get_session
from api.services import (
    agent_deployer,
    audit_retention,
    auth_audit,
    endpoint_retention,
    legal_hold,
    retention_policy,
    risk_snapshots,
    run_retention,
    screenshot_retention,
    workflow_events,
)
from api.services import tenants as tenants_service
from api.services.integrations import webhooks
from api.services.reports import store as report_store
from api.settings import Settings
from tests.conftest import make_settings, requires_postgres

pytestmark = requires_postgres

OWN = "own-window"
HELD = "on-hold"
PLAIN = "plain"


def _naive(moment: datetime) -> datetime:
    return moment.astimezone(UTC).replace(tzinfo=None)


def _set_policy(settings: Settings, tenant_id: str, **days: int) -> None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.TenantRetentionPolicy, tenant_id)
        if row is None:
            row = models.TenantRetentionPolicy(
                tenant_id=tenant_id, updated_at=_naive(datetime.now(UTC)), updated_by="tests"
            )
            session.add(row)
        for column, value in days.items():
            setattr(row, column, value)


@pytest.fixture()
def settings(tmp_path):
    """Three tenants beside ``default``: one with its own windows, one on hold."""
    s = make_settings(tmp_path)
    s.output_dir.mkdir(parents=True, exist_ok=True)
    s.state_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(s)
    tenants_service.load_tenants(s)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(s)
    for tenant_id in (OWN, HELD, PLAIN):
        tenants_service.create_tenant(name=tenant_id, tenant_id=tenant_id)
    legal_hold.place_hold(s, HELD, reason="matter 2026-17", set_by="tests")
    yield s
    # The hold's foreign key is RESTRICT: leaving it would break the next
    # test's tenant reset, and an order-dependent failure is the worst kind.
    with get_session(s.postgres_url) as session:
        session.query(models.TenantLegalHold).delete()
        session.query(models.TenantRetentionPolicy).delete()


# --------------------------------------------------------------------------- #
# The plan
# --------------------------------------------------------------------------- #


def test_the_categories_are_the_policy_tables_columns():
    """One column per category, and each names a real platform setting."""
    migration = (
        Path(__file__).resolve().parents[1]
        / "api/db/migrations/versions/0065_tenant_retention_legal_hold.py"
    ).read_text(encoding="utf-8")
    table = models.TenantRetentionPolicy.__table__
    for category in retention_policy.CATEGORIES:
        assert category.column in table.columns, category.key
        assert table.columns[category.column].nullable, category.key
        assert f'"{category.column}"' in migration, category.key
        assert hasattr(Settings(), category.setting), category.key
    day_columns = {name for name in table.columns.keys() if name.endswith("_days")}
    assert day_columns == {category.column for category in retention_policy.CATEGORIES}


def test_bounds_hold_the_audit_floor_and_refuse_what_cannot_apply(tmp_path, monkeypatch):
    s = make_settings(tmp_path)
    assert retention_policy.bounds(s)["audit_events"] == (365, 3650)
    s.retention_bounds = {"audit_events": {"min": 730}}
    assert retention_policy.bounds(s)["audit_events"] == (730, 3650)
    for bad in (
        {"no_such_category": {"min": 1}},
        {"runs": {"min": 0}},
        {"runs": {"min": 10, "max": 5}},
        {"reports": {"max": 100_000}},
    ):
        s.retention_bounds = bad
        with pytest.raises(ValueError):
            retention_policy.validate_configuration(s)

    # And the environment: malformed refuses to load rather than falling back
    # to compiled defaults that may be lower than what the operator meant.
    from api import settings as settings_module

    monkeypatch.setenv("OCTO_RETENTION_BOUNDS", '{"audit_events": {"min": "a year"}}')
    with pytest.raises(ValueError):
        settings_module._retention_bounds()
    monkeypatch.setenv("OCTO_RETENTION_BOUNDS", '{"audit_events": {"min": 730, "max": 1000}}')
    assert settings_module._retention_bounds() == {"audit_events": {"min": 730, "max": 1000}}


def test_a_plan_gives_each_tenant_its_own_window_and_a_held_tenant_none(settings):
    _set_policy(settings, OWN, run_days=90)
    # A held tenant's override is ignored, not merely outranked: the plan
    # never lists it, so no pass can pick it up by accident.
    _set_policy(settings, HELD, run_days=1)
    plan = retention_policy.load_plan(settings, retention_policy.RUNS)
    assert plan.default_days == settings.run_retention_days == 30
    assert plan.days_for(OWN) == 90
    assert plan.days_for(PLAIN) == 30
    assert plan.days_for(HELD) == 0
    assert HELD not in plan.overrides
    assert plan.excluded == {OWN, HELD}


# --------------------------------------------------------------------------- #
# Artifact reapers: runs, job inputs, screenshots
# --------------------------------------------------------------------------- #


def _age(path: Path, *, days: float) -> None:
    when = time.time() - days * 86400.0
    for item in [path, *path.rglob("*")]:
        os.utime(item, (when, when))


def _tenant_run(settings: Settings, tenant_id: str, run_id: str, *, days: float) -> Path:
    run_dir = settings.output_dir / "runs" / "_tenants" / tenant_id / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "run_meta.json").write_text(json.dumps({"run_id": run_id}), encoding="utf-8")
    (run_dir / "tenant.json").write_text(json.dumps({"tenant_id": tenant_id}), encoding="utf-8")
    _age(run_dir, days=days)
    return run_dir


def _flat_run(settings: Settings, run_id: str, *, marker: str | None, days: float) -> Path:
    run_dir = settings.output_dir / "runs" / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "run_meta.json").write_text(json.dumps({"run_id": run_id}), encoding="utf-8")
    if marker is not None:
        (run_dir / "tenant.json").write_text(marker, encoding="utf-8")
    _age(run_dir, days=days)
    return run_dir


def test_run_retention_sweeps_each_tenant_on_its_own_window(settings):
    _set_policy(settings, OWN, run_days=90)
    plain = _tenant_run(settings, PLAIN, "run-plain", days=45)
    own = _tenant_run(settings, OWN, "run-own", days=45)
    own_expired = _tenant_run(settings, OWN, "run-own-old", days=120)
    held = _tenant_run(settings, HELD, "run-held", days=400)
    # Pre-#427 flat runs: the owner is the marker, and no marker is default's.
    flat_own = _flat_run(settings, "flat-own", marker=json.dumps({"tenant_id": OWN}), days=45)
    flat_held = _flat_run(settings, "flat-held", marker=json.dumps({"tenant_id": HELD}), days=400)
    flat_default = _flat_run(settings, "flat-default", marker=None, days=45)

    stats = run_retention.sweep(settings)

    assert not plain.exists()
    assert own.exists()
    assert not own_expired.exists()
    assert held.exists()
    assert flat_own.exists()
    assert flat_held.exists()
    assert not flat_default.exists()
    assert stats["deleted"] == 3
    assert stats["kept"] == 4


def test_a_shorter_window_of_its_own_is_honoured_too(settings):
    _set_policy(settings, OWN, run_days=7)
    own = _tenant_run(settings, OWN, "run-own", days=10)
    plain = _tenant_run(settings, PLAIN, "run-plain", days=10)
    run_retention.sweep(settings)
    assert not own.exists()
    assert plain.exists()


def test_a_run_whose_owner_cannot_be_read_is_left_for_the_next_tick(settings):
    """An unreadable marker is not a missing one: guessing "default" could be
    deleting a held tenant's run."""
    garbled = _flat_run(settings, "flat-garbled", marker="{not json", days=400)
    stats = run_retention.sweep(settings)
    assert garbled.exists()
    assert stats["errors"] == 1


def test_a_plan_that_cannot_be_read_deletes_nothing(settings, monkeypatch):
    plain = _tenant_run(settings, PLAIN, "run-plain", days=400)

    def unreadable(_session):
        raise RuntimeError("hold table unavailable")

    monkeypatch.setattr(legal_hold, "held_tenants", unreadable)
    with pytest.raises(RuntimeError):
        run_retention.sweep(settings)
    assert plain.exists()


def _job(settings: Settings, tenant_id: str) -> str:
    job_id = f"job-{uuid.uuid4().hex[:8]}"
    with get_session(settings.postgres_url) as session:
        session.add(
            models.Job(job_id=job_id, tenant_id=tenant_id, queued_at=_naive(datetime.now(UTC)))
        )
    return job_id


def _job_inputs(settings: Settings, job_id: str, *, days: float) -> Path:
    directory = settings.state_dir / "job_inputs" / job_id
    directory.mkdir(parents=True)
    (directory / "targets.txt").write_text("10.0.0.1\n", encoding="utf-8")
    _age(directory, days=days)
    return directory


def test_unfinished_job_inputs_follow_their_tenants_window(settings):
    _set_policy(settings, OWN, run_days=90)
    held = _job_inputs(settings, _job(settings, HELD), days=400)
    own = _job_inputs(settings, _job(settings, OWN), days=45)
    plain = _job_inputs(settings, _job(settings, PLAIN), days=45)
    orphan = _job_inputs(settings, "job-without-a-row", days=45)

    stats = run_retention.sweep(settings)

    assert held.exists()
    assert own.exists()
    assert not plain.exists()
    assert not orphan.exists()
    assert stats["job_inputs_deleted"] == 2


def _screenshot(run_dir: Path, *, days: float) -> Path:
    shots = run_dir / "screenshots"
    shots.mkdir(exist_ok=True)
    png = shots / "host.png"
    png.write_bytes(b"\x89PNG\r\n")
    _age(run_dir, days=days)
    return png


def test_screenshot_retention_follows_the_runs_owner(settings):
    _set_policy(settings, OWN, screenshot_days=60)
    plain = _screenshot(_tenant_run(settings, PLAIN, "run-plain", days=30), days=30)
    own = _screenshot(_tenant_run(settings, OWN, "run-own", days=30), days=30)
    held = _screenshot(_tenant_run(settings, HELD, "run-held", days=300), days=300)
    flat_held = _screenshot(
        _flat_run(settings, "flat-held", marker=json.dumps({"tenant_id": HELD}), days=300),
        days=300,
    )

    stats = screenshot_retention.sweep(settings)

    assert not plain.exists()
    assert own.exists()
    assert held.exists()
    assert flat_held.exists()
    assert stats["deleted"] == 1


# --------------------------------------------------------------------------- #
# Table reapers
# --------------------------------------------------------------------------- #


def _inventory(tenant_id: str, snapshot_id: str, *packages: str):
    from api.schemas import EndpointInventorySnapshotRequest, EndpointSoftwareItem

    return EndpointInventorySnapshotRequest(
        schema_version=1,
        snapshot_id=snapshot_id,
        agent_id=f"agent-{tenant_id}",
        collected_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        hostname=f"host-{tenant_id}.example.internal",
        os_family="linux",
        os_name="Ubuntu",
        os_version="24.04",
        os_arch="x86_64",
        agent_version="1.0.0",
        labels={},
        identifiers=[],
        software=[
            EndpointSoftwareItem(name=name, version="1.0", publisher="Debian", source="dpkg")
            for name in packages
        ],
        collector_warnings=[],
    )


def test_endpoint_retention_honours_the_tenant_window_and_the_hold(settings):
    from api.services import endpoint_inventory

    endpoint_inventory.configure(settings)
    now = datetime.now(UTC)
    for tenant_id in (OWN, HELD, PLAIN):
        for index, packages in enumerate((("curl",), ("curl", "vim"))):
            endpoint_inventory.ingest_snapshot(
                tenant_id=tenant_id,
                agent_id=f"agent-{tenant_id}",
                request=_inventory(tenant_id, f"snap-{tenant_id}-{index}", *packages),
            )
    with get_session(settings.postgres_url) as session:
        for change in session.query(models.EndpointSoftwareChange):
            change.observed_at = now - timedelta(days=500)
    _set_policy(settings, OWN, endpoint_change_days=730)

    totals = endpoint_retention.sweep(settings, now=now)

    with get_session(settings.postgres_url) as session:
        left = set(
            session.execute(select(models.EndpointSoftwareChange.tenant_id)).scalars()
        )
    assert left == {OWN, HELD}
    assert totals["changes_deleted"] > 0
    # A direct per-tenant call asks about the hold too; no entry point skips it.
    assert endpoint_retention.sweep_tenant(settings, HELD, now=now)["changes_deleted"] == 0


def test_risk_snapshot_retention_per_tenant(settings):
    now = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
    _set_policy(settings, OWN, risk_snapshot_days=365)
    for tenant_id in (OWN, HELD, PLAIN):
        risk_snapshots.take_snapshot(
            settings, tenant_id=tenant_id, source="run", now=now - timedelta(days=200)
        )
    assert risk_snapshots.sweep(settings, now=now) == {"deleted": 1}
    assert risk_snapshots.list_snapshots(settings, tenant_id=PLAIN) == []
    assert len(risk_snapshots.list_snapshots(settings, tenant_id=OWN)) == 1
    assert len(risk_snapshots.list_snapshots(settings, tenant_id=HELD)) == 1
    # The forced-window form still stops at the hold.
    assert risk_snapshots.prune_snapshots(settings, retention_days=1, now=now) == 1
    assert len(risk_snapshots.list_snapshots(settings, tenant_id=HELD)) == 1


def test_report_retention_per_tenant(settings):
    now = datetime.now(UTC)
    _set_policy(settings, OWN, report_days=1000)
    with get_session(settings.postgres_url) as session:
        for tenant_id in (OWN, HELD, PLAIN):
            session.add(
                models.GeneratedReport(
                    report_id=f"rep-{tenant_id}",
                    tenant_id=tenant_id,
                    status="ready",
                    storage_path=f"reports/{tenant_id}/rep-{tenant_id}.json",
                    fmt="json",
                    generated_at=_naive(now - timedelta(days=500)),
                )
            )
    result = report_store.prune_reports(settings, now=now)
    assert result["deleted"] == 1
    with get_session(settings.postgres_url) as session:
        left = set(session.execute(select(models.GeneratedReport.tenant_id)).scalars())
    assert left == {OWN, HELD}


def test_webhook_delivery_retention_per_tenant(settings):
    webhooks.configure(settings)
    old = _naive(datetime.now(UTC) - timedelta(days=100))
    _set_policy(settings, OWN, webhook_delivery_days=200)
    with get_session(settings.postgres_url) as session:
        for tenant_id in (OWN, HELD, PLAIN):
            session.add(
                models.WebhookSubscription(
                    subscription_id=f"sub-{tenant_id}",
                    tenant_id=tenant_id,
                    name=tenant_id,
                    url="https://receiver.invalid/hook",
                    created_at=old,
                )
            )
            session.flush()
            session.add(
                models.WebhookDelivery(
                    delivery_id=f"del-{tenant_id}",
                    tenant_id=tenant_id,
                    subscription_id=f"sub-{tenant_id}",
                    event_id=f"ev-{tenant_id}",
                    event_kind="test",
                    status="delivered",
                    created_at=old,
                    updated_at=old,
                )
            )
    assert webhooks.prune_deliveries() == 1
    with get_session(settings.postgres_url) as session:
        left = set(session.execute(select(models.WebhookDelivery.tenant_id)).scalars())
    assert left == {OWN, HELD}


def test_workflow_marker_retention_per_tenant(settings):
    now = datetime.now(UTC)
    _set_policy(settings, OWN, workflow_marker_days=1000)
    with get_session(settings.postgres_url) as session:
        for tenant_id in (OWN, HELD, PLAIN):
            session.add(
                models.WorkflowEventMarker(
                    marker_id=f"m-{tenant_id}",
                    tenant_id=tenant_id,
                    kind="sla_breached",
                    subject_id="vuln-1",
                    marker="2025-01-01",
                    created_at=_naive(now - timedelta(days=500)),
                )
            )
    assert workflow_events.prune_markers(settings, now=now) == 1
    with get_session(settings.postgres_url) as session:
        left = set(session.execute(select(models.WorkflowEventMarker.tenant_id)).scalars())
    assert left == {OWN, HELD}


# --------------------------------------------------------------------------- #
# The audit trail: per tenant, and the hold enforced by the database
# --------------------------------------------------------------------------- #


def _audit_row(settings: Settings, tenant_id: str | None, resource_id: str, *, days: int) -> None:
    with get_session(settings.postgres_url) as session:
        session.execute(
            text(
                "INSERT INTO audit_events "
                "(occurred_at, tenant_id, actor, actor_type, action, resource_type, "
                "resource_id, client_ip, user_agent) "
                "VALUES (:occurred_at, :tenant_id, 'admin', 'user', 'config.update', "
                "'config', :resource_id, '', '')"
            ),
            {
                "occurred_at": _naive(datetime.now(UTC) - timedelta(days=days)),
                "tenant_id": tenant_id,
                "resource_id": resource_id,
            },
        )


def _audit_ids(settings: Settings) -> set[str]:
    with get_session(settings.postgres_url) as session:
        return set(
            session.execute(
                text("SELECT resource_id FROM audit_events WHERE resource_type = 'config'")
            ).scalars()
        )


def test_audit_retention_per_tenant_and_never_a_held_tenants_trail(settings):
    from api.services import audit as audit_service

    audit_service.configure(settings)
    audit_service.reset_for_tests()
    settings.audit_event_retention_days = 365
    _set_policy(settings, OWN, audit_event_days=800)
    _audit_row(settings, PLAIN, "plain-500", days=500)
    _audit_row(settings, None, "platform-500", days=500)
    _audit_row(settings, OWN, "own-500", days=500)
    _audit_row(settings, OWN, "own-900", days=900)
    _audit_row(settings, HELD, "held-5000", days=5000)
    # A tenant that no longer exists has no policy and no hold: the default.
    _audit_row(settings, "deleted-tenant", "gone-500", days=500)

    removed = audit_retention.sweep(settings)

    assert _audit_ids(settings) == {"own-500", "held-5000"}
    assert removed == 4


def test_the_database_refuses_to_prune_a_held_tenant_whoever_asks(settings):
    """The functions check the hold themselves, so a retention job with a
    wrong plan — or one built before this migration — cannot get past it."""
    _audit_row(settings, HELD, "held", days=5000)
    _audit_row(settings, PLAIN, "plain", days=5000)
    far_future = datetime(2999, 1, 1)
    with get_session(settings.postgres_url) as session:
        session.execute(text("SELECT audit_events_prune(:c)"), {"c": far_future})
        tenant_pass = session.execute(
            text("SELECT audit_events_prune_tenant(:t, :c)"), {"t": HELD, "c": far_future}
        ).scalar_one()
    assert tenant_pass == 0
    assert "held" in _audit_ids(settings)
    assert "plain" not in _audit_ids(settings)


def test_a_held_tenant_cannot_be_deleted(settings):
    with pytest.raises(IntegrityError):
        with get_session(settings.postgres_url) as session:
            session.execute(text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": HELD})
    assert tenants_service.get_tenant(HELD) is not None


def test_the_contract_for_tenant_deletion(settings):
    """What #325 builds on: one session, one refusal naming the hold."""
    with get_session(settings.postgres_url) as session:
        assert legal_hold.is_on_legal_hold(session, HELD)
        assert not legal_hold.is_on_legal_hold(session, PLAIN)
        legal_hold.assert_not_on_hold(session, PLAIN, action="tenant.delete")
        with pytest.raises(legal_hold.LegalHoldActive) as refused:
            legal_hold.assert_not_on_hold(session, HELD, action="tenant.delete")
    assert isinstance(refused.value, PermissionError)
    assert refused.value.tenant_id == HELD
    assert "matter 2026-17" in str(refused.value)
    assert "tenant.delete" in str(refused.value)


# --------------------------------------------------------------------------- #
# The reapers without a category: the login trail and the deployment journal
# --------------------------------------------------------------------------- #


def test_sign_ins_of_a_held_tenants_members_outlive_the_login_window(settings):
    from api.services import users as users_service

    users_service.configure(settings)
    auth_audit.configure(settings)
    auth_audit.reset_for_tests()
    settings.auth_event_retention_days = 90
    now = datetime.now(UTC)
    with get_session(settings.postgres_url) as session:
        for username in ("custodian", "bystander"):
            session.add(
                models.User(
                    username=username, created_at=_naive(now), updated_at=_naive(now)
                )
            )
        session.flush()
        session.add(
            models.UserTenant(
                username="custodian", tenant_id=HELD, role="viewer", created_at=_naive(now)
            )
        )
        for username in ("custodian", "bystander"):
            session.add(
                models.AuthEvent(
                    occurred_at=_naive(now - timedelta(days=400)),
                    username=username,
                    client_ip="192.0.2.10",
                    outcome="success",
                )
            )
    try:
        auth_audit._maybe_prune(settings)
        with get_session(settings.postgres_url) as session:
            left = set(session.execute(select(models.AuthEvent.username)).scalars())
        assert left == {"custodian"}
    finally:
        with get_session(settings.postgres_url) as session:
            session.query(models.User).filter(
                models.User.username.in_(("custodian", "bystander"))
            ).delete()


def test_the_deployment_journal_of_a_held_tenant_is_not_trimmed(settings, monkeypatch):
    monkeypatch.setattr(agent_deployer, "_MAX_HISTORY", 1)
    started = _naive(datetime.now(UTC))
    with get_session(settings.postgres_url) as session:
        for tenant_id in (HELD, PLAIN):
            for index in range(3):
                session.add(
                    models.AgentDeployment(
                        deploy_id=f"dep-{tenant_id}-{index}",
                        tenant_id=tenant_id,
                        started_at=started + timedelta(seconds=index),
                    )
                )
        session.flush()
        agent_deployer._prune_history(session, HELD)
        agent_deployer._prune_history(session, PLAIN)
    with get_session(settings.postgres_url) as session:
        counts = {
            tenant_id: session.query(models.AgentDeployment).filter_by(tenant_id=tenant_id).count()
            for tenant_id in (HELD, PLAIN)
        }
    assert counts == {HELD: 3, PLAIN: 1}
