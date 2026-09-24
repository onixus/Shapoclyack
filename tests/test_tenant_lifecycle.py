"""Suspending, resuming and deleting a tenant, through the API (#325).

Suspension is only worth the word if it cuts every path in, so there is one
test per path: a console session, a service token, a provisioning key, an
agent's JWT, the scans it had queued and running, its schedules and the workers
that act for it without a request. Each one fails if its cut is removed.

Deletion is two decisions, a grace period and — by default — two people; the
tests below walk each refusal on the way (typed confirmation, the default
tenant, the grace period, the requester approving themselves, a legal hold)
and then the purge itself, whose store-by-store behaviour is
``tests/test_tenant_purge.py``'s.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, update

from api.db import models
from api.db.engine import get_session
from api.services import legal_hold
from api.services import tenant_lifecycle as lifecycle
from api.services import scan_schedules
from api.services import sessions as sessions_service
from api.services import tenant_purge
from api.services import tenants as tenants_service
from api.services.integrations import channels as channels_service
from api.services.integrations import secure_webhooks
from api.services.integrations import ticket_sync_worker
from api.services.reports import store as report_store
from api.settings import Settings
from tests.conftest import (
    approve_scan_scope_via_api,
    auth_headers,
    bearer,
    configured_client,
    login,
    make_settings,
    requires_postgres,
)
from tests.test_api_mfa import Clock, enrol

pytestmark = requires_postgres

ACME = "acme"
GLOBEX = "globex"

_NOW = datetime.now(UTC).replace(tzinfo=None, microsecond=0)


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Two tenants beside ``default``, agent mode, a zero grace period, one admin."""
    settings = make_settings(
        tmp_path,
        job_execution_mode="agent",
        agent_token="",
        tenant_deletion_grace_days=0,
        tenant_deletion_two_person=False,
        tenant_purge_batch_size=100,
        # No ClickHouse or NATS here, and said so: a purge fails on a store
        # that is merely not configured (review round 1, finding 7).
        tenant_purge_unused_stores=("clickhouse", "jetstream"),
    )
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    for tenant_id in (ACME, GLOBEX):
        created = client.post(
            "/api/tenants", headers=admin, json={"name": tenant_id, "tenant_id": tenant_id}
        )
        assert created.status_code == 201, created.text
        approve_scan_scope_via_api(client, tenant_id, admin)
    yield client, settings, admin
    with get_session(settings.postgres_url) as session:
        session.query(models.TenantLegalHold).delete()


def _member(client, admin, username: str, *tenants: str, role: str = "operator") -> dict:
    password = f"{username}-password-1234"
    created = client.post(
        "/api/users",
        headers=admin,
        json={"username": username, "password": password, "role": "viewer"},
    )
    assert created.status_code == 201, created.text
    for tenant_id in tenants:
        granted = client.put(
            f"/api/tenants/{tenant_id}/members/{username}", headers=admin, json={"role": role}
        )
        assert granted.status_code == 200, granted.text
    return bearer(login(client, username, password))


def _suspend(client, admin, tenant_id: str = ACME, **body) -> dict:
    response = client.post(
        f"/api/tenants/{tenant_id}/suspend",
        headers=admin,
        json={"reason": "invoice 2026-114 unpaid", **body},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _resume(client, admin, tenant_id: str = ACME) -> dict:
    response = client.post(f"/api/tenants/{tenant_id}/resume", headers=admin)
    assert response.status_code == 200, response.text
    return response.json()


def _key(client, admin, tenant_id: str = ACME) -> str:
    minted = client.post(
        f"/api/tenants/{tenant_id}/provisioning-keys", headers=admin, json={"label": "edge"}
    )
    assert minted.status_code == 201, minted.text
    return minted.json()["key"]


def _agent(client, key: str, agent_id: str = "edge-1") -> dict[str, str]:
    exchanged = client.post(
        "/api/auth/agent/token", json={"provisioning_key": key, "agent_id": agent_id}
    )
    assert exchanged.status_code == 200, exchanged.text
    token = bearer(exchanged.json()["access_token"])
    registered = client.post("/api/agent/register", headers=token, json={"hostname": agent_id})
    assert registered.status_code == 200, registered.text
    return token


def _heartbeat(client, token, agent_id: str = "edge-1", job_id: str | None = None):
    body = {"agent_id": agent_id, "status": "busy" if job_id else "idle"}
    if job_id:
        body["current_job_id"] = job_id
    return client.post("/api/agent/heartbeat", headers=token, json=body)


def _queue(client, admin, tenant_id: str = ACME) -> str:
    job = client.post(
        f"/api/jobs?tenant_id={tenant_id}",
        headers=admin,
        json={"mode": "safe", "skip_nse": True, "ranges": "127.0.0.1\n", "ports": "80\n"},
    )
    assert job.status_code == 202, job.text
    return job.json()["job_id"]


def _job_status(settings: Settings, job_id: str) -> str:
    with get_session(settings.postgres_url) as session:
        return session.get(models.Job, job_id).status


def _audit(settings: Settings, action: str) -> list[models.AuditEvent]:
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.AuditEvent)
            .where(models.AuditEvent.action == action)
            .order_by(models.AuditEvent.id)
        ).scalars().all()
        session.expunge_all()
        return rows


# --------------------------------------------------------------------------- #
# Who may
# --------------------------------------------------------------------------- #


def test_only_a_platform_admin_suspends_or_deletes(env):
    client, _settings, admin = env
    tenant_admin = _member(client, admin, "acme-admin", ACME, role="admin")
    for method, path, body in (
        ("post", f"/api/tenants/{ACME}/suspend", {"reason": "x"}),
        ("post", f"/api/tenants/{ACME}/resume", None),
        ("post", f"/api/tenants/{ACME}/deletion", {"confirm": ACME, "reason": "x"}),
        ("delete", f"/api/tenants/{ACME}/deletion", None),
        ("post", f"/api/tenants/{ACME}/deletion/approve", {"confirm": ACME}),
        ("get", f"/api/tenants/{ACME}/lifecycle", None),
        ("get", "/api/tenants/deletions", None),
    ):
        kwargs = {"headers": tenant_admin}
        if body is not None:
            kwargs["json"] = body
        refused = getattr(client, method)(path, **kwargs)
        assert refused.status_code == 403, (method, path, refused.text)
        assert "platform.tenant.lifecycle" in refused.json()["detail"]


def test_a_service_token_reaches_none_of_it(env):
    client, _settings, admin = env
    minted = client.post(
        f"/api/tenants/{ACME}/service-tokens",
        headers=admin,
        json={"name": "ci", "role": "admin", "scopes": ["*"], "ttl_days": 1},
    )
    assert minted.status_code == 201, minted.text
    token = bearer(minted.json()["token"])
    assert client.post(
        f"/api/tenants/{ACME}/suspend", headers=token, json={"reason": "x"}
    ).status_code == 403
    assert client.get("/api/tenants/deletions", headers=token).status_code == 403


def test_every_change_needs_a_recent_second_factor(tmp_path, monkeypatch):
    clock = Clock()
    monkeypatch.setattr("api.services.mfa._now", clock)
    client = configured_client(tmp_path, monkeypatch)
    headers = auth_headers(client, "admin")
    assert client.post(
        "/api/tenants", headers=headers, json={"name": ACME, "tenant_id": ACME}
    ).status_code == 201
    enrol(client, headers, clock)
    for path, body in (
        (f"/api/tenants/{ACME}/suspend", {"reason": "x"}),
        (f"/api/tenants/{ACME}/resume", None),
        (f"/api/tenants/{ACME}/deletion", {"confirm": ACME, "reason": "x"}),
        (f"/api/tenants/{ACME}/deletion/approve", {"confirm": ACME}),
        (f"/api/tenants/{ACME}/deletion/retry", None),
    ):
        refused = client.post(path, headers=headers, json=body)
        assert refused.status_code == 403, (path, refused.text)
        assert "multi-factor" in refused.json()["detail"]
    refused = client.delete(f"/api/tenants/{ACME}/deletion", headers=headers)
    assert refused.status_code == 403 and "multi-factor" in refused.json()["detail"]
    # Reading is not a change.
    assert client.get(f"/api/tenants/{ACME}/lifecycle", headers=headers).status_code == 200


def test_the_default_tenant_is_neither_suspended_nor_deleted(env):
    client, _settings, admin = env
    suspended = client.post(
        "/api/tenants/default/suspend", headers=admin, json={"reason": "x"}
    )
    assert suspended.status_code == 409 and "default tenant" in suspended.json()["detail"]
    deleted = client.post(
        "/api/tenants/default/deletion", headers=admin, json={"confirm": "default", "reason": "x"}
    )
    assert deleted.status_code == 409 and "default tenant" in deleted.json()["detail"]


# --------------------------------------------------------------------------- #
# Suspension cuts every path in — one test per path
# --------------------------------------------------------------------------- #


def test_suspension_ends_the_sessions_of_members_with_nowhere_else_to_go(env):
    client, settings, admin = env
    only_acme = _member(client, admin, "ada", ACME)
    both = _member(client, admin, "bob", ACME, GLOBEX)
    assert client.get("/api/auth/me", headers=only_acme).status_code == 200

    cut = _suspend(client, admin)["cut"]
    assert cut["sessions_ended"] == {"count": 1, "ids": ["ada"]}

    # Ada's token is dead everywhere, not merely refused in acme.
    assert client.get("/api/auth/me", headers=only_acme).status_code == 401
    # Bob keeps his session, and with it globex; acme refuses him per request.
    assert client.get(f"/api/assets?tenant_id={GLOBEX}", headers=both).status_code == 200
    refused = client.get(f"/api/assets?tenant_id={ACME}", headers=both)
    assert refused.status_code == 403 and "suspended" in refused.json()["detail"]
    # The platform admin is never cut: somebody has to lift it.
    assert client.get(f"/api/assets?tenant_id={ACME}", headers=admin).status_code == 200
    with get_session(settings.postgres_url) as session:
        families = session.execute(
            select(models.SessionFamily.revoked_reason).where(
                models.SessionFamily.username == "ada"
            )
        ).scalars().all()
    assert families and set(families) == {sessions_service.END_TENANT_CLOSED}


def test_suspension_revokes_the_tenants_service_tokens(env):
    client, settings, admin = env
    minted = client.post(
        f"/api/tenants/{ACME}/service-tokens",
        headers=admin,
        json={"name": "siem", "role": "viewer", "scopes": ["assets:read"], "ttl_days": 30},
    )
    assert minted.status_code == 201, minted.text
    token = bearer(minted.json()["token"])
    assert client.get("/api/assets", headers=token).status_code == 200

    cut = _suspend(client, admin)["cut"]
    assert cut["service_tokens_revoked"]["ids"] == [minted.json()["token_id"]]
    assert client.get("/api/assets", headers=token).status_code == 401
    # And resuming does not bring it back: revoked is revoked.
    _resume(client, admin)
    assert client.get("/api/assets", headers=token).status_code == 401


def test_a_kept_service_token_is_refused_while_suspended_and_works_after(env):
    """``revoke_credentials=false``: authentication itself refuses a token of a
    tenant that is not active (``service_tokens.verify_token``), so keeping it
    only saves minting a new one after the resume."""
    client, settings, admin = env
    minted = client.post(
        f"/api/tenants/{ACME}/service-tokens",
        headers=admin,
        json={"name": "siem", "role": "viewer", "scopes": ["assets:read"], "ttl_days": 30},
    )
    token = bearer(minted.json()["token"])
    cut = _suspend(client, admin, revoke_credentials=False)["cut"]
    assert cut["service_tokens_revoked"]["count"] == 0
    assert client.get("/api/assets", headers=token).status_code == 401
    with get_session(settings.postgres_url) as session:
        assert session.get(models.ServiceToken, minted.json()["token_id"]).revoked_at is None
    _resume(client, admin)
    assert client.get("/api/assets", headers=token).status_code == 200


def test_suspension_revokes_provisioning_keys_and_refuses_the_agents_jwt(env):
    client, _settings, admin = env
    key = _key(client, admin)
    agent = _agent(client, key)
    assert _heartbeat(client, agent).status_code == 200

    cut = _suspend(client, admin)["cut"]
    assert cut["provisioning_keys_revoked"]["count"] == 1
    # The JWT minted before the suspension: refused on its next request.
    assert _heartbeat(client, agent).status_code == 401
    assert client.post("/api/agent/jobs/claim?agent_id=edge-1", headers=agent).status_code == 401
    # And the key cannot mint another.
    again = client.post("/api/auth/agent/token", json={"provisioning_key": key})
    assert again.status_code == 401


def test_an_agent_with_a_kept_key_is_refused_until_the_resume(env):
    """``revoke_credentials=false``: the key survives, the tenant check does not."""
    client, _settings, admin = env
    key = _key(client, admin)
    agent = _agent(client, key)
    _suspend(client, admin, revoke_credentials=False)
    refused = _heartbeat(client, agent)
    assert refused.status_code == 401
    assert "suspended" in refused.json()["detail"]
    assert client.post("/api/auth/agent/token", json={"provisioning_key": key}).status_code == 401
    _resume(client, admin)
    assert _heartbeat(client, agent).status_code == 200


def test_suspension_cancels_queued_scans_and_stops_the_ones_agents_are_running(env):
    client, settings, admin = env
    agent = _agent(client, _key(client, admin))
    running = _queue(client, admin)
    claimed = client.post("/api/agent/jobs/claim?agent_id=edge-1", headers=agent)
    assert claimed.status_code == 200, claimed.text
    assert _heartbeat(client, agent, job_id=running).status_code == 200
    queued = _queue(client, admin)
    other = _queue(client, admin, GLOBEX)

    cut = _suspend(client, admin)["cut"]
    assert cut["jobs_cancelled"]["ids"] == [queued]
    assert cut["jobs_stopping"]["ids"] == [running]
    assert _job_status(settings, queued) == "cancelled"
    # #360's channel: not requeued by the lease reaper, closed by the grace reaper.
    assert _job_status(settings, running) == "cancelling"
    assert _job_status(settings, other) == "queued"
    # New scans are refused at admission.
    assert client.post(
        f"/api/jobs?tenant_id={ACME}",
        headers=admin,
        json={"mode": "safe", "ranges": "127.0.0.1\n", "ports": "80\n"},
    ).status_code in (400, 403, 409, 422)


def test_suspension_pauses_schedules_and_the_resume_does_not_fire_a_burst(env):
    client, settings, admin = env
    overdue = _NOW - timedelta(days=3)
    with get_session(settings.postgres_url) as session:
        for tenant_id in (ACME, GLOBEX):
            session.add(
                models.ScanSchedule(
                    schedule_id=f"sch-{tenant_id}",
                    tenant_id=tenant_id,
                    name="hourly",
                    enabled=True,
                    interval_seconds=3600,
                    scan_options={},
                    targets={"ranges": "127.0.0.1"},
                    next_run_at=overdue,
                    created_at=_NOW,
                )
            )
    due = {s["schedule_id"] for s in scan_schedules.due_schedules(datetime.now(UTC))}
    assert due == {"sch-acme", "sch-globex"}

    _suspend(client, admin)
    due = {s["schedule_id"] for s in scan_schedules.due_schedules(datetime.now(UTC))}
    assert due == {"sch-globex"}
    with get_session(settings.postgres_url) as session:
        # Paused by the status, not disabled row by row.
        assert session.get(models.ScanSchedule, "sch-acme").enabled is True

    resumed = _resume(client, admin)
    assert resumed["status"] == "active"
    due = {s["schedule_id"] for s in scan_schedules.due_schedules(datetime.now(UTC))}
    # Seventy-two missed hourly ticks, and none of them fires now: the next
    # one is an hour away.
    assert due == {"sch-globex"}
    with get_session(settings.postgres_url) as session:
        moved = session.get(models.ScanSchedule, "sch-acme").next_run_at
    # The clock now, not the module's: in a full run it was read an hour ago.
    now = datetime.now(UTC).replace(tzinfo=None)
    assert now < moved <= now + timedelta(hours=1, minutes=1)
    [row] = _audit(settings, "tenant.resume")
    assert row.after["scan_schedules_reanchored"] == 1


def test_the_workers_that_act_for_a_tenant_skip_it_while_suspended(env):
    """Report schedules, webhook deliveries, ticket-sync polling and run
    notifications: none of them has a request behind it for the gate to refuse."""
    client, settings, admin = env
    with get_session(settings.postgres_url) as session:
        session.add(
            models.ReportTemplate(
                template_id="tpl-acme", tenant_id=ACME, name="exec", created_at=_NOW,
                updated_at=_NOW,
            )
        )
        session.flush()
        session.add(
            models.ReportSchedule(
                schedule_id="rs-acme", tenant_id=ACME, template_id="tpl-acme", name="weekly",
                enabled=True, cron="0 6 * * 1", next_run_at=_NOW - timedelta(days=1),
                created_at=_NOW,
            )
        )
        session.add(
            models.WebhookSubscription(
                subscription_id="sub-acme", tenant_id=ACME, name="jira",
                url="https://jira.invalid", enabled=True, transport="jira", created_at=_NOW,
            )
        )
        session.flush()
        session.add(
            models.WebhookDelivery(
                delivery_id="dlv-acme", tenant_id=ACME, subscription_id="sub-acme",
                event_id="e1", event_kind="asset_created", status="pending",
                next_attempt_at=_NOW - timedelta(minutes=1), created_at=_NOW, updated_at=_NOW,
            )
        )
        session.add(
            models.NotificationChannel(
                channel_id="chn-acme", tenant_id=ACME, name="slack", kind="slack",
                enabled=True, endpoint="https://hooks.invalid/x", created_at=_NOW,
                updated_at=_NOW,
            )
        )

    def claimed() -> list[str]:
        with get_session(settings.postgres_url) as session:
            rows = secure_webhooks._claim_due(  # noqa: SLF001
                session, now=datetime.now(UTC).replace(tzinfo=None), limit=10
            )
            ids = [row.delivery_id for row in rows]
            session.rollback()
        return ids

    assert [s["schedule_id"] for s in report_store.due_schedules(settings, datetime.now(UTC))] == [
        "rs-acme"
    ]
    assert claimed() == ["dlv-acme"]
    assert [s["tenant_id"] for s in ticket_sync_worker.subscriptions(settings)] == [ACME]

    _suspend(client, admin)
    assert report_store.due_schedules(settings, datetime.now(UTC)) == []
    assert claimed() == []
    assert ticket_sync_worker.subscriptions(settings) == []
    sent = channels_service.notify_run_complete(
        tenant_id=ACME, run_id="r1", run_dir=settings.output_dir, post_fn=lambda *a, **k: None
    )
    assert sent == []

    _resume(client, admin)
    # Held, not dropped: the delivery goes out once the tenant is back.
    assert claimed() == ["dlv-acme"]
    with get_session(settings.postgres_url) as session:
        moved = session.get(models.ReportSchedule, "rs-acme").next_run_at
    # The column is timestamptz (migration 0029), unlike most of the schema.
    assert moved.astimezone(UTC).replace(tzinfo=None) > _NOW


def test_sla_escalation_does_not_page_about_a_suspended_tenants_silent_agents(env):
    from api.services import sla_escalation

    client, settings, admin = env
    _agent(client, _key(client, admin), "edge-quiet")
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.Agent)
            .where(models.Agent.agent_id == "edge-quiet")
            .values(last_seen_at=_NOW - timedelta(hours=2))
        )
    announced: list[str] = []
    real_emit_once = sla_escalation.workflow_events.emit_once

    def record(settings_, kind, **kwargs):
        announced.append(kwargs["subject_id"])
        return real_emit_once(settings_, kind, **kwargs)

    worker = sla_escalation.SlaEscalationWorker(settings=settings)
    _suspend(client, admin)
    sla_escalation.workflow_events.emit_once = record
    try:
        worker._agents(datetime.now(UTC))  # noqa: SLF001
    finally:
        sla_escalation.workflow_events.emit_once = real_emit_once
    assert "edge-quiet" not in announced


def test_suspending_twice_is_one_decision_and_resuming_an_active_tenant_is_none(env):
    client, settings, admin = env
    _suspend(client, admin)
    again = _suspend(client, admin, reason="a different reason")
    assert again["status_reason"] == "invoice 2026-114 unpaid"
    _resume(client, admin)
    _resume(client, admin)
    assert len(_audit(settings, "tenant.suspend")) == 1
    assert len(_audit(settings, "tenant.resume")) == 1


def test_the_suspension_is_recorded_at_platform_level_with_what_was_cut(env):
    client, settings, admin = env
    _key(client, admin)
    tenant_admin = _member(client, admin, "acme-admin", GLOBEX, ACME, role="admin")
    _suspend(client, admin)
    [row] = _audit(settings, "tenant.suspend")
    assert row.tenant_id is None and row.resource_id == ACME
    assert row.actor == "admin"
    assert row.after["reason"] == "invoice 2026-114 unpaid"
    assert row.after["provisioning_keys_revoked"]["count"] == 1
    # Not in the tenant's own trail: why a customer was suspended is the platform's.
    listed = client.get(
        f"/api/audit?tenant_id={GLOBEX}&action=tenant.suspend", headers=tenant_admin
    )
    assert listed.status_code == 200 and listed.json()["items"] == []


# --------------------------------------------------------------------------- #
# Deletion: two steps, a grace period, two people, and the hold
# --------------------------------------------------------------------------- #


def _request(client, admin, tenant_id: str = ACME, **body):
    return client.post(
        f"/api/tenants/{tenant_id}/deletion",
        headers=admin,
        json={"confirm": tenant_id, "reason": "contract ended 2026-09-30", **body},
    )


def _approve(client, headers, tenant_id: str = ACME, **body):
    return client.post(
        f"/api/tenants/{tenant_id}/deletion/approve",
        headers=headers,
        json={"confirm": tenant_id, **body},
    )


def test_a_deletion_needs_the_tenant_id_typed_and_a_reason(env):
    client, _settings, admin = env
    wrong = _request(client, admin, confirm="ACME")
    assert wrong.status_code == 422 and "typed exactly" in wrong.json()["detail"]
    blank = _request(client, admin, reason="   ")
    assert blank.status_code == 422


def test_a_deletion_request_suspends_and_can_be_cancelled_in_its_grace_period(env):
    client, settings, admin = env
    settings.tenant_deletion_grace_days = 7
    member = _member(client, admin, "ada", ACME)
    requested = _request(client, admin)
    assert requested.status_code == 202, requested.text
    body = requested.json()
    assert body["status"] == "pending_deletion"
    assert body["deletion"]["state"] == "pending"
    assert [step["step"] for step in body["deletion"]["steps"]] == [
        "quiesce", "outbox", "jetstream", "artifacts", "clickhouse", "postgres", "finalize",
    ]
    # Suspension semantics from the first moment.
    assert client.get("/api/auth/me", headers=member).status_code == 401
    # A second request is a mistake, not a queue.
    assert _request(client, admin).status_code == 409

    early = _approve(client, admin)
    assert early.status_code == 409 and "grace period" in early.json()["detail"]

    cancelled = client.delete(f"/api/tenants/{ACME}/deletion", headers=admin)
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["status"] == "suspended"
    assert cancelled.json()["deletion"] is None
    assert cancelled.json()["history"][0]["state"] == "cancelled"
    # Cancelled means nothing was lost, and nothing is due.
    assert tenant_purge.run_once(settings)["outcome"] == "idle"
    assert _resume(client, admin)["status"] == "active"


def test_the_purge_needs_a_second_platform_admin_by_default(env):
    client, settings, admin = env
    settings.tenant_deletion_two_person = True
    created = client.post(
        "/api/users",
        headers=admin,
        json={"username": "root2", "password": "root2-password-1234", "role": "admin"},
    )
    assert created.status_code == 201, created.text
    second = bearer(login(client, "root2", "root2-password-1234"))
    assert _request(client, admin).status_code == 202

    self_approved = _approve(client, admin)
    assert self_approved.status_code == 403
    assert "second person" in self_approved.json()["detail"]
    wrong = _approve(client, second, confirm=GLOBEX)
    assert wrong.status_code == 422
    approved = _approve(client, second)
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "deleting"
    assert approved.json()["deletion"]["approved_by"] == "root2"
    # Too late to cancel.
    late = client.delete(f"/api/tenants/{ACME}/deletion", headers=admin)
    assert late.status_code == 409


def test_a_tenant_on_legal_hold_cannot_be_requested_or_approved_for_deletion(env):
    client, settings, admin = env
    legal_hold.place_hold(settings, ACME, reason="matter 2026-17", set_by="counsel")
    refused = _request(client, admin)
    assert refused.status_code == 409
    # The platform admin is told whose hold and why; nobody else reaches this.
    assert "matter 2026-17" in refused.json()["detail"]
    assert "tenant.delete" in refused.json()["detail"]

    legal_hold.release_hold(settings, ACME)
    assert _request(client, admin).status_code == 202
    legal_hold.place_hold(settings, ACME, reason="matter 2026-18", set_by="counsel")
    refused = _approve(client, admin)
    assert refused.status_code == 409 and "matter 2026-18" in refused.json()["detail"]
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Tenant, ACME).status == "pending_deletion"


def test_a_tenant_is_deleted_end_to_end_and_the_journal_keeps_the_tombstone(env):
    client, settings, admin = env
    member = _member(client, admin, "ada", ACME)
    assert _request(client, admin).status_code == 202
    assert _approve(client, admin).status_code == 200
    assert tenant_purge.run_once(settings)["outcome"] == "completed"

    view = client.get(f"/api/tenants/{ACME}/lifecycle", headers=admin)
    assert view.status_code == 200, view.text
    assert view.json()["status"] == "deleted"
    assert view.json()["history"][0]["state"] == "completed"
    journal = client.get("/api/tenants/deletions?state=completed", headers=admin)
    assert journal.status_code == 200
    [entry] = journal.json()
    assert entry["tenant_id"] == ACME
    assert entry["outcome"]["stores"]["postgres"]["service_tokens"] == 0
    assert {t["tenant_id"] for t in client.get("/api/tenants", headers=admin).json()} == {
        "default",
        GLOBEX,
    }
    # The member's only tenant is gone: disabled, not moved into ``default``.
    assert client.post(
        "/api/auth/login", json={"username": "ada", "password": "ada-password-1234"}
    ).status_code in (401, 403)
    assert client.get("/api/auth/me", headers=member).status_code == 401
    # The id is spent.
    reused = client.post("/api/tenants", headers=admin, json={"name": "acme", "tenant_id": ACME})
    assert reused.status_code == 422 and "not reused" in reused.json()["detail"]
    actions = [row.action for row in _audit(settings, "tenant.delete.complete")]
    assert actions == ["tenant.delete.complete"]


def test_a_failed_step_is_visible_and_can_be_retried_now(env, monkeypatch):
    client, settings, admin = env
    assert _request(client, admin).status_code == 202
    assert _approve(client, admin).status_code == 200

    def broken(ctx):
        raise RuntimeError("bucket policy denies s3:DeleteObject")

    working = tenant_purge.STEP_FUNCTIONS["artifacts"]
    monkeypatch.setitem(tenant_purge.STEP_FUNCTIONS, "artifacts", broken)
    assert tenant_purge.run_once(settings)["outcome"] == "failed"
    view = client.get(f"/api/tenants/{ACME}/lifecycle", headers=admin).json()
    assert view["status"] == "deleting"
    step = next(s for s in view["deletion"]["steps"] if s["step"] == "artifacts")
    assert step["state"] == "failed" and "DeleteObject" in step["last_error"]
    assert view["deletion"]["next_attempt_at"] is not None
    assert tenant_purge.run_once(settings)["outcome"] == "idle"

    monkeypatch.setitem(tenant_purge.STEP_FUNCTIONS, "artifacts", working)
    retried = client.post(f"/api/tenants/{ACME}/deletion/retry", headers=admin)
    assert retried.status_code == 200, retried.text
    assert tenant_purge.run_once(settings)["outcome"] == "completed"
    assert [row.after["step"] for row in _audit(settings, "tenant.delete.fail")] == ["artifacts"]
    assert len(_audit(settings, "tenant.delete.retry")) == 1


def test_a_tenant_being_deleted_cannot_be_resumed_or_suspended(env):
    client, _settings, admin = env
    assert _request(client, admin).status_code == 202
    refused = client.post(f"/api/tenants/{ACME}/resume", headers=admin)
    assert refused.status_code == 409 and "cancel the deletion" in refused.json()["detail"]
    assert _approve(client, admin).status_code == 200
    assert client.post(f"/api/tenants/{ACME}/resume", headers=admin).status_code == 409
    assert client.post(
        f"/api/tenants/{ACME}/suspend", headers=admin, json={"reason": "x"}
    ).status_code == 409


def test_a_members_listing_no_longer_offers_a_tenant_being_deleted(env):
    client, _settings, admin = env
    both = _member(client, admin, "bob", ACME, GLOBEX)
    assert _request(client, admin).status_code == 202
    listed = client.get("/api/tenants", headers=admin)
    assert {t["tenant_id"]: t["status"] for t in listed.json()}[ACME] == "pending_deletion"
    refused = client.get(f"/api/assets?tenant_id={ACME}", headers=both)
    assert refused.status_code == 403 and "pending_deletion" in refused.json()["detail"]


def test_tenants_status_is_one_of_the_schema_words(env):
    """Every status the lifecycle writes is one ``TenantInfo`` can serialise —
    a word it cannot is a 500 on the console's tenant switcher."""
    from typing import get_args

    from api.schemas import TenantStatus

    assert set(get_args(TenantStatus)) == set(tenants_service.STATUSES)


# --------------------------------------------------------------------------- #
# Review round 1
# --------------------------------------------------------------------------- #


def test_suspending_again_with_revoke_revokes_what_the_first_kept(env):
    """Kept for a short suspension, then leaked: the second suspension revokes."""
    client, settings, admin = env
    minted = client.post(
        f"/api/tenants/{ACME}/service-tokens",
        headers=admin,
        json={"name": "siem", "role": "viewer", "scopes": ["assets:read"], "ttl_days": 30},
    )
    key = _key(client, admin)
    _suspend(client, admin, revoke_credentials=False)
    again = _suspend(client, admin, revoke_credentials=True)
    assert again["cut"]["service_tokens_revoked"]["ids"] == [minted.json()["token_id"]]
    assert again["cut"]["provisioning_keys_revoked"]["count"] == 1
    with get_session(settings.postgres_url) as session:
        assert session.get(models.ServiceToken, minted.json()["token_id"]).revoked_at is not None
    rows = _audit(settings, "tenant.suspend")
    assert len(rows) == 2 and rows[1].after["service_tokens_revoked"]["count"] == 1
    _resume(client, admin)
    token = bearer(minted.json()["token"])
    assert client.get("/api/assets", headers=token).status_code == 401
    assert client.post("/api/auth/agent/token", json={"provisioning_key": key}).status_code == 401
    # Nothing left to revoke: a third request is the idempotent one again.
    _suspend(client, admin)
    _suspend(client, admin, revoke_credentials=True)
    assert len(_audit(settings, "tenant.suspend")) == 3


def test_a_suspended_tenants_agent_is_still_told_to_stop_its_running_scan(env):
    """#360's stop travels on the heartbeat's answer, so that answer — and only
    that — still reaches a closed tenant's agent, with a revoked key too."""
    client, settings, admin = env
    agent = _agent(client, _key(client, admin))
    running = _queue(client, admin)
    assert client.post("/api/agent/jobs/claim?agent_id=edge-1", headers=agent).status_code == 200
    assert _heartbeat(client, agent, job_id=running).status_code == 200
    with get_session(settings.postgres_url) as session:
        seen = session.get(models.Agent, "edge-1").last_seen_at

    _suspend(client, admin)
    stop = _heartbeat(client, agent, job_id=running)
    assert stop.status_code == 200, stop.text
    assert stop.json()["cancel_requested"] is True
    with get_session(settings.postgres_url) as session:
        job = session.get(models.Job, running)
        assert job.status == "cancelling" and job.claimed_until is None
        # Answered, not accepted: the agent is not seen, the lease not renewed.
        assert session.get(models.Agent, "edge-1").last_seen_at == seen
    # Anything else it sends is refused like every other request.
    idle = _heartbeat(client, agent)
    assert idle.status_code == 401 and "suspended" in idle.json()["detail"]
    other = _heartbeat(client, agent, job_id="job-it-does-not-hold")
    assert other.status_code == 401
    assert client.post("/api/agent/jobs/claim?agent_id=edge-1", headers=agent).status_code == 401
    # Once the job is closed there is nothing left to say.
    with get_session(settings.postgres_url) as session:
        session.get(models.Job, running).status = "cancelled"
    assert _heartbeat(client, agent, job_id=running).status_code == 401


def test_a_scan_admitted_as_the_tenant_is_suspended_is_refused_not_left_queued(
    env, monkeypatch
):
    """Admission reads the status in a transaction of its own; the insert
    re-reads it under FOR SHARE, which the suspension's FOR UPDATE serialises
    against."""
    client, settings, admin = env
    from api.services import job_submission

    real = job_submission.scan_admission.admit_scan

    def admit_then_suspend(*args, **kwargs):
        admitted = real(*args, **kwargs)
        lifecycle.suspend(settings, ACME, reason="race", actor="root")
        return admitted

    monkeypatch.setattr(job_submission.scan_admission, "admit_scan", admit_then_suspend)
    refused = client.post(
        f"/api/jobs?tenant_id={ACME}",
        headers=admin,
        json={"mode": "safe", "skip_nse": True, "ranges": "127.0.0.1\n", "ports": "80\n"},
    )
    assert refused.status_code in (400, 403, 409, 422), refused.text
    with get_session(settings.postgres_url) as session:
        queued = session.execute(
            select(models.Job.job_id).where(
                models.Job.tenant_id == ACME, models.Job.status == "queued"
            )
        ).all()
    assert queued == []


def test_the_journal_listing_is_paged(env):
    client, settings, admin = env
    for tenant_id in (ACME, GLOBEX):
        assert _request(client, admin, tenant_id).status_code == 202
        assert client.delete(f"/api/tenants/{tenant_id}/deletion", headers=admin).status_code == 200
    first = client.get("/api/tenants/deletions?limit=1", headers=admin)
    assert first.status_code == 200, first.text
    second = client.get("/api/tenants/deletions?limit=1&offset=1", headers=admin)
    assert [len(first.json()), len(second.json())] == [1, 1]
    assert first.json()[0]["tenant_id"] != second.json()[0]["tenant_id"]
    # Steps come with every row, loaded in one query for the page.
    assert len(first.json()[0]["steps"]) == len(lifecycle.STEPS)
    assert client.get("/api/tenants/deletions?limit=0", headers=admin).status_code == 422


def test_the_two_person_rule_fails_closed_on_what_it_does_not_recognise(monkeypatch):
    from api.settings import load_settings

    for raw, expected in (
        ("on", True),
        ("enabled", True),
        ("true ", True),
        ("tru", True),
        (" FALSE ", False),
        ("off", False),
        ("0", False),
        ("no", False),
    ):
        monkeypatch.setenv("OCTO_TENANT_DELETION_TWO_PERSON", raw)
        assert load_settings().tenant_deletion_two_person is expected, raw


def test_the_unused_stores_setting_refuses_a_name_it_does_not_know(monkeypatch):
    from api.settings import load_settings

    monkeypatch.setenv("OCTO_TENANT_PURGE_UNUSED_STORES", " JetStream , clickhouse,")
    assert load_settings().tenant_purge_unused_stores == ("clickhouse", "jetstream")
    monkeypatch.setenv("OCTO_TENANT_PURGE_UNUSED_STORES", "clickhouse,minio")
    with pytest.raises(ValueError, match="minio"):
        load_settings()
