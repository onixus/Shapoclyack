"""The SLA escalation worker (#349).

The rule under test: a deadline that passes has to become an event exactly
once, whatever the tick interval, and the escalation that follows it happens
only where the tenant asked for it.

Every test drives ``tick(now=...)`` directly with an explicit clock rather than
starting the thread — the thing being asserted is what one pass decides, and a
worker whose "later" is a ``sleep`` is a worker whose tests are flaky.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from api.db import models
from api.db.engine import get_session
from api.services import agents as agents_service
from api.services import sla_escalation
from api.services import tenants as tenants_service
from api.services import vuln_states
from api.services import vulnerabilities as vulns
from api.services import workflow_events
from api.services.integrations import webhooks
from api.settings import Settings
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres

pytestmark = requires_postgres

_HOSTS = [{"host": "10.0.0.5", "hostname": "app.example.com"}]
_FINDINGS = [
    {
        "host": "10.0.0.5",
        "port": "443",
        "cve": "CVE-2026-0001",
        "cvss": 7.5,
        "severity": "high",
    },
]


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    base = make_settings(tmp_path)
    base.output_dir.mkdir(parents=True, exist_ok=True)
    base.state_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(base)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(base)
    webhooks.configure(base)
    webhooks.reset_for_tests()
    return base


def _subscribe(kinds: list[str]) -> None:
    webhooks.create_subscription(
        tenant_id="default",
        name="soc",
        url="https://receiver.example/hook",
        event_kinds=kinds,
        created_by="admin",
    )


def _queued(settings: Settings, kind: str) -> list[dict]:
    with get_session(settings.postgres_url) as session:
        return [
            row.payload
            for row in session.query(models.WebhookDelivery).all()
            if row.event_kind == kind
        ]


def _seed_finding(settings: Settings, *, owner_email: str | None = None) -> str:
    from api.services import assets as assets_service

    run_dir = settings.output_dir / "runs" / "run-1"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "alive_hosts.json").write_text(json.dumps(_HOSTS), encoding="utf-8")
    (run_dir / "vulnerabilities.json").write_text(json.dumps(_FINDINGS), encoding="utf-8")
    assets_service.upsert_assets_from_run(settings, tenant_id="default", run_id="run-1")
    vulns.register_findings_from_run(settings, tenant_id="default", run_id="run-1")
    items, _ = vulns.list_vulnerabilities(settings, tenant_id="default")
    vuln_id = items[0]["vuln_id"]
    if owner_email:
        with get_session(settings.postgres_url) as session:
            row = session.get(models.Asset, items[0]["asset_id"])
            row.owner_email = owner_email
    return vuln_id


def _set_due(settings: Settings, vuln_id: str, due_at: datetime) -> None:
    """Move a deadline instead of waiting one out."""
    with get_session(settings.postgres_url) as session:
        session.get(models.Vulnerability, vuln_id).due_at = due_at.replace(tzinfo=None)


def _set_last_seen(settings: Settings, agent_id: str, last_seen: datetime) -> None:
    """Age an agent's heartbeat instead of waiting one out. Set explicitly
    rather than derived from the test clock: ``register_agent`` stamps the real
    wall clock, which is not ``_NOW``."""
    with get_session(settings.postgres_url) as session:
        session.get(models.Agent, agent_id).last_seen_at = last_seen.replace(tzinfo=None)


def _worker(settings: Settings) -> sla_escalation.SlaEscalationWorker:
    return sla_escalation.SlaEscalationWorker(settings=settings)


_NOW = datetime(2026, 9, 10, 12, 0, tzinfo=UTC)


# --------------------------------------------------------------------------
# SLA events
# --------------------------------------------------------------------------


def test_a_passed_deadline_is_announced_once_however_often_the_worker_looks(settings):
    """The defect #349 names: the breach was derived on read, so nobody was
    told — and a worker that emitted on truth rather than on change would then
    page the tenant on every tick."""
    _subscribe(["sla_breached"])
    vuln_id = _seed_finding(settings)
    _set_due(settings, vuln_id, _NOW - timedelta(days=3))
    worker = _worker(settings)

    worker.tick(now=_NOW)
    worker.tick(now=_NOW + timedelta(minutes=15))

    events = _queued(settings, "sla_breached")
    assert len(events) == 1
    data = events[0]["event"]["data"]
    assert data["vuln_id"] == vuln_id
    assert data["cve"] == "CVE-2026-0001"
    assert data["days_overdue"] == 3
    assert worker.stats["breached"] == 1


def test_a_deadline_inside_the_window_is_due_soon_not_breached(settings):
    _subscribe(list(workflow_events.WORKFLOW_EVENT_KINDS))
    vuln_id = _seed_finding(settings)
    _set_due(settings, vuln_id, _NOW + timedelta(days=2))

    _worker(settings).tick(now=_NOW)

    assert len(_queued(settings, "sla_due_soon")) == 1
    assert _queued(settings, "sla_breached") == []


def test_a_deadline_beyond_the_window_says_nothing(settings):
    _subscribe(list(workflow_events.WORKFLOW_EVENT_KINDS))
    vuln_id = _seed_finding(settings)
    _set_due(settings, vuln_id, _NOW + timedelta(days=90))

    _worker(settings).tick(now=_NOW)

    assert _queued(settings, "sla_due_soon") == []


def test_accepted_risk_suspends_the_clock_and_the_notification_with_it(settings):
    """``sla_state`` reads an accepted finding as ``accepted``; the worker's
    query has to agree with it, or the two would disagree about one row."""
    _subscribe(["sla_breached"])
    vuln_id = _seed_finding(settings)
    _set_due(settings, vuln_id, _NOW - timedelta(days=3))
    vulns.set_exception(
        settings,
        tenant_id="default",
        vuln_id=vuln_id,
        until=_NOW + timedelta(days=30),
        reason="waiting on the vendor",
        actor="admin",
    )

    _worker(settings).tick(now=_NOW)

    assert _queued(settings, "sla_breached") == []


def test_an_expired_acceptance_brings_the_breach_back(settings):
    _subscribe(["sla_breached"])
    vuln_id = _seed_finding(settings)
    _set_due(settings, vuln_id, _NOW - timedelta(days=3))
    vulns.set_exception(
        settings,
        tenant_id="default",
        vuln_id=vuln_id,
        until=_NOW + timedelta(days=1),
        reason="short grace",
        actor="admin",
    )
    worker = _worker(settings)
    worker.tick(now=_NOW)

    worker.tick(now=_NOW + timedelta(days=2))

    assert len(_queued(settings, "sla_breached")) == 1


def test_a_reopened_finding_is_announced_against_its_new_deadline(settings):
    """The clock restarts on a reopen, so the same finding breaching again is a
    second occurrence — that is why the marker carries the deadline."""
    _subscribe(["sla_breached"])
    vuln_id = _seed_finding(settings)
    _set_due(settings, vuln_id, _NOW - timedelta(days=3))
    worker = _worker(settings)
    worker.tick(now=_NOW)

    vulns.transition(
        settings, tenant_id="default", vuln_id=vuln_id, to_state=vuln_states.CLOSED
    )
    vulns.transition(
        settings, tenant_id="default", vuln_id=vuln_id, to_state=vuln_states.OPEN
    )
    _set_due(settings, vuln_id, _NOW + timedelta(days=1))
    worker.tick(now=_NOW + timedelta(days=5))

    assert len(_queued(settings, "sla_breached")) == 2


def test_a_closed_finding_has_no_deadline_to_miss(settings):
    _subscribe(["sla_breached"])
    vuln_id = _seed_finding(settings)
    _set_due(settings, vuln_id, _NOW - timedelta(days=3))
    vulns.transition(
        settings, tenant_id="default", vuln_id=vuln_id, to_state=vuln_states.CLOSED
    )

    _worker(settings).tick(now=_NOW)

    assert _queued(settings, "sla_breached") == []


def test_one_tick_announces_at_most_the_configured_number_of_findings(settings):
    """A tenant importing a backlog must not turn one tick into a delivery
    storm; the rest are announced by the ticks that follow."""
    settings.sla_escalation_max_findings = 1
    _subscribe(["sla_breached"])
    vuln_id = _seed_finding(settings)
    _set_due(settings, vuln_id, _NOW - timedelta(days=3))
    # A second finding on the same asset, breaching later.
    second = vulns.finding_key(asset_id="x", cve="CVE-2026-0002", script_id=None, port="80")
    with get_session(settings.postgres_url) as session:
        template = session.get(models.Vulnerability, vuln_id)
        session.add(
            models.Vulnerability(
                vuln_id="vln_second",
                tenant_id="default",
                asset_id=template.asset_id,
                finding_key=second,
                cve="CVE-2026-0002",
                port="80",
                title="second",
                severity="high",
                state=vuln_states.OPEN,
                state_changed_at=template.state_changed_at,
                due_at=(_NOW - timedelta(days=1)).replace(tzinfo=None),
                first_seen_at=template.first_seen_at,
                last_seen_at=template.last_seen_at,
                sla_started_at=template.sla_started_at,
                created_at=template.created_at,
                updated_at=template.updated_at,
            )
        )

    _worker(settings).tick(now=_NOW)

    # The oldest deadline first, and only it.
    events = _queued(settings, "sla_breached")
    assert len(events) == 1
    assert events[0]["event"]["data"]["vuln_id"] == vuln_id


# --------------------------------------------------------------------------
# Expiring exceptions
# --------------------------------------------------------------------------


def test_an_expiring_exception_warns_at_the_nearest_threshold_only(settings):
    """A five-day acceptance must produce one notice, not one per threshold."""
    _subscribe(["exception_expiring"])
    vuln_id = _seed_finding(settings)
    vulns.set_exception(
        settings,
        tenant_id="default",
        vuln_id=vuln_id,
        until=_NOW + timedelta(days=5),
        reason="vendor patch pending",
        actor="admin",
    )

    _worker(settings).tick(now=_NOW)

    events = _queued(settings, "exception_expiring")
    assert len(events) == 1
    data = events[0]["event"]["data"]
    assert data["threshold_days"] == 7
    assert data["days_remaining"] == 5
    assert data["exception_reason"] == "vendor patch pending"


def test_each_threshold_warns_once_as_the_expiry_approaches(settings):
    _subscribe(["exception_expiring"])
    vuln_id = _seed_finding(settings)
    until = _NOW + timedelta(days=40)
    vulns.set_exception(
        settings,
        tenant_id="default",
        vuln_id=vuln_id,
        until=until,
        reason="long acceptance",
        actor="admin",
    )
    worker = _worker(settings)

    # Outside every threshold: nothing yet.
    worker.tick(now=_NOW)
    assert _queued(settings, "exception_expiring") == []

    for offset, expected in ((15, 30), (30, 14), (35, 7)):
        worker.tick(now=_NOW + timedelta(days=offset))
    thresholds = [
        item["event"]["data"]["threshold_days"]
        for item in _queued(settings, "exception_expiring")
    ]
    assert thresholds == [30, 14, 7]
    # And a tick that changes nothing adds nothing.
    worker.tick(now=_NOW + timedelta(days=35, hours=1))
    assert len(_queued(settings, "exception_expiring")) == 3


def test_an_exception_that_already_lapsed_is_not_warned_about(settings):
    """It is not expiring; it is expired, and the finding is back in the breach
    population where ``sla_breached`` covers it."""
    _subscribe(["exception_expiring"])
    vuln_id = _seed_finding(settings)
    vulns.set_exception(
        settings,
        tenant_id="default",
        vuln_id=vuln_id,
        until=_NOW + timedelta(days=1),
        reason="short",
        actor="admin",
    )

    _worker(settings).tick(now=_NOW + timedelta(days=5))

    assert _queued(settings, "exception_expiring") == []


# --------------------------------------------------------------------------
# Escalation
# --------------------------------------------------------------------------


def test_without_a_policy_nothing_is_reassigned(settings):
    """The events need no policy; rewriting somebody's work queue does."""
    _subscribe(["sla_breached"])
    vuln_id = _seed_finding(settings)
    _set_due(settings, vuln_id, _NOW - timedelta(days=1))

    _worker(settings).tick(now=_NOW)

    row = vulns.get_vulnerability(settings, tenant_id="default", vuln_id=vuln_id)
    assert row["assignee"] is None
    assert row["severity"] == "high"
    assert _queued(settings, "sla_breached")[0]["event"]["data"]["escalation"] is None


def test_an_enabled_policy_reassigns_and_bumps_severity_once(settings):
    _subscribe(["sla_breached"])
    vuln_id = _seed_finding(settings)
    _set_due(settings, vuln_id, _NOW - timedelta(days=1))
    vulns.upsert_escalation_policy(
        settings,
        tenant_id="default",
        enabled=True,
        escalate_to="soc@example.com",
        escalate_owner_team="platform",
        bump_severity=True,
        updated_by="admin",
    )
    worker = _worker(settings)

    worker.tick(now=_NOW)

    row = vulns.get_vulnerability(settings, tenant_id="default", vuln_id=vuln_id)
    assert row["assignee"] == "soc@example.com"
    assert row["owner_team"] == "platform"
    assert row["severity"] == "critical"
    # The event describes the finding after the escalation, or the receiver's
    # copy of the owner would be wrong.
    data = _queued(settings, "sla_breached")[0]["event"]["data"]
    assert data["assignee"] == "soc@example.com"
    assert data["severity"] == "critical"
    assert data["escalation"]["severity_to"] == "critical"
    # Recorded in the finding's own trail, with no actor: the platform did it.
    events, _ = vulns.list_events(settings, tenant_id="default", vuln_id=vuln_id)
    escalated = next(item for item in events if item["kind"] == "escalated")
    assert escalated["actor"] is None

    # A second tick has nothing left to change, so it does not bump again.
    worker.tick(now=_NOW + timedelta(days=1))
    assert vulns.get_vulnerability(settings, tenant_id="default", vuln_id=vuln_id)[
        "severity"
    ] == "critical"
    assert worker.stats["escalated"] == 1


def test_a_grace_period_delays_the_escalation_but_not_the_event(settings):
    _subscribe(["sla_breached"])
    vuln_id = _seed_finding(settings)
    _set_due(settings, vuln_id, _NOW - timedelta(days=1))
    vulns.upsert_escalation_policy(
        settings,
        tenant_id="default",
        enabled=True,
        escalate_after_days=5,
        escalate_to="soc@example.com",
        updated_by="admin",
    )
    worker = _worker(settings)

    worker.tick(now=_NOW)
    assert vulns.get_vulnerability(settings, tenant_id="default", vuln_id=vuln_id)[
        "assignee"
    ] is None
    # The breach was still announced on day one; only the reassignment waits.
    assert len(_queued(settings, "sla_breached")) == 1

    worker.tick(now=_NOW + timedelta(days=6))
    assert vulns.get_vulnerability(settings, tenant_id="default", vuln_id=vuln_id)[
        "assignee"
    ] == "soc@example.com"


def test_severity_bump_is_capped_and_unknown_lands_in_the_middle():
    assert vulns._raise_severity("high") == "critical"  # noqa: SLF001
    assert vulns._raise_severity("critical") == "critical"  # noqa: SLF001
    # An unrated finding nobody fixed in time is not evidence that it is mild.
    assert vulns._raise_severity("unknown") == "medium"  # noqa: SLF001


def test_an_enabled_policy_with_no_action_is_refused(settings):
    """A switch that reads as "escalation is on" and does nothing is worse than
    an off switch."""
    with pytest.raises(ValueError):
        vulns.upsert_escalation_policy(settings, tenant_id="default", enabled=True)


def test_an_unset_policy_reads_as_unconfigured_rather_than_disabled(settings):
    policy = vulns.get_escalation_policy(settings, tenant_id="default")
    assert policy["configured"] is False
    assert policy["enabled"] is False

    vulns.upsert_escalation_policy(
        settings, tenant_id="default", enabled=False, updated_by="admin"
    )
    assert vulns.get_escalation_policy(settings, tenant_id="default")["configured"] is True


# --------------------------------------------------------------------------
# Offline agents and the owner digest
# --------------------------------------------------------------------------


def test_a_quiet_agent_is_announced_once_per_silence(settings):
    _subscribe(["agent_offline"])
    agents_service.configure(settings)
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    worker = _worker(settings)
    later = _NOW + timedelta(seconds=settings.agent_stale_seconds + 60)
    _set_last_seen(settings, "agent-1", _NOW)

    worker.tick(now=later)
    worker.tick(now=later + timedelta(minutes=15))

    events = _queued(settings, "agent_offline")
    assert len(events) == 1
    assert events[0]["event"]["data"]["agent_id"] == "agent-1"
    assert events[0]["event"]["data"]["silent_for_seconds"] > settings.agent_stale_seconds

    # It comes back, then goes quiet again: a new silence, announced again.
    _set_last_seen(settings, "agent-1", later)
    worker.tick(now=later + timedelta(days=1))
    assert len(_queued(settings, "agent_offline")) == 2


def test_a_retired_agent_is_not_news(settings):
    _subscribe(["agent_offline"])
    agents_service.configure(settings)
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    agents_service.set_lifecycle_status(
        "agent-1", lifecycle_status="disabled", reason="decommissioned"
    )
    _set_last_seen(settings, "agent-1", _NOW)

    _worker(settings).tick(now=_NOW + timedelta(seconds=settings.agent_stale_seconds + 60))

    assert _queued(settings, "agent_offline") == []


def test_the_owner_digest_is_sent_once_a_day_to_the_asset_owner(settings, monkeypatch):
    sent: list[tuple[str, str, str]] = []
    monkeypatch.setattr(
        sla_escalation.mail,
        "send_notice",
        lambda _settings, *, to, subject, body: sent.append((to, subject, body)) or None,
    )
    vuln_id = _seed_finding(settings, owner_email="owner@example.com")
    _set_due(settings, vuln_id, _NOW - timedelta(days=2))
    vulns.upsert_escalation_policy(
        settings, tenant_id="default", enabled=True, digest_enabled=True, updated_by="admin"
    )
    worker = _worker(settings)

    worker.tick(now=_NOW)
    worker.tick(now=_NOW + timedelta(hours=1))

    assert len(sent) == 1
    to, subject, body = sent[0]
    assert to == "owner@example.com"
    assert "past SLA" in subject
    assert "CVE-2026-0001" in body

    # The next day is a new digest: it is "what is on your plate today", not a
    # change feed.
    worker.tick(now=_NOW + timedelta(days=1))
    assert len(sent) == 2


def test_no_digest_without_the_policy_or_without_an_owner(settings, monkeypatch):
    sent: list[str] = []
    monkeypatch.setattr(
        sla_escalation.mail,
        "send_notice",
        lambda _settings, *, to, subject, body: sent.append(to) or None,
    )
    vuln_id = _seed_finding(settings)  # no owner_email on the asset
    _set_due(settings, vuln_id, _NOW - timedelta(days=2))
    worker = _worker(settings)

    worker.tick(now=_NOW)
    assert sent == []

    vulns.upsert_escalation_policy(
        settings, tenant_id="default", enabled=True, digest_enabled=True, updated_by="admin"
    )
    worker.tick(now=_NOW + timedelta(hours=1))
    # Still nothing: there is nobody to send it to.
    assert sent == []


def test_turning_the_policy_off_stops_the_digest_too(settings, monkeypatch):
    """``enabled`` is the one off switch: a tenant that turned escalation off
    did not ask to keep receiving mail about it."""
    sent: list[str] = []
    monkeypatch.setattr(
        sla_escalation.mail,
        "send_notice",
        lambda _settings, *, to, subject, body: sent.append(to) or None,
    )
    vuln_id = _seed_finding(settings, owner_email="owner@example.com")
    _set_due(settings, vuln_id, _NOW - timedelta(days=2))
    vulns.upsert_escalation_policy(
        settings, tenant_id="default", enabled=False, digest_enabled=True, updated_by="admin"
    )

    _worker(settings).tick(now=_NOW)

    assert sent == []


def test_a_relay_failure_is_counted_and_does_not_stop_the_tick(settings, monkeypatch):
    monkeypatch.setattr(
        sla_escalation.mail,
        "send_notice",
        lambda _settings, *, to, subject, body: "SMTPException: relay refused",
    )
    _subscribe(["sla_breached"])
    vuln_id = _seed_finding(settings, owner_email="owner@example.com")
    _set_due(settings, vuln_id, _NOW - timedelta(days=2))
    vulns.upsert_escalation_policy(
        settings, tenant_id="default", enabled=True, digest_enabled=True, updated_by="admin"
    )
    worker = _worker(settings)

    worker.tick(now=_NOW)

    assert worker.stats["digest_failures"] == 1
    # The webhook event went out regardless: two channels, one of which failed.
    assert len(_queued(settings, "sla_breached")) == 1


# --------------------------------------------------------------------------
# The policy API
# --------------------------------------------------------------------------


def test_reading_the_policy_needs_viewer_and_writing_it_needs_admin(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    viewer = auth_headers(client, "viewer")
    operator = auth_headers(client, "operator")
    admin = auth_headers(client, "admin")

    read = client.get("/api/vulnerabilities/sla-escalation", headers=viewer)
    assert read.status_code == 200
    assert read.json()["configured"] is False

    body = {"enabled": True, "escalate_to": "soc@example.com"}
    assert client.put(
        "/api/vulnerabilities/sla-escalation", headers=operator, json=body
    ).status_code == 403

    written = client.put("/api/vulnerabilities/sla-escalation", headers=admin, json=body)
    assert written.status_code == 200
    assert written.json()["escalate_to"] == "soc@example.com"
    assert written.json()["updated_by"] == "admin"

    # The refusal an operator would otherwise only discover by nothing
    # happening.
    refused = client.put(
        "/api/vulnerabilities/sla-escalation", headers=admin, json={"enabled": True}
    )
    assert refused.status_code == 422
