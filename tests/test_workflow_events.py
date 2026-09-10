"""Remediation-workflow events (#349): vocabulary, routing, markers, emitters.

Split like ``tests/test_vuln_lifecycle.py``: the envelope, the subject and the
subscription-matching rules are pure and run everywhere, while anything that
queues a delivery or writes a marker needs the Postgres the rest of the suite
needs (``requires_postgres``).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from api.db import models
from api.db.engine import get_session
from api.schemas import StartScanRequest
from api.services import agents as agents_service
from api.services import jobs as jobs_service
from api.services import nats_bus
from api.services import tenants as tenants_service
from api.services import vuln_states
from api.services import vulnerabilities as vulns
from api.services import workflow_events
from api.services.integrations import webhooks
from api.settings import Settings
from tests.conftest import approve_scan_scope, make_settings, requires_postgres

# --------------------------------------------------------------------------
# Vocabulary, subject and envelope
# --------------------------------------------------------------------------


def test_the_eight_kinds_are_the_ones_the_issue_names():
    assert set(workflow_events.WORKFLOW_EVENT_KINDS) == {
        "sla_due_soon",
        "sla_breached",
        "exception_expiring",
        "vuln_state_changed",
        "vuln_assigned",
        "scan_failed",
        "report_generated",
        "agent_offline",
    }
    # A workflow kind must never collide with a discovery kind: both are a
    # subscription's ``event_kinds`` entries and one token cannot mean two
    # things.
    from api.services import asset_events

    assert not set(workflow_events.WORKFLOW_EVENT_KINDS) & set(asset_events.EVENT_KINDS)


def test_severity_bearing_kinds_are_the_ones_about_a_finding():
    """A "critical only" subscription must not silence a failed scan."""
    assert "scan_failed" not in workflow_events.SEVERITY_BEARING_KINDS
    assert "agent_offline" not in workflow_events.SEVERITY_BEARING_KINDS
    assert "report_generated" not in workflow_events.SEVERITY_BEARING_KINDS
    assert "sla_breached" in workflow_events.SEVERITY_BEARING_KINDS


def test_subject_puts_tenant_before_kind_and_keeps_valid_ids_verbatim():
    assert (
        nats_bus.workflow_event_subject("ten_acme", "sla_breached")
        == "events.workflow.ten_acme.sla_breached"
    )
    assert nats_bus.workflow_event_subject("", "") == "events.workflow.default.unknown"
    # A tenant id that is not a subject token is encoded, not mangled onto a
    # neighbour's subject.
    assert nats_bus.workflow_event_subject("acme.eu", "sla_breached") != (
        nats_bus.workflow_event_subject("acme_eu", "sla_breached")
    )


def test_event_id_is_stable_and_every_part_participates():
    base = dict(tenant_id="default", kind="sla_breached", subject_id="vln_1", marker="d1")
    assert workflow_events.event_id(**base) == workflow_events.event_id(**base)
    # The marker is what makes two occurrences of one predicate distinct: the
    # same finding with a new deadline is a new event.
    assert workflow_events.event_id(**{**base, "marker": "d2"}) != (
        workflow_events.event_id(**base)
    )
    assert workflow_events.event_id(**{**base, "tenant_id": "other"}) != (
        workflow_events.event_id(**base)
    )


def test_envelope_keeps_the_asset_event_shape():
    envelope = workflow_events.build_envelope(
        kind="sla_breached",
        tenant_id="default",
        subject_id="vln_1",
        marker="2026-09-01T00:00:00",
        data={"severity": "high", "cve": "CVE-2026-1"},
    )
    assert envelope["kind"] == "sla_breached"
    assert envelope["subject_id"] == "vln_1"
    assert envelope["source"] == "workflow"
    assert envelope["data"] == {"severity": "high", "cve": "CVE-2026-1"}
    # The keys webhooks.enqueue_event routes on, so no second code path.
    assert set(envelope) >= {"kind", "tenant_id", "event_id", "occurred_at", "data"}


# --------------------------------------------------------------------------
# Subscription matching
# --------------------------------------------------------------------------


def _sub(**overrides):
    base = {"enabled": True, "event_kinds": [], "min_severity": None}
    return {**base, **overrides}


def _envelope(kind: str, *, severity: str | None = None):
    return workflow_events.build_envelope(
        kind=kind,
        tenant_id="default",
        subject_id="vln_1",
        marker="m",
        data={"severity": severity} if severity else {},
    )


def test_a_subscription_with_no_kinds_does_not_start_taking_workflow_events():
    """The #328 rule, applied again: an upgrade must not add traffic nobody asked
    for to a receiver configured for new criticals."""
    assert webhooks.matches(_sub(), _envelope("vuln_assigned")) is False
    assert webhooks.matches(_sub(), _envelope("sla_breached", severity="critical")) is False
    # The discovery events it was created for still match.
    assert webhooks.matches(_sub(), {"kind": "new_asset", "data": {}}) is True


def test_naming_the_kind_is_how_a_tenant_asks_for_it():
    sub = _sub(event_kinds=["sla_breached"])
    assert webhooks.matches(sub, _envelope("sla_breached", severity="low")) is True
    assert webhooks.matches(sub, _envelope("sla_due_soon", severity="low")) is False


def test_min_severity_filters_finding_events_but_not_infrastructure_ones():
    sub = _sub(event_kinds=["sla_breached", "scan_failed"], min_severity="high")
    assert webhooks.matches(sub, _envelope("sla_breached", severity="medium")) is False
    assert webhooks.matches(sub, _envelope("sla_breached", severity="critical")) is True
    # No severity to compare, so the filter does not apply: a failed scan is
    # not a low-severity finding.
    assert webhooks.matches(sub, _envelope("scan_failed")) is True


def test_emit_refuses_an_unknown_kind_without_raising(tmp_path):
    """The kind becomes a subject token, so a typo must not invent a subject."""
    settings = make_settings(tmp_path)
    assert workflow_events.emit(
        settings, "sla_exploded", tenant_id="default", subject_id="vln_1"
    ) is False


def test_emit_is_a_no_op_when_the_feature_is_off(tmp_path):
    settings = make_settings(tmp_path, workflow_events_enabled=False)
    assert workflow_events.emit(
        settings, "sla_breached", tenant_id="default", subject_id="vln_1"
    ) is False


def test_emit_needs_a_tenant(tmp_path):
    """A workflow event with no tenant has no correct recipient: subscriptions
    belong to a tenant."""
    settings = make_settings(tmp_path)
    assert workflow_events.emit(
        settings, "sla_breached", tenant_id=None, subject_id="vln_1"
    ) is False


# --------------------------------------------------------------------------
# Queueing, markers and the emitters at the write sites
# --------------------------------------------------------------------------


def _settings(tmp_path: Path, **overrides) -> Settings:
    settings = make_settings(tmp_path, **overrides)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(settings)
    webhooks.configure(settings)
    webhooks.reset_for_tests()
    return settings


def _subscribe(kinds: list[str], **overrides) -> dict:
    payload = {
        "tenant_id": "default",
        "name": "soc",
        "url": "https://receiver.example/hook",
        "event_kinds": kinds,
        "created_by": "admin",
    }
    payload.update(overrides)
    return webhooks.create_subscription(**payload)


def _queued(settings: Settings, kind: str | None = None) -> list[models.WebhookDelivery]:
    """The queued deliveries, read as rows.

    ``webhooks.list_deliveries`` is the console view and does not carry the
    payload; these tests are about what a receiver would be handed, so they
    read the column.
    """
    with get_session(settings.postgres_url) as session:
        rows = session.query(models.WebhookDelivery).all()
        return [
            row.payload for row in rows if kind is None or row.event_kind == kind
        ]


_HOSTS = [{"host": "10.0.0.5", "hostname": "app.example.com"}]
_FINDINGS = [
    {"host": "10.0.0.5", "port": "443", "cve": "CVE-2026-0001", "cvss": 9.8, "severity": "critical"},
]


def _seed_finding(settings: Settings, run_id: str = "run-1") -> str:
    from api.services import assets as assets_service

    run_dir = settings.output_dir / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "alive_hosts.json").write_text(json.dumps(_HOSTS), encoding="utf-8")
    (run_dir / "vulnerabilities.json").write_text(json.dumps(_FINDINGS), encoding="utf-8")
    assets_service.upsert_assets_from_run(settings, tenant_id="default", run_id=run_id)
    vulns.register_findings_from_run(settings, tenant_id="default", run_id=run_id)
    items, _ = vulns.list_vulnerabilities(settings, tenant_id="default")
    return items[0]["vuln_id"]


@requires_postgres
def test_the_new_kinds_are_accepted_on_a_subscription(tmp_path):
    _settings(tmp_path)
    created = _subscribe(list(workflow_events.WORKFLOW_EVENT_KINDS))
    assert set(created["event_kinds"]) == set(workflow_events.WORKFLOW_EVENT_KINDS)
    with pytest.raises(ValueError):
        _subscribe(["sla_exploded"], name="typo")


@requires_postgres
def test_emit_queues_one_delivery_and_a_replay_does_not_queue_a_second(tmp_path):
    """The bus consumer is at-least-once and ``emit`` also queues directly, so
    the same event reaching the queue twice must stay one delivery."""
    settings = _settings(tmp_path)
    _subscribe(["sla_breached"])

    assert workflow_events.emit(
        settings,
        "sla_breached",
        tenant_id="default",
        subject_id="vln_1",
        marker="2026-09-01T00:00:00",
        data={"severity": "critical"},
    ) is True
    workflow_events.emit(
        settings,
        "sla_breached",
        tenant_id="default",
        subject_id="vln_1",
        marker="2026-09-01T00:00:00",
        data={"severity": "critical"},
    )

    assert len(_queued(settings, "sla_breached")) == 1


@requires_postgres
def test_a_claim_is_won_once_and_a_new_marker_re_arms_it(tmp_path):
    settings = _settings(tmp_path)
    claim = dict(tenant_id="default", kind="sla_breached", subject_id="vln_1")

    assert workflow_events.claim(settings, **claim, marker="due-1") is True
    assert workflow_events.claim(settings, **claim, marker="due-1") is False
    assert workflow_events.marker_exists(settings, **claim, marker="due-1") is True
    # A finding whose clock restarted has a new deadline, so it is announced
    # again — that is the whole reason the marker is not just the vuln id.
    assert workflow_events.claim(settings, **claim, marker="due-2") is True


@requires_postgres
def test_emit_once_sends_nothing_the_second_time(tmp_path):
    settings = _settings(tmp_path)
    _subscribe(["sla_breached"])
    args = dict(tenant_id="default", subject_id="vln_1", marker="due-1")

    assert workflow_events.emit_once(settings, "sla_breached", **args) is True
    assert workflow_events.emit_once(settings, "sla_breached", **args) is False
    assert len(_queued(settings, "sla_breached")) == 1


@requires_postgres
def test_pruning_a_marker_re_arms_its_event(tmp_path):
    settings = _settings(tmp_path, workflow_marker_retention_days=30)
    workflow_events.claim(settings, tenant_id="default", kind="sla_breached", subject_id="v", marker="d")
    with get_session(settings.postgres_url) as session:
        row = session.query(models.WorkflowEventMarker).one()
        row.created_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=40)

    assert workflow_events.prune_markers(settings) == 1
    assert workflow_events.claim(
        settings, tenant_id="default", kind="sla_breached", subject_id="v", marker="d"
    ) is True


@requires_postgres
def test_retention_of_zero_days_keeps_every_marker(tmp_path):
    settings = _settings(tmp_path, workflow_marker_retention_days=0)
    workflow_events.claim(settings, tenant_id="default", kind="sla_breached", subject_id="v", marker="d")
    assert workflow_events.prune_markers(settings) == 0


@requires_postgres
def test_a_transition_emits_vuln_state_changed_with_both_ends(tmp_path):
    settings = _settings(tmp_path)
    _subscribe(["vuln_state_changed"])
    vuln_id = _seed_finding(settings)

    vulns.transition(
        settings,
        tenant_id="default",
        vuln_id=vuln_id,
        to_state=vuln_states.ACKNOWLEDGED,
        actor="operator",
    )

    deliveries = _queued(settings, "vuln_state_changed")
    assert len(deliveries) == 1
    data = deliveries[0]["event"]["data"]
    assert (data["from_state"], data["to_state"]) == (vuln_states.OPEN, vuln_states.ACKNOWLEDGED)
    assert data["reopened"] is False
    assert data["cve"] == "CVE-2026-0001"
    # The payload names the finding and stops there: no false-positive
    # evidence, no observation bookkeeping.
    assert "fp_evidence" not in data


@requires_postgres
def test_two_transitions_are_two_events(tmp_path):
    settings = _settings(tmp_path)
    _subscribe(["vuln_state_changed"])
    vuln_id = _seed_finding(settings)

    vulns.transition(
        settings, tenant_id="default", vuln_id=vuln_id, to_state=vuln_states.ACKNOWLEDGED
    )
    vulns.transition(
        settings, tenant_id="default", vuln_id=vuln_id, to_state=vuln_states.FIXING
    )

    assert len(_queued(settings, "vuln_state_changed")) == 2


@requires_postgres
def test_assigning_emits_vuln_assigned_with_the_handover(tmp_path):
    settings = _settings(tmp_path)
    _subscribe(["vuln_assigned"])
    vuln_id = _seed_finding(settings)

    vulns.assign(
        settings,
        tenant_id="default",
        vuln_id=vuln_id,
        assignee="ops@example.com",
        owner_team="platform",
        actor="operator",
    )

    deliveries = _queued(settings, "vuln_assigned")
    assert len(deliveries) == 1
    data = deliveries[0]["event"]["data"]
    assert data["assignee_to"] == "ops@example.com"
    assert data["owner_team_to"] == "platform"
    assert data["actor"] == "operator"


@requires_postgres
def test_a_failed_scan_emits_scan_failed_once(tmp_path):
    """The lease-expiry path: nobody is watching a console when an executor
    stops reporting, which is exactly why it has to be an event."""
    settings = _settings(tmp_path, job_execution_mode="agent", job_max_attempts=1)
    approve_scan_scope(settings)
    agents_service.configure(settings)
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    _subscribe(["scan_failed"])

    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    jobs_service.claim_job(settings, "agent-1")
    with get_session(settings.postgres_url) as session:
        session.get(models.Job, job.job_id).claimed_until = (
            datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=1)
        )

    assert jobs_service.reap_expired_leases(settings)["failed"] == 1

    deliveries = _queued(settings, "scan_failed")
    assert len(deliveries) == 1
    data = deliveries[0]["event"]["data"]
    assert data["job_id"] == job.job_id
    assert data["execution"] == "agent"
    assert "Lease expired" in data["error"]
    # A second sweep finds nothing in flight, so nobody is told twice.
    jobs_service.reap_expired_leases(settings)
    assert len(_queued(settings, "scan_failed")) == 1


@requires_postgres
def test_a_generated_report_emits_report_generated(tmp_path):
    from api.services.reports import store as report_store

    settings = _settings(tmp_path)
    _subscribe(["report_generated"])

    report = report_store.generate(
        settings, tenant_id="default", kind="executive", fmt="json", actor="admin"
    )

    deliveries = _queued(settings, "report_generated")
    assert len(deliveries) == 1
    data = deliveries[0]["event"]["data"]
    assert data["report_id"] == report["report_id"]
    assert data["status"] == report["status"]


@requires_postgres
def test_a_tenant_with_no_matching_subscription_queues_nothing(tmp_path):
    """The ordinary case, and not a failure: nothing raises and no row appears."""
    settings = _settings(tmp_path)
    _subscribe(["new_cve"])
    vuln_id = _seed_finding(settings)

    vulns.transition(
        settings, tenant_id="default", vuln_id=vuln_id, to_state=vuln_states.ACKNOWLEDGED
    )

    assert _queued(settings) == []


@requires_postgres
def test_an_unconfigured_webhook_service_does_not_break_the_transition(tmp_path, monkeypatch):
    """Fail-soft, deliberately: a notification that cannot be queued must not
    turn an operator's transition into a 500."""
    settings = _settings(tmp_path)
    vuln_id = _seed_finding(settings)
    monkeypatch.setattr(
        webhooks, "enqueue_event", lambda envelope: (_ for _ in ()).throw(RuntimeError("boom"))
    )

    row = vulns.transition(
        settings, tenant_id="default", vuln_id=vuln_id, to_state=vuln_states.ACKNOWLEDGED
    )

    assert row["state"] == vuln_states.ACKNOWLEDGED
