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
from tests.conftest import (
    accept_risk,
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

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


def _set_last_seen(
    settings: Settings,
    agent_id: str,
    last_seen: datetime,
    *,
    healthy_since: datetime | None = None,
) -> None:
    """Age an agent's heartbeat instead of waiting one out. Set explicitly
    rather than derived from the test clock: ``register_agent`` stamps the real
    wall clock, which is not ``_NOW``.

    ``healthy_since`` is the start of the run of heartbeats that ends at
    ``last_seen`` — the column ``api/services/agents.py`` keeps and the worker
    reads to tell a recovery from a flap. It defaults to ``last_seen``, which
    is a run of exactly one beat: what a flapping agent has.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Agent, agent_id)
        row.last_seen_at = last_seen.replace(tzinfo=None)
        row.healthy_since = (healthy_since or last_seen).replace(tzinfo=None)


def _seed_second_finding(settings: Settings, vuln_id: str, due_at: datetime) -> str:
    """A second finding on the same asset, breaching at ``due_at``.

    Inserted rather than scanned in: the registration path derives ``due_at``
    from the SLA table and this test is about the order two deadlines are
    announced in.
    """
    key = vulns.finding_key(asset_id="x", cve="CVE-2026-0002", script_id=None, port="80")
    with get_session(settings.postgres_url) as session:
        template = session.get(models.Vulnerability, vuln_id)
        session.add(
            models.Vulnerability(
                vuln_id="vln_second",
                tenant_id="default",
                asset_id=template.asset_id,
                finding_key=key,
                cve="CVE-2026-0002",
                port="80",
                title="second",
                severity="high",
                state=vuln_states.OPEN,
                state_changed_at=template.state_changed_at,
                due_at=due_at.replace(tzinfo=None),
                first_seen_at=template.first_seen_at,
                last_seen_at=template.last_seen_at,
                sla_started_at=template.sla_started_at,
                created_at=template.created_at,
                updated_at=template.updated_at,
            )
        )
    return "vln_second"


def _worker(settings: Settings) -> sla_escalation.SlaEscalationWorker:
    return sla_escalation.SlaEscalationWorker(settings=settings)


#: The simulated clock every test in this file hangs its timeline on.
#:
#: Anchored to the real clock rather than written out as a literal. A literal
#: works until wall-clock time passes it: ``accept_risk`` validates
#: ``exception_until`` against ``datetime.now`` (api/services/vulnerabilities.py,
#: "exception_until must be in the future") and not against the ``now`` the
#: worker is handed, so a test granting an acceptance at ``_NOW + 1 day`` began
#: raising ValueError the moment that day arrived — on every branch at once,
#: hours after the code it tests had stopped changing. Truncated to the hour so
#: a run is still reproducible from its logs.
_NOW = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)


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
    accept_risk(
        settings,
        tenant_id="default",
        vuln_id=vuln_id,
        until=_NOW + timedelta(days=30),
        reason="waiting on the vendor",
        requester="admin",
    )

    _worker(settings).tick(now=_NOW)

    assert _queued(settings, "sla_breached") == []


def test_an_expired_acceptance_brings_the_breach_back(settings):
    _subscribe(["sla_breached"])
    vuln_id = _seed_finding(settings)
    _set_due(settings, vuln_id, _NOW - timedelta(days=3))
    accept_risk(
        settings,
        tenant_id="default",
        vuln_id=vuln_id,
        until=_NOW + timedelta(days=1),
        reason="short grace",
        requester="admin",
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
    storm."""
    settings.sla_escalation_max_findings = 1
    _subscribe(["sla_breached"])
    vuln_id = _seed_finding(settings)
    _set_due(settings, vuln_id, _NOW - timedelta(days=3))
    _seed_second_finding(settings, vuln_id, _NOW - timedelta(days=1))

    _worker(settings).tick(now=_NOW)

    # The oldest deadline first, and only it.
    events = _queued(settings, "sla_breached")
    assert len(events) == 1
    assert events[0]["event"]["data"]["vuln_id"] == vuln_id


def test_the_ticks_that_follow_announce_the_rest_of_the_backlog(settings):
    """The budget is a window, not a ceiling.

    Nothing drops out of the candidate query once it has been announced — the
    finding is still open, still overdue, still the oldest — so a tick that
    re-read the first N rows would announce those N and never the (N+1)th: a
    tenant with six hundred overdue findings would get five hundred events and
    then silence until somebody closed one of them by hand.
    """
    settings.sla_escalation_max_findings = 1
    _subscribe(["sla_breached"])
    first = _seed_finding(settings)
    _set_due(settings, first, _NOW - timedelta(days=3))
    second = _seed_second_finding(settings, first, _NOW - timedelta(days=1))
    worker = _worker(settings)

    worker.tick(now=_NOW)
    worker.tick(now=_NOW + timedelta(minutes=15))

    announced = [
        item["event"]["data"]["vuln_id"] for item in _queued(settings, "sla_breached")
    ]
    assert announced == [first, second]
    # And once the backlog is drained the window starts over without saying
    # anything a second time.
    worker.tick(now=_NOW + timedelta(minutes=30))
    assert len(_queued(settings, "sla_breached")) == 2


# --------------------------------------------------------------------------
# Expiring exceptions
# --------------------------------------------------------------------------


def test_an_expiring_exception_warns_at_the_nearest_threshold_only(settings):
    """A five-day acceptance must produce one notice, not one per threshold."""
    _subscribe(["exception_expiring"])
    vuln_id = _seed_finding(settings)
    accept_risk(
        settings,
        tenant_id="default",
        vuln_id=vuln_id,
        until=_NOW + timedelta(days=5),
        reason="vendor patch pending",
        requester="admin",
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
    accept_risk(
        settings,
        tenant_id="default",
        vuln_id=vuln_id,
        until=until,
        reason="long acceptance",
        requester="admin",
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
    accept_risk(
        settings,
        tenant_id="default",
        vuln_id=vuln_id,
        until=_NOW + timedelta(days=1),
        reason="short",
        requester="admin",
    )

    _worker(settings).tick(now=_NOW + timedelta(days=5))

    assert _queued(settings, "exception_expiring") == []


def test_a_request_waiting_for_approval_is_not_announced_as_expiring(settings):
    """Nothing is accepted yet, so there is nothing to expire (#348). The
    worker's predicate reads ``exception_until``, which only an approval
    writes; a request that also warned would page an on-call about a decision
    nobody has taken."""
    _subscribe(["exception_expiring"])
    vuln_id = _seed_finding(settings)
    vulns.request_exception(
        settings,
        tenant_id="default",
        vuln_id=vuln_id,
        until=_NOW + timedelta(days=5),
        reason="waiting on a signature",
        actor="admin",
    )

    _worker(settings).tick(now=_NOW)

    assert _queued(settings, "exception_expiring") == []


def test_the_tick_records_an_acceptance_that_has_run_out(settings):
    """The reminders are the warning; this is the obituary (#348). Without it
    the lapse is visible only to whoever happens to re-read the finding."""
    vuln_id = _seed_finding(settings)
    accept_risk(
        settings,
        tenant_id="default",
        vuln_id=vuln_id,
        until=_NOW + timedelta(days=2),
        reason="two days to migrate",
        requester="admin",
    )
    worker = _worker(settings)

    assert worker.tick(now=_NOW)["exception_expired"] == 0

    stats = worker.tick(now=_NOW + timedelta(days=3))

    assert stats["exception_expired"] == 1
    events, _total = vulns.list_events(settings, tenant_id="default", vuln_id=vuln_id)
    lapsed = next(event for event in events if event["kind"] == "exception_expired")
    # Nobody performed it, which is exactly why it is written down.
    assert lapsed["actor"] is None


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


def test_a_finding_an_operator_picked_up_is_not_taken_back_every_tick(settings):
    """Escalation is once per missed deadline, by record and not by accident.

    "Already assigned where the policy points" stops being true the moment
    somebody takes the finding, and re-applying the policy then would move it
    back to the SOC address every fifteen minutes and write an ``escalated``
    row in the trail each time.
    """
    _subscribe(["sla_breached"])
    vuln_id = _seed_finding(settings)
    _set_due(settings, vuln_id, _NOW - timedelta(days=1))
    vulns.upsert_escalation_policy(
        settings,
        tenant_id="default",
        enabled=True,
        escalate_to="soc@example.com",
        bump_severity=True,
        updated_by="admin",
    )
    worker = _worker(settings)
    worker.tick(now=_NOW)
    assert vulns.get_vulnerability(settings, tenant_id="default", vuln_id=vuln_id)[
        "assignee"
    ] == "soc@example.com"

    vulns.assign(
        settings,
        tenant_id="default",
        vuln_id=vuln_id,
        assignee="alice@example.com",
        actor="alice",
    )
    worker.tick(now=_NOW + timedelta(minutes=15))
    worker.tick(now=_NOW + timedelta(minutes=30))

    row = vulns.get_vulnerability(settings, tenant_id="default", vuln_id=vuln_id)
    assert row["assignee"] == "alice@example.com"
    events, _ = vulns.list_events(settings, tenant_id="default", vuln_id=vuln_id)
    assert len([item for item in events if item["kind"] == "escalated"]) == 1
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

    # It comes back for good — a run of heartbeats long enough to be a
    # recovery rather than a flap — and the claim is given back on the tick
    # that sees it.
    back = later + timedelta(minutes=15)
    recovered_at = back + timedelta(seconds=settings.agent_stale_seconds * 3)
    _set_last_seen(settings, "agent-1", recovered_at, healthy_since=back)
    worker.tick(now=recovered_at)
    assert worker.stats["agents_recovered"] == 1

    # ...and then goes quiet again: a new silence, announced again.
    _set_last_seen(settings, "agent-1", recovered_at)
    worker.tick(now=recovered_at + timedelta(days=1))
    events = _queued(settings, "agent_offline")
    assert len(events) == 2
    # Two episodes are two envelopes, not one said twice: the claim is keyed on
    # the agent, the event on the beat it fell silent after.
    assert events[0]["event"]["event_id"] != events[1]["event"]["event_id"]


def test_an_agent_that_reaches_the_api_every_other_beat_is_announced_once(settings):
    """The duplicate storm this marker scheme exists to stop.

    ``OCTO_AGENT_STALE_SECONDS`` is 120 and the agent beats every 60: a
    degraded link means one beat in two arrives, so at any tick the agent's
    last beat is either fresh or just over the threshold — and it is a
    *different* last beat every time. Keyed on ``last_seen_at`` the claim was
    new on every tick, so one degraded agent produced an ``agent_offline``
    every fifteen minutes, ninety-six a day, with nothing to tell them apart.
    One flap is one episode.
    """
    _subscribe(["agent_offline"])
    agents_service.configure(settings)
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    worker = _worker(settings)
    stale = settings.agent_stale_seconds

    for i in range(8):
        at = _NOW + timedelta(minutes=15 * i)
        # Alternately just past the threshold and just inside it — a run of one
        # beat either way, because the beat before it never arrived.
        age = stale + 10 if i % 2 == 0 else stale - 60
        _set_last_seen(settings, "agent-1", at - timedelta(seconds=age))
        worker.tick(now=at)

    assert len(_queued(settings, "agent_offline")) == 1
    # And it is never called recovered: being *seen* is not the same as being
    # back, or the next tick would announce the same flap all over again.
    assert worker.stats["agents_recovered"] == 0


def test_an_agent_that_really_went_away_is_announced_on_the_next_tick(settings):
    """The other side of the same fix: the claim-per-episode must not turn the
    false positives into false negatives. An agent that stops beating is
    announced by the first tick after ``OCTO_AGENT_STALE_SECONDS`` passes, with
    no confirmation window and no second opinion."""
    _subscribe(["agent_offline"])
    agents_service.configure(settings)
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    worker = _worker(settings)
    last_beat = _NOW
    _set_last_seen(settings, "agent-1", last_beat, healthy_since=_NOW - timedelta(hours=6))

    # One tick while it is still inside the window says nothing...
    worker.tick(now=last_beat + timedelta(seconds=settings.agent_stale_seconds - 5))
    assert _queued(settings, "agent_offline") == []

    # ...and the first one after it crosses does.
    worker.tick(now=last_beat + timedelta(seconds=settings.agent_stale_seconds + 5))
    events = _queued(settings, "agent_offline")
    assert len(events) == 1
    assert events[0]["event"]["data"]["agent_id"] == "agent-1"


def test_one_tick_announces_at_most_the_configured_number_of_agents(settings):
    """The offline sweep was the one query in this worker with no ``limit`` and
    no cursor: every quiet agent of every tenant, in one tick, outside the
    budget that bounds every other fan-out here. A fleet whose uplink drops
    would deliver the whole fleet at once."""
    settings.sla_escalation_max_findings = 2
    _subscribe(["agent_offline"])
    agents_service.configure(settings)
    quiet = [f"agent-{i}" for i in range(5)]
    for index, agent_id in enumerate(quiet):
        agents_service.register_agent(agent_id=agent_id, tenant_id="default")
        # Distinct ages, so "oldest silence first" is an order and not a tie.
        _set_last_seen(settings, agent_id, _NOW - timedelta(minutes=10 - index))
    worker = _worker(settings)

    worker.tick(now=_NOW)
    assert len(_queued(settings, "agent_offline")) == 2

    # The window walks on rather than re-reading the same two for ever: a quiet
    # agent stays quiet, so without the cursor the other three would never be
    # announced at all.
    worker.tick(now=_NOW + timedelta(minutes=15))
    worker.tick(now=_NOW + timedelta(minutes=30))
    announced = [
        item["event"]["data"]["agent_id"] for item in _queued(settings, "agent_offline")
    ]
    assert sorted(announced) == sorted(quiet)


def test_a_run_of_heartbeats_is_broken_by_a_gap_and_only_by_a_gap(settings, monkeypatch):
    """The half of the fix the worker only reads: who writes ``healthy_since``.

    Every test above ages an agent by writing both columns itself, so none of
    them exercises ``agents._note_seen`` — and a run that never restarts turns
    a flapping agent into a recovery, which is the duplicate storm this whole
    change exists to stop. So: beat, beat inside the stale window, beat after
    a longer gap, and read the column back.
    """
    agents_service.configure(settings)
    stale = settings.agent_stale_seconds
    # Naive UTC, as ``agents._now`` reads it, and driven rather than slept
    # through — the gap under test is two minutes long.
    clock = _NOW.replace(tzinfo=None)
    monkeypatch.setattr(agents_service, "_now", lambda: clock)
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")

    def _healthy_since() -> datetime:
        with get_session(settings.postgres_url) as session:
            return session.get(models.Agent, "agent-1").healthy_since

    agents_service.heartbeat("agent-1")
    assert _healthy_since() == clock

    # A beat that arrives while the previous one is still fresh continues the
    # run: the agent has been there all along.
    begun = clock
    clock = clock + timedelta(seconds=stale - 30)
    agents_service.heartbeat("agent-1")
    assert _healthy_since() == begun

    # One that arrives after a longer gap does not: the agent was away in
    # between, whatever it says now, so its run starts over.
    clock = clock + timedelta(seconds=stale + 30)
    agents_service.heartbeat("agent-1")
    assert _healthy_since() == clock


def test_a_claim_whose_fan_out_failed_is_given_back(settings, monkeypatch):
    """A marker standing for an event nobody received is worse here than
    anywhere else in this worker: an ``agent_offline`` claim is held for the
    whole episode, so a database hiccup on the fan-out would suppress the agent
    until it came back — which, for a host that died, is never."""
    _subscribe(["agent_offline"])
    agents_service.configure(settings)
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    worker = _worker(settings)
    _set_last_seen(settings, "agent-1", _NOW)
    later = _NOW + timedelta(seconds=settings.agent_stale_seconds + 60)

    def _explode(_envelope):
        raise RuntimeError("the fan-out hiccupped")

    monkeypatch.setattr(webhooks, "enqueue_event", _explode)
    worker.tick(now=later)
    assert _queued(settings, "agent_offline") == []
    assert worker.stats["agents_offline"] == 0

    monkeypatch.undo()
    worker.tick(now=later + timedelta(minutes=15))
    assert len(_queued(settings, "agent_offline")) == 1
    assert worker.stats["agents_offline"] == 1


def test_an_agent_that_came_back_briefly_and_died_for_good_is_announced_again(settings):
    """The second death has to be announced too.

    Releasing on "seen inside the stale window *at this instant*" made that
    depend on the tick landing in a 120-second window it visits every fifteen
    minutes: an agent that was genuinely back for ten minutes and then died
    stayed "already announced" for ever, and the on-call kept the event from
    two hours ago — the one they had already closed. What the release asks now
    is what was *observed*: an unbroken run, begun after the claim was taken,
    of at least twice the stale window.
    """
    _subscribe(["agent_offline"])
    agents_service.configure(settings)
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    worker = _worker(settings)
    stale = settings.agent_stale_seconds
    # A long run that ended before the claim is not a recovery, or every dead
    # agent would be released on the tick after it was announced.
    _set_last_seen(settings, "agent-1", _NOW, healthy_since=_NOW - timedelta(hours=6))

    worker.tick(now=_NOW + timedelta(seconds=stale + 60))
    worker.tick(now=_NOW + timedelta(minutes=15))
    assert len(_queued(settings, "agent_offline")) == 1
    assert worker.stats["agents_recovered"] == 0

    # It comes back twenty minutes later, beats for ten minutes, and the host
    # dies for good. No tick fell inside those ten minutes — at the default
    # interval, five times out of six none does.
    back = _NOW + timedelta(minutes=20)
    _set_last_seen(settings, "agent-1", back + timedelta(minutes=10), healthy_since=back)
    worker.tick(now=_NOW + timedelta(minutes=45))
    assert worker.stats["agents_recovered"] == 1

    worker.tick(now=_NOW + timedelta(hours=1))
    events = _queued(settings, "agent_offline")
    assert len(events) == 2
    assert events[0]["event"]["event_id"] != events[1]["event"]["event_id"]
    # Computed, not written out: _NOW follows the real clock now, so a literal
    # here would expire the way the one in accept_risk's window did.
    second_silence_began = back + timedelta(minutes=10)
    assert events[1]["event"]["data"]["last_seen_at"].startswith(
        second_silence_began.strftime("%Y-%m-%dT%H:%M")
    )


def test_a_blink_between_two_silences_is_still_one_episode(settings):
    """The other direction of the same release. Three minutes of uptime is a
    crash loop, not a recovery: below :data:`AGENT_RECOVERY_FACTOR` stale
    windows the claim stays, and the agent stays one episode however many times
    it blinks."""
    _subscribe(["agent_offline"])
    agents_service.configure(settings)
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    worker = _worker(settings)
    stale = settings.agent_stale_seconds
    _set_last_seen(settings, "agent-1", _NOW)

    worker.tick(now=_NOW + timedelta(seconds=stale + 60))
    for i in range(1, 6):
        blink = _NOW + timedelta(minutes=15 * i)
        _set_last_seen(
            settings, "agent-1", blink + timedelta(seconds=stale - 30), healthy_since=blink
        )
        worker.tick(now=blink + timedelta(minutes=10))

    assert worker.stats["agents_recovered"] == 0
    assert len(_queued(settings, "agent_offline")) == 1

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


def test_a_relay_failure_does_not_cost_the_owner_the_whole_day(settings, monkeypatch):
    """The day marker exists so a fifteen-minute tick does not mail somebody
    ninety-six times, not so that one ``421 too many connections`` at 00:07
    costs the owner their digest until tomorrow."""
    outcomes = ["SMTPException: 421 too many connections", None]
    sent: list[str] = []

    def _relay(_settings, *, to, subject, body):
        error = outcomes.pop(0) if outcomes else None
        if not error:
            sent.append(to)
        return error

    monkeypatch.setattr(sla_escalation.mail, "send_notice", _relay)
    vuln_id = _seed_finding(settings, owner_email="owner@example.com")
    _set_due(settings, vuln_id, _NOW - timedelta(days=2))
    vulns.upsert_escalation_policy(
        settings, tenant_id="default", enabled=True, digest_enabled=True, updated_by="admin"
    )
    worker = _worker(settings)

    worker.tick(now=_NOW)
    assert sent == []
    assert worker.stats["digest_failures"] == 1

    # The relay comes back a quarter of an hour later, on the same day.
    worker.tick(now=_NOW + timedelta(minutes=15))
    assert sent == ["owner@example.com"]
    # And that success is claimed: the rest of the day stays quiet.
    worker.tick(now=_NOW + timedelta(minutes=30))
    assert sent == ["owner@example.com"]


def test_the_digest_lists_what_is_overdue_and_not_only_what_this_tick_said(
    settings, monkeypatch
):
    """The digest is "what is on your plate", not a change feed.

    It is read separately from the announcement window for that reason: a
    breach announced on an earlier tick is still overdue this morning, while
    the events have already been claimed and will not be said again.
    """
    sent: list[str] = []
    monkeypatch.setattr(
        sla_escalation.mail,
        "send_notice",
        lambda _settings, *, to, subject, body: sent.append(body) or None,
    )
    _subscribe(["sla_breached"])
    first = _seed_finding(settings, owner_email="owner@example.com")
    _set_due(settings, first, _NOW - timedelta(days=3))
    second = _seed_second_finding(settings, first, _NOW - timedelta(days=1))
    vulns.upsert_escalation_policy(
        settings, tenant_id="default", enabled=True, digest_enabled=True, updated_by="admin"
    )
    # The older breach was announced yesterday, so this tick has one event to
    # send and two findings to list.
    assert workflow_events.claim(
        settings,
        tenant_id="default",
        kind="sla_breached",
        subject_id=first,
        marker=(_NOW - timedelta(days=3)).replace(tzinfo=None).isoformat(),
    ) is True

    _worker(settings).tick(now=_NOW)

    announced = [
        item["event"]["data"]["vuln_id"] for item in _queued(settings, "sla_breached")
    ]
    assert announced == [second]
    assert len(sent) == 1
    assert "CVE-2026-0001" in sent[0]
    assert "CVE-2026-0002" in sent[0]


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
