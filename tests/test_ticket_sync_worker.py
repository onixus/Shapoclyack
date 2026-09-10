"""The inbound half of two-way ticket sync (#347).

Before this, ``sync_ticket_status`` ran only when an operator clicked a button,
the outbound map was a boolean (closed / not closed), a closed Jira issue could
not be reopened at all, and a Jira Cloud token had to be hand-written into
``headers`` because the only auth scheme was ``Bearer``. Each of those is one
test below.

The worker's thread and leader lock are the report dispatcher's and are
covered there; what is specific here is *which* findings a tick considers due,
what a failing tracker does to the rest of the batch, and that the poller does
not turn "nothing changed" into an audit row per finding per tick.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import tenants as tenants_service
from api.services import vuln_states
from api.services import vulnerabilities as vulns_service
from api.services.integrations import ticket_sync, ticket_sync_worker, tickets, webhooks
from api.services.integrations.delivery import DeliveryResult
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres


# --------------------------------------------------------------------------
# auth_mode: Jira Cloud is Basic, and it used to be unreachable (no database)
# --------------------------------------------------------------------------


def test_basic_auth_mode_sends_the_pair_jira_cloud_wants():
    headers = tickets.request_headers(
        "jira", secret="soc@example.com:api-token", extra_headers=None, auth_mode="basic"
    )
    expected = base64.b64encode(b"soc@example.com:api-token").decode("ascii")
    assert headers["Authorization"] == f"Basic {expected}"


def test_bearer_stays_the_default_so_existing_subscriptions_do_not_break():
    """The knob is new; a subscription created before it must behave the same."""
    assert (
        tickets.request_headers("jira", secret="tok", extra_headers=None)["Authorization"]
        == "Bearer tok"
    )
    assert (
        tickets.request_headers("defectdojo", secret="tok", extra_headers=None)["Authorization"]
        == "Token tok"
    )


def test_basic_without_a_pair_is_refused_rather_than_guessed():
    """A lone token base64'd is a username with no password, i.e. a 401 that
    looks exactly like no credential at all."""
    with pytest.raises(tickets.TicketSpecError, match="user:token"):
        tickets.request_headers(
            "jira", secret="lonely-token", extra_headers=None, auth_mode="basic"
        )


def test_an_unknown_auth_mode_is_a_subscription_error():
    with pytest.raises(tickets.TicketSpecError, match="auth_mode"):
        tickets.validate_transport_config(
            "jira", {"project_key": "SEC", "auth_mode": "basic_auth"}
        )


def test_a_hand_written_authorization_header_still_wins():
    """The escape hatch for a tracker behind a scheme none of the modes covers."""
    headers = tickets.request_headers(
        "jira",
        secret="tok",
        extra_headers={"Authorization": "Negotiate abc"},
        auth_mode="basic",
    )
    assert headers["Authorization"] == "Negotiate abc"


def test_the_per_subscription_cadence_is_validated_and_floored():
    cfg = tickets.validate_transport_config(
        "jira", {"project_key": "SEC", "sync_interval_seconds": 3600}
    )
    assert cfg["sync_interval_seconds"] == 3600
    # 0 means "platform default", which is not the same as "every second".
    assert (
        tickets.validate_transport_config("jira", {"project_key": "SEC"})[
            "sync_interval_seconds"
        ]
        == 0
    )
    with pytest.raises(tickets.TicketSpecError, match="sync_interval_seconds"):
        tickets.validate_transport_config(
            "jira", {"project_key": "SEC", "sync_interval_seconds": 5}
        )


# --------------------------------------------------------------------------
# The outbound map is no longer a boolean (no database)
# --------------------------------------------------------------------------


def _jira_pusher(available: list[dict[str, str]]) -> tuple[list, callable]:
    seen: list[tuple[str, bytes]] = []

    def fake_request(method, url, body, headers, **kwargs):
        seen.append((method, body))
        if method == "GET":
            return DeliveryResult(
                ok=True,
                status_code=200,
                error=None,
                retryable=False,
                body=json.dumps({"transitions": available}),
            )
        return DeliveryResult(ok=True, status_code=200, error=None, retryable=False)

    return seen, fake_request


def test_a_closed_jira_issue_is_reopened_instead_of_silently_ignored():
    """The reopen was the loudest gap: a Done issue offers "Reopen", the code
    only ever asked for "In Progress", and the failure was an info log."""
    seen, fake_request = _jira_pusher([{"id": "41", "name": "Reopen"}])

    assert ticket_sync.push_status_update(
        transport="jira",
        base_url="https://jira.example.com",
        ticket_key="SEC-1",
        to_state=vuln_states.OPEN,
        request_fn=fake_request,
    )
    assert json.loads(seen[-1][1]) == {"transition": {"id": "41"}}


def test_acknowledged_does_not_tell_the_assignee_work_has_started():
    """Every non-CLOSED state used to push "In Progress"."""
    seen, fake_request = _jira_pusher(
        [{"id": "11", "name": "In Progress"}, {"id": "21", "name": "Triage"}]
    )

    assert ticket_sync.push_status_update(
        transport="jira",
        base_url="https://jira.example.com",
        ticket_key="SEC-1",
        to_state=vuln_states.ACKNOWLEDGED,
        request_fn=fake_request,
    )
    assert json.loads(seen[-1][1]) == {"transition": {"id": "21"}}


def test_servicenow_gets_a_state_per_lifecycle_state_not_two():
    def fake_request(method, url, body, headers, **kwargs):
        if method == "GET":
            return DeliveryResult(
                ok=True,
                status_code=200,
                error=None,
                retryable=False,
                body=json.dumps({"result": [{"sys_id": "abc123"}]}),
            )
        seen.append(json.loads(body))
        return DeliveryResult(ok=True, status_code=200, error=None, retryable=False)

    seen: list[dict] = []
    for state, expected in (
        (vuln_states.OPEN, "1"),
        (vuln_states.PLANNED, "3"),
        (vuln_states.FIXING, "2"),
        (vuln_states.CLOSED, "6"),
    ):
        assert ticket_sync.push_status_update(
            transport="servicenow",
            base_url="https://snow.example.com",
            ticket_key="INC001",
            to_state=state,
            request_fn=fake_request,
        )
        assert seen[-1]["incident_state"] == expected, state


def test_a_finding_under_verification_is_not_pulled_back_out_of_it():
    """No tracker has a "we are re-scanning" state, and every name that comes
    close reads back as FIXING — which is a legal move out of VERIFYING, so
    pushing one would end the verification the finding is waiting on. Asserted
    through the mapper rather than by "the key is absent", which would pass on
    an empty table."""
    for transport, state, _pushed, read_back in _round_trip_pairs():
        if state != vuln_states.VERIFYING:
            continue
        assert read_back in (None, vuln_states.VERIFYING), transport
    assert vuln_states.VERIFYING not in ticket_sync.SNOW_PUSH_STATE
    assert vuln_states.VERIFYING not in ticket_sync.DEFECTDOJO_PUSH_FLAGS
    assert vuln_states.VERIFYING not in ticket_sync.JIRA_TRANSITIONS


def _round_trip_pairs():
    """Every ``(transport, state, pushed, read_back)`` the outbound maps allow.

    Built through the real inbound mapper rather than by indexing the inbound
    tables, so a tracker payload shape that the mapper treats specially — as
    DefectDojo's flags are — is covered the same way as a status name.
    """
    for state, statuses in ticket_sync.JIRA_TRANSITIONS.items():
        for name in statuses:
            read_back, _ = ticket_sync.map_remote_status_to_vuln_state(
                "jira", {"fields": {"status": {"name": name}}}
            )
            yield "jira", state, name, read_back
    for state, incident_state in ticket_sync.SNOW_PUSH_STATE.items():
        read_back, _ = ticket_sync.map_remote_status_to_vuln_state(
            "servicenow", {"result": [{"incident_state": incident_state}]}
        )
        yield "servicenow", state, incident_state, read_back
    for state, flags in ticket_sync.DEFECTDOJO_PUSH_FLAGS.items():
        read_back, _ = ticket_sync.map_remote_status_to_vuln_state("defectdojo", dict(flags))
        yield "defectdojo", state, str(flags), read_back


def test_what_we_push_cannot_be_read_back_as_a_move_nobody_asked_for():
    """Round-trip stability, the property that keeps the two directions from
    oscillating: the state a tracker reports after our push must be the state
    the finding is already in, one it cannot legally move to, or nothing at all.

    Asserted over all three maps. Checking only ServiceNow — the one map that
    happened to satisfy it — hid seven violations: Jira's default
    ``To Do / In Progress / Done`` workflow read `ACKNOWLEDGED` back as
    `PLANNED`, `VERIFYING` back as `FIXING`, and DefectDojo read every
    not-closed state back as `FIXING`.
    """
    for transport, state, pushed, read_back in _round_trip_pairs():
        assert (
            read_back is None
            or read_back == state
            or not vuln_states.can_transition(state, read_back)
        ), (
            f"pushing {state} to {transport} as {pushed!r} reads back as "
            f"{read_back}, which the next poll would apply"
        )


# --------------------------------------------------------------------------
# The worker (Postgres)
# --------------------------------------------------------------------------

pytestmark_pg = requires_postgres


@pytest.fixture()
def settings(tmp_path: Path):
    s = make_settings(tmp_path)
    tenants_service.configure(s)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(s)
    webhooks.configure(s)
    webhooks.reset_for_tests()
    return s


def _link(settings, *, vuln_id: str, ticket_key: str, state: str = vuln_states.OPEN, **columns):
    """One tracked finding with a linked ticket, on a shared asset."""
    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        if session.get(models.Asset, "asset-sync") is None:
            session.add(
                models.Asset(
                    asset_id="asset-sync",
                    tenant_id="default",
                    status="active",
                    first_seen=now,
                    last_seen=now,
                )
            )
            session.flush()
        session.add(
            models.Vulnerability(
                vuln_id=vuln_id,
                tenant_id="default",
                asset_id="asset-sync",
                finding_key=vulns_service.finding_key(
                    asset_id="asset-sync", cve=vuln_id, script_id=None, port="443"
                ),
                cve=vuln_id.upper(),
                port="443",
                title=vuln_id,
                severity="high",
                state=state,
                state_changed_at=now,
                first_seen_at=now,
                last_seen_at=now,
                sla_started_at=now,
                created_at=now,
                updated_at=now,
                ticket_system="jira",
                ticket_key=ticket_key,
                **columns,
            )
        )


def _subscription(settings, **config):
    return webhooks.create_subscription(
        tenant_id="default",
        name="jira-soc",
        url="https://jira.example.com",
        transport="jira",
        transport_config={"project_key": "SEC", **config},
        secret="jira-token",
        created_by="admin",
    )


def _jira_status(name: str):
    def fake_request(method, url, body, headers, **kwargs):
        return DeliveryResult(
            ok=True,
            status_code=200,
            error=None,
            retryable=False,
            body=json.dumps({"fields": {"status": {"name": name}}}),
        )

    return fake_request


def _events(settings, vuln_id: str, kind: str) -> list[int]:
    with get_session(settings.postgres_url) as session:
        return [
            int(row.id)
            for row in session.scalars(
                select(models.VulnerabilityEvent).where(
                    models.VulnerabilityEvent.vuln_id == vuln_id,
                    models.VulnerabilityEvent.kind == kind,
                )
            ).all()
        ]


@requires_postgres
def test_a_linked_finding_is_due_and_stops_being_due_once_read(settings):
    """The defect itself: nothing read a ticket back unless a human clicked."""
    _subscription(settings)
    _link(settings, vuln_id="vln_due", ticket_key="SEC-1", state=vuln_states.PLANNED)
    worker = ticket_sync_worker.TicketSyncWorker(
        settings=settings, request_fn=_jira_status("To Do")
    )

    due = ticket_sync_worker.due_findings(
        settings, tenant_id="default", transport="jira", cutoff=datetime.now(UTC), limit=10
    )
    assert [item["vuln_id"] for item in due] == ["vln_due"]

    worker.tick()

    assert worker.stats["polled"] == 1
    row = vulns_service.get_vulnerability(settings, tenant_id="default", vuln_id="vln_due")
    # A read that agrees with the row is a read, not a transition.
    assert row["state"] == vuln_states.PLANNED
    assert row["ticket_remote_status"] == "To Do"
    assert (
        ticket_sync_worker.due_findings(
            settings,
            tenant_id="default",
            transport="jira",
            cutoff=datetime.now(UTC) - timedelta(seconds=900),
            limit=10,
        )
        == []
    )


@requires_postgres
def test_the_tracker_closes_the_finding_as_ticket_resolved(settings):
    _subscription(settings)
    _link(settings, vuln_id="vln_done", ticket_key="SEC-2", state=vuln_states.FIXING)

    ticket_sync_worker.TicketSyncWorker(
        settings=settings, request_fn=_jira_status("Done")
    ).tick()

    row = vulns_service.get_vulnerability(settings, tenant_id="default", vuln_id="vln_done")
    assert row["state"] == vuln_states.CLOSED
    assert row["closure_reason"] == "ticket_resolved"
    # A tracker cannot assert a verified fix, whatever it says.
    assert row["machine_verified"] is False
    assert row["ticket_remote_status"] == "Done"
    assert row["ticket_synced_at"] is not None


@requires_postgres
def test_an_unchanged_ticket_writes_no_audit_row(settings, monkeypatch):
    """One poll per finding per interval times one event per poll is a table
    that grows forever to record that nothing happened. The button still
    records — an operator asked, and "I checked and it still says Open" is
    exactly what the trail is for."""
    _subscription(settings)
    _link(settings, vuln_id="vln_quiet", ticket_key="SEC-3")

    # "Open" maps to the state the finding is already in, so the poll agrees
    # with the row and there is nothing to record.
    ticket_sync_worker.TicketSyncWorker(
        settings=settings, request_fn=_jira_status("Open")
    ).tick()
    assert _events(settings, "vln_quiet", "ticket_synced") == []

    monkeypatch.setattr(
        ticket_sync, "fetch_ticket_status", lambda **kwargs: (vuln_states.OPEN, "Open", {})
    )
    vulns_service.sync_ticket_status(
        settings, tenant_id="default", vuln_id="vln_quiet", actor="operator"
    )
    assert len(_events(settings, "vln_quiet", "ticket_synced")) == 1


@requires_postgres
def test_a_verified_closure_is_never_re_polled_but_a_ticket_closure_is(settings):
    """The reopen path has to stay open, and the queue has to stay bounded."""
    _subscription(settings)
    closed_at = datetime.now(UTC).replace(tzinfo=None)
    _link(
        settings,
        vuln_id="vln_verified",
        ticket_key="SEC-4",
        state=vuln_states.CLOSED,
        closure_reason="verified_remediated",
        machine_verified=True,
        closed_at=closed_at,
    )
    _link(
        settings,
        vuln_id="vln_by_ticket",
        ticket_key="SEC-5",
        state=vuln_states.CLOSED,
        closure_reason="ticket_resolved",
        closed_at=closed_at,
    )

    due = ticket_sync_worker.due_findings(
        settings, tenant_id="default", transport="jira", cutoff=datetime.now(UTC), limit=10
    )
    assert [item["vuln_id"] for item in due] == ["vln_by_ticket"]


@requires_postgres
def test_the_subscription_cadence_overrides_the_platform_default(settings):
    _subscription(settings, sync_interval_seconds=3600)
    _link(settings, vuln_id="vln_slow", ticket_key="SEC-6")
    worker = ticket_sync_worker.TicketSyncWorker(
        settings=settings, request_fn=_jira_status("To Do")
    )

    worker.tick()
    assert worker.stats["polled"] == 1

    # 15 minutes later the platform default (900s) would poll again; this
    # subscription asked for an hour.
    worker.tick(now=datetime.now(UTC) + timedelta(minutes=15))
    assert worker.stats["polled"] == 1


@requires_postgres
def test_a_tracker_that_is_down_is_asked_once_not_once_per_finding(settings):
    """The whole subscription backs off. Burning the batch at one futile
    request each, every tick, is how an outage becomes an outbound flood."""
    _subscription(settings)
    for index in range(4):
        _link(settings, vuln_id=f"vln_out_{index}", ticket_key=f"SEC-1{index}")
    calls: list[str] = []

    def unreachable(method, url, body, headers, **kwargs):
        calls.append(url)
        return DeliveryResult(
            ok=False, status_code=503, error="HTTP 503", retryable=True, body=None
        )

    worker = ticket_sync_worker.TicketSyncWorker(settings=settings, request_fn=unreachable)

    worker.tick()
    assert len(calls) == 1
    assert worker.stats["failed"] == 1
    first_lag = worker.stats["lag_seconds"]

    # The next tick does not ask again, and the lag it reports keeps growing:
    # a held-off subscription is exactly the one an operator needs to see, so
    # reporting 0 for it would silence the metric in the one case it exists for.
    worker.tick(now=datetime.now(UTC) + timedelta(seconds=60))
    assert len(calls) == 1
    assert worker.stats["skipped_backoff"] == 1
    assert worker.stats["lag_seconds"] >= first_lag + 55

    # Past the backoff, it is retried.
    worker.tick(now=datetime.now(UTC) + timedelta(seconds=300))
    assert len(calls) == 2


@requires_postgres
def test_one_unreadable_ticket_does_not_silence_the_rest(settings):
    """A 404 is that ticket's problem — a renamed key, a deleted issue — and it
    is recorded on the row rather than stopping the sweep."""
    _subscription(settings)
    _link(settings, vuln_id="vln_gone", ticket_key="SEC-404")
    _link(settings, vuln_id="vln_fine", ticket_key="SEC-200")

    def mixed(method, url, body, headers, **kwargs):
        if "SEC-404" in url:
            return DeliveryResult(
                ok=False, status_code=404, error="HTTP 404", retryable=False, body=None
            )
        return DeliveryResult(
            ok=True,
            status_code=200,
            error=None,
            retryable=False,
            body=json.dumps({"fields": {"status": {"name": "Done"}}}),
        )

    worker = ticket_sync_worker.TicketSyncWorker(settings=settings, request_fn=mixed)

    worker.tick()

    assert worker.stats["polled"] == 2
    assert worker.stats["skipped_backoff"] == 0
    broken = vulns_service.get_vulnerability(
        settings, tenant_id="default", vuln_id="vln_gone"
    )
    assert broken["ticket_sync_error"] == "HTTP 404"
    assert broken["state"] == vuln_states.OPEN
    healthy = vulns_service.get_vulnerability(
        settings, tenant_id="default", vuln_id="vln_fine"
    )
    assert healthy["state"] == vuln_states.CLOSED
    assert healthy["ticket_sync_error"] is None


@requires_postgres
def test_the_poller_does_not_overrule_an_operator_every_interval(settings):
    """The worst shape this feature can take: an operator reopens a finding
    whose Jira issue is still Done — the normal case, because the outbound push
    cannot reopen an issue whose workflow has no reopen step — and the poller
    closes it again on the next tick, and every tick after that, so the finding
    cannot be held open without editing somebody else's Jira."""
    _subscription(settings)
    _link(settings, vuln_id="vln_fight", ticket_key="SEC-8", state=vuln_states.FIXING)
    worker = ticket_sync_worker.TicketSyncWorker(
        settings=settings, request_fn=_jira_status("Done")
    )

    worker.tick()
    assert (
        vulns_service.get_vulnerability(settings, tenant_id="default", vuln_id="vln_fight")[
            "state"
        ]
        == vuln_states.CLOSED
    )

    # The operator disagrees. Jira still says Done and nothing over there moved.
    vulns_service.transition(
        settings,
        tenant_id="default",
        vuln_id="vln_fight",
        to_state=vuln_states.OPEN,
        actor="operator",
    )

    for minutes in (20, 40, 60):
        worker.tick(now=datetime.now(UTC) + timedelta(minutes=minutes))
    row = vulns_service.get_vulnerability(settings, tenant_id="default", vuln_id="vln_fight")
    assert row["state"] == vuln_states.OPEN
    assert row["state_changed_by"] == "operator"

    # ...but a tracker that genuinely moves is still obeyed.
    worker._request_fn = _jira_status("In Progress")  # noqa: SLF001
    worker.tick(now=datetime.now(UTC) + timedelta(minutes=80))
    assert (
        vulns_service.get_vulnerability(settings, tenant_id="default", vuln_id="vln_fight")[
            "state"
        ]
        == vuln_states.FIXING
    )


@requires_postgres
def test_the_button_takes_the_trackers_current_word_even_when_it_has_not_moved(
    settings, monkeypatch
):
    """The counterpart: `only_on_remote_change` is the poller's rule, not a
    property of the reconciliation. A person clicking Sync is asking for the
    tracker's word whatever it is."""
    _subscription(settings)
    _link(settings, vuln_id="vln_button", ticket_key="SEC-9", state=vuln_states.FIXING)
    ticket_sync_worker.TicketSyncWorker(
        settings=settings, request_fn=_jira_status("Done")
    ).tick()
    vulns_service.transition(
        settings,
        tenant_id="default",
        vuln_id="vln_button",
        to_state=vuln_states.OPEN,
        actor="operator",
    )

    monkeypatch.setattr(
        ticket_sync, "fetch_ticket_status", lambda **kwargs: (vuln_states.CLOSED, "Done", {})
    )
    after = vulns_service.sync_ticket_status(
        settings, tenant_id="default", vuln_id="vln_button", actor="operator"
    )
    assert after["state"] == vuln_states.CLOSED


@requires_postgres
def test_a_ticket_driven_closure_leaves_the_queue_after_the_reopen_window(settings):
    """Closed findings have to stay pollable for the reopen path to exist, and
    have to leave eventually: a year of them fills the batch ahead of the
    findings somebody is working on, at one GET each against a tracker that
    belongs to somebody else."""
    _subscription(settings)
    _link(
        settings,
        vuln_id="vln_old_closure",
        ticket_key="SEC-10",
        state=vuln_states.CLOSED,
        closure_reason="ticket_resolved",
        closed_at=datetime.now(UTC).replace(tzinfo=None) - timedelta(days=90),
    )

    assert (
        ticket_sync_worker.due_findings(
            settings,
            tenant_id="default",
            transport="jira",
            cutoff=datetime.now(UTC),
            limit=10,
            reopen_window_days=30,
        )
        == []
    )
    assert [
        item["vuln_id"]
        for item in ticket_sync_worker.due_findings(
            settings,
            tenant_id="default",
            transport="jira",
            cutoff=datetime.now(UTC),
            limit=10,
            reopen_window_days=365,
        )
    ] == ["vln_old_closure"]


@requires_postgres
def test_a_basic_secret_that_is_not_a_pair_is_recorded_and_not_a_traceback(settings):
    """The one misconfiguration only the request can discover. Left to
    propagate it aborted the whole tick with a traceback, wrote nothing to any
    row, and left `ticket_sync_error` — which the runbook tells operators to
    read — empty."""
    _subscription(settings, auth_mode="basic")
    _link(settings, vuln_id="vln_badauth", ticket_key="SEC-11")
    calls: list[str] = []

    def never_called(method, url, body, headers, **kwargs):
        calls.append(url)
        raise AssertionError("no request should be attempted")

    worker = ticket_sync_worker.TicketSyncWorker(settings=settings, request_fn=never_called)
    worker.tick()

    assert calls == []
    assert worker.stats["errors"] == 0
    assert worker.stats["failed"] == 1
    row = vulns_service.get_vulnerability(
        settings, tenant_id="default", vuln_id="vln_badauth"
    )
    assert "user:token" in (row["ticket_sync_error"] or "")


@requires_postgres
def test_relinking_or_unlinking_clears_the_previous_links_sync_error(settings):
    """The documented fix for a 404 is to re-link or clear the ticket
    (docs/operations.md). Without this the row kept the old error, the console
    kept rendering "Last read failed: HTTP 404" — on a finding that no longer
    has a ticket at all — and there was no poll coming to clear it."""
    _subscription(settings)
    _link(settings, vuln_id="vln_relink", ticket_key="SEC-404")

    def gone(method, url, body, headers, **kwargs):
        return DeliveryResult(
            ok=False, status_code=404, error="HTTP 404", retryable=False, body=None
        )

    ticket_sync_worker.TicketSyncWorker(settings=settings, request_fn=gone).tick()
    assert (
        vulns_service.get_vulnerability(settings, tenant_id="default", vuln_id="vln_relink")[
            "ticket_sync_error"
        ]
        == "HTTP 404"
    )

    relinked = vulns_service.set_ticket(
        settings,
        tenant_id="default",
        vuln_id="vln_relink",
        system="jira",
        key="SEC-405",
        url=None,
        actor="operator",
    )
    assert relinked["ticket_sync_error"] is None
    assert relinked["ticket_synced_at"] is None

    ticket_sync_worker.TicketSyncWorker(settings=settings, request_fn=gone).tick()
    cleared = vulns_service.clear_ticket(
        settings, tenant_id="default", vuln_id="vln_relink", actor="operator"
    )
    assert cleared["ticket_sync_error"] is None


@requires_postgres
def test_another_tenants_tracker_is_not_polled_through_this_subscription(settings):
    """Tenant scope is the subscription, as it is for the manual button."""
    _subscription(settings)
    _link(settings, vuln_id="vln_mine", ticket_key="SEC-7")

    assert (
        ticket_sync_worker.due_findings(
            settings,
            tenant_id="other",
            transport="jira",
            cutoff=datetime.now(UTC),
            limit=10,
        )
        == []
    )


@requires_postgres
def test_the_route_refuses_a_misconfigured_auth_mode_or_cadence(tmp_path, monkeypatch):
    """422 at the subscription, rather than a tracker answering 401 forever for
    a reason nothing in the console explains."""
    client = configured_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    body = {
        "name": "jira-cloud",
        "url": "https://jira.example.com",
        "transport": "jira",
        "transport_config": {"project_key": "SEC", "auth_mode": "basic_auth"},
        "secret": "soc@example.com:tok",
    }

    refused = client.post("/api/webhooks", json=body, headers=admin)
    assert refused.status_code == 422
    assert "auth_mode" in refused.json()["detail"]

    body["transport_config"] = {"project_key": "SEC", "sync_interval_seconds": 5}
    too_fast = client.post("/api/webhooks", json=body, headers=admin)
    assert too_fast.status_code == 422
    assert "sync_interval_seconds" in too_fast.json()["detail"]

    body["transport_config"] = {"project_key": "SEC", "auth_mode": "basic"}
    created = client.post("/api/webhooks", json=body, headers=admin)
    assert created.status_code == 201
    assert created.json()["transport_config"]["auth_mode"] == "basic"
