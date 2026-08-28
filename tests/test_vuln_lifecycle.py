"""Vulnerability lifecycle, SLA and audit trail (#145).

Split in two: the state machine and the SLA arithmetic are pure and run
everywhere, while anything that stores a finding needs the Postgres the rest of
the suite needs (``requires_postgres``).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from api.services import vuln_states
from api.services import vulnerabilities as vulns
from tests.conftest import POSTGRES_URL, requires_postgres


# --------------------------------------------------------------------------
# State machine
# --------------------------------------------------------------------------


def test_happy_path_is_legal_end_to_end():
    chain = [
        vuln_states.OPEN,
        vuln_states.ACKNOWLEDGED,
        vuln_states.PLANNED,
        vuln_states.FIXING,
        vuln_states.VERIFYING,
        vuln_states.CLOSED,
    ]
    for current, following in zip(chain, chain[1:]):
        assert vuln_states.can_transition(current, following), f"{current} → {following}"


def test_same_state_move_is_refused():
    """A double-clicked button must not write a second audit entry."""
    for state in vuln_states.ALL:
        assert not vuln_states.can_transition(state, state)
    with pytest.raises(vuln_states.InvalidVulnTransition):
        vuln_states.check_transition("vln_1", vuln_states.FIXING, vuln_states.FIXING)


def test_closed_is_not_terminal_but_only_reopens():
    assert vuln_states.can_transition(vuln_states.CLOSED, vuln_states.OPEN)
    for state in (vuln_states.ACKNOWLEDGED, vuln_states.PLANNED, vuln_states.FIXING):
        assert not vuln_states.can_transition(vuln_states.CLOSED, state)


def test_open_is_only_reachable_from_closed():
    """OPEN means "nobody has looked at this yet" — nothing triaged goes back."""
    for state, targets in vuln_states.TRANSITIONS.items():
        if vuln_states.OPEN in targets:
            assert state == vuln_states.CLOSED


def test_false_positive_can_be_closed_from_open():
    assert vuln_states.can_transition(vuln_states.OPEN, vuln_states.CLOSED)


def test_verification_failure_goes_back_to_fixing():
    assert vuln_states.can_transition(vuln_states.VERIFYING, vuln_states.FIXING)


def test_unknown_state_is_rejected():
    with pytest.raises(vuln_states.InvalidVulnTransition):
        vuln_states.check_transition("vln_1", vuln_states.OPEN, "WONTFIX")


def test_active_is_everything_but_closed():
    assert vuln_states.ACTIVE == vuln_states.ALL - {vuln_states.CLOSED}


# --------------------------------------------------------------------------
# Identity and SLA arithmetic
# --------------------------------------------------------------------------


def test_finding_key_is_stable_and_scoped():
    key = dict(asset_id="asset-1", cve="CVE-2024-1", script_id=None, port="443")
    assert vulns.finding_key(**key) == vulns.finding_key(**key)
    # Case and whitespace in the CVE are not a different finding.
    assert vulns.finding_key(**{**key, "cve": " cve-2024-1 "}) == vulns.finding_key(**key)
    # Every part of the triple participates.
    assert vulns.finding_key(**{**key, "port": "80"}) != vulns.finding_key(**key)
    assert vulns.finding_key(**{**key, "asset_id": "asset-2"}) != vulns.finding_key(**key)


def test_finding_key_falls_back_to_script_id():
    """Exposure/nuclei findings have no CVE, so the script is the identity."""
    a = vulns.finding_key(asset_id="a", cve=None, script_id="ssl-expired", port="443")
    b = vulns.finding_key(asset_id="a", cve=None, script_id="ssl-weak-cipher", port="443")
    assert a != b


def _row(**overrides):
    base = {"state": vuln_states.OPEN, "due_at": None, "exception_until": None}
    return {**base, **overrides}


def test_sla_state_readings():
    now = datetime(2026, 8, 17, 12, 0, 0)
    assert vulns.sla_state(_row(due_at=now + timedelta(days=60)), now=now) == "on_track"
    assert vulns.sla_state(_row(due_at=now + timedelta(days=3)), now=now) == "due_soon"
    assert vulns.sla_state(_row(due_at=now - timedelta(days=1)), now=now) == "breached"
    assert vulns.sla_state(_row(due_at=now), now=now) == "breached"
    # Closed findings have no deadline to read, whatever due_at still says.
    assert vulns.sla_state(_row(state=vuln_states.CLOSED, due_at=now), now=now) == "none"


def test_accepted_risk_reads_as_accepted_not_on_track():
    now = datetime(2026, 8, 17, 12, 0, 0)
    row = _row(due_at=now + timedelta(days=30), exception_until=now + timedelta(days=30))
    assert vulns.sla_state(row, now=now) == "accepted"


def test_expired_acceptance_stops_suspending_the_clock():
    """The point of an expiry: the finding comes back into the breach report."""
    now = datetime(2026, 8, 17, 12, 0, 0)
    row = _row(due_at=now - timedelta(days=1), exception_until=now - timedelta(days=1))
    assert vulns.sla_state(row, now=now) == "breached"


def test_sla_state_accepts_iso_strings_and_aware_datetimes():
    """``summary`` passes rows straight from SQL; the API passes serialised ones."""
    now = datetime(2026, 8, 17, 12, 0, 0)
    aware = (now + timedelta(days=60)).replace(tzinfo=UTC)
    assert vulns.sla_state(_row(due_at=aware), now=now) == "on_track"
    assert vulns.sla_state(_row(due_at="2026-10-16T12:00:00Z"), now=now) == "on_track"


def test_default_sla_days_are_strictest_for_critical():
    days = vulns.DEFAULT_SLA_DAYS
    assert days["critical"] < days["high"] < days["medium"] < days["low"]


# --------------------------------------------------------------------------
# Storage: observation, transitions, audit
# --------------------------------------------------------------------------


def _write_run(output_dir: Path, run_id: str, hosts: list[dict], findings: list[dict]) -> None:
    run_dir = output_dir / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "alive_hosts.json").write_text(json.dumps(hosts), encoding="utf-8")
    (run_dir / "vulnerabilities.json").write_text(json.dumps(findings), encoding="utf-8")


def _settings(tmp_path: Path):
    from api.services import tenants as tenants_service
    from api.settings import Settings

    settings = Settings(
        output_dir=tmp_path / "output",
        state_dir=tmp_path / "state",
        postgres_url=POSTGRES_URL,
    )
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(settings)
    return settings


_HOSTS = [{"host": "10.0.0.5", "hostname": "app.example.com"}]
_FINDINGS = [
    {"host": "10.0.0.5", "port": "443", "cve": "CVE-2024-0001", "cvss": 9.8, "severity": "critical"},
    {"host": "10.0.0.5", "port": "80", "cve": "CVE-2024-0002", "cvss": 5.0, "severity": "medium"},
]


def _seed(tmp_path: Path, run_id: str = "run-1", findings: list[dict] | None = None):
    from api.services import assets as assets_service
    from api.services import tenants as tenants_service

    settings = _settings(tmp_path)
    tenant_id = tenants_service.DEFAULT_TENANT_ID
    _write_run(settings.output_dir, run_id, _HOSTS, findings if findings is not None else _FINDINGS)
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id=run_id)
    return settings, tenant_id


@requires_postgres
def test_registering_a_run_creates_tracked_findings(tmp_path):
    settings, tenant_id = _seed(tmp_path)

    stats = vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")

    assert (stats.created, stats.reobserved, stats.reopened) == (2, 0, 0)
    items, total = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)
    assert total == 2
    assert {item["state"] for item in items} == {vuln_states.OPEN}
    critical = next(item for item in items if item["severity"] == "critical")
    assert critical["due_at"] is not None
    assert critical["sla_days"] == vulns.DEFAULT_SLA_DAYS["critical"]
    assert critical["sla_source"] == "default"
    assert critical["observation_count"] == 1


@requires_postgres
def test_re_registering_the_same_run_is_idempotent(tmp_path):
    """Both job-completion paths can be retried; identity is the finding."""
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")

    stats = vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")

    assert (stats.created, stats.reobserved) == (0, 2)
    _, total = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)
    assert total == 2


@requires_postgres
def test_a_later_run_updates_the_same_row(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")

    _write_run(settings.output_dir, "run-2", _HOSTS, _FINDINGS)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-2")

    items, total = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)
    assert total == 2
    assert all(item["last_seen_run_id"] == "run-2" for item in items)
    assert all(item["first_seen_run_id"] == "run-1" for item in items)
    assert all(item["observation_count"] == 2 for item in items)


@requires_postgres
def test_findings_that_stop_being_observed_are_not_auto_closed(tmp_path):
    """Absence is a scanning outcome, not a fix. It shows as staleness instead."""
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")

    _write_run(settings.output_dir, "run-2", _HOSTS, [_FINDINGS[0]])
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-2")

    items, _ = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)
    gone = next(item for item in items if item["cve"] == "CVE-2024-0002")
    assert gone["state"] == vuln_states.OPEN
    assert gone["last_seen_run_id"] == "run-1"


@requires_postgres
def test_transitions_are_audited_and_illegal_ones_raise(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    items, _ = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)
    vuln_id = items[0]["vuln_id"]

    vulns.transition(
        settings,
        tenant_id=tenant_id,
        vuln_id=vuln_id,
        to_state=vuln_states.ACKNOWLEDGED,
        actor="operator",
        note="triaged",
    )
    row = vulns.transition(
        settings,
        tenant_id=tenant_id,
        vuln_id=vuln_id,
        to_state=vuln_states.FIXING,
        actor="operator",
    )
    assert row["state"] == vuln_states.FIXING
    assert row["state_changed_by"] == "operator"

    with pytest.raises(vuln_states.InvalidVulnTransition):
        vulns.transition(
            settings, tenant_id=tenant_id, vuln_id=vuln_id, to_state=vuln_states.OPEN
        )

    events, total = vulns.list_events(settings, tenant_id=tenant_id, vuln_id=vuln_id)
    kinds = [event["kind"] for event in events]
    assert kinds.count("state_change") == 2
    assert "observed" in kinds
    triage = next(event for event in events if event["to_state"] == vuln_states.ACKNOWLEDGED)
    assert (triage["actor"], triage["note"]) == ("operator", "triaged")
    # The observation carries no actor: the platform saw it, nobody said it.
    assert next(event for event in events if event["kind"] == "observed")["actor"] is None
    assert total == len(events)


@requires_postgres
def test_a_closed_finding_that_comes_back_is_reopened_with_a_fresh_clock(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    items, _ = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)
    vuln_id = items[0]["vuln_id"]
    closed = vulns.transition(
        settings, tenant_id=tenant_id, vuln_id=vuln_id, to_state=vuln_states.CLOSED, actor="admin"
    )
    assert closed["closed_at"] is not None
    first_due = closed["due_at"]

    _write_run(settings.output_dir, "run-2", _HOSTS, _FINDINGS)
    stats = vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-2")

    assert stats.reopened == 1
    row = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln_id)
    assert row["state"] == vuln_states.OPEN
    assert row["closed_at"] is None
    assert row["reopen_count"] == 1
    # The clock restarted: the deadline for something that came back is not
    # measured from before it was fixed.
    assert row["due_at"] > first_due
    events, _ = vulns.list_events(settings, tenant_id=tenant_id, vuln_id=vuln_id)
    assert any(event["kind"] == "reopened" for event in events)


@requires_postgres
def test_sla_policy_beats_the_default_and_criticality_beats_the_fallback(tmp_path):
    from api.services import assets as assets_service

    settings, tenant_id = _seed(tmp_path)
    vulns.upsert_sla_policy(
        settings, tenant_id=tenant_id, severity="critical", remediation_days=45
    )
    vulns.upsert_sla_policy(
        settings,
        tenant_id=tenant_id,
        severity="critical",
        remediation_days=2,
        asset_criticality=4,
    )
    items, _ = assets_service.list_assets(settings, tenant_id)
    asset_id = items[0]["asset_id"]

    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    critical, _ = vulns.list_vulnerabilities(settings, tenant_id=tenant_id, severity="critical")
    assert critical[0]["sla_days"] == 45  # tenant fallback, asset has no criticality
    assert critical[0]["sla_source"] == "policy"

    # Now the asset is business-critical, and the narrower scope wins.
    assets_service.update_asset(settings, tenant_id, asset_id, {"asset_criticality": 4})
    _write_run(settings.output_dir, "run-2", _HOSTS, _FINDINGS)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-2")
    reopened, _ = vulns.list_vulnerabilities(settings, tenant_id=tenant_id, severity="critical")
    # Re-observation does not re-date an existing finding's deadline; the policy
    # applies to findings discovered from now on.
    assert reopened[0]["sla_days"] == 45

    _write_run(settings.output_dir, "run-3", _HOSTS, [
        {"host": "10.0.0.5", "port": "8443", "cve": "CVE-2024-0003", "cvss": 9.9, "severity": "critical"}
    ])
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-3")
    fresh = next(
        item
        for item in vulns.list_vulnerabilities(settings, tenant_id=tenant_id)[0]
        if item["cve"] == "CVE-2024-0003"
    )
    assert fresh["sla_days"] == 2


@requires_postgres
def test_upserting_a_policy_scope_edits_it_rather_than_duplicating(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    first = vulns.upsert_sla_policy(
        settings, tenant_id=tenant_id, severity="high", remediation_days=30
    )
    second = vulns.upsert_sla_policy(
        settings, tenant_id=tenant_id, severity="high", remediation_days=14
    )
    assert first["policy_id"] == second["policy_id"]
    policies = vulns.list_sla_policies(settings, tenant_id=tenant_id)
    assert len(policies) == 1
    assert policies[0]["remediation_days"] == 14


@requires_postgres
def test_exception_suspends_the_clock_and_clearing_it_does_not_restart_it(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    items, _ = vulns.list_vulnerabilities(settings, tenant_id=tenant_id, severity="critical")
    vuln_id = items[0]["vuln_id"]
    original_due = items[0]["due_at"]

    accepted = vulns.set_exception(
        settings,
        tenant_id=tenant_id,
        vuln_id=vuln_id,
        until=datetime.now(UTC) + timedelta(days=180),
        reason="vendor patch scheduled for Q4",
        actor="admin",
    )
    assert accepted["sla_state"] == "accepted"
    assert accepted["sla_source"] == "exception"
    assert accepted["due_at"] > original_due

    cleared = vulns.clear_exception(
        settings, tenant_id=tenant_id, vuln_id=vuln_id, actor="admin"
    )
    assert cleared["exception_until"] is None
    # Recomputed from when the clock started, so the acceptance did not buy the
    # finding a fresh window.
    assert cleared["due_at"] == original_due
    kinds = [
        event["kind"]
        for event in vulns.list_events(settings, tenant_id=tenant_id, vuln_id=vuln_id)[0]
    ]
    assert "exception_set" in kinds and "exception_cleared" in kinds


@requires_postgres
def test_exception_needs_a_future_expiry_and_a_reason(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vuln_id = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)[0][0]["vuln_id"]

    with pytest.raises(ValueError):
        vulns.set_exception(
            settings,
            tenant_id=tenant_id,
            vuln_id=vuln_id,
            until=datetime.now(UTC) + timedelta(days=1),
            reason="   ",
            actor="admin",
        )
    with pytest.raises(ValueError):
        vulns.set_exception(
            settings,
            tenant_id=tenant_id,
            vuln_id=vuln_id,
            until=datetime.now(UTC) - timedelta(days=1),
            reason="already expired",
            actor="admin",
        )


@requires_postgres
def test_closing_a_finding_clears_its_acceptance(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vuln_id = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)[0][0]["vuln_id"]
    vulns.set_exception(
        settings,
        tenant_id=tenant_id,
        vuln_id=vuln_id,
        until=datetime.now(UTC) + timedelta(days=30),
        reason="accepted",
        actor="admin",
    )

    closed = vulns.transition(
        settings, tenant_id=tenant_id, vuln_id=vuln_id, to_state=vuln_states.CLOSED, actor="admin"
    )
    assert closed["exception_until"] is None


@requires_postgres
def test_assignment_defaults_from_the_asset_and_null_unassigns(tmp_path):
    from api.services import assets as assets_service

    settings, tenant_id = _seed(tmp_path)
    asset_id = assets_service.list_assets(settings, tenant_id)[0][0]["asset_id"]
    assets_service.update_asset(
        settings, tenant_id, asset_id, {"owner_email": "team@example.com", "business_unit": "payments"}
    )
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    row = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)[0][0]
    assert (row["assignee"], row["owner_team"]) == ("team@example.com", "payments")

    reassigned = vulns.assign(
        settings,
        tenant_id=tenant_id,
        vuln_id=row["vuln_id"],
        assignee="someone@example.com",
        actor="operator",
        fields={"assignee"},
    )
    assert reassigned["assignee"] == "someone@example.com"
    assert reassigned["owner_team"] == "payments"  # untouched key

    unassigned = vulns.assign(
        settings,
        tenant_id=tenant_id,
        vuln_id=row["vuln_id"],
        assignee=None,
        actor="operator",
        fields={"assignee"},
    )
    assert unassigned["assignee"] is None


@requires_postgres
def test_breach_filter_and_summary_agree(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    # Backdate one finding's deadline rather than waiting 15 days for it.
    from api.db import models
    from api.db.engine import get_session

    items, _ = vulns.list_vulnerabilities(settings, tenant_id=tenant_id, severity="critical")
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Vulnerability, items[0]["vuln_id"])
        row.due_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=2)

    breached, total = vulns.list_vulnerabilities(settings, tenant_id=tenant_id, sla="breached")
    assert total == 1
    assert breached[0]["sla_state"] == "breached"

    report = vulns.summary(settings, tenant_id=tenant_id)
    assert report["breached"] == 1
    assert report["worst_breached_severity"] == "critical"
    assert report["open_total"] == 2
    assert report["untriaged"] == 2
    assert report["by_state"][vuln_states.OPEN] == 2
    assert report["by_severity_open"]["critical"] == 1
    assert report["unassigned"] == 2
    assert report["estate_risk"] in {"very_low", "low", "moderate", "high", "very_high"}
    assert sum(report["by_risk_level_open"].values()) == 2


@requires_postgres
def test_findings_on_unknown_hosts_are_skipped_not_invented(tmp_path):
    settings, tenant_id = _seed(
        tmp_path,
        findings=[{"host": "192.0.2.99", "port": "443", "cve": "CVE-2024-9999", "severity": "high"}],
    )

    stats = vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")

    assert (stats.created, stats.skipped_unknown_asset) == (0, 1)


@requires_postgres
def test_another_tenants_finding_is_not_visible_or_writable(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vuln_id = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)[0][0]["vuln_id"]

    assert vulns.get_vulnerability(settings, tenant_id="other", vuln_id=vuln_id) is None
    assert (
        vulns.transition(
            settings, tenant_id="other", vuln_id=vuln_id, to_state=vuln_states.CLOSED
        )
        is None
    )
