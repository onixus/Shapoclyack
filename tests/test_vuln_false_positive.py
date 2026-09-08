"""False-positive verdicts and the suppression they carry (ROADMAP Track E).

The property under test is that marking noise honestly is not punished. Before
this feature ``register_findings_from_run`` re-opened *any* closed row it saw
again — so a correct false-positive verdict cost a reopen, a restarted SLA
clock and a permanent place in the breach report, and the cheapest way to keep
the numbers clean was to close nothing at all.

The opposite risk gets the same attention here: a suppression is the strongest
control in the lifecycle, so the tests pin the guardrails that stop it hiding a
real finding — a mandatory reason and expiry, ``admin`` to set it, the
escalation override, and the fact that the finding never leaves the estate's
picture, only the *active* half of it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, update

from api.db import models
from api.db.engine import get_session
from api.services import vuln_states
from api.services import vulnerabilities as vulns
from tests.conftest import auth_headers, configured_client, requires_postgres
from tests.test_vuln_lifecycle import _FINDINGS, _HOSTS, _seed, _settings, _write_run

pytestmark = requires_postgres


def _ids(settings, tenant_id: str) -> dict[str, str]:
    items, _ = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)
    return {item["cve"]: item["vuln_id"] for item in items}


def _kinds(settings, tenant_id: str, vuln_id: str) -> list[str]:
    items, _ = vulns.list_events(settings, tenant_id=tenant_id, vuln_id=vuln_id)
    return [item["kind"] for item in items]


def _event(settings, tenant_id: str, vuln_id: str, kind: str) -> dict:
    items, _ = vulns.list_events(settings, tenant_id=tenant_id, vuln_id=vuln_id)
    return next(item for item in items if item["kind"] == kind)


def _expire_suppression(settings, vuln_id: str) -> None:
    """Age the verdict out without sleeping through a 24-hour minimum."""
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.Vulnerability)
            .where(models.Vulnerability.vuln_id == vuln_id)
            .values(fp_suppress_until=datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=1))
        )


def _marked(tmp_path, **kwargs):
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vuln_id = _ids(settings, tenant_id)["CVE-2024-0001"]
    row = vulns.mark_false_positive(
        settings,
        tenant_id=tenant_id,
        vuln_id=vuln_id,
        reason=kwargs.pop("reason", "Port 443 is a load balancer health check, not the app"),
        actor=kwargs.pop("actor", "admin"),
        **kwargs,
    )
    return settings, tenant_id, vuln_id, row


# --------------------------------------------------------------------------
# The verdict itself
# --------------------------------------------------------------------------


def test_marking_closes_the_finding_and_records_the_verdict(tmp_path):
    settings, tenant_id, vuln_id, row = _marked(tmp_path, suppress_days=30)

    assert row["state"] == vuln_states.CLOSED
    assert row["closure_reason"] == vulns.FALSE_POSITIVE
    assert row["fp_marked_by"] == "admin"
    assert row["fp_reason"].startswith("Port 443")
    assert row["fp_suppressed"] is True
    assert row["fp_observations"] == 0
    # Nothing was remediated, so nothing was verified. The whole value of this
    # column is that it cannot be asserted by the person being measured.
    assert row["machine_verified"] is False
    assert _kinds(settings, tenant_id, vuln_id)[0] == "false_positive_set"


def test_evidence_is_kept_so_the_verdict_can_be_re_checked(tmp_path):
    evidence = {"run_id": "run-1", "port": "443", "output": "HTTP/1.1 200 OK"}
    _, _, _, row = _marked(tmp_path, evidence=evidence)

    assert row["fp_evidence"] == evidence


def test_a_verdict_needs_a_reason_and_a_bounded_expiry(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vuln_id = _ids(settings, tenant_id)["CVE-2024-0001"]

    with pytest.raises(ValueError):
        vulns.mark_false_positive(settings, tenant_id=tenant_id, vuln_id=vuln_id, reason="  ")
    # "Forever" cannot be spelled: an indefinite suppression is a finding that
    # leaves the picture and never comes back to be reviewed.
    for days in (0, vulns.MAX_FP_SUPPRESS_DAYS + 1):
        with pytest.raises(ValueError):
            vulns.mark_false_positive(
                settings, tenant_id=tenant_id, vuln_id=vuln_id, reason="noise", suppress_days=days
            )


def test_marking_an_already_closed_finding_is_the_usual_illegal_move(tmp_path):
    settings, tenant_id, vuln_id, _ = _marked(tmp_path)

    with pytest.raises(vuln_states.InvalidVulnTransition):
        vulns.mark_false_positive(
            settings, tenant_id=tenant_id, vuln_id=vuln_id, reason="again", actor="admin"
        )


def test_marking_clears_an_accepted_exception(tmp_path):
    """A risk that turns out not to exist has nothing left to accept."""
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vuln_id = _ids(settings, tenant_id)["CVE-2024-0001"]
    vulns.set_exception(
        settings,
        tenant_id=tenant_id,
        vuln_id=vuln_id,
        until=datetime.now(UTC) + timedelta(days=10),
        reason="waiting on the vendor",
        actor="admin",
    )

    row = vulns.mark_false_positive(
        settings, tenant_id=tenant_id, vuln_id=vuln_id, reason="not our stack", actor="admin"
    )

    assert row["exception_until"] is None
    assert _event(settings, tenant_id, vuln_id, "false_positive_set")["detail"][
        "cleared_exception_until"
    ]


# --------------------------------------------------------------------------
# Re-observation: the defect this feature exists to fix
# --------------------------------------------------------------------------


def test_a_suppressed_finding_is_not_reopened_by_a_later_run(tmp_path):
    """The regression guard: before this, an honest verdict cost a reopen."""
    settings, tenant_id, vuln_id, before = _marked(tmp_path)

    _write_run(settings.output_dir, "run-2", _HOSTS, _FINDINGS)
    stats = vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-2")

    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln_id)
    assert stats.reopened == 0
    assert stats.fp_suppressed == 1
    assert after["state"] == vuln_states.CLOSED
    assert after["closure_reason"] == vulns.FALSE_POSITIVE
    # The finding is still being tracked — it just is not being re-opened.
    assert after["observation_count"] == before["observation_count"] + 1
    assert after["fp_observations"] == 1
    assert after["last_seen_run_id"] == "run-2"
    # The two numbers a wrongly-suppressed finding would otherwise corrupt.
    assert after["reopen_count"] == before["reopen_count"] == 0
    assert after["sla_started_at"] == before["sla_started_at"]


def test_the_suppressed_reobservation_event_is_written_once_not_per_scan(tmp_path):
    """``vulnerability_events`` has no retention sweep; one row per verdict."""
    settings, tenant_id, vuln_id, _ = _marked(tmp_path)

    for run_id in ("run-2", "run-3", "run-4"):
        _write_run(settings.output_dir, run_id, _HOSTS, _FINDINGS)
        vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id=run_id)

    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln_id)
    assert after["fp_observations"] == 3
    assert _kinds(settings, tenant_id, vuln_id).count("fp_reobserved") == 1


def test_a_lapsed_suppression_falls_back_to_the_ordinary_reopen(tmp_path):
    settings, tenant_id, vuln_id, _ = _marked(tmp_path, suppress_days=1)
    _expire_suppression(settings, vuln_id)

    _write_run(settings.output_dir, "run-2", _HOSTS, _FINDINGS)
    stats = vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-2")

    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln_id)
    assert stats.reopened == 1
    assert after["state"] == vuln_states.OPEN
    assert after["reopen_count"] == 1
    # The verdict is dropped rather than left on an open row, where the next
    # reader would take it for a current judgement.
    assert after["closure_reason"] is None
    assert after["fp_suppress_until"] is None and after["fp_reason"] is None
    assert _event(settings, tenant_id, vuln_id, "reopened")["detail"]["after_fp_suppression"] is True


def test_an_escalation_breaks_the_suppression_early(tmp_path):
    """The verdict was about the evidence then; new intelligence is new evidence."""
    settings, tenant_id, vuln_id, _ = _marked(tmp_path, suppress_days=365)

    worse = [{**_FINDINGS[0], "severity": "critical"}, _FINDINGS[1]]
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.Vulnerability)
            .where(models.Vulnerability.vuln_id == vuln_id)
            .values(severity="medium")
        )
    _write_run(settings.output_dir, "run-2", _HOSTS, worse)
    stats = vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-2")

    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln_id)
    assert stats.fp_overridden == 1
    assert stats.reopened == 1
    assert after["state"] == vuln_states.OPEN
    assert after["fp_suppress_until"] is None
    override = _event(settings, tenant_id, vuln_id, "fp_overridden")
    assert "severity" in override["detail"]["changed"]
    assert override["detail"]["fp_marked_by"] == "admin"


def test_an_unchanged_assessment_does_not_break_the_suppression(tmp_path):
    """Only the four escalation signals count — not a score drifting in-band."""
    settings, tenant_id, vuln_id, _ = _marked(tmp_path, suppress_days=365)

    _write_run(settings.output_dir, "run-2", _HOSTS, _FINDINGS)
    stats = vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-2")

    assert stats.fp_overridden == 0
    assert "fp_overridden" not in _kinds(settings, tenant_id, vuln_id)


# --------------------------------------------------------------------------
# Withdrawal
# --------------------------------------------------------------------------


def test_clearing_puts_the_finding_back_on_the_queue(tmp_path):
    settings, tenant_id, vuln_id, _ = _marked(tmp_path)

    after = vulns.clear_false_positive(
        settings, tenant_id=tenant_id, vuln_id=vuln_id, actor="operator", note="it is real"
    )

    assert after["state"] == vuln_states.OPEN
    assert after["closure_reason"] is None
    assert after["closed_at"] is None
    assert after["fp_reason"] is None and after["fp_suppress_until"] is None
    assert after["due_at"] is not None
    # Withdrawing a verdict is a correction to the record, not a regression in
    # the estate, so the "how often does this come back" counter stays put.
    assert after["reopen_count"] == 0
    assert _kinds(settings, tenant_id, vuln_id)[0] == "false_positive_cleared"


def test_clearing_a_finding_that_has_no_verdict_is_refused_not_reported_as_done(tmp_path):
    """A withdrawal that withdrew nothing must not answer "withdrawn".

    The console offers the button whenever the finding looks marked, so a
    silent success there tells an operator the finding is back on the queue
    when it never left it.
    """
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vuln_id = _ids(settings, tenant_id)["CVE-2024-0001"]

    with pytest.raises(ValueError):
        vulns.clear_false_positive(settings, tenant_id=tenant_id, vuln_id=vuln_id, actor="op")

    assert "false_positive_cleared" not in _kinds(settings, tenant_id, vuln_id)


def test_withdrawing_a_verdict_that_is_not_there_is_a_conflict(tmp_path, monkeypatch):
    client, _, _, vuln_id = _seeded_client(tmp_path, monkeypatch)
    url = f"/api/vulnerabilities/{vuln_id}/false-positive"
    operator = auth_headers(client, "operator")

    assert client.delete(url, headers=operator).status_code == 409

    assert (
        client.post(url, json={"reason": "noise"}, headers=auth_headers(client, "admin")).status_code
        == 200
    )
    assert client.delete(url, headers=operator).status_code == 200
    # ...and a second withdrawal is the conflict again rather than a second 200.
    assert client.delete(url, headers=operator).status_code == 409


def test_a_ticket_reopening_a_finding_drops_the_verdict(tmp_path, monkeypatch):
    """The fourth re-open path. There is one rule for "this is real again".

    ``sync_ticket_status`` cleared ``closure_reason`` and left the ``fp_*``
    columns behind, so an *open* finding kept advertising a suppression that
    was no longer suppressing anything — and the console's Withdraw button
    followed the columns.
    """
    from api.services.integrations import ticket_sync

    settings, tenant_id, vuln_id, _ = _marked(tmp_path, suppress_days=365)
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Vulnerability, vuln_id)
        row.ticket_system = "jira"
        row.ticket_key = "SEC-1"
    monkeypatch.setattr(
        vulns, "_ticket_endpoint", lambda *args, **kwargs: ("https://jira.example.com", None, {})
    )
    monkeypatch.setattr(
        ticket_sync, "fetch_ticket_status", lambda **kwargs: (vuln_states.OPEN, "Reopened", {})
    )

    after = vulns.sync_ticket_status(settings, tenant_id=tenant_id, vuln_id=vuln_id, actor="op")

    assert after["state"] == vuln_states.OPEN
    assert after["closure_reason"] is None
    assert after["fp_reason"] is None and after["fp_suppress_until"] is None
    assert after["fp_suppressed"] is False
    assert _event(settings, tenant_id, vuln_id, "ticket_synced")["detail"]["after_fp_suppression"]


# --------------------------------------------------------------------------
# Consumers, and the adjacent defect in the observer's reopen
# --------------------------------------------------------------------------


def test_a_suppressed_finding_leaves_the_active_population(tmp_path):
    """Compliance, posture and reports all filter on vuln_states.ACTIVE.

    Pinned deliberately: the scores those consumers produce will rise when noise
    is marked, with no change in the estate's actual assessment, and that has to
    be a decision on the record rather than something noticed later.
    """
    settings, tenant_id, vuln_id, _ = _marked(tmp_path)

    summary = vulns.summary(settings, tenant_id=tenant_id)
    active, _ = vulns.list_vulnerabilities(
        settings, tenant_id=tenant_id, states=sorted(vuln_states.ACTIVE)
    )

    assert vuln_id not in {item["vuln_id"] for item in active}
    assert summary["closed_total"] == 1
    # ...but it is still there, and still findable by what closed it.
    closed, total = vulns.list_vulnerabilities(
        settings, tenant_id=tenant_id, state=vuln_states.CLOSED
    )
    assert total == 1 and closed[0]["vuln_id"] == vuln_id


def test_every_active_state_consumer_drops_the_verdict_together(tmp_path):
    """Compliance, posture and the report factory must not disagree with the page.

    All four consumers filter on ``vuln_states.ACTIVE`` and none of them knows
    what a false-positive verdict is, so a verdict removes the finding from all
    of them at once — the compliance score rises with no change in the estate's
    actual assessment. That is the intended consequence of calling something
    noise, and it is pinned here so it stays a decision rather than a surprise:
    if a consumer ever starts reading closed findings, this breaks first.
    """
    from api.services import assets as assets_service
    from api.services import compliance as compliance_service
    from api.services import tenant_posture

    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vuln_id = _ids(settings, tenant_id)["CVE-2024-0001"]

    def _readings() -> tuple[int, int, int]:
        # A.8.8 is "management of technical vulnerabilities" — the control whose
        # evidence *is* the open findings, so it moves if anything does.
        posture = compliance_service.assess(
            settings, framework_id="iso-27001-2022", tenant_id=tenant_id
        )
        control = next(row for row in posture["controls"] if row["control_id"] == "A.8.8")
        estate = next(
            row for row in tenant_posture.list_posture(settings) if row["tenant_id"] == tenant_id
        )
        inventory, _ = assets_service.list_assets(settings, tenant_id=tenant_id)
        return (
            control["failing_count"],
            estate["open_total"],
            sum(item["open_findings"] for item in inventory),
        )

    before = _readings()
    vulns.mark_false_positive(
        settings,
        tenant_id=tenant_id,
        vuln_id=vuln_id,
        reason="the TLS banner is the load balancer's, not the origin's",
        actor="admin",
    )
    after = _readings()

    # The critical finding leaves every active-state reading in one step —
    # including the compliance evidence, which is the reading that turns
    # "we called this noise" into "we look more compliant".
    assert after == (before[0] - 1, before[1] - 1, before[2] - 1)


def test_the_observers_reopen_drops_a_stale_verified_closure(tmp_path):
    """Adjacent defect: only the *operator* reopen reset these two columns.

    A machine-verified closure that came back stayed ``machine_verified`` while
    OPEN, still claiming a verification run had confirmed the fix.
    """
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vuln_id = _ids(settings, tenant_id)["CVE-2024-0001"]
    vulns.transition(
        settings, tenant_id=tenant_id, vuln_id=vuln_id, to_state=vuln_states.CLOSED, actor="admin"
    )
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.Vulnerability)
            .where(models.Vulnerability.vuln_id == vuln_id)
            .values(machine_verified=True, closure_reason="verified_remediated")
        )

    _write_run(settings.output_dir, "run-2", _HOSTS, _FINDINGS)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-2")

    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln_id)
    assert after["state"] == vuln_states.OPEN
    assert after["machine_verified"] is False
    assert after["closure_reason"] is None


# --------------------------------------------------------------------------
# Routes: roles and tenant isolation
# --------------------------------------------------------------------------


def _seeded_client(tmp_path, monkeypatch):
    from api.services import tenants as tenants_service

    client = configured_client(tmp_path, monkeypatch)
    settings = _settings(tmp_path)
    tenant_id = tenants_service.DEFAULT_TENANT_ID
    _write_run(settings.output_dir, "run-1", _HOSTS, _FINDINGS)
    from api.services import assets as assets_service

    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    return client, settings, tenant_id, _ids(settings, tenant_id)["CVE-2024-0001"]


def test_setting_needs_admin_and_clearing_only_operator(tmp_path, monkeypatch):
    client, _, _, vuln_id = _seeded_client(tmp_path, monkeypatch)
    body = {"reason": "load balancer probe", "suppress_days": 30}

    assert client.post(
        f"/api/vulnerabilities/{vuln_id}/false-positive",
        json=body,
        headers=auth_headers(client, "viewer"),
    ).status_code == 403
    # An operator may close a finding by hand but not suppress it: this one
    # commits the tenant, the way accepting risk does.
    assert client.post(
        f"/api/vulnerabilities/{vuln_id}/false-positive",
        json=body,
        headers=auth_headers(client, "operator"),
    ).status_code == 403

    ok = client.post(
        f"/api/vulnerabilities/{vuln_id}/false-positive",
        json=body,
        headers=auth_headers(client, "admin"),
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["fp_suppressed"] is True

    # Releasing it is cheaper than applying it, on purpose.
    undo = client.delete(
        f"/api/vulnerabilities/{vuln_id}/false-positive",
        headers=auth_headers(client, "operator"),
    )
    assert undo.status_code == 200, undo.text
    assert undo.json()["state"] == vuln_states.OPEN


def test_the_route_refuses_an_unbounded_or_unjustified_verdict(tmp_path, monkeypatch):
    client, _, _, vuln_id = _seeded_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    url = f"/api/vulnerabilities/{vuln_id}/false-positive"

    assert client.post(url, json={"suppress_days": 30}, headers=admin).status_code == 422
    assert client.post(url, json={"reason": "x", "suppress_days": 0}, headers=admin).status_code == 422
    assert client.post(url, json={"reason": "x", "suppress_days": 900}, headers=admin).status_code == 422
    # The default is a review date, not "forever".
    assert client.post(url, json={"reason": "x"}, headers=admin).json()["fp_suppress_until"]


def test_marking_a_closed_finding_through_the_route_is_a_conflict(tmp_path, monkeypatch):
    client, _, _, vuln_id = _seeded_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    url = f"/api/vulnerabilities/{vuln_id}/false-positive"
    assert client.post(url, json={"reason": "noise"}, headers=admin).status_code == 200

    assert client.post(url, json={"reason": "noise"}, headers=admin).status_code == 409


def test_another_tenants_finding_is_not_found_rather_than_forbidden(tmp_path, monkeypatch):
    """404, as for jobs and webhooks: a write scope must not confirm existence."""
    from api.services import tenants as tenants_service

    client, settings, tenant_id, _ = _seeded_client(tmp_path, monkeypatch)
    other = tenants_service.create_tenant(tenant_id="ten_other", name="Other")
    with get_session(settings.postgres_url) as session:
        row = session.execute(
            select(models.Vulnerability).where(models.Vulnerability.tenant_id == tenant_id)
        ).scalars().first()
        row.tenant_id = other["tenant_id"]
        foreign_id = row.vuln_id

    # The service refuses it too, so the 404 is not a route-only guard.
    assert (
        vulns.mark_false_positive(
            settings, tenant_id=tenant_id, vuln_id=foreign_id, reason="noise"
        )
        is None
    )
    assert vulns.clear_false_positive(settings, tenant_id=tenant_id, vuln_id=foreign_id) is None

    url = f"/api/vulnerabilities/{foreign_id}/false-positive"
    # A tenant-scoped principal is pinned to its own tenant by ``_write_scope``,
    # so a guessed id from another tenant is missing rather than forbidden.
    assert client.delete(url, headers=auth_headers(client, "operator")).status_code == 404
    assert (
        client.post(
            url, json={"reason": "noise"}, headers=auth_headers(client, "viewer")
        ).status_code
        == 403
    )
    # The built-in ``admin`` is a *platform* admin, which ``_write_scope``
    # deliberately leaves unscoped — as on every other write route, not a
    # property of this one. Pinned so a future change to that is a decision.
    assert (
        client.post(url, json={"reason": "noise"}, headers=auth_headers(client, "admin")).status_code
        == 200
    )
