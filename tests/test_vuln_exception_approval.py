"""Accepted risk needs two people, and lapses in public (#348).

Every test here fails on the pre-#348 code, which is what makes them worth
having: there, ``POST /{id}/exception`` *was* the acceptance, one tenant admin
wrote it, and nothing recorded that it ran out.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime, timedelta

import pytest

from api.db import models
from api.db.engine import get_session
from api.services import audit as audit_service
from api.services import vuln_states
from api.services import vulnerabilities as vulns
from api.services.reports import content as content_builder
from api.services.reports import render as renderer
from tests.conftest import (
    accept_risk,
    auth_headers,
    configured_client,
    requires_postgres,
)
from tests.test_api_rbac_permissions import _account
from tests.test_api_vulnerabilities import _seed

pytestmark = requires_postgres

_TENANT = "default"


def _vuln_id(client, headers: dict[str, str]) -> str:
    return client.get("/api/vulnerabilities", headers=headers).json()["items"][0]["vuln_id"]


def _until(days: int = 90) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


def _request(client, headers: dict[str, str], vuln_id: str, *, days: int = 90):
    return client.post(
        f"/api/vulnerabilities/{vuln_id}/exception",
        json={"until": _until(days), "reason": "vendor patch lands in Q4"},
        headers=headers,
    )


# --------------------------------------------------------------------------
# Two people
# --------------------------------------------------------------------------


def test_a_second_role_approves_and_only_then_is_the_clock_suspended(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    admin = auth_headers(client, "admin")
    approver = _account(client, "risk-boss", _TENANT, "risk-approver")
    vuln_id = _vuln_id(client, admin)
    before_due = client.get(f"/api/vulnerabilities/{vuln_id}", headers=admin).json()["due_at"]

    requested = _request(client, admin, vuln_id)
    assert requested.status_code == 200, requested.text
    assert requested.json()["due_at"] == before_due

    approved = client.post(
        f"/api/vulnerabilities/{vuln_id}/exception/approve",
        json={"note": "compensating control in place"},
        headers=approver,
    )
    assert approved.status_code == 200, approved.text
    body = approved.json()
    assert body["exception_state"] == vuln_states.EXCEPTION_APPROVED
    assert body["sla_state"] == "accepted"
    assert body["exception_requested_by"] == "admin"
    assert body["exception_by"] == "risk-boss"
    assert body["exception_decided_by"] == "risk-boss"
    assert body["due_at"] > before_due


def test_the_requester_cannot_approve_even_holding_every_permission(tmp_path, monkeypatch):
    """The platform admin carries ``vulnerability.exception.approve``. The bar
    that stops them signing their own request is the one that separates the
    duties at all — a permission check alone would let it through."""
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    admin = auth_headers(client, "admin")
    vuln_id = _vuln_id(client, admin)
    _request(client, admin, vuln_id)

    refused = client.post(
        f"/api/vulnerabilities/{vuln_id}/exception/approve", json={}, headers=admin
    )
    assert refused.status_code == 403
    assert "cannot approve" in refused.json()["detail"]
    # And nothing was granted on the way past.
    assert (
        client.get(f"/api/vulnerabilities/{vuln_id}", headers=admin).json()["exception_state"]
        == vuln_states.EXCEPTION_REQUESTED
    )


def test_the_name_is_compared_case_insensitively(tmp_path, monkeypatch):
    """``Admin`` approving ``admin``'s request is one person with two spellings."""
    client = configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    vuln_id = _vuln_id(client, auth_headers(client, "admin"))
    vulns.request_exception(
        settings,
        tenant_id=tenant_id,
        vuln_id=vuln_id,
        until=datetime.now(UTC) + timedelta(days=30),
        reason="vendor",
        actor="Alice",
    )
    with pytest.raises(PermissionError):
        vulns.approve_exception(
            settings, tenant_id=tenant_id, vuln_id=vuln_id, actor="  alice "
        )


def test_an_operator_cannot_approve_and_a_risk_approver_cannot_transition(
    tmp_path, monkeypatch
):
    """The permission, not the rank: ``risk-approver`` is rank 1 and approves;
    ``operator`` is rank 2 and does not."""
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    admin = auth_headers(client, "admin")
    operator = auth_headers(client, "operator")
    approver = _account(client, "risk-boss", _TENANT, "risk-approver")
    vuln_id = _vuln_id(client, admin)
    _request(client, admin, vuln_id)

    assert (
        client.post(
            f"/api/vulnerabilities/{vuln_id}/exception/approve", json={}, headers=operator
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/vulnerabilities/{vuln_id}/transition",
            json={"state": "ACKNOWLEDGED"},
            headers=approver,
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/vulnerabilities/{vuln_id}/exception/approve", json={}, headers=approver
        ).status_code
        == 200
    )


def test_approving_nothing_or_twice_is_a_conflict(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    admin = auth_headers(client, "admin")
    approver = _account(client, "risk-boss", _TENANT, "risk-approver")
    vuln_id = _vuln_id(client, admin)

    nothing = client.post(
        f"/api/vulnerabilities/{vuln_id}/exception/approve", json={}, headers=approver
    )
    assert nothing.status_code == 409

    _request(client, admin, vuln_id)
    assert (
        client.post(
            f"/api/vulnerabilities/{vuln_id}/exception/approve", json={}, headers=approver
        ).status_code
        == 200
    )
    again = client.post(
        f"/api/vulnerabilities/{vuln_id}/exception/approve", json={}, headers=approver
    )
    assert again.status_code == 409


def test_a_rejection_leaves_the_deadline_alone_and_can_be_asked_again(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    admin = auth_headers(client, "admin")
    approver = _account(client, "risk-boss", _TENANT, "risk-approver")
    vuln_id = _vuln_id(client, admin)
    before_due = client.get(f"/api/vulnerabilities/{vuln_id}", headers=admin).json()["due_at"]
    _request(client, admin, vuln_id)

    rejected = client.post(
        f"/api/vulnerabilities/{vuln_id}/exception/reject",
        json={"note": "patch is available today"},
        headers=approver,
    )
    assert rejected.status_code == 200
    assert rejected.json()["exception_state"] == vuln_states.EXCEPTION_REJECTED
    assert rejected.json()["exception_until"] is None
    assert rejected.json()["due_at"] == before_due
    assert rejected.json()["exception_decision_note"] == "patch is available today"

    # Refused is not final: circumstances change.
    assert _request(client, admin, vuln_id).status_code == 200


def test_a_request_never_shortens_an_acceptance_already_in_force(tmp_path, monkeypatch):
    """Asking for an extension is legal; being refused one must not take away
    the window somebody already signed for."""
    client = configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    admin = auth_headers(client, "admin")
    approver = _account(client, "risk-boss", _TENANT, "risk-approver")
    vuln_id = _vuln_id(client, admin)
    _request(client, admin, vuln_id, days=30)
    granted = client.post(
        f"/api/vulnerabilities/{vuln_id}/exception/approve", json={}, headers=approver
    ).json()

    _request(client, admin, vuln_id, days=200)
    pending = client.get(f"/api/vulnerabilities/{vuln_id}", headers=admin).json()
    assert pending["exception_state"] == vuln_states.EXCEPTION_REQUESTED
    assert pending["exception_until"] == granted["exception_until"]
    assert pending["sla_state"] == "accepted"

    refused = client.post(
        f"/api/vulnerabilities/{vuln_id}/exception/reject", json={}, headers=approver
    ).json()
    assert refused["exception_until"] == granted["exception_until"]
    # And the documents #348 exists to produce still show it. Keyed on
    # ``exception_state``, both of them dropped the finding the moment the
    # extension was asked for: the register stopped listing an acceptance that
    # was in force, and the SLA reading stayed ``accepted`` — so the one case
    # an auditor most wants ("they were refused more time") was in no document
    # at all.
    for stage in (pending, refused):
        assert stage["sla_state"] == "accepted"
    entries = vulns.risk_acceptance_register(settings, tenant_id=tenant_id)
    assert [entry["vuln_id"] for entry in entries] == [vuln_id]
    assert entries[0]["status"] == "active"


def test_an_extension_request_never_rewrites_the_acceptance_it_wants_to_replace(
    tmp_path, monkeypatch
):
    """The register prints what was signed, not what is being asked for.

    The request wrote its justification over ``exception_reason`` and wiped the
    decision columns, so while an extension waited the register showed an
    unapproved argument, and once it was refused ``approved_by`` named the
    person who had said no.
    """
    client = configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    admin = auth_headers(client, "admin")
    approver = _account(client, "risk-boss", _TENANT, "risk-approver")
    vuln_id = _vuln_id(client, admin)

    client.post(
        f"/api/vulnerabilities/{vuln_id}/exception",
        json={"until": _until(30), "reason": "vendor patch lands in Q4"},
        headers=admin,
    )
    client.post(
        f"/api/vulnerabilities/{vuln_id}/exception/approve",
        json={"note": "compensating control in place"},
        headers=approver,
    )
    client.post(
        f"/api/vulnerabilities/{vuln_id}/exception",
        json={"until": _until(200), "reason": "EXTENSION not yet approved"},
        headers=admin,
    )

    while_pending = vulns.risk_acceptance_register(settings, tenant_id=tenant_id)[0]
    assert while_pending["reason"] == "vendor patch lands in Q4"
    assert while_pending["approved_by"] == "risk-boss"
    assert while_pending["requested_by"] == "admin"
    assert while_pending["self_approved"] is False

    client.post(
        f"/api/vulnerabilities/{vuln_id}/exception/reject",
        json={"note": "six months is not a plan"},
        headers=approver,
    )
    after = vulns.risk_acceptance_register(settings, tenant_id=tenant_id)[0]
    assert after["reason"] == "vendor patch lands in Q4"
    assert after["approved_by"] == "risk-boss"
    # The row the finding carries says the same thing, so the console and the
    # report cannot disagree with the register.
    body = client.get(f"/api/vulnerabilities/{vuln_id}", headers=admin).json()
    assert body["exception_reason"] == "vendor patch lands in Q4"
    assert body["exception_requested_reason"] == "EXTENSION not yet approved"
    assert body["exception_by"] == "risk-boss"
    assert body["exception_decided_by"] == "risk-boss"


def test_a_lapse_is_recorded_even_when_the_extension_was_refused(tmp_path, monkeypatch):
    """The obituary is owed to the window, not to the workflow state.

    Refusing an extension parks ``exception_state`` at ``exception_rejected``
    for good, and a sweep that looked for ``exception_approved`` therefore
    never wrote the expiry for the acceptance underneath it — no event, no
    audit row, and an entry that would sit in the register as "in force" until
    somebody noticed the date.
    """
    client = configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    admin = auth_headers(client, "admin")
    approver = _account(client, "risk-boss", _TENANT, "risk-approver")
    vuln_id = _vuln_id(client, admin)

    _request(client, admin, vuln_id, days=10)
    client.post(f"/api/vulnerabilities/{vuln_id}/exception/approve", json={}, headers=approver)
    _request(client, admin, vuln_id, days=200)
    client.post(f"/api/vulnerabilities/{vuln_id}/exception/reject", json={}, headers=approver)

    later = datetime.now(UTC) + timedelta(days=11)
    assert vulns.expire_exceptions(settings, tenant_id=tenant_id, now=later) == 1
    # Once, as for any other acceptance.
    assert vulns.expire_exceptions(settings, tenant_id=tenant_id, now=later) == 0
    kinds = [
        event["kind"]
        for event in client.get(
            f"/api/vulnerabilities/{vuln_id}/events", headers=admin
        ).json()["items"]
    ]
    assert "exception_expired" in kinds
    assert audit_service.ACTION_VULN_EXCEPTION_EXPIRE in _actions(client, admin, vuln_id)
    # The refusal is still on the row: the lapse of the granted window is not
    # an answer to the request that was turned down.
    row = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln_id)
    assert row["exception_state"] == vuln_states.EXCEPTION_REJECTED
    assert row["exception_expired_at"] is not None
    entry = vulns.risk_acceptance_register(settings, tenant_id=tenant_id, now=later)[0]
    assert entry["status"] == "expired"


def test_a_closed_finding_is_neither_in_the_register_nor_swept(tmp_path, monkeypatch):
    """What the machine closing paths left behind before they dropped the
    acceptance, and what an installation upgraded from that state still has:
    a CLOSED row with an acceptance on it. Neither document may take it."""
    configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    vuln_id = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)[0][0]["vuln_id"]
    accept_risk(
        settings,
        tenant_id=tenant_id,
        vuln_id=vuln_id,
        until=datetime.now(UTC) + timedelta(days=5),
        reason="a week to migrate",
    )
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Vulnerability, vuln_id)
        row.state = vuln_states.CLOSED
        row.closure_reason = "verified_remediated"

    assert vulns.risk_acceptance_register(settings, tenant_id=tenant_id) == []
    later = datetime.now(UTC) + timedelta(days=6)
    assert vulns.expire_exceptions(settings, tenant_id=tenant_id, now=later) == 0


def test_the_pending_requests_are_a_queue_somebody_can_open(tmp_path, monkeypatch):
    """``?exception_state=exception_requested`` — the filter the register's own
    docstring points the approver at. Nothing notifies them, so a query
    parameter FastAPI silently ignored handed them every finding in the tenant
    and called it the queue."""
    client = configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    admin = auth_headers(client, "admin")
    approver = _account(client, "risk-boss", _TENANT, "risk-approver")
    rows, total = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)
    assert total > 1
    waiting, other = rows[0]["vuln_id"], rows[1]["vuln_id"]
    _request(client, admin, waiting)

    queue = client.get(
        "/api/vulnerabilities",
        params={"exception_state": vuln_states.EXCEPTION_REQUESTED},
        headers=approver,
    )
    assert queue.status_code == 200
    assert [item["vuln_id"] for item in queue.json()["items"]] == [waiting]
    assert queue.json()["total"] == 1
    assert other not in [item["vuln_id"] for item in queue.json()["items"]]

    # And an answered request leaves the queue rather than sitting in it.
    client.post(f"/api/vulnerabilities/{waiting}/exception/approve", json={}, headers=approver)
    assert (
        client.get(
            "/api/vulnerabilities",
            params={"exception_state": vuln_states.EXCEPTION_REQUESTED},
            headers=approver,
        ).json()["total"]
        == 0
    )
    unknown = client.get(
        "/api/vulnerabilities", params={"exception_state": "exception_maybe"}, headers=approver
    )
    assert unknown.status_code == 422


# --------------------------------------------------------------------------
# The trail
# --------------------------------------------------------------------------


def _actions(client, headers: dict[str, str], vuln_id: str) -> list[str]:
    events = client.get(
        "/api/audit",
        params={"resource_type": "vulnerability", "resource_id": vuln_id},
        headers=headers,
    ).json()["items"]
    return [event["action"] for event in events]


def test_every_step_is_an_audit_row_and_a_finding_event(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    admin = auth_headers(client, "admin")
    approver = _account(client, "risk-boss", _TENANT, "risk-approver")
    vuln_id = _vuln_id(client, admin)

    _request(client, admin, vuln_id, days=1)
    client.post(f"/api/vulnerabilities/{vuln_id}/exception/approve", json={}, headers=approver)
    # The window runs out; the worker's sweep is what records it.
    assert (
        vulns.expire_exceptions(
            settings, tenant_id=tenant_id, now=datetime.now(UTC) + timedelta(days=2)
        )
        == 1
    )

    actions = _actions(client, admin, vuln_id)
    assert audit_service.ACTION_VULN_EXCEPTION_REQUEST in actions
    assert audit_service.ACTION_VULN_EXCEPTION_APPROVE in actions
    assert audit_service.ACTION_VULN_EXCEPTION_EXPIRE in actions

    kinds = [
        event["kind"]
        for event in client.get(
            f"/api/vulnerabilities/{vuln_id}/events", headers=admin
        ).json()["items"]
    ]
    assert {"exception_requested", "exception_approved", "exception_expired"} <= set(kinds)


def test_the_expiry_sweep_runs_once_per_acceptance(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    rows, _total = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)
    accept_risk(
        settings,
        tenant_id=tenant_id,
        vuln_id=rows[0]["vuln_id"],
        until=datetime.now(UTC) + timedelta(days=2),
        reason="short grace",
    )
    later = datetime.now(UTC) + timedelta(days=3)

    assert vulns.expire_exceptions(settings, tenant_id=tenant_id, now=later) == 1
    # The state move *is* the marker: a second tick finds nothing.
    assert vulns.expire_exceptions(settings, tenant_id=tenant_id, now=later) == 0
    row = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=rows[0]["vuln_id"])
    assert row["exception_state"] == vuln_states.EXCEPTION_EXPIRED
    # Not cleared: the register's expired half is read off this.
    assert row["exception_until"] is not None
    # And the clock is running again, derived rather than written: read at the
    # sweep's own moment, the finding is no longer "accepted".
    assert vulns.sla_state(row, now=later.replace(tzinfo=None)) != "accepted"


# --------------------------------------------------------------------------
# The register
# --------------------------------------------------------------------------


def _register(settings, tenant_id: str):
    return vulns.risk_acceptance_register(settings, tenant_id=tenant_id)


def test_the_register_holds_what_is_in_force_and_what_has_lapsed(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    rows, _total = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)
    live, lapsed = rows[0]["vuln_id"], rows[1]["vuln_id"]
    accept_risk(
        settings,
        tenant_id=tenant_id,
        vuln_id=live,
        until=datetime.now(UTC) + timedelta(days=60),
        reason="vendor patch in Q4",
        requester="admin",
        approver="risk-boss",
    )
    accept_risk(
        settings,
        tenant_id=tenant_id,
        vuln_id=lapsed,
        until=datetime.now(UTC) + timedelta(minutes=1),
        reason="a week to migrate",
    )
    entries = vulns.risk_acceptance_register(
        settings, tenant_id=tenant_id, now=datetime.now(UTC) + timedelta(days=1)
    )

    by_id = {entry["vuln_id"]: entry for entry in entries}
    assert by_id[live]["status"] == "active"
    assert by_id[live]["requested_by"] == "admin"
    assert by_id[live]["approved_by"] == "risk-boss"
    assert by_id[live]["reason"] == "vendor patch in Q4"
    assert by_id[live]["self_approved"] is False
    # Lapsed, and still in the register — without waiting for the worker's
    # sweep to have written ``exception_expired``.
    assert by_id[lapsed]["status"] == "expired"
    assert by_id[lapsed]["days_remaining"] is None


def test_a_self_approved_acceptance_is_named_as_one(tmp_path, monkeypatch):
    """What migration 0050 leaves behind for every pre-#348 acceptance: one
    person on both sides. No live path can produce it any more — hence the
    hand-written row — and the register reports them rather than hiding them.
    """
    configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    vuln_id = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)[0][0]["vuln_id"]
    until = datetime.now(UTC).replace(tzinfo=None) + timedelta(days=10)
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Vulnerability, vuln_id)
        row.exception_state = vuln_states.EXCEPTION_APPROVED
        row.exception_until = until
        row.exception_reason = "legacy acceptance"
        row.exception_by = "solo"
        row.exception_requested_by = "solo"
        row.exception_requested_until = until
        row.exception_decided_by = "solo"

    entry = _register(settings, tenant_id)[0]
    assert entry["self_approved"] is True
    assert entry["status"] == "active"


def test_the_register_endpoint_exports_csv_and_stays_in_one_tenant(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    vuln_id = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)[0][0]["vuln_id"]
    accept_risk(
        settings,
        tenant_id=tenant_id,
        vuln_id=vuln_id,
        until=datetime.now(UTC) + timedelta(days=45),
        reason="=cmd|calc",
        requester="admin",
        approver="risk-boss",
    )
    viewer = auth_headers(client, "viewer")

    listed = client.get("/api/vulnerabilities/risk-register", headers=viewer)
    assert listed.status_code == 200
    assert [entry["vuln_id"] for entry in listed.json()] == [vuln_id]

    export = client.get(
        "/api/vulnerabilities/risk-register", params={"format": "csv"}, headers=viewer
    )
    assert export.status_code == 200
    assert export.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(export.text)))
    assert len(rows) == 1
    assert rows[0]["approved_by"] == "risk-boss"
    assert rows[0]["requested_by"] == "admin"
    assert rows[0]["until"]
    # A justification a spreadsheet would execute is defanged, as in the audit
    # export: this file is written to be opened in Excel.
    assert rows[0]["reason"].startswith("'=")


def test_the_report_carries_the_register(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    vuln_id = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)[0][0]["vuln_id"]
    accept_risk(
        settings,
        tenant_id=tenant_id,
        vuln_id=vuln_id,
        until=datetime.now(UTC) + timedelta(days=45),
        reason="vendor patch in Q4",
        requester="admin",
        approver="risk-boss",
    )

    body = content_builder.build(settings, tenant_id=tenant_id, kind="executive")
    assert "risk_acceptance" in body["sections"]
    register = body["risk_acceptance"]
    assert register["active"] == 1
    assert register["expired"] == 0
    assert register["entries"][0]["approved_by"] == "risk-boss"

    html = renderer.render_html(body)
    assert "Accepted risk register" in html
    assert "risk-boss" in html
    # The PDF renderer has to know the section too, or the two documents
    # disagree about the same month.
    assert renderer.render_pdf(body)


def test_a_technical_report_still_omits_it(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    body = content_builder.build(settings, tenant_id=tenant_id, kind="technical")
    assert "risk_acceptance" not in body["sections"]
    assert "risk_acceptance" not in body


# --------------------------------------------------------------------------
# Taking it back: whose request, and whose signature (#348 debt)
# --------------------------------------------------------------------------


def test_withdrawing_an_extension_request_leaves_the_signed_window_alone(
    tmp_path, monkeypatch
):
    """The defect the two routes exist for.

    An acceptance signed by a second person is in force; the tenant admin asks
    for an extension, mistypes the date, and takes the request back. Before the
    split there was one route for both acts, so what went was the *acceptance*:
    ``exception_until`` and ``exception_by`` were nulled, ``due_at`` was
    recomputed from ``sla_started_at``, and the finding was breached with no
    second signature available to put it back.
    """
    client = configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    admin = auth_headers(client, "admin")
    approver = _account(client, "risk-boss", _TENANT, "risk-approver")
    vuln_id = _vuln_id(client, admin)

    _request(client, admin, vuln_id, days=60)
    granted = client.post(
        f"/api/vulnerabilities/{vuln_id}/exception/approve", json={}, headers=approver
    ).json()
    assert granted["sla_state"] == "accepted"

    # The typo, and taking it back.
    _request(client, admin, vuln_id, days=2000)
    withdrawn = client.delete(
        f"/api/vulnerabilities/{vuln_id}/exception/request", headers=admin
    )
    assert withdrawn.status_code == 200, withdrawn.text
    body = withdrawn.json()

    assert body["exception_until"] == granted["exception_until"]
    assert body["exception_by"] == "risk-boss"
    assert body["due_at"] == granted["due_at"]
    assert body["exception_state"] == vuln_states.EXCEPTION_APPROVED
    assert body["sla_state"] == "accepted"
    # The ask is gone, and only the ask.
    assert body["exception_requested_by"] is None
    assert body["exception_requested_until"] is None
    assert body["exception_reason"] == "vendor patch lands in Q4"

    # The register still prints the signed acceptance.
    entries = vulns.risk_acceptance_register(settings, tenant_id=tenant_id)
    assert [entry["vuln_id"] for entry in entries] == [vuln_id]
    assert entries[0]["approved_by"] == "risk-boss"
    assert entries[0]["status"] == "active"

    # And the withdrawal is its own row in the finding's history, distinct
    # from an acceptance being revoked.
    kinds = {
        event["kind"]
        for event in client.get(
            f"/api/vulnerabilities/{vuln_id}/events", headers=admin
        ).json()["items"]
    }
    assert "exception_request_withdrawn" in kinds
    assert "exception_cleared" not in kinds


def test_only_the_requester_withdraws_a_request(tmp_path, monkeypatch):
    """Somebody else's request is answered, not erased.

    Whoever holds ``vulnerability.exception.approve`` rejects it — which leaves
    a decision and a decider in the trail — rather than making it disappear.
    """
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    admin = auth_headers(client, "admin")
    approver = _account(client, "risk-boss", _TENANT, "risk-approver")
    other_admin = _account(client, "second-admin", _TENANT, "admin")
    vuln_id = _vuln_id(client, admin)
    _request(client, admin, vuln_id, days=30)

    # Another tenant admin holds the rank this route gates on and is still
    # refused: the bar is whose request it is, not what they may do.
    refused = client.delete(
        f"/api/vulnerabilities/{vuln_id}/exception/request", headers=other_admin
    )
    assert refused.status_code == 403, refused.text
    assert "withdraw" in refused.json()["detail"]
    # The approver never reaches that check — filing and unfiling are the
    # requester's rank, and ``risk-approver`` is rank 1 by design.
    assert (
        client.delete(
            f"/api/vulnerabilities/{vuln_id}/exception/request", headers=approver
        ).status_code
        == 403
    )

    # The requester's own withdrawal lands, and a second one has nothing to
    # take back — a 409 rather than a silent 200 that changed nothing.
    first = client.delete(f"/api/vulnerabilities/{vuln_id}/exception/request", headers=admin)
    assert first.status_code == 200, first.text
    again = client.delete(f"/api/vulnerabilities/{vuln_id}/exception/request", headers=admin)
    assert again.status_code == 409, again.text


def test_revoking_a_signed_acceptance_needs_the_hand_that_could_have_signed_it(
    tmp_path, monkeypatch
):
    """``DELETE /{id}/exception`` moved from the rank to the permission.

    It was ``require_tenant(admin)``: the tenant admin who filed a request —
    and who deliberately does *not* hold ``vulnerability.exception.approve`` —
    could undo the approval the separation of duties exists to require.
    """
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    admin = auth_headers(client, "admin")
    approver = _account(client, "risk-boss", _TENANT, "risk-approver")
    tenant_admin = _account(client, "acme-admin", _TENANT, "admin")
    vuln_id = _vuln_id(client, admin)

    _request(client, tenant_admin, vuln_id, days=60)
    granted = client.post(
        f"/api/vulnerabilities/{vuln_id}/exception/approve", json={}, headers=approver
    ).json()

    refused = client.delete(f"/api/vulnerabilities/{vuln_id}/exception", headers=tenant_admin)
    assert refused.status_code == 403, refused.text
    still = client.get(f"/api/vulnerabilities/{vuln_id}", headers=admin).json()
    assert still["exception_until"] == granted["exception_until"]

    revoked = client.delete(f"/api/vulnerabilities/{vuln_id}/exception", headers=approver)
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["exception_until"] is None
    assert revoked.json()["exception_state"] == vuln_states.EXCEPTION_NONE
    assert revoked.json()["sla_state"] != "accepted"


def test_revoking_an_acceptance_leaves_a_pending_extension_waiting(tmp_path, monkeypatch):
    """The mirror of the first test: the two acts do not consume each other."""
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    admin = auth_headers(client, "admin")
    approver = _account(client, "risk-boss", _TENANT, "risk-approver")
    vuln_id = _vuln_id(client, admin)
    _request(client, admin, vuln_id, days=60)
    client.post(f"/api/vulnerabilities/{vuln_id}/exception/approve", json={}, headers=approver)
    _request(client, admin, vuln_id, days=120)

    revoked = client.delete(f"/api/vulnerabilities/{vuln_id}/exception", headers=approver)
    assert revoked.status_code == 200, revoked.text
    body = revoked.json()
    assert body["exception_until"] is None
    assert body["exception_state"] == vuln_states.EXCEPTION_REQUESTED
    assert body["exception_requested_by"] == "admin"
    # Still answerable, and approving it grants the new window on its own.
    approved = client.post(
        f"/api/vulnerabilities/{vuln_id}/exception/approve", json={}, headers=approver
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["sla_state"] == "accepted"


def test_a_requester_may_correct_their_own_pending_request(tmp_path, monkeypatch):
    """``requested -> requested`` for the same person, 409 for anybody else.

    Fixing a date used to be a two-step operation whose first step was the
    button that destroyed the acceptance.
    """
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    admin = auth_headers(client, "admin")
    other = _account(client, "second-admin", _TENANT, "admin")
    vuln_id = _vuln_id(client, admin)

    first = _request(client, admin, vuln_id, days=30)
    assert first.status_code == 200, first.text
    corrected = client.post(
        f"/api/vulnerabilities/{vuln_id}/exception",
        json={"until": _until(45), "reason": "vendor patch lands in Q4, revised"},
        headers=admin,
    )
    assert corrected.status_code == 200, corrected.text
    assert corrected.json()["exception_requested_reason"] == "vendor patch lands in Q4, revised"

    clash = _request(client, other, vuln_id, days=90)
    assert clash.status_code == 409, clash.text
    assert "waiting for a decision" in clash.json()["detail"]


def test_both_undo_paths_leave_their_own_audit_row(tmp_path, monkeypatch):
    """One action name for two acts could not answer "who cancelled it"."""
    client = configured_client(tmp_path, monkeypatch)
    settings, _ = _seed(tmp_path)
    admin = auth_headers(client, "admin")
    approver = _account(client, "risk-boss", _TENANT, "risk-approver")
    vuln_id = _vuln_id(client, admin)
    _request(client, admin, vuln_id, days=60)
    client.post(f"/api/vulnerabilities/{vuln_id}/exception/approve", json={}, headers=approver)
    _request(client, admin, vuln_id, days=120)
    client.delete(f"/api/vulnerabilities/{vuln_id}/exception/request", headers=admin)
    client.delete(f"/api/vulnerabilities/{vuln_id}/exception", headers=approver)

    with get_session(settings.postgres_url) as session:
        actions = [
            row.action
            for row in session.query(models.AuditEvent)
            .filter(models.AuditEvent.resource_id == vuln_id)
            .all()
        ]
    assert audit_service.ACTION_VULN_EXCEPTION_REQUEST_WITHDRAW in actions
    assert audit_service.ACTION_VULN_EXCEPTION_WITHDRAW in actions
