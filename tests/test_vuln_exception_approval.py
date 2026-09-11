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
    _seed(tmp_path)
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
