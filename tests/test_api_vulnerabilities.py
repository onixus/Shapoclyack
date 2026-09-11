"""HTTP surface of the vulnerability tracker (#145): RBAC, filters, 409s."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from api.services import vuln_states
from api.services import vulnerabilities as vulns
from tests.conftest import (
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres

# Public addresses so #171 does not collapse both likelihoods to zero
# (RFC1918 + theoretical ceiling) and scramble worst-first sort.
_HOSTS = [{"host": "8.8.8.8", "hostname": "app.example.com"}]
_FINDINGS = [
    {"host": "8.8.8.8", "port": "443", "cve": "CVE-2024-0001", "cvss": 9.8, "severity": "critical"},
    {"host": "8.8.8.8", "port": "80", "cve": "CVE-2024-0002", "cvss": 5.0, "severity": "medium"},
]


def _seed(tmp_path: Path) -> tuple:
    """Register two findings against the client's own database and run dir.

    ``make_settings(tmp_path)`` reproduces exactly what ``configured_client``
    built for the app, so the seed lands where the requests will read it.
    """
    from api.services import assets as assets_service
    from api.services import tenants as tenants_service

    settings = make_settings(tmp_path)
    run_dir = settings.output_dir / "runs" / "run-1"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "alive_hosts.json").write_text(json.dumps(_HOSTS), encoding="utf-8")
    (run_dir / "vulnerabilities.json").write_text(json.dumps(_FINDINGS), encoding="utf-8")

    tenant_id = tenants_service.DEFAULT_TENANT_ID
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    return settings, tenant_id


def test_list_and_get_need_only_viewer(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    viewer = auth_headers(client, "viewer")

    listed = client.get("/api/vulnerabilities", headers=viewer)
    assert listed.status_code == 200
    body = listed.json()
    assert body["total"] == 2
    # Default sort is worst-first, which is what the Vulnerability Center opens on.
    assert body["items"][0]["severity"] == "critical"

    vuln_id = body["items"][0]["vuln_id"]
    detail = client.get(f"/api/vulnerabilities/{vuln_id}", headers=viewer)
    assert detail.status_code == 200
    assert detail.json()["sla_state"] in {"on_track", "due_soon"}

    assert client.get("/api/vulnerabilities/vln_nope", headers=viewer).status_code == 404


def test_filters_and_summary(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    viewer = auth_headers(client, "viewer")

    critical = client.get(
        "/api/vulnerabilities", params={"severity": "critical"}, headers=viewer
    )
    assert critical.json()["total"] == 1

    assert (
        client.get("/api/vulnerabilities", params={"severity": "spicy"}, headers=viewer).status_code
        == 422
    )
    assert (
        client.get("/api/vulnerabilities", params={"sla": "whenever"}, headers=viewer).status_code
        == 422
    )

    summary = client.get("/api/vulnerabilities/summary", headers=viewer)
    assert summary.status_code == 200
    body = summary.json()
    assert body["open_total"] == 2
    assert body["untriaged"] == 2
    assert body["breached"] == 0
    assert body["unassigned"] == 2
    assert body["estate_risk"] in {"very_low", "low", "moderate", "high", "very_high"}
    assert sum(body["by_risk_level_open"].values()) == 2

    assert client.get(
        "/api/vulnerabilities", params={"unassigned": True}, headers=viewer
    ).json()["total"] == 2
    assert (
        client.get(
            "/api/vulnerabilities",
            params={"unassigned": True, "assignee": "ada"},
            headers=viewer,
        ).status_code
        == 422
    )


def _set_exposure(settings, exposures: dict[str, str | None]) -> None:
    """Force the finding-level exposure signal, keyed by CVE.

    Includes the NULL a finding scored before the signal existed carries: it is
    the case the ``unknown`` filter has to cover, and no seed produces it.
    """
    from sqlalchemy import select

    from api.db import models
    from api.db.engine import get_session

    with get_session(settings.postgres_url) as session:
        for cve, exposure in exposures.items():
            row = session.execute(
                select(models.Vulnerability).where(models.Vulnerability.cve == cve)
            ).scalar_one()
            row.network_exposure = exposure


def test_network_exposure_filter_and_summary(tmp_path, monkeypatch):
    """#173's external/internal signal is filterable, and NULL reads as unknown."""
    client = configured_client(tmp_path, monkeypatch)
    settings, _ = _seed(tmp_path)
    viewer = auth_headers(client, "viewer")
    _set_exposure(settings, {"CVE-2024-0001": "external", "CVE-2024-0002": None})

    def _cves(**params) -> list[str]:
        listed = client.get("/api/vulnerabilities", params=params, headers=viewer)
        assert listed.status_code == 200
        return [item["cve"] for item in listed.json()["items"]]

    assert _cves(network_exposure="external") == ["CVE-2024-0001"]
    # NULL is unknown, not a fourth bucket — the old rows are the ones an
    # operator most needs to see.
    assert _cves(network_exposure="unknown") == ["CVE-2024-0002"]
    assert _cves(network_exposure="internal") == []

    _set_exposure(settings, {"CVE-2024-0002": "internal"})
    assert _cves(network_exposure="internal") == ["CVE-2024-0002"]
    assert _cves(network_exposure="unknown") == []

    assert (
        client.get(
            "/api/vulnerabilities", params={"network_exposure": "dmz"}, headers=viewer
        ).status_code
        == 422
    )

    _set_exposure(settings, {"CVE-2024-0002": None})
    body = client.get("/api/vulnerabilities/summary", headers=viewer).json()
    assert body["by_network_exposure_open"] == {"external": 1, "internal": 0, "unknown": 1}
    assert sum(body["by_network_exposure_open"].values()) == body["open_total"]


def test_viewer_cannot_transition_operator_can_and_illegal_moves_are_409(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    viewer = auth_headers(client, "viewer")
    operator = auth_headers(client, "operator")
    vuln_id = client.get("/api/vulnerabilities", headers=viewer).json()["items"][0]["vuln_id"]

    assert (
        client.post(
            f"/api/vulnerabilities/{vuln_id}/transition",
            json={"state": "ACKNOWLEDGED"},
            headers=viewer,
        ).status_code
        == 403
    )

    accepted = client.post(
        f"/api/vulnerabilities/{vuln_id}/transition",
        json={"state": "ACKNOWLEDGED", "note": "triaged"},
        headers=operator,
    )
    assert accepted.status_code == 200
    assert accepted.json()["state"] == vuln_states.ACKNOWLEDGED

    # ACKNOWLEDGED → OPEN is not a move; the request is well-formed, so 409.
    conflict = client.post(
        f"/api/vulnerabilities/{vuln_id}/transition", json={"state": "OPEN"}, headers=operator
    )
    assert conflict.status_code == 409

    # An unknown state never reaches the service: it fails Pydantic validation.
    assert (
        client.post(
            f"/api/vulnerabilities/{vuln_id}/transition",
            json={"state": "WONTFIX"},
            headers=operator,
        ).status_code
        == 422
    )

    timeline = client.get(f"/api/vulnerabilities/{vuln_id}/events", headers=viewer)
    assert timeline.status_code == 200
    assert timeline.json()["items"][0]["kind"] == "state_change"
    assert timeline.json()["items"][0]["actor"] == "operator"
    assert client.get("/api/vulnerabilities/vln_nope/events", headers=viewer).status_code == 404


def test_comment_and_ticket_link(tmp_path, monkeypatch):
    """#138: comments and ticket *links* (the platform does not open tickets)."""
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    viewer = auth_headers(client, "viewer")
    operator = auth_headers(client, "operator")
    vuln_id = client.get("/api/vulnerabilities", headers=viewer).json()["items"][0]["vuln_id"]

    assert (
        client.post(
            f"/api/vulnerabilities/{vuln_id}/comment",
            json={"note": "looking at this"},
            headers=viewer,
        ).status_code
        == 403
    )
    commented = client.post(
        f"/api/vulnerabilities/{vuln_id}/comment",
        json={"note": "looking at this"},
        headers=operator,
    )
    assert commented.status_code == 200
    assert commented.json()["state"] == vuln_states.OPEN

    empty = client.post(
        f"/api/vulnerabilities/{vuln_id}/comment",
        json={"note": "   "},
        headers=operator,
    )
    assert empty.status_code == 422

    linked = client.post(
        f"/api/vulnerabilities/{vuln_id}/ticket",
        json={
            "system": "jira",
            "key": "SEC-1",
            "url": "https://jira.example/browse/SEC-1",
        },
        headers=operator,
    )
    assert linked.status_code == 200
    assert linked.json()["ticket_system"] == "jira"
    assert linked.json()["ticket_key"] == "SEC-1"

    assert (
        client.post(
            f"/api/vulnerabilities/{vuln_id}/ticket",
            json={"system": "jira"},
            headers=operator,
        ).status_code
        == 422
    )
    assert (
        client.post(
            f"/api/vulnerabilities/{vuln_id}/ticket",
            json={"system": "jira", "url": "javascript:alert(1)"},
            headers=operator,
        ).status_code
        == 422
    )

    cleared = client.delete(f"/api/vulnerabilities/{vuln_id}/ticket", headers=operator)
    assert cleared.status_code == 200
    assert cleared.json()["ticket_key"] is None

    kinds = [
        item["kind"]
        for item in client.get(f"/api/vulnerabilities/{vuln_id}/events", headers=viewer).json()[
            "items"
        ]
    ]
    assert "comment" in kinds
    assert "ticket_set" in kinds
    assert "ticket_cleared" in kinds


def test_assign_touches_only_the_keys_that_were_sent(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    operator = auth_headers(client, "operator")
    vuln_id = client.get("/api/vulnerabilities", headers=operator).json()["items"][0]["vuln_id"]

    client.post(
        f"/api/vulnerabilities/{vuln_id}/assign",
        json={"assignee": "someone@example.com", "owner_team": "payments"},
        headers=operator,
    )
    partial = client.post(
        f"/api/vulnerabilities/{vuln_id}/assign",
        json={"owner_team": "platform"},
        headers=operator,
    )
    assert partial.status_code == 200
    assert partial.json()["owner_team"] == "platform"
    assert partial.json()["assignee"] == "someone@example.com"

    cleared = client.post(
        f"/api/vulnerabilities/{vuln_id}/assign", json={"assignee": None}, headers=operator
    )
    assert cleared.json()["assignee"] is None
    assert cleared.json()["owner_team"] == "platform"


def test_requesting_risk_acceptance_is_admin_only(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    operator = auth_headers(client, "operator")
    admin = auth_headers(client, "admin")
    vuln_id = client.get("/api/vulnerabilities", headers=operator).json()["items"][0]["vuln_id"]
    until = (datetime.now(UTC) + timedelta(days=90)).isoformat()

    assert (
        client.post(
            f"/api/vulnerabilities/{vuln_id}/exception",
            json={"until": until, "reason": "vendor patch pending"},
            headers=operator,
        ).status_code
        == 403
    )

    requested = client.post(
        f"/api/vulnerabilities/{vuln_id}/exception",
        json={"until": until, "reason": "vendor patch pending"},
        headers=admin,
    )
    assert requested.status_code == 200
    # An admin asks; the clock does not stop until a risk-approver signs (#348,
    # tests/test_vuln_exception_approval.py).
    assert requested.json()["exception_state"] == "exception_requested"
    assert requested.json()["sla_state"] != "accepted"
    assert requested.json()["exception_requested_by"] == "admin"
    assert requested.json()["exception_until"] is None

    expired = client.post(
        f"/api/vulnerabilities/{vuln_id}/exception",
        json={
            "until": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
            "reason": "backdated",
        },
        headers=admin,
    )
    assert expired.status_code == 422

    withdrawn = client.delete(f"/api/vulnerabilities/{vuln_id}/exception", headers=admin)
    assert withdrawn.status_code == 200
    assert withdrawn.json()["exception_until"] is None
    assert withdrawn.json()["exception_state"] == "none"


def test_sla_policy_crud_is_admin_only(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    viewer = auth_headers(client, "viewer")
    admin = auth_headers(client, "admin")

    assert (
        client.put(
            "/api/vulnerabilities/sla-policies",
            json={"severity": "critical", "remediation_days": 7},
            headers=viewer,
        ).status_code
        == 403
    )

    created = client.put(
        "/api/vulnerabilities/sla-policies",
        json={"severity": "critical", "remediation_days": 7, "asset_criticality": 4},
        headers=admin,
    )
    assert created.status_code == 200
    policy_id = created.json()["policy_id"]

    # Same scope again is an edit, not a second policy.
    edited = client.put(
        "/api/vulnerabilities/sla-policies",
        json={"severity": "critical", "remediation_days": 3, "asset_criticality": 4},
        headers=admin,
    )
    assert edited.json()["policy_id"] == policy_id
    assert edited.json()["remediation_days"] == 3

    listed = client.get("/api/vulnerabilities/sla-policies", headers=viewer)
    assert [item["policy_id"] for item in listed.json()] == [policy_id]

    assert (
        client.put(
            "/api/vulnerabilities/sla-policies",
            json={"severity": "critical", "remediation_days": 0},
            headers=admin,
        ).status_code
        == 422
    )

    assert (
        client.delete(f"/api/vulnerabilities/sla-policies/{policy_id}", headers=admin).status_code
        == 204
    )
    assert (
        client.delete(f"/api/vulnerabilities/sla-policies/{policy_id}", headers=admin).status_code
        == 404
    )


def _retag_as_software(settings, cve: str) -> str:
    """Flip one seeded finding to ``source="endpoint_software"``.

    The real path that writes those rows has its own two files
    (``tests/test_software_findings.py``); what is under test here is the HTTP
    surface's behaviour once such a row exists, so the row is made directly
    rather than by standing up an endpoint agent.
    """
    from sqlalchemy import select

    from api.db import models
    from api.db.engine import get_session

    with get_session(settings.postgres_url) as session:
        row = session.scalars(
            select(models.Vulnerability).where(models.Vulnerability.cve == cve)
        ).one()
        row.source = "endpoint_software"
        return row.vuln_id


def test_source_filter_separates_the_two_observers(tmp_path, monkeypatch):
    """``GET /api/vulnerabilities?source=`` (Track E, M3).

    The Vulnerability Center holds both kinds of finding now, and "what did the
    endpoint inventory find" and "what did the scanner find" are different
    questions with different remediation paths.
    """
    client = configured_client(tmp_path, monkeypatch)
    settings, _ = _seed(tmp_path)
    viewer = auth_headers(client, "viewer")

    # Everything a run registers is `scan`, with no backfill: the column's
    # server default is what makes migration 0032 need none.
    assert (
        client.get("/api/vulnerabilities", params={"source": "scan"}, headers=viewer).json()[
            "total"
        ]
        == 2
    )
    assert (
        client.get(
            "/api/vulnerabilities", params={"source": "endpoint_software"}, headers=viewer
        ).json()["total"]
        == 0
    )

    _retag_as_software(settings, "CVE-2024-0002")

    assert (
        client.get(
            "/api/vulnerabilities", params={"source": "endpoint_software"}, headers=viewer
        ).json()["total"]
        == 1
    )
    assert (
        client.get("/api/vulnerabilities", params={"source": "scan"}, headers=viewer).json()[
            "total"
        ]
        == 1
    )
    assert (
        client.get(
            "/api/vulnerabilities", params={"source": "telepathy"}, headers=viewer
        ).status_code
        == 422
    )


def test_verifying_a_software_finding_is_refused(tmp_path, monkeypatch):
    """A network re-scan cannot observe an installed package.

    ``_verification_target`` would happily return the asset's address and a
    scan would happily run, and the finding would then be closed as
    ``machine_verified`` on the strength of a scan that never looked at it —
    the exact thing the verification loop exists to prevent. Its verification
    is the device's next accepted inventory snapshot.
    """
    client = configured_client(tmp_path, monkeypatch)
    settings, _ = _seed(tmp_path)
    operator = auth_headers(client, "operator")
    vuln_id = _retag_as_software(settings, "CVE-2024-0001")

    response = client.post(f"/api/vulnerabilities/{vuln_id}/verify", headers=operator)
    assert response.status_code == 409
    assert "inventory" in response.json()["detail"]
    # And it stays where it was rather than parking in VERIFYING with nothing
    # looking at it.
    assert (
        client.get(f"/api/vulnerabilities/{vuln_id}", headers=operator).json()["state"]
        == vuln_states.OPEN
    )
