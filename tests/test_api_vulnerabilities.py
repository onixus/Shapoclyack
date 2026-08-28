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


def test_accepting_risk_is_admin_only(tmp_path, monkeypatch):
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

    accepted = client.post(
        f"/api/vulnerabilities/{vuln_id}/exception",
        json={"until": until, "reason": "vendor patch pending"},
        headers=admin,
    )
    assert accepted.status_code == 200
    assert accepted.json()["sla_state"] == "accepted"
    assert accepted.json()["exception_by"] == "admin"

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
