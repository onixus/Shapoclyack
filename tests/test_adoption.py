"""Adoption metrics (ROADMAP Track E, "What to measure").

What is under test is the shape of the numbers as much as their values: a
share with no denominator is ``None`` rather than a percentage that reads as
either a triumph or a disaster, closures are read from the finding row so this
page and the summary agree, and the window really excludes older closures.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import update

from api.db import models
from api.db.engine import get_session
from api.services import adoption, vuln_states
from api.services import vulnerabilities as vulns
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres
from tests.test_vuln_lifecycle import _seed, _settings

pytestmark = requires_postgres


def _close(settings, tenant_id: str, vuln_id: str, *, actor: str, closed_at: datetime | None = None,
           machine_verified: bool = False) -> None:
    vulns.transition(settings, tenant_id=tenant_id, vuln_id=vuln_id, to_state=vuln_states.CLOSED, actor=actor)
    values: dict = {}
    if closed_at is not None:
        values["closed_at"] = closed_at.replace(tzinfo=None)
    if machine_verified:
        values["machine_verified"] = True
        values["closure_reason"] = "verified_remediated"
    if values:
        with get_session(settings.postgres_url) as session:
            session.execute(
                update(models.Vulnerability).where(models.Vulnerability.vuln_id == vuln_id).values(**values)
            )


def _ids(settings, tenant_id: str) -> dict[str, str]:
    items, _ = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)
    return {item["cve"]: item["vuln_id"] for item in items}


def test_an_empty_tenant_reports_no_shares_rather_than_zero(tmp_path):
    settings = _settings(tmp_path)
    from api.services import tenants as tenants_service

    report = adoption.metrics(settings, tenant_id=tenants_service.DEFAULT_TENANT_ID)

    assert report["findings"]["open"] == 0
    assert report["findings"]["closed_in_window"] == 0
    assert report["findings"]["machine_verified_share"] is None
    assert report["findings"]["closed_within_sla_share"] is None
    assert report["findings"]["mttr_hours"] is None
    assert report["assets"]["active"] == 0
    assert report["assets"]["with_owner_share"] is None
    assert report["assets"]["scanned_recently_share"] is None
    assert report["analysts"] == []
    assert report["onboarding"]["tenant_created_at"] is not None
    assert report["onboarding"]["first_successful_scan_at"] is None
    assert report["onboarding"]["hours_to_first_scan"] is None
    # Enrichment age is reported even for an empty tenant: it is a property of
    # the installation, and a stale overlay is stale for everyone.
    assert {row["name"] for row in report["enrichment"]}


def test_closures_are_read_from_the_finding_and_the_summary_agrees(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    ids = _ids(settings, tenant_id)
    vulns.assign(settings, tenant_id=tenant_id, vuln_id=ids["CVE-2024-0001"], assignee="alice", actor="admin")
    _close(settings, tenant_id, ids["CVE-2024-0001"], actor="alice", machine_verified=True)

    report = adoption.metrics(settings, tenant_id=tenant_id, window_days=30)
    summary = vulns.summary(settings, tenant_id=tenant_id)

    findings = report["findings"]
    assert findings["open"] == 1
    assert findings["closed_in_window"] == summary["closed_total"] == 1
    assert findings["machine_verified_closed"] == summary["machine_verified_closed"] == 1
    assert findings["machine_verified_share"] == 100.0
    # Closed today against a deadline days away: inside SLA.
    assert findings["closed_within_sla_share"] == 100.0
    assert findings["mttr_hours"] is not None and findings["mttr_hours"] < 1.0
    assert findings["mttr_hours_by_severity"]["critical"] == findings["mttr_hours"]
    assert findings["mttr_hours_by_severity"]["medium"] is None
    assert findings["open_per_asset"] == 1.0
    assert report["analysts"] == [{"analyst": "alice", "closed": 1, "machine_verified": 1}]

    assets = report["assets"]
    assert assets["active"] == 1
    assert assets["with_owner_share"] == 0.0
    assert assets["unowned"] == 1
    assert assets["scanned_recently_share"] == 100.0
    assert assets["dual_source_share"] == 0.0
    assert report["onboarding"]["first_tracked_finding_at"] is not None


def test_the_window_excludes_older_closures_and_manual_ones_count_as_unverified(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    ids = _ids(settings, tenant_id)
    long_ago = datetime.now(UTC) - timedelta(days=200)
    _close(settings, tenant_id, ids["CVE-2024-0001"], actor="bob", closed_at=long_ago)
    _close(settings, tenant_id, ids["CVE-2024-0002"], actor="bob")

    report = adoption.metrics(settings, tenant_id=tenant_id, window_days=90)

    findings = report["findings"]
    assert findings["closed_in_window"] == 1
    assert findings["machine_verified_closed"] == 0
    assert findings["machine_verified_share"] == 0.0
    # Nobody was assigned: the closure is attributed to "unassigned", not to
    # whoever pressed the button, because the question is about ownership.
    assert report["analysts"] == [{"analyst": adoption.UNASSIGNED, "closed": 1, "machine_verified": 0}]

    wide = adoption.metrics(settings, tenant_id=tenant_id, window_days=365)
    assert wide["findings"]["closed_in_window"] == 2


def test_owner_and_context_shares_follow_the_asset_columns(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.Asset)
            .where(models.Asset.tenant_id == tenant_id)
            .values(owner_email="owner@example.com", environment="prod")
        )

    report = adoption.metrics(settings, tenant_id=tenant_id)

    assert report["assets"]["with_owner_share"] == 100.0
    assert report["assets"]["with_context_share"] == 100.0
    assert report["assets"]["unowned"] == 0


def test_route_is_viewer_readable_and_bounds_the_window(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    make_settings(tmp_path)
    viewer = auth_headers(client, "viewer")

    ok = client.get("/api/adoption", headers=viewer)
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["window_days"] == adoption.DEFAULT_WINDOW_DAYS
    assert set(body) >= {"findings", "assets", "analysts", "onboarding", "enrichment"}

    assert client.get("/api/adoption", params={"window_days": 3}, headers=viewer).status_code == 422
    assert client.get("/api/adoption", params={"window_days": 30}, headers=viewer).json()["window_days"] == 30
    assert client.get("/api/adoption").status_code == 401
