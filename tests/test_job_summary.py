"""``GET /api/jobs/summary`` — queue depth by status and by surface.

The counts a scan console renders above the job list. They are one grouped
query rather than a page of jobs the client tallies itself: the console shows
them on every screen, and a tally over one page is wrong the moment the queue
is longer than the page.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from api.schemas import StartScanRequest
from api.services import agents as agents_service
from api.services import job_states
from api.services import jobs as jobs_service
from api.services import tenants as tenants_service
from tests.conftest import (
    approve_scan_scope,
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres


@pytest.fixture()
def settings(tmp_path: Path):
    """Agent mode keeps ``start_scan`` from spawning a real scanner thread —
    these tests are about the rows it writes."""
    base = make_settings(tmp_path, job_execution_mode="agent")
    base.state_dir.mkdir(parents=True, exist_ok=True)
    base.output_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(base)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(base)
    approve_scan_scope(base)
    agents_service.configure(base)
    return base


def test_summary_counts_by_status_and_by_surface(settings):
    external = jobs_service.start_scan(
        settings, StartScanRequest(domains="example.com"), username="admin"
    )
    internal = jobs_service.start_scan(
        settings, StartScanRequest(ranges="10.0.0.0/24"), username="admin"
    )
    mixed = jobs_service.start_scan(
        settings, StartScanRequest(ranges="10.0.0.1", domains="example.com"), username="admin"
    )
    # No targets: the server's default input files, which nothing classifies.
    jobs_service.start_scan(settings, StartScanRequest(), username="admin")

    jobs_service.force_status(settings, external.job_id, job_states.RUNNING)
    jobs_service.force_status(settings, internal.job_id, job_states.CLAIMED)
    jobs_service.force_status(settings, mixed.job_id, job_states.SUCCEEDED)

    result = jobs_service.summary(settings)

    # All six lifecycle states, zero-filled: a console renders a stable set of
    # tiles rather than one that appears as jobs happen to exist.
    assert set(result["by_status"]) == set(job_states.ALL)
    assert result["by_status"] == {
        "queued": 1,
        "claimed": 1,
        "running": 1,
        "succeeded": 1,
        "failed": 0,
        "cancelled": 0,
    }
    assert result["running"] == 1
    # queued + claimed: a job an agent holds but has not started is still work
    # waiting to be done.
    assert result["queued"] == 2
    assert result["by_surface"] == {
        "external": {"running": 1, "queued": 0, "total": 1},
        "internal": {"running": 0, "queued": 1, "total": 1},
        "mixed": {"running": 0, "queued": 0, "total": 1},
        "unknown": {"running": 0, "queued": 1, "total": 1},
    }
    assert result["generated_at"]


def test_summary_counts_only_the_named_tenant(settings):
    tenants_service.create_tenant(tenant_id="ten_a", name="Tenant A")
    approve_scan_scope(settings, "ten_a")
    jobs_service.start_scan(
        settings, StartScanRequest(domains="example.com"), username="admin"
    )
    jobs_service.start_scan(
        settings,
        StartScanRequest(domains="other.example", tenant_id="ten_a"),
        username="admin",
    )

    mine = jobs_service.summary(settings, tenant_id="default")
    assert mine["by_status"]["queued"] == 1
    assert mine["by_surface"]["external"]["total"] == 1

    # No tenant named: the fleet-wide view only an unscoped platform admin gets.
    fleet = jobs_service.summary(settings)
    assert fleet["by_status"]["queued"] == 2
    assert fleet["by_surface"]["external"]["total"] == 2


def test_summary_over_http_is_operator_only(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch, job_execution_mode="agent")
    operator = auth_headers(client, "operator")
    client.post("/api/jobs", headers=operator, json={"mode": "safe", "ranges": "10.0.0.0/24"})

    response = client.get("/api/jobs/summary", headers=operator)
    assert response.status_code == 200
    body = response.json()
    assert body["queued"] == 1
    assert body["by_surface"]["internal"] == {"running": 0, "queued": 1, "total": 1}

    # Starting a scan is operator work, and so is watching the queue it feeds.
    assert client.get("/api/jobs/summary", headers=auth_headers(client, "viewer")).status_code == 403


def test_summary_is_not_read_as_a_job_id(tmp_path, monkeypatch):
    """The route is declared before ``/{job_id}``; without that ordering this
    would 404 as a lookup for the job called "summary"."""
    client = configured_client(tmp_path, monkeypatch, job_execution_mode="agent")
    assert client.get("/api/jobs/summary", headers=auth_headers(client, "operator")).status_code == 200
