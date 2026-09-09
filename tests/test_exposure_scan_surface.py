"""An operator-declared scan surface as evidence of network exposure (#171).

The scorer refuses to read a public address as "internet-facing", which on a
real installation left nearly every finding at ``unknown`` and the console's
external-surface counter at zero. A surface the operator *declared* on the scan
request is a named decision and does count; the one the server derived from the
targets does not. These tests hold that line at both ends: the helper that
decides which surfaces qualify, and the tracked findings a run produces.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from api.services import scan_surface
from api.services import vulnerabilities as vulns
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres

pytestmark = requires_postgres

_HOSTS = [{"host": "8.8.8.8", "hostname": "app.example.com"}]
_FINDINGS = [
    {"host": "8.8.8.8", "port": "443", "cve": "CVE-2024-0001", "cvss": 9.8, "severity": "critical"},
]


def test_declared_surface_for_job_accepts_only_a_declaration():
    """Derived is the address-space rule again; ``mixed`` names both answers."""
    assert scan_surface.declared_surface_for_job(
        {"surface": "external", "surface_source": "operator"}
    ) == "external"
    assert scan_surface.declared_surface_for_job(
        {"surface": "internal", "surface_source": "operator"}
    ) == "internal"
    assert (
        scan_surface.declared_surface_for_job(
            {"surface": "external", "surface_source": "derived"}
        )
        is None
    )
    assert (
        scan_surface.declared_surface_for_job({"surface": "mixed", "surface_source": "operator"})
        is None
    )
    # A job written before the surface was recorded at all, and one with none.
    assert scan_surface.declared_surface_for_job({"mode": "balanced"}) is None
    assert scan_surface.declared_surface_for_job(None) is None


def _seed_run(tmp_path: Path, *, scan_options: dict) -> tuple:
    """One finding on a public host, registered from a run owned by a job.

    The job is inserted directly rather than started through ``start_scan``:
    what is under test is how the tracker reads ``scan_options`` off whatever
    job owns the run, not how the job came to have them.
    """
    from api.db import models
    from api.db.engine import get_session
    from api.services import assets as assets_service
    from api.services import job_states
    from api.services import tenants as tenants_service

    settings = make_settings(tmp_path)
    run_dir = settings.output_dir / "runs" / "run-1"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "alive_hosts.json").write_text(json.dumps(_HOSTS), encoding="utf-8")
    (run_dir / "vulnerabilities.json").write_text(json.dumps(_FINDINGS), encoding="utf-8")

    tenant_id = tenants_service.DEFAULT_TENANT_ID
    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        session.add(
            models.Job(
                job_id="job-surface-1",
                tenant_id=tenant_id,
                status=job_states.SUCCEEDED,
                execution="local",
                mode="balanced",
                run_id="run-1",
                command=["echo"],
                scan_options=scan_options,
                requested_by="admin",
                queued_at=now,
            )
        )

    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    return settings, tenant_id


def test_run_from_an_operator_declared_external_job_marks_findings_external(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    _seed_run(
        tmp_path,
        scan_options={"mode": "balanced", "surface": "external", "surface_source": "operator"},
    )
    viewer = auth_headers(client, "viewer")

    listed = client.get(
        "/api/vulnerabilities", params={"network_exposure": "external"}, headers=viewer
    )
    assert listed.status_code == 200
    body = listed.json()
    assert body["total"] == 1
    assert body["items"][0]["network_exposure"] == "external"
    assert body["items"][0]["network_exposure_source"] == "scan-surface"

    summary = client.get("/api/vulnerabilities/summary", headers=viewer)
    assert summary.json()["by_network_exposure_open"]["external"] == 1


def test_run_from_a_derived_surface_leaves_exposure_unknown(tmp_path, monkeypatch):
    """The same public host, classified by the server: still no evidence."""
    client = configured_client(tmp_path, monkeypatch)
    _seed_run(
        tmp_path,
        scan_options={"mode": "balanced", "surface": "external", "surface_source": "derived"},
    )
    viewer = auth_headers(client, "viewer")

    listed = client.get("/api/vulnerabilities", headers=viewer)
    item = listed.json()["items"][0]
    assert item["network_exposure"] == "unknown"
    assert item["network_exposure_source"] == "none"
