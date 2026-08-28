from __future__ import annotations

import io
import tarfile
from pathlib import Path

from fastapi.testclient import TestClient

from api.settings import Settings
from tests.conftest import configured_client, login, make_settings, requires_postgres

pytestmark = requires_postgres


# Agent mode, but with the legacy shared token still configured.
SETTINGS = {"job_execution_mode": "agent"}


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    return make_settings(tmp_path, **{**SETTINGS, **overrides})


def _client(tmp_path: Path, monkeypatch, **overrides: object) -> TestClient:
    return configured_client(tmp_path, monkeypatch, **{**SETTINGS, **overrides})


def _agent_headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-agent-token"}


def test_agent_api_requires_auth_when_legacy_token_unset(tmp_path, monkeypatch):
    """Without OCTO_AGENT_TOKEN, agent routes still accept provisioning JWTs but require a bearer."""
    client = _client(tmp_path, monkeypatch, agent_token="")
    response = client.post("/api/agent/register", json={"hostname": "a"})
    assert response.status_code == 401


def test_agent_register_heartbeat_and_list(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    reg = client.post(
        "/api/agent/register",
        headers=_agent_headers(),
        json={"hostname": "edge-1", "version": "0.3.2.1", "labels": {"zone": "lab"}},
    )
    assert reg.status_code == 200
    agent_id = reg.json()["agent_id"]
    assert reg.json()["online"] is True

    hb = client.post(
        "/api/agent/heartbeat",
        headers=_agent_headers(),
        json={"agent_id": agent_id, "status": "idle"},
    )
    assert hb.status_code == 200
    assert hb.json()["status"] == "idle"

    token = login(client, "operator")
    listed = client.get("/api/agents", headers={"Authorization": f"Bearer {token}"})
    assert listed.status_code == 200
    body = listed.json()
    assert body["total"] == 1
    assert body["items"][0]["hostname"] == "edge-1"


def test_stale_agents_are_searchable_and_sortable_by_the_status_returned(tmp_path, monkeypatch):
    """`status` is derived: the row keeps what the agent reported, the response
    says "stale" past agent_stale_seconds. Search and sort must run against the
    value the caller actually sees, or ?q=stale would match nothing and
    sort=status would order the page by invisible values."""
    from datetime import UTC, datetime, timedelta

    from api.db import models
    from api.db.engine import get_session

    client = _client(tmp_path, monkeypatch)
    settings = _settings(tmp_path)
    for hostname in ("fresh-1", "old-1"):
        client.post("/api/agent/register", headers=_agent_headers(), json={"hostname": hostname})

    with get_session(settings.postgres_url) as session:
        row = session.query(models.Agent).filter_by(hostname="old-1").one()
        row.last_seen_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(
            seconds=settings.agent_stale_seconds + 60
        )
        stale_id = row.agent_id

    headers = {"Authorization": f"Bearer {login(client, 'operator')}"}
    found = client.get("/api/agents?q=stale", headers=headers).json()
    assert [item["agent_id"] for item in found["items"]] == [stale_id]
    assert found["total"] == 1

    ordered = client.get("/api/agents?sort=status&order=asc", headers=headers).json()
    assert [item["status"] for item in ordered["items"]] == ["idle", "stale"]


def test_legacy_agent_import_rehomes_an_unknown_tenant(tmp_path, monkeypatch):
    """load_agents runs inside create_app(). tenant_id is a FK, so an agent whose
    tenant is gone -- a tenant database restored separately from the state
    volume, say -- would fail startup and do it again on every restart. Re-home
    it instead, as the job importer does."""
    import json

    from api.services import agents as agents_service

    client = _client(tmp_path, monkeypatch)  # seeds the default tenant
    settings = _settings(tmp_path)
    (settings.state_dir / "api_agents.json").write_text(
        json.dumps([{"agent_id": "orphan-1", "hostname": "h", "tenant_id": "ten_deleted"}]),
        encoding="utf-8",
    )

    agents_service.load_agents(settings)

    imported = agents_service.get_agent("orphan-1")
    assert imported is not None
    assert imported.tenant_id == "default"
    assert client.app is not None  # the app that seeded the tenant is still usable


def test_agent_claim_and_upload_results(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    reg = client.post(
        "/api/agent/register",
        headers=_agent_headers(),
        json={"hostname": "worker"},
    )
    agent_id = reg.json()["agent_id"]

    token = login(client, "operator")
    job = client.post(
        "/api/jobs",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "mode": "safe",
            "skip_nse": True,
            "ranges": "127.0.0.1\n",
            "domains": "\n",
            "ports": "80\n",
        },
    )
    assert job.status_code == 202
    body = job.json()
    assert body["execution"] == "agent"
    assert body["status"] == "queued"
    assert body["run_id"]
    job_id = body["job_id"]
    run_id = body["run_id"]

    empty = client.post(
        f"/api/agent/jobs/claim?agent_id={agent_id}xx",
        headers=_agent_headers(),
    )
    assert empty.status_code == 404

    claimed = client.post(
        f"/api/agent/jobs/claim?agent_id={agent_id}",
        headers=_agent_headers(),
    )
    assert claimed.status_code == 200
    assert claimed.json()["job_id"] == job_id
    assert "ranges.txt" in claimed.json()["inputs"]
    assert "ports.txt" in claimed.json()["inputs"]

    # Second claim should be empty while job is running.
    none = client.post(
        f"/api/agent/jobs/claim?agent_id={agent_id}",
        headers=_agent_headers(),
    )
    assert none.status_code == 204

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b'{"ok": true}\n'
        info = tarfile.TarInfo(name="findings.json")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
        summary = b'{"alive_hosts": 1}\n'
        sinfo = tarfile.TarInfo(name="summary.json")
        sinfo.size = len(summary)
        tf.addfile(sinfo, io.BytesIO(summary))
    archive = buf.getvalue()

    done = client.post(
        f"/api/agent/jobs/{job_id}/results",
        headers=_agent_headers(),
        data={
            "agent_id": agent_id,
            "exit_code": "0",
            "run_id": run_id,
        },
        files={"archive": ("run.tar.gz", archive, "application/gzip")},
    )
    assert done.status_code == 200
    assert done.json()["status"] == "succeeded"
    assert done.json()["assigned_agent_id"] == agent_id

    settings = _settings(tmp_path)
    run_dir = settings.output_dir / "runs" / run_id
    assert (run_dir / "findings.json").is_file()
    pointer = settings.state_dir / "latest_run.json"
    assert pointer.is_file()
    assert run_id in pointer.read_text(encoding="utf-8")


def test_reject_path_traversal_archive(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    reg = client.post(
        "/api/agent/register",
        headers=_agent_headers(),
        json={"hostname": "worker"},
    )
    agent_id = reg.json()["agent_id"]
    token = login(client, "operator")
    job = client.post(
        "/api/jobs",
        headers={"Authorization": f"Bearer {token}"},
        json={"mode": "safe"},
    )
    job_id = job.json()["job_id"]
    run_id = job.json()["run_id"]
    client.post(f"/api/agent/jobs/claim?agent_id={agent_id}", headers=_agent_headers())

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b"nope"
        info = tarfile.TarInfo(name="../evil.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    bad = client.post(
        f"/api/agent/jobs/{job_id}/results",
        headers=_agent_headers(),
        data={"agent_id": agent_id, "exit_code": "0", "run_id": run_id},
        files={"archive": ("run.tar.gz", buf.getvalue(), "application/gzip")},
    )
    assert bad.status_code == 422


def test_operator_cancels_a_queued_job_but_not_one_already_running(tmp_path, monkeypatch):
    """POST /jobs/{id}/cancel (ROADMAP P1.3) only prevents execution: once the
    agent reports the scan started there is no channel to stop it, so the API
    answers 409 rather than marking a stop that never happened."""
    client = _client(tmp_path, monkeypatch)
    agent_id = client.post(
        "/api/agent/register", headers=_agent_headers(), json={"hostname": "worker"}
    ).json()["agent_id"]
    token = login(client, "operator")
    auth = {"Authorization": f"Bearer {token}"}

    first = client.post("/api/jobs", headers=auth, json={"mode": "safe"}).json()["job_id"]
    cancelled = client.post(f"/api/jobs/{first}/cancel", headers=auth)
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    assert cancelled.json()["error"] == "Cancelled by operator"

    # A cancelled job is no longer claimable.
    assert client.post(
        f"/api/agent/jobs/claim?agent_id={agent_id}", headers=_agent_headers()
    ).status_code == 204

    second = client.post("/api/jobs", headers=auth, json={"mode": "safe"}).json()["job_id"]
    client.post(f"/api/agent/jobs/claim?agent_id={agent_id}", headers=_agent_headers())
    assert client.get(f"/api/jobs/{second}", headers=auth).json()["status"] == "claimed"

    # The heartbeat naming the job is what promotes claimed → running.
    client.post(
        "/api/agent/heartbeat",
        headers=_agent_headers(),
        json={"agent_id": agent_id, "status": "busy", "current_job_id": second},
    )
    assert client.get(f"/api/jobs/{second}", headers=auth).json()["status"] == "running"

    conflict = client.post(f"/api/jobs/{second}/cancel", headers=auth)
    assert conflict.status_code == 409

    assert client.post("/api/jobs/nope/cancel", headers=auth).status_code == 404


def test_viewer_cannot_cancel_a_job(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    operator = {"Authorization": f"Bearer {login(client, 'operator')}"}
    job_id = client.post("/api/jobs", headers=operator, json={"mode": "safe"}).json()["job_id"]

    viewer = {"Authorization": f"Bearer {login(client, 'viewer')}"}
    assert client.post(f"/api/jobs/{job_id}/cancel", headers=viewer).status_code == 403


def test_results_upload_over_body_cap_is_rejected_before_the_route(tmp_path, monkeypatch):
    """#222: the archive part was buffered in full before anything looked at it.

    The cap is a Content-Length check, so the rejection is a middleware response
    and the job is left untouched — no run directory, no terminal status.
    """
    client = _client(tmp_path, monkeypatch, agent_results_max_body_bytes=512)
    reg = client.post(
        "/api/agent/register",
        headers=_agent_headers(),
        json={"hostname": "worker"},
    )
    agent_id = reg.json()["agent_id"]

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b"x" * 8192
        info = tarfile.TarInfo(name="findings.json")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    resp = client.post(
        "/api/agent/jobs/job-does-not-exist/results",
        headers=_agent_headers(),
        data={"agent_id": agent_id, "exit_code": "0", "run_id": "run-1"},
        files={"archive": ("run.tar.gz", buf.getvalue(), "application/gzip")},
    )
    assert resp.status_code == 413
    assert "exceeds limit 512" in resp.json()["detail"]
    # A missing job would answer 404 — proof the cap ran before routing.
    assert not (make_settings(tmp_path).output_dir / "runs" / "run-1").exists()


def test_claim_endpoint_is_not_capped_by_the_results_limit(tmp_path, monkeypatch):
    """The results cap is matched by pattern, not by the shared path prefix:
    ``/api/agent/jobs/claim`` must keep answering normally."""
    client = _client(tmp_path, monkeypatch, agent_results_max_body_bytes=1)
    reg = client.post(
        "/api/agent/register",
        headers=_agent_headers(),
        json={"hostname": "worker"},
    )
    agent_id = reg.json()["agent_id"]
    claimed = client.post(
        f"/api/agent/jobs/claim?agent_id={agent_id}",
        headers=_agent_headers(),
    )
    assert claimed.status_code == 204
