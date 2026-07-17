from __future__ import annotations

import io
import tarfile
from pathlib import Path

from fastapi.testclient import TestClient

from api.app import create_app
from api.settings import Settings


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    base = Settings(
        output_dir=tmp_path / "output",
        state_dir=tmp_path / "state",
        config_path=Path("scanner/config/default.yaml"),
        allow_scan_start=True,
        job_execution_mode="agent",
        agent_token="test-agent-token",
        agent_stale_seconds=120,
        jwt_secret="test-secret",
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def _client(tmp_path: Path, monkeypatch, **overrides: object) -> TestClient:
    settings = _settings(tmp_path, **overrides)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("api.auth.load_settings", lambda: settings)
    monkeypatch.setattr("api.app.get_settings", lambda: settings)
    # Reset in-memory registries between tests via fresh app + load.
    from api.services import agents as agents_service
    from api.services import jobs as jobs_service

    jobs_service._JOBS.clear()  # noqa: SLF001
    agents_service._agents.clear()  # noqa: SLF001
    return TestClient(create_app())


def _operator_token(client: TestClient) -> str:
    response = client.post(
        "/api/auth/login",
        json={"username": "operator", "password": "operator-change-me"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


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

    token = _operator_token(client)
    listed = client.get("/api/agents", headers={"Authorization": f"Bearer {token}"})
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert listed.json()[0]["hostname"] == "edge-1"


def test_agent_claim_and_upload_results(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    reg = client.post(
        "/api/agent/register",
        headers=_agent_headers(),
        json={"hostname": "worker"},
    )
    agent_id = reg.json()["agent_id"]

    token = _operator_token(client)
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
    token = _operator_token(client)
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
