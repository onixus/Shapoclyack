"""Unit tests for NATS ingest gateway helpers (no live broker required)."""

from __future__ import annotations

import io
import tarfile

import pytest

from api.services import nats_bus, results_ingest


def _archive(name: str = "findings.json", data: bytes = b'{"ok":true}\n') -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_validate_archive_rejects_traversal():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b"x"
        info = tarfile.TarInfo(name="../evil")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    with pytest.raises(results_ingest.IngestError):
        results_ingest.validate_archive(buf.getvalue())


def test_ingest_msg_id_stable():
    a = nats_bus.ingest_msg_id(job_id="j1", run_id="r1", archive_sha256="abc")
    b = nats_bus.ingest_msg_id(job_id="j1", run_id="r1", archive_sha256="abc")
    c = nats_bus.ingest_msg_id(job_id="j1", run_id="r1", archive_sha256="abd")
    assert a == b
    assert a != c


def test_publish_raw_results_without_nats(monkeypatch):
    nats_bus.reset_bus_for_tests()
    archive = _archive()
    meta = results_ingest.publish_raw_results(
        nats_url="",
        job_id="job1",
        run_id="run1",
        agent_id="agent1",
        exit_code=0,
        archive_bytes=archive,
    )
    assert meta["published"] is False
    assert meta["msg_id"]
    assert meta["archive_sha256"] == nats_bus.archive_sha256(archive)


def test_claim_specific_job_id(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from api.app import create_app
    from api.settings import Settings
    from api.services import agents as agents_service
    from api.services import jobs as jobs_service

    settings = Settings(
        output_dir=tmp_path / "output",
        state_dir=tmp_path / "state",
        allow_scan_start=True,
        job_execution_mode="agent",
        agent_token="test-agent-token",
        jwt_secret="test-secret",
        nats_url="",
    )
    settings.output_dir.mkdir(parents=True)
    settings.state_dir.mkdir(parents=True)
    monkeypatch.setattr("api.auth.load_settings", lambda: settings)
    monkeypatch.setattr("api.app.get_settings", lambda: settings)
    jobs_service._JOBS.clear()  # noqa: SLF001
    agents_service._agents.clear()  # noqa: SLF001
    client = TestClient(create_app())

    reg = client.post(
        "/api/agent/register",
        headers={"Authorization": "Bearer test-agent-token"},
        json={"hostname": "w"},
    )
    agent_id = reg.json()["agent_id"]
    login = client.post(
        "/api/auth/login",
        json={"username": "operator", "password": "operator-change-me"},
    )
    token = login.json()["access_token"]
    j1 = client.post(
        "/api/jobs",
        headers={"Authorization": f"Bearer {token}"},
        json={"mode": "safe"},
    ).json()
    j2 = client.post(
        "/api/jobs",
        headers={"Authorization": f"Bearer {token}"},
        json={"mode": "safe"},
    ).json()

    # Claim the second job specifically (NATS path).
    claimed = client.post(
        f"/api/agent/jobs/claim?agent_id={agent_id}&job_id={j2['job_id']}",
        headers={"Authorization": "Bearer test-agent-token"},
    )
    assert claimed.status_code == 200
    assert claimed.json()["job_id"] == j2["job_id"]

    # First job still queued for generic claim.
    other = client.post(
        f"/api/agent/jobs/claim?agent_id={agent_id}",
        headers={"Authorization": "Bearer test-agent-token"},
    )
    assert other.status_code == 200
    assert other.json()["job_id"] == j1["job_id"]
