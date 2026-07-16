from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from api.app import create_app
from api.schemas import JobInfo


def _client() -> TestClient:
    return TestClient(create_app())


def _token(client: TestClient, username: str, password: str) -> str:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


def test_viewer_cannot_start_jobs():
    client = _client()
    token = _token(client, "viewer", "viewer-change-me")
    response = client.post(
        "/api/jobs",
        headers={"Authorization": f"Bearer {token}"},
        json={"mode": "balanced"},
    )
    assert response.status_code == 403


def test_operator_can_start_jobs():
    client = _client()
    token = _token(client, "operator", "operator-change-me")

    fake = JobInfo(
        job_id="abc123",
        status="queued",
        run_id=None,
        mode="balanced",
        command=["python", "-m", "scanner.main"],
        started_at=None,
        finished_at=None,
        exit_code=None,
        error=None,
        requested_by="operator",
    )
    with patch("api.routes.jobs.jobs_service.start_scan", return_value=fake):
        response = client.post(
            "/api/jobs",
            headers={"Authorization": f"Bearer {token}"},
            json={"mode": "balanced", "delta": False, "skip_nse": True, "notify": False},
        )
    assert response.status_code == 202
    assert response.json()["job_id"] == "abc123"
