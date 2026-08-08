from __future__ import annotations

from unittest.mock import patch


from api.schemas import JobInfo
from tests.conftest import api_client, login, requires_postgres

pytestmark = requires_postgres




def test_viewer_cannot_start_jobs():
    client = api_client()
    token = login(client, "viewer")
    response = client.post(
        "/api/jobs",
        headers={"Authorization": f"Bearer {token}"},
        json={"mode": "balanced"},
    )
    assert response.status_code == 403


def test_operator_can_start_jobs():
    client = api_client()
    token = login(client, "operator")

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
