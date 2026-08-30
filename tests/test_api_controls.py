"""API tests for the security controls matrix endpoint GET /api/runs/{run_id}/controls."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from api.app import create_app
from api.settings import Settings
from tests.conftest import auth_headers, login, requires_postgres

pytestmark = requires_postgres


def _setup_test_run(output_dir: Path, run_id: str, *, with_controls: bool = True) -> None:
    run_dir = output_dir / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run_meta.json").write_text(
        json.dumps({"run_id": run_id, "profile": "balanced"}),
        encoding="utf-8",
    )
    (run_dir / "tenant.json").write_text(
        json.dumps({"tenant_id": "default"}),
        encoding="utf-8",
    )

    if with_controls:
        (run_dir / "controls.json").write_text(
            json.dumps({
                "overall_verdict": "fail",
                "overall_risk": "high",
                "evaluated_at": "2026-08-30T10:00:00Z",
                "controls": [
                    {
                        "control": "dns_structure",
                        "title": "DNS структура",
                        "status": "ok",
                        "impact": "medium",
                        "risk_level": "very_low",
                        "coverage": {"checked": 5, "total": 5},
                        "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                        "top_findings": [],
                        "evidence": ["dns_hygiene.json"],
                        "why": "All 5 domains passed",
                    },
                    {
                        "control": "mail_protection",
                        "title": "Почтовая защита",
                        "status": "fail",
                        "impact": "high",
                        "risk_level": "high",
                        "coverage": {"checked": 2, "total": 2},
                        "findings_by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0},
                        "top_findings": [
                            {
                                "id": "dmarc_missing",
                                "domain": "example.com",
                                "severity": "high",
                                "detail": "Missing DMARC policy",
                            }
                        ],
                        "evidence": ["mail_posture.json"],
                        "why": "1 high issue",
                    },
                ],
            }),
            encoding="utf-8",
        )


def _client(tmp_path: Path) -> TestClient:
    output = tmp_path / "output"
    state = tmp_path / "state"
    output.mkdir(exist_ok=True)
    state.mkdir(exist_ok=True)

    _setup_test_run(output, "run-with-controls", with_controls=True)
    _setup_test_run(output, "run-without-controls", with_controls=False)

    settings = Settings(output_dir=output, state_dir=state)
    app = create_app()
    from api.auth import get_settings

    app.dependency_overrides[get_settings] = lambda: settings
    return TestClient(app)


def test_get_controls_success(tmp_path: Path):
    client = _client(tmp_path)
    headers = auth_headers(client, "viewer")

    response = client.get("/api/runs/run-with-controls/controls", headers=headers)
    assert response.status_code == 200, response.text
    data = response.json()

    assert data["overall_verdict"] == "fail"
    assert data["overall_risk"] == "high"
    assert len(data["controls"]) == 2
    assert data["controls"][0]["control"] == "dns_structure"
    assert data["controls"][0]["status"] == "ok"
    assert data["controls"][1]["control"] == "mail_protection"
    assert data["controls"][1]["status"] == "fail"
    assert len(data["controls"][1]["top_findings"]) == 1


def test_get_controls_missing_artifact(tmp_path: Path):
    client = _client(tmp_path)
    headers = auth_headers(client, "viewer")

    response = client.get("/api/runs/run-without-controls/controls", headers=headers)
    assert response.status_code == 404
    assert "Controls summary not found" in response.json()["detail"]


def test_get_controls_nonexistent_run(tmp_path: Path):
    client = _client(tmp_path)
    headers = auth_headers(client, "viewer")

    response = client.get("/api/runs/nonexistent-run/controls", headers=headers)
    assert response.status_code == 404


def test_get_controls_requires_auth(tmp_path: Path):
    client = _client(tmp_path)
    response = client.get("/api/runs/run-with-controls/controls")
    assert response.status_code == 401
