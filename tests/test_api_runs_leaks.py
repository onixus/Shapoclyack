"""API & RBAC tests for credential leaks identifiers endpoint and artifact gates (org_profile M5)."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.app import create_app
from api.settings import Settings
from tests.conftest import auth_headers, requires_postgres

pytestmark = requires_postgres


def _setup_test_run(output_dir: Path, run_id: str) -> None:
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

    (run_dir / "credential_leaks.json").write_text(
        json.dumps({
            "status": "fail",
            "provider": "hibp",
            "breaches_count": 1,
            "accounts_count": 2,
            "domains": {
                "example.com": {
                    "breaches": [
                        {
                            "name": "Breach2024",
                            "masked_identifiers": ["j***@example.com", "a***@example.com"],
                        }
                    ]
                }
            },
        }),
        encoding="utf-8",
    )

    (run_dir / "credential_leaks_identifiers.json").write_text(
        json.dumps({
            "total_identifiers": 2,
            "domains": {
                "example.com": {
                    "Breach2024": ["john.doe@example.com", "alice.smith@example.com"]
                }
            },
            "generated_at": "2026-08-30T10:00:00Z",
        }),
        encoding="utf-8",
    )


def _client(tmp_path: Path) -> TestClient:
    output = tmp_path / "output"
    state = tmp_path / "state"
    output.mkdir(exist_ok=True)
    state.mkdir(exist_ok=True)

    _setup_test_run(output, "run-with-leaks")

    settings = Settings(output_dir=output, state_dir=state)
    app = create_app()
    from api.auth import get_settings

    app.dependency_overrides[get_settings] = lambda: settings
    return TestClient(app)


def test_get_leak_identifiers_operator_success(tmp_path: Path):
    client = _client(tmp_path)
    headers = auth_headers(client, "operator")

    response = client.get("/api/runs/run-with-leaks/leaks/identifiers", headers=headers)
    assert response.status_code == 200, response.text
    data = response.json()

    assert data["run_id"] == "run-with-leaks"
    assert data["total_identifiers"] == 2
    assert "john.doe@example.com" in data["domains"]["example.com"]["Breach2024"]


def test_get_leak_identifiers_forbidden_for_viewer(tmp_path: Path):
    client = _client(tmp_path)
    headers = auth_headers(client, "viewer")

    response = client.get("/api/runs/run-with-leaks/leaks/identifiers", headers=headers)
    assert response.status_code == 403


def test_get_leak_identifiers_requires_auth(tmp_path: Path):
    client = _client(tmp_path)
    response = client.get("/api/runs/run-with-leaks/leaks/identifiers")
    assert response.status_code == 401


def test_restricted_artifact_gate_on_preview_and_download(tmp_path: Path):
    client = _client(tmp_path)
    viewer_headers = auth_headers(client, "viewer")
    operator_headers = auth_headers(client, "operator")

    # Viewer cannot preview or download credential_leaks_identifiers.json -> 404
    viewer_preview = client.get(
        "/api/runs/run-with-leaks/artifacts/credential_leaks_identifiers.json",
        headers=viewer_headers,
    )
    assert viewer_preview.status_code == 404

    viewer_download = client.get(
        "/api/runs/run-with-leaks/artifacts/credential_leaks_identifiers.json/download",
        headers=viewer_headers,
    )
    assert viewer_download.status_code == 404

    # Operator can preview and download restricted artifacts -> 200
    op_preview = client.get(
        "/api/runs/run-with-leaks/artifacts/credential_leaks_identifiers.json",
        headers=operator_headers,
    )
    assert op_preview.status_code == 200
    assert "john.doe@example.com" in op_preview.text
