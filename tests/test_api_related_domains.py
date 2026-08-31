"""API tests for org-profile and related-domains promotion endpoints (org_profile M4)."""

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

    (run_dir / "ownership.json").write_text(
        json.dumps({
            "domains": {
                "example.com": {
                    "org_name": "Acme Inc.",
                    "registrar": "MarkMonitor",
                    "dnssec": True,
                }
            }
        }),
        encoding="utf-8",
    )

    (run_dir / "related_domains.json").write_text(
        json.dumps({
            "status": "ok",
            "seed_domains": ["example.com"],
            "confirmed_count": 1,
            "candidate_count": 0,
            "total_candidates": 1,
            "truncated": False,
            "auto_merged": False,
            "merged_domains": [],
            "disclaimer": "Attribution is probabilistic.",
            "candidates": [
                {
                    "domain": "acme-partner.com",
                    "status": "confirmed",
                    "confidence": 0.85,
                    "sources": ["cert_san", "ct_org"],
                    "evidence": [
                        {
                            "source": "cert_san",
                            "indicator": "tls_san",
                            "detail": "Observed in TLS SAN",
                        }
                    ],
                }
            ],
            "evaluated_at": "2026-08-30T10:00:00Z",
        }),
        encoding="utf-8",
    )


def _client(tmp_path: Path) -> TestClient:
    output = tmp_path / "output"
    state = tmp_path / "state"
    output.mkdir(exist_ok=True)
    state.mkdir(exist_ok=True)

    _setup_test_run(output, "run-org-profile")

    settings = Settings(output_dir=output, state_dir=state)
    app = create_app()
    from api.auth import get_settings

    app.dependency_overrides[get_settings] = lambda: settings
    return TestClient(app)


def test_get_org_profile_success(tmp_path: Path):
    client = _client(tmp_path)
    headers = auth_headers(client, "viewer")

    response = client.get("/api/runs/run-org-profile/org-profile", headers=headers)
    assert response.status_code == 200, response.text
    data = response.json()

    assert data["run_id"] == "run-org-profile"
    assert data["seed_domains"] == ["example.com"]
    assert data["ownership"]["domains"]["example.com"]["org_name"] == "Acme Inc."
    assert data["related_domains"]["confirmed_count"] == 1
    assert data["related_domains"]["candidates"][0]["domain"] == "acme-partner.com"


def test_promote_related_domain_operator(tmp_path: Path):
    client = _client(tmp_path)
    headers = auth_headers(client, "operator")

    response = client.post(
        "/api/runs/run-org-profile/related-domains/acme-partner.com/promote",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    data = response.json()

    assert data["domain"] == "acme-partner.com"
    assert data["promoted"] is True
    assert "promoted to scope" in data["message"]

    # Verify promoted domain shows up in subsequent org-profile call
    get_res = client.get("/api/runs/run-org-profile/org-profile", headers=headers)
    assert "acme-partner.com" in get_res.json()["promoted_domains"]


def test_promote_related_domain_forbidden_for_viewer(tmp_path: Path):
    client = _client(tmp_path)
    headers = auth_headers(client, "viewer")

    response = client.post(
        "/api/runs/run-org-profile/related-domains/acme-partner.com/promote",
        headers=headers,
    )
    assert response.status_code == 403


def test_get_org_profile_nonexistent_run(tmp_path: Path):
    client = _client(tmp_path)
    headers = auth_headers(client, "viewer")

    response = client.get("/api/runs/missing-run/org-profile", headers=headers)
    assert response.status_code == 404
