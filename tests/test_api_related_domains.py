"""API tests for org-profile and related-domains promotion endpoints (org_profile M4)."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.app import create_app
from api.settings import Settings
from api.services import promoted_domains
from tests.conftest import approve_scan_scope, auth_headers, requires_postgres

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
                    "evidence": [],
                },
                {
                    "domain": "denied-partner.com",
                    "status": "candidate",
                    "confidence": 0.5,
                    "sources": ["reverse_ns"],
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
    # Promotion is held to the approved scope (#226): allow everything except
    # one candidate, so the refusal path has something to refuse.
    approve_scan_scope(
        settings,
        entries=[
            {"effect": "allow", "kind": "domain", "value": "*"},
            {"effect": "deny", "kind": "domain", "value": "denied-partner.com"},
        ],
    )
    promoted_domains.reset_for_tests(settings)
    app = create_app()
    from api.auth import get_settings

    app.dependency_overrides[get_settings] = lambda: settings
    return TestClient(app)


def test_get_org_profile_success(tmp_path: Path):
    client = _client(tmp_path)
    headers = auth_headers(client, "operator")

    response = client.get("/api/runs/run-org-profile/org-profile", headers=headers)
    assert response.status_code == 200, response.text
    data = response.json()

    assert data["run_id"] == "run-org-profile"
    assert data["seed_domains"] == ["example.com"]
    assert data["ownership"]["domains"]["example.com"]["org_name"] == "Acme Inc."
    assert data["ownership_restricted"] is False
    assert data["related_domains"]["confirmed_count"] == 1
    assert data["related_domains"]["candidates"][0]["domain"] == "acme-partner.com"


def test_org_profile_withholds_ownership_from_a_viewer(tmp_path: Path):
    """``ownership.json`` is a restricted artifact and 404s for a viewer on the
    artifact endpoints; the org-profile view must not hand the same RDAP
    registrant/abuse contacts back inline."""
    client = _client(tmp_path)
    headers = auth_headers(client, "viewer")

    response = client.get("/api/runs/run-org-profile/org-profile", headers=headers)
    assert response.status_code == 200, response.text
    data = response.json()

    assert data["ownership"] is None
    assert data["ownership_restricted"] is True
    # The non-restricted parts of the profile are still served.
    assert data["related_domains"]["confirmed_count"] == 1


def test_promote_rejects_a_newline_injected_domain(tmp_path: Path):
    """A promoted name is scope for every later scan, so an embedded newline
    must not smuggle a second entry into it."""
    client = _client(tmp_path)
    headers = auth_headers(client, "operator")

    response = client.post(
        "/api/runs/run-org-profile/related-domains/"
        "acme-partner.com%0Aevil.example.net/promote",
        headers=headers,
    )
    assert response.status_code == 400, response.text

    settings = Settings(output_dir=tmp_path / "output", state_dir=tmp_path / "state")
    assert promoted_domains.list_promoted(settings, "default") == []


def test_promote_rejects_a_domain_this_run_never_discovered(tmp_path: Path):
    client = _client(tmp_path)
    headers = auth_headers(client, "operator")

    response = client.post(
        "/api/runs/run-org-profile/related-domains/not-a-candidate.example/promote",
        headers=headers,
    )
    assert response.status_code == 400, response.text
    assert "candidate" in response.json()["detail"]


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

    # ...and is withdrawn by the same operator through the DELETE counterpart.
    withdrawn = client.delete(
        "/api/runs/run-org-profile/related-domains/acme-partner.com/promote",
        headers=headers,
    )
    assert withdrawn.status_code == 200, withdrawn.text
    assert withdrawn.json()["promoted"] is False
    get_res = client.get("/api/runs/run-org-profile/org-profile", headers=headers)
    assert get_res.json()["promoted_domains"] == []


def test_promote_outside_the_approved_scope_is_403_and_journalled(tmp_path: Path):
    """The operator decides attribution; the admin decides authorization."""
    client = _client(tmp_path)
    headers = auth_headers(client, "operator")

    response = client.post(
        "/api/runs/run-org-profile/related-domains/denied-partner.com/promote",
        headers=headers,
    )
    assert response.status_code == 403, response.text
    assert "approved scan scope" in response.json()["detail"]

    settings = Settings(output_dir=tmp_path / "output", state_dir=tmp_path / "state")
    assert promoted_domains.list_promoted(settings, "default") == []

    # The refusal lands in the same journal a refused scan start goes to.
    events = client.get("/api/auth/events", headers=auth_headers(client, "admin")).json()
    items = events["items"] if isinstance(events, dict) else events
    assert any("denied-partner.com" in json.dumps(item) for item in items)


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
