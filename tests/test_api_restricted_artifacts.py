"""Operator-only ownership artifacts (org_profile M1, #182)."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from tests.conftest import auth_headers, configured_client, requires_postgres

pytestmark = requires_postgres

OWNERSHIP = {
    "seed_domains": ["example.com"],
    "domains": {
        "example.com": {
            "status": "ok",
            "reason": None,
            "registrar": "RESERVED-Registrar",
            "org_name": "Example Holding LLC",
            "abuse_email": "abuse@registrar.example",
            "registrant_status": "public",
        }
    },
    "identifiers": [],
    "truncated": False,
    "skipped_reason": None,
}


def _seed_run(output: Path, run_id: str = "run-own") -> Path:
    run_dir = output / "runs" / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "run_meta.json").write_text(json.dumps({"run_id": run_id}), encoding="utf-8")
    (run_dir / "summary.json").write_text("{}", encoding="utf-8")
    (run_dir / "ownership.json").write_text(json.dumps(OWNERSHIP), encoding="utf-8")
    (run_dir / "ownership_findings.txt").write_text(
        "example.com:ok:registrant=public:registrar=RESERVED-Registrar\n", encoding="utf-8"
    )
    return run_dir


def _client(tmp_path: Path, monkeypatch) -> TestClient:
    client = configured_client(tmp_path, monkeypatch)
    _seed_run(tmp_path / "output")
    return client


def test_run_detail_omits_restricted_artifacts(tmp_path: Path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    detail = client.get("/api/runs/run-own", headers=auth_headers(client, "operator"))
    assert detail.status_code == 200
    artifacts = detail.json()["artifacts"]
    assert "summary.json" in artifacts
    assert "ownership.json" not in artifacts
    assert "ownership_findings.txt" not in artifacts


def test_viewer_cannot_read_or_download_ownership(tmp_path: Path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    headers = auth_headers(client, "viewer")
    for rel in ("ownership.json", "ownership_findings.txt"):
        text = client.get(f"/api/runs/run-own/artifacts/{rel}", headers=headers)
        assert text.status_code == 404, rel
        download = client.get(f"/api/runs/run-own/download/{rel}", headers=headers)
        assert download.status_code == 404, rel


def test_operator_reads_and_downloads_ownership(tmp_path: Path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    headers = auth_headers(client, "operator")

    text = client.get("/api/runs/run-own/artifacts/ownership.json", headers=headers)
    assert text.status_code == 200
    assert json.loads(text.text)["domains"]["example.com"]["abuse_email"] == "abuse@registrar.example"

    download = client.get("/api/runs/run-own/download/ownership.json", headers=headers)
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("application/json")


def test_unrestricted_artifact_stays_readable_for_a_viewer(tmp_path: Path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    text = client.get("/api/runs/run-own/artifacts/summary.json", headers=auth_headers(client, "viewer"))
    assert text.status_code == 200
