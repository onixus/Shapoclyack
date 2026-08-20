"""Operator-only screenshot PNG access (P4.4)."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from scanner.pipeline.screenshots import screenshot_filename
from tests.conftest import auth_headers, configured_client, requires_postgres

pytestmark = requires_postgres

PNG = b"\x89PNG\r\n\x1a\nredacted-pixels"
FILE_NAME = screenshot_filename("10.0.0.1", 443, "https")


def _seed_run(output: Path, run_id: str = "run-shot") -> Path:
    run_dir = output / "runs" / run_id
    shots = run_dir / "screenshots"
    shots.mkdir(parents=True)
    (run_dir / "run_meta.json").write_text(
        json.dumps({"run_id": run_id}), encoding="utf-8"
    )
    (run_dir / "summary.json").write_text("{}", encoding="utf-8")
    (shots / FILE_NAME).write_bytes(PNG)
    (run_dir / "screenshots.json").write_text(
        json.dumps(
            {
                "skipped_reason": None,
                "captured_count": 1,
                "redacted_fields": 2,
                "truncated": False,
                "findings": [
                    {
                        "host": "10.0.0.1",
                        "port": 443,
                        "scheme": "https",
                        "url": "https://10.0.0.1",
                        "file": f"screenshots/{FILE_NAME}",
                        "redacted_fields": 2,
                        "error": None,
                    },
                    {
                        "host": "10.0.0.2",
                        "port": 80,
                        "scheme": "http",
                        "url": "http://10.0.0.2",
                        "file": "screenshots/missing.png",
                        "redacted_fields": 0,
                        "error": None,
                    },
                    {
                        "host": "10.0.0.3",
                        "port": 8080,
                        "scheme": "http",
                        "url": "http://10.0.0.3:8080",
                        "file": "screenshots/failed.png",
                        "redacted_fields": 0,
                        "error": "capture_failed",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return run_dir


def _client(tmp_path: Path, monkeypatch) -> TestClient:
    client = configured_client(tmp_path, monkeypatch)
    _seed_run(tmp_path / "output")
    return client


def test_run_detail_omits_png_from_artifact_list(tmp_path: Path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    headers = auth_headers(client, "viewer")
    detail = client.get("/api/runs/run-shot", headers=headers)
    assert detail.status_code == 200
    artifacts = detail.json()["artifacts"]
    assert "screenshots.json" in artifacts
    assert all(not path.lower().endswith(".png") for path in artifacts)


def test_viewer_text_and_download_png_are_404(tmp_path: Path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    headers = auth_headers(client, "viewer")
    rel = f"screenshots/{FILE_NAME}"
    text = client.get(f"/api/runs/run-shot/artifacts/{rel}", headers=headers)
    assert text.status_code == 404
    download = client.get(f"/api/runs/run-shot/download/{rel}", headers=headers)
    assert download.status_code == 404
    listed = client.get("/api/runs/run-shot/screenshots", headers=headers)
    assert listed.status_code == 403


def test_operator_downloads_png_and_lists_manifest(tmp_path: Path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    headers = auth_headers(client, "operator")
    rel = f"screenshots/{FILE_NAME}"
    # Text preview still 404s — PNG is not UTF-8 source.
    text = client.get(f"/api/runs/run-shot/artifacts/{rel}", headers=headers)
    assert text.status_code == 404

    download = client.get(f"/api/runs/run-shot/download/{rel}", headers=headers)
    assert download.status_code == 200
    assert download.content == PNG
    assert download.headers["content-type"].startswith("image/png")

    listed = client.get("/api/runs/run-shot/screenshots", headers=headers)
    assert listed.status_code == 200
    body = listed.json()
    assert body["captured_count"] == 1
    assert body["redacted_fields"] == 2
    assert body["truncated"] is False
    assert body["skipped_reason"] is None
    files = {item["file"]: item for item in body["items"]}
    assert files[rel]["available"] is True
    assert files[rel]["host"] == "10.0.0.1"
    assert files["screenshots/missing.png"]["available"] is False
    assert "screenshots/failed.png" not in files


def test_admin_can_list_screenshots(tmp_path: Path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    headers = auth_headers(client, "admin")
    listed = client.get("/api/runs/run-shot/screenshots", headers=headers)
    assert listed.status_code == 200
    assert listed.json()["captured_count"] == 1


def test_missing_run_is_404_for_operator(tmp_path: Path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    headers = auth_headers(client, "operator")
    resp = client.get("/api/runs/no-such-run/screenshots", headers=headers)
    assert resp.status_code == 404
