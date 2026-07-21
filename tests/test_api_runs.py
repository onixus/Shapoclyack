from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.app import create_app
from api.settings import Settings
from tests.conftest import requires_postgres

pytestmark = requires_postgres


def _write_run(root: Path, run_id: str) -> None:
    run_dir = root / "runs" / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "run_meta.json").write_text(
        json.dumps({"run_id": run_id, "profile": "balanced", "started_at": "2026-07-16T10:00:00+00:00"}),
        encoding="utf-8",
    )
    (run_dir / "summary.json").write_text(
        json.dumps(
            {
                "alive_hosts": 2,
                "open_host_port_pairs": 3,
                "potential_vulnerabilities": 1,
                "vulnerable_hosts": 1,
                "vulnerabilities_by_severity": {
                    "critical": 0,
                    "high": 1,
                    "medium": 0,
                    "low": 0,
                    "unknown": 0,
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {
                    "host": "10.0.0.2",
                    "port": "80",
                    "cve": "CVE-2020-2",
                    "cvss": 4.0,
                    "cvss4": 4.2,
                    "severity": "medium",
                    "script_id": "vulners",
                    "country": "Germany",
                    "city": "Berlin",
                    "country_iso": "DE",
                },
                {
                    "host": "10.0.0.1",
                    "port": "22",
                    "cve": "CVE-2020-1",
                    "cvss": 7.5,
                    "cvss4": 8.1,
                    "severity": "high",
                    "script_id": "vulners",
                    "country": "United States",
                    "city": "Ashburn",
                    "country_iso": "US",
                },
                {
                    "host": "10.0.0.3",
                    "port": "443",
                    "cve": "CVE-2020-0",
                    "cvss": 9.8,
                    "cvss4": 10.0,
                    "severity": "critical",
                    "script_id": "vulners",
                    "country": "France",
                    "city": "Paris",
                    "country_iso": "FR",
                },
            ]
        ),
        encoding="utf-8",
    )
    (run_dir / "alive_hosts.json").write_text(
        json.dumps(
            [
                {
                    "host": "10.0.0.1",
                    "hostname": "alpha.lab",
                    "names": ["alpha.lab"],
                    "country": "United States",
                    "city": "Ashburn",
                    "country_iso": "US",
                },
                {
                    "host": "10.0.0.2",
                    "hostname": "",
                    "names": [],
                    "country": "Germany",
                    "city": "Berlin",
                    "country_iso": "DE",
                },
            ]
        ),
        encoding="utf-8",
    )
    (run_dir / "open_ports.txt").write_text(
        "10.0.0.1:22/tcp\n10.0.0.2:80/tcp\n10.0.0.3:443/tcp\n10.0.0.1:443/tcp\n",
        encoding="utf-8",
    )
    (run_dir / "diff.json").write_text(
        json.dumps({"has_changes": True, "counts": {"hosts_added": 1, "hosts_removed": 0}}),
        encoding="utf-8",
    )
    (run_dir / "summary.md").write_text("# Scan Summary\n", encoding="utf-8")


def _client(tmp_path: Path) -> TestClient:
    output = tmp_path / "output"
    state = tmp_path / "state"
    output.mkdir()
    state.mkdir()
    _write_run(output, "run-a")

    settings = Settings(output_dir=output, state_dir=state)

    app = create_app()
    app.dependency_overrides = {}
    from api.auth import get_settings

    app.dependency_overrides[get_settings] = lambda: settings
    return TestClient(app)


def _token(client: TestClient, username: str = "viewer", password: str = "viewer-change-me") -> str:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


def test_list_and_get_run(tmp_path: Path):
    client = _client(tmp_path)
    token = _token(client)
    headers = {"Authorization": f"Bearer {token}"}

    listed = client.get("/api/runs", headers=headers)
    assert listed.status_code == 200
    assert listed.json()[0]["run_id"] == "run-a"
    assert listed.json()[0]["has_diff"] is True

    detail = client.get("/api/runs/run-a", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["summary"]["alive_hosts"] == 2

    vulns = client.get("/api/runs/run-a/vulnerabilities", headers=headers)
    assert vulns.status_code == 200
    payload = vulns.json()
    cves = [item["cve"] for item in payload]
    assert cves == ["CVE-2020-0", "CVE-2020-1", "CVE-2020-2"]
    assert payload[0]["cvss4"] == 10.0
    assert payload[0]["city"] == "Paris"
    assert payload[0]["country"] == "France"

    filtered = client.get("/api/runs/run-a/vulnerabilities?host=10.0.0.1", headers=headers)
    assert filtered.status_code == 200
    assert [item["cve"] for item in filtered.json()] == ["CVE-2020-1"]

    by_port = client.get("/api/runs/run-a/vulnerabilities?port=443", headers=headers)
    assert by_port.status_code == 200
    assert [item["cve"] for item in by_port.json()] == ["CVE-2020-0"]

    hosts = client.get("/api/runs/run-a/hosts", headers=headers)
    assert hosts.status_code == 200
    host_payload = hosts.json()
    assert {row["host"] for row in host_payload} == {"10.0.0.1", "10.0.0.2"}
    ashburn = next(row for row in host_payload if row["host"] == "10.0.0.1")
    assert ashburn["city"] == "Ashburn"
    assert ashburn["country"] == "United States"
    assert ashburn["vulnerability_count"] == 1

    ports = client.get("/api/runs/run-a/ports", headers=headers)
    assert ports.status_code == 200
    port_map = {row["port"]: row for row in ports.json()}
    assert port_map["443"]["host_count"] == 2
    assert port_map["22"]["host_count"] == 1
    assert port_map["443"]["vulnerability_count"] == 1

    diff = client.get("/api/runs/run-a/diff", headers=headers)
    assert diff.status_code == 200
    assert diff.json()["has_changes"] is True

    artifact = client.get("/api/runs/run-a/artifacts/summary.md", headers=headers)
    assert artifact.status_code == 200
    assert "Scan Summary" in artifact.text


def test_path_traversal_blocked(tmp_path: Path):
    from api.services.runs import read_artifact_text
    from api.settings import Settings

    output = tmp_path / "output"
    settings = Settings(output_dir=output, state_dir=tmp_path / "state")
    assert read_artifact_text(settings, "run-a", "../secret.txt") is None
    assert read_artifact_text(settings, "run-a", "/etc/passwd") is None

    client = _client(tmp_path)
    token = _token(client)
    response = client.get(
        "/api/runs/run-a/artifacts/..%2F..%2Fsecret.txt",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404
