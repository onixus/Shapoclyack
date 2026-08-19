from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.app import create_app
from api.settings import Settings
from tests.conftest import auth_headers, login, requires_postgres

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
                "unconfirmed_findings": 1,
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
                    "latitude": 39.04,
                    "longitude": -77.49,
                    "os_name": "Linux 5.x",
                    "os_accuracy": 95,
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
    (run_dir / "findings.json").write_text(
        json.dumps(
            [
                {"host": "10.0.0.1", "port": "22", "protocol": "tcp", "service": "ssh"},
                {"host": "10.0.0.2", "port": "80", "protocol": "tcp", "service": "http"},
                {"host": "10.0.0.3", "port": "443", "protocol": "tcp", "service": "https"},
                {"host": "10.0.0.1", "port": "443", "protocol": "tcp", "service": "https"},
            ]
        ),
        encoding="utf-8",
    )
    (run_dir / "diff.json").write_text(
        json.dumps({"has_changes": True, "counts": {"hosts_added": 1, "hosts_removed": 0}}),
        encoding="utf-8",
    )
    (run_dir / "summary.md").write_text("# Scan Summary\n", encoding="utf-8")
    # A binary artifact with non-UTF8 bytes (0xFF/0xFE are invalid UTF-8) so we
    # can assert the download endpoint streams it byte-for-byte, unlike the
    # text endpoint which decodes with errors="replace".
    (run_dir / "summary.pdf").write_bytes(b"%PDF-1.4\n\xff\xfe binary body \x00\x01\x02%%EOF")


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



def test_list_and_get_run(tmp_path: Path):
    client = _client(tmp_path)
    token = login(client)
    headers = {"Authorization": f"Bearer {token}"}

    listed = client.get("/api/runs", headers=headers)
    assert listed.status_code == 200
    body = listed.json()
    assert body["items"][0]["run_id"] == "run-a"
    assert body["items"][0]["has_diff"] is True
    assert body["items"][0]["unconfirmed_findings"] == 1
    assert body["total"] == len(body["items"])
    assert body["has_more"] is False

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
    assert ashburn["os_name"] == "Linux 5.x"
    assert ashburn["os_accuracy"] == 95
    assert ashburn["latitude"] == 39.04
    assert ashburn["longitude"] == -77.49
    berlin = next(row for row in host_payload if row["host"] == "10.0.0.2")
    assert berlin["os_name"] is None
    assert berlin["os_accuracy"] is None
    # A run scanned before the scanner recorded coordinates: the country
    # survives, and the Geo Map falls back to its centroid rather than
    # dropping the host.
    assert berlin["latitude"] is None
    assert berlin["country_iso"] == "DE"

    ports = client.get("/api/runs/run-a/ports", headers=headers)
    assert ports.status_code == 200
    port_map = {row["port"]: row for row in ports.json()}
    assert port_map["443"]["host_count"] == 2
    assert port_map["22"]["host_count"] == 1
    assert port_map["443"]["vulnerability_count"] == 1
    assert port_map["443"]["services"] == ["https"]
    assert port_map["22"]["services"] == ["ssh"]

    diff = client.get("/api/runs/run-a/diff", headers=headers)
    assert diff.status_code == 200
    assert diff.json()["has_changes"] is True

    artifact = client.get("/api/runs/run-a/artifacts/summary.md", headers=headers)
    assert artifact.status_code == 200
    assert "Scan Summary" in artifact.text


def test_list_runs_unconfirmed_findings_absent_for_older_runs(tmp_path: Path):
    """A run scanned before the field existed reads back null, not zero.

    Zero would claim every finding was confirmed, which is exactly the
    overstatement the field exists to prevent -- the UI shows the hint only
    when the count is a number, so null has to survive the round trip.
    """
    client = _client(tmp_path)
    legacy = tmp_path / "output" / "runs" / "run-legacy"
    legacy.mkdir(parents=True)
    (legacy / "run_meta.json").write_text(json.dumps({"run_id": "run-legacy"}), encoding="utf-8")
    (legacy / "summary.json").write_text(
        json.dumps({"alive_hosts": 1, "potential_vulnerabilities": 4}), encoding="utf-8"
    )

    token = login(client)
    listed = client.get("/api/runs", headers={"Authorization": f"Bearer {token}"})
    assert listed.status_code == 200
    items = {item["run_id"]: item for item in listed.json()["items"]}
    assert items["run-legacy"]["potential_vulnerabilities"] == 4
    assert items["run-legacy"]["unconfirmed_findings"] is None


def test_vulnerabilities_carry_prioritisation_and_an_explanation(tmp_path: Path):
    """Every finding is scored and explained on read (ROADMAP P4), and an
    unconfirmed one is ranked below a confirmed exploited one no matter how
    alarming its own CVSS looks."""
    output = tmp_path / "output"
    state = tmp_path / "state"
    output.mkdir()
    state.mkdir()
    _write_run(output, "run-a")
    (output / "runs" / "run-a" / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {
                    "host": "10.0.0.1",
                    "port": "3389",
                    "cve": "CVE-2019-0708",
                    "cvss": 9.8,
                    "severity": "critical",
                    "source": "pulse",
                    "finding_class": "keyword_cve",
                    "confidence": 40,
                    "requires_confirmation": True,
                },
                {
                    "host": "10.0.0.1",
                    "port": "8080",
                    "cve": "CVE-2021-44228",
                    "cvss": 10.0,
                    "severity": "critical",
                    "source": "pulse",
                    "finding_class": "version_cve",
                    "confidence": 90,
                    "epss": 0.97,
                    "in_kev": True,
                },
                {
                    "host": "10.0.0.1",
                    "port": "445",
                    "cve": "",
                    "script_id": "pulse:exposure:445:eternalblue-smbv1-rce",
                    "cvss": 5.0,
                    "severity": "medium",
                    "source": "pulse",
                    "finding_class": "exposure",
                    "confidence": 45,
                    "requires_confirmation": True,
                },
            ]
        ),
        encoding="utf-8",
    )

    settings = Settings(output_dir=output, state_dir=state)
    app = create_app()
    from api.auth import get_settings

    app.dependency_overrides = {get_settings: lambda: settings}
    client = TestClient(app)
    headers = auth_headers(client)

    payload = client.get("/api/runs/run-a/vulnerabilities", headers=headers).json()
    assert [item["port"] for item in payload] == ["8080", "3389", "445"]

    confirmed = payload[0]
    assert confirmed["epss"] == 0.97
    assert confirmed["in_kev"] is True
    assert confirmed["cisa_decision"] == "Immediate"
    assert "EPSS 0.970 (scanner)" in confirmed["risk_explanation"]
    # The NIST assessment reaches the API, not just the scorer (#144).
    # 10.0.0.1 is RFC1918, so #171 lowers likelihood; AV:N/KEV alone is not
    # "this host is on the internet".
    assert confirmed["network_exposure"] == "internal"
    assert confirmed["network_exposure_source"] == "address-space"
    assert "network exposure internal (address-space)" in confirmed["risk_explanation"]
    assert confirmed["likelihood"] != "very_high"
    assert confirmed["impact"] == "very_high"
    assert confirmed["exploit_maturity"] == "attacked"
    assert any("cisa-kev" in source for source in confirmed["exploit_evidence"])

    unverified = payload[1]
    assert unverified["finding_class"] == "keyword_cve"
    assert unverified["requires_confirmation"] is True
    assert unverified["cisa_decision"] == "Attend"
    assert unverified["contextual_score"] < confirmed["contextual_score"]

    # The CVE-less exposure is present rather than dropped, and explained.
    exposure = payload[2]
    assert exposure["cve"] == ""
    assert exposure["finding_class"] == "exposure"
    assert "unconfirmed exposure" in exposure["risk_explanation"]


def test_vulnerabilities_name_an_on_path_waf_from_fingerprint(tmp_path: Path):
    """A CDN/WAF observed on the same host:port is a named discount, not a
    claim the control blocks the CVE (#173). A match on another port is not."""
    output = tmp_path / "output"
    state = tmp_path / "state"
    output.mkdir()
    state.mkdir()
    _write_run(output, "run-a")
    (output / "runs" / "run-a" / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {
                    "host": "8.8.8.8",
                    "port": "443",
                    "cve": "CVE-2021-44228",
                    "cvss": 10.0,
                    "severity": "critical",
                    "source": "pulse",
                    "finding_class": "version_cve",
                    "confidence": 90,
                    "epss": 0.97,
                    "in_kev": True,
                },
                {
                    "host": "8.8.8.8",
                    "port": "80",
                    "cve": "CVE-2021-44228",
                    "cvss": 10.0,
                    "severity": "critical",
                    "source": "pulse",
                    "finding_class": "version_cve",
                    "confidence": 90,
                    "epss": 0.97,
                    "in_kev": True,
                },
            ]
        ),
        encoding="utf-8",
    )
    (output / "runs" / "run-a" / "fingerprint.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "host": "8.8.8.8",
                        "port": 443,
                        "scheme": "https",
                        "cdn_waf": ["cloudflare"],
                        "cms_framework": ["wordpress"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    settings = Settings(output_dir=output, state_dir=state)
    app = create_app()
    from api.auth import get_settings

    app.dependency_overrides = {get_settings: lambda: settings}
    client = TestClient(app)
    headers = auth_headers(client)

    payload = client.get("/api/runs/run-a/vulnerabilities", headers=headers).json()
    by_port = {item["port"]: item for item in payload}
    shielded = by_port["443"]
    other = by_port["80"]
    assert shielded["cdn_waf"] == ["cloudflare"]
    assert shielded["compensating_control_source"] == "fingerprint"
    assert "CDN/WAF cloudflare on this host:port (fingerprint)" in shielded["risk_explanation"]
    assert "not proof the vuln is blocked" in shielded["risk_explanation"]
    assert other["cdn_waf"] == []
    assert "CDN/WAF" not in other["risk_explanation"]
    assert shielded["contextual_score"] < other["contextual_score"]


def test_download_artifact_binary_intact(tmp_path: Path):
    client = _client(tmp_path)
    headers = auth_headers(client)

    resp = client.get("/api/runs/run-a/download/summary.pdf", headers=headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert "attachment" in resp.headers["content-disposition"]
    assert "summary.pdf" in resp.headers["content-disposition"]
    # Byte-for-byte identical to what was written (the text endpoint would have
    # mangled the invalid-UTF8 bytes via errors="replace").
    assert resp.content == b"%PDF-1.4\n\xff\xfe binary body \x00\x01\x02%%EOF"

    # An extensionless / unknown type falls back to octet-stream, not text.
    missing = client.get("/api/runs/run-a/download/does-not-exist.bin", headers=headers)
    assert missing.status_code == 404


def test_download_artifact_path_traversal_blocked(tmp_path: Path):
    client = _client(tmp_path)
    headers = auth_headers(client)
    resp = client.get("/api/runs/run-a/download/..%2F..%2Fsecret.txt", headers=headers)
    assert resp.status_code == 404


def test_path_traversal_blocked(tmp_path: Path):
    from api.services.runs import read_artifact_text
    from api.settings import Settings

    output = tmp_path / "output"
    settings = Settings(output_dir=output, state_dir=tmp_path / "state")
    assert read_artifact_text(settings, "run-a", "../secret.txt") is None
    assert read_artifact_text(settings, "run-a", "/etc/passwd") is None

    client = _client(tmp_path)
    token = login(client)
    response = client.get(
        "/api/runs/run-a/artifacts/..%2F..%2Fsecret.txt",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404
