"""Unit tests for DefectDojo Generic Findings export."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from scanner.pipeline.config_schema import DefectDojoConfig
from scanner.pipeline.defectdojo import (
    export_to_defectdojo,
    map_vulnerabilities_to_generic_findings,
)


def test_map_vulnerabilities_filters_by_min_severity_and_maps_fields():
    payload = map_vulnerabilities_to_generic_findings(
        [
            {
                "host": "10.0.0.1",
                "port": "22",
                "script_id": "vulners",
                "cve": "CVE-2016-10012",
                "cvss": 9.8,
                "severity": "critical",
            },
            {
                "host": "10.0.0.1",
                "port": "80",
                "script_id": "http-csrf",
                "cve": None,
                "cvss": None,
                "severity": "low",
            },
        ],
        run_id="run-1",
        min_severity="high",
        include_without_cve=True,
        script_findings=[
            {
                "host": "10.0.0.1",
                "port": "22",
                "script_id": "vulners",
                "output": "CVE list truncated",
            }
        ],
    )
    assert payload["type"] == "Octo-man"
    assert len(payload["findings"]) == 1
    finding = payload["findings"][0]
    assert finding["severity"] == "Critical"
    assert finding["cve"] == "CVE-2016-10012"
    assert finding["cvssv3_score"] == 9.8
    assert finding["endpoints"] == ["10.0.0.1:22"]
    assert "CVE list truncated" in finding["description"]
    assert finding["vulnerability_ids"] == ["CVE-2016-10012"]


def test_map_skips_without_cve_when_disabled():
    payload = map_vulnerabilities_to_generic_findings(
        [
            {
                "host": "10.0.0.2",
                "port": "443",
                "script_id": "ssl-heartbleed",
                "cve": None,
                "severity": "critical",
            }
        ],
        run_id="r",
        min_severity="low",
        include_without_cve=False,
    )
    assert payload["findings"] == []


def test_export_skipped_when_disabled(tmp_path: Path):
    result = export_to_defectdojo(
        DefectDojoConfig(enabled=False),
        run_id="r",
        output_dir=tmp_path,
    )
    assert result["attempted"] is False
    assert result["skipped_reason"] == "defectdojo.disabled"


def test_export_writes_payload_and_reports_missing_credentials(tmp_path: Path):
    (tmp_path / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {
                    "host": "10.0.0.1",
                    "port": "22",
                    "script_id": "vulners",
                    "cve": "CVE-2016-10012",
                    "cvss": 7.5,
                    "severity": "high",
                }
            ]
        ),
        encoding="utf-8",
    )
    result = export_to_defectdojo(
        DefectDojoConfig(enabled=True, url="", api_key="", min_severity="high"),
        run_id="run-cred",
        output_dir=tmp_path,
    )
    assert result["attempted"] is False
    assert result["skipped_reason"] == "missing_credentials"
    assert (tmp_path / "defectdojo_findings.json").exists()
    assert result["findings_count"] == 1


def test_export_posts_multipart_on_success(tmp_path: Path):
    (tmp_path / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {
                    "host": "10.0.0.1",
                    "port": "22",
                    "script_id": "vulners",
                    "cve": "CVE-2016-10012",
                    "cvss": 9.8,
                    "severity": "critical",
                }
            ]
        ),
        encoding="utf-8",
    )

    mock_response = MagicMock()
    mock_response.status = 201
    mock_response.getcode.return_value = 201
    mock_response.read.return_value = b'{"test": 1}'
    mock_response.__enter__.return_value = mock_response
    mock_response.__exit__.return_value = None

    with patch("scanner.pipeline.defectdojo.urllib.request.urlopen", return_value=mock_response) as mocked:
        result = export_to_defectdojo(
            DefectDojoConfig(
                enabled=True,
                url="https://dd.example.com",
                api_key="secret-token",
                product_name="Prod",
                engagement_name="Eng",
                min_severity="high",
            ),
            run_id="run-ok",
            output_dir=tmp_path,
        )

    assert result["attempted"] is True
    assert result["status"] == "ok"
    assert result["http_status"] == 201
    assert result["findings_count"] == 1
    mocked.assert_called_once()
    request = mocked.call_args.args[0]
    assert request.full_url.endswith("/api/v2/reimport-scan/")
    headers = {k.lower(): v for k, v in request.header_items()}
    assert headers.get("authorization") == "Token secret-token"
    body = request.data
    assert b"Generic Findings Import" in body
    assert b"CVE-2016-10012" in body
