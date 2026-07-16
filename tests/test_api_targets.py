"""Tests for API scan-target parsing and job input overrides."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.schemas import StartScanRequest
from api.services.jobs import start_scan
from api.services.targets import parse_target_payload
from api.settings import Settings


def test_parse_target_payload_none_when_empty():
    assert parse_target_payload(ranges_text="", domains_text=None, ports_text="  ") is None


def test_parse_target_payload_host_override_requires_valid_entry():
    parsed = parse_target_payload(
        ranges_text="10.0.0.0/24\n# comment\n",
        domains_text="scanme.nmap.org",
        ports_text="22,80\n443",
        ports_udp_text="53,123",
    )
    assert parsed is not None
    assert parsed.ranges == ["10.0.0.0/24"]
    assert parsed.domains == ["scanme.nmap.org"]
    assert parsed.ports == ["22", "443", "80"]
    assert parsed.ports_udp == ["123", "53"]


def test_parse_target_payload_ports_only_keeps_default_hosts():
    parsed = parse_target_payload(ranges_text=None, domains_text=None, ports_text="80,443")
    assert parsed is not None
    assert parsed.ranges is None
    assert parsed.domains is None
    assert parsed.ports == ["443", "80"]
    assert parsed.ports_udp is None


def test_parse_target_payload_udp_only():
    parsed = parse_target_payload(
        ranges_text=None,
        domains_text=None,
        ports_text=None,
        ports_udp_text="u:53\n161-162",
    )
    assert parsed is not None
    assert parsed.ports is None
    assert parsed.ports_udp == ["161-162", "53"]


def test_parse_target_payload_rejects_invalid():
    with pytest.raises(ValueError, match="invalid scan targets"):
        parse_target_payload(ranges_text="not-a-cidr", domains_text=None, ports_text=None)


def test_start_scan_writes_job_inputs_and_cli_flags(tmp_path: Path):
    settings = Settings(
        output_dir=tmp_path / "out",
        state_dir=tmp_path / "state",
        config_path=Path("scanner/config/default.yaml"),
        allow_scan_start=True,
    )
    request = StartScanRequest(
        mode="safe",
        skip_nse=True,
        ranges="10.1.0.0/28",
        domains="example.com",
        ports="22\n80-90",
        ports_udp="53\n123",
    )

    with patch("api.services.jobs.threading.Thread") as thread_cls:
        thread_cls.return_value.start = lambda: None
        job = start_scan(settings, request, username="operator")

    assert job.target_counts == {"ranges": 1, "domains": 1, "ports": 2, "ports_udp": 2}
    assert "--ranges" in job.command
    assert "--domains" in job.command
    assert "--ports-file" in job.command
    assert "--ports-udp-file" in job.command

    ranges_idx = job.command.index("--ranges")
    domains_idx = job.command.index("--domains")
    ports_idx = job.command.index("--ports-file")
    ports_udp_idx = job.command.index("--ports-udp-file")
    ranges_path = Path(job.command[ranges_idx + 1])
    domains_path = Path(job.command[domains_idx + 1])
    ports_path = Path(job.command[ports_idx + 1])
    ports_udp_path = Path(job.command[ports_udp_idx + 1])
    assert ranges_path.read_text(encoding="utf-8") == "10.1.0.0/28\n"
    assert domains_path.read_text(encoding="utf-8") == "example.com\n"
    assert "22" in ports_path.read_text(encoding="utf-8")
    assert "80-90" in ports_path.read_text(encoding="utf-8")
    assert "53" in ports_udp_path.read_text(encoding="utf-8")
    assert "123" in ports_udp_path.read_text(encoding="utf-8")


def test_api_rejects_invalid_targets_with_422():
    client = TestClient(create_app())
    login = client.post(
        "/api/auth/login",
        json={"username": "operator", "password": "operator-change-me"},
    )
    token = login.json()["access_token"]
    response = client.post(
        "/api/jobs",
        headers={"Authorization": f"Bearer {token}"},
        json={"mode": "balanced", "ranges": "%%%"},
    )
    assert response.status_code == 422
    assert "invalid scan targets" in response.json()["detail"]
