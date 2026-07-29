"""Unit tests for direct TLS probe (Phase 4) — no live network."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from scanner.pipeline.config_schema import TlsPostureConfig
from scanner.pipeline.tls_posture import check_tls_posture
from scanner.pipeline.tls_probe import (
    _classify_from_cert,
    _parse_tls_endpoints,
    probe_tls_endpoints,
    write_tls_probe_json,
)


def test_parse_tls_endpoints_filters_ports():
    open_ports = [
        "10.0.0.1:443/tcp",
        "10.0.0.1:80/tcp",
        "10.0.0.2:8443/tcp",
        "10.0.0.3:22/tcp",
        "10.0.0.1:443/tcp",  # dup
    ]
    got = _parse_tls_endpoints(open_ports, {443, 8443})
    assert got == [("10.0.0.1", 443), ("10.0.0.2", 8443)]


def test_parse_tls_endpoints_empty_allowlist():
    assert _parse_tls_endpoints(["10.0.0.1:443/tcp"], set()) == []


def test_classify_expired_and_self_signed():
    now = datetime(2026, 7, 22, tzinfo=timezone.utc)
    cert = {
        "subject_cn": "internal.local",
        "issuer_cn": "internal.local",
        "subject": "CN=internal.local",
        "issuer": "CN=internal.local",
        "not_after": "Jan  1 00:00:00 2021 GMT",
        "not_after_dt": datetime(2021, 1, 1, tzinfo=timezone.utc),
    }
    kinds = {i["kind"] for i in _classify_from_cert(cert, now, 30)}
    assert "cert_expired" in kinds
    assert "self_signed" in kinds


def test_write_tls_probe_json(tmp_path: Path):
    findings = [
        {
            "host": "10.0.0.1",
            "port": "443",
            "issues": [{"kind": "self_signed", "severity": "medium"}],
            "source": "pulse-tls-probe",
        }
    ]
    path = write_tls_probe_json(tmp_path, findings)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema"] == "octo.tls_probe.v1"
    assert data["checked_count"] == 1


def test_check_tls_posture_probe_fallback_when_no_nmap(tmp_path: Path):
    """Empty nmap dir + open_ports → probe path (mocked handshake)."""
    nmap_dir = tmp_path / "nmap"
    nmap_dir.mkdir()
    fake = [
        {
            "host": "10.0.0.9",
            "port": "443",
            "cert": {"subject_cn": "x", "issuer_cn": "x"},
            "cipher_versions": [{"version": "TLSv1.3", "ciphers": ["TLS_AES_256"], "least_strength": None}],
            "issues": [
                {
                    "kind": "self_signed",
                    "severity": "medium",
                    "detail": "subject matches issuer (heuristic)",
                    "heuristic": True,
                }
            ],
            "source": "pulse-tls-probe",
            "negotiated_protocol": "TLSv1.3",
            "negotiated_cipher": "TLS_AES_256",
        }
    ]
    cfg = TlsPostureConfig(enabled=True, probe_fallback=True)
    with patch(
        "scanner.pipeline.tls_posture.probe_tls_endpoints",
        return_value=fake,
    ) as mock_probe:
        result = check_tls_posture(
            nmap_dir,
            cfg,
            tmp_path,
            open_ports=["10.0.0.9:443/tcp", "10.0.0.9:80/tcp"],
        )
    mock_probe.assert_called_once()
    assert result["source"] == "pulse-tls-probe"
    assert result["checked_count"] == 1
    assert result["findings"][0]["issues"][0]["kind"] == "self_signed"
    assert (tmp_path / "tls_posture.json").exists()
    assert (tmp_path / "tls_probe.json").exists()
    lines = (tmp_path / "tls_posture_findings.txt").read_text(encoding="utf-8").splitlines()
    assert lines == ["10.0.0.9:443:self_signed"]


def test_check_tls_posture_no_fallback_when_disabled(tmp_path: Path):
    nmap_dir = tmp_path / "nmap"
    nmap_dir.mkdir()
    cfg = TlsPostureConfig(enabled=True, probe_fallback=False)
    with patch("scanner.pipeline.tls_posture.probe_tls_endpoints") as mock_probe:
        result = check_tls_posture(
            nmap_dir,
            cfg,
            tmp_path,
            open_ports=["10.0.0.1:443/tcp"],
        )
    mock_probe.assert_not_called()
    assert result["skipped_reason"] == "no_tls_endpoints"
    assert result["source"] is None


def test_check_tls_posture_prefers_nmap_over_probe(tmp_path: Path):
    from xml.sax.saxutils import quoteattr

    nmap_dir = tmp_path / "nmap" / "tcp"
    nmap_dir.mkdir(parents=True)
    cert_out = """Subject: commonName=example.com
Issuer: commonName=R3
Not valid before: 2026-05-01T00:00:00
Not valid after:  2027-05-01T23:59:59
"""
    xml = f"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" />
        <script id="ssl-cert" output={quoteattr(cert_out)} />
      </port>
    </ports>
  </host>
</nmaprun>
"""
    (nmap_dir / "h.xml").write_text(xml, encoding="utf-8")
    cfg = TlsPostureConfig(enabled=True, probe_fallback=True)
    now = datetime(2026, 7, 22, tzinfo=timezone.utc)
    with patch("scanner.pipeline.tls_posture.probe_tls_endpoints") as mock_probe:
        result = check_tls_posture(
            tmp_path / "nmap",
            cfg,
            tmp_path,
            now=now,
            open_ports=["10.0.0.1:443/tcp"],
        )
    mock_probe.assert_not_called()
    assert result["source"] == "nmap-nse"
    assert result["checked_count"] == 1
    assert result["findings"][0]["source"] == "nmap-nse"


def test_probe_tls_endpoints_respects_max_targets():
    ports = [f"10.0.0.{i}:443/tcp" for i in range(1, 6)]
    with patch("scanner.pipeline.tls_probe._probe_one", return_value=None) as mock_one:
        findings = probe_tls_endpoints(
            ports,
            max_targets=2,
            concurrency=2,
            tls_ports={443},
        )
    assert findings == []
    assert mock_one.call_count == 2
