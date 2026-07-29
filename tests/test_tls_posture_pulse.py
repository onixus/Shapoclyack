"""tls_posture integration with Pulse pulse/tls.json (Phase 4.3)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from scanner.pipeline.config_schema import TlsPostureConfig
from scanner.pipeline.tls_posture import (
    check_tls_posture,
    findings_from_pulse_tls,
    _normalize_proto_label,
)


def test_normalize_proto_label():
    assert _normalize_proto_label("TLSv1_3") == "TLSv1.3"
    assert _normalize_proto_label("TLSv1.0") == "TLSv1.0"
    assert _normalize_proto_label("tlsv1_1") == "TLSv1.1"


def test_findings_from_pulse_tls_maps_issues():
    now = datetime(2026, 7, 29, tzinfo=timezone.utc)
    artifact = {
        "tls": [
            {
                "ip": "10.0.0.5",
                "host": "app.local (10.0.0.5)",
                "port": 443,
                "subject_cn": "app.local",
                "issuer_cn": "app.local",
                "self_signed": True,
                "expired": False,
                "expires_in_days": 10,
                "not_after": "2026-08-08 12:00:00.0 +00:00:00",
                "not_before": "2025-08-08 12:00:00.0 +00:00:00",
                "negotiated_protocol": "TLSv1_2",
                "accepts_weak_protocols": ["TLSv1.0", "TLSv1.1"],
                "san": ["DNSName(\"app.local\")"],
            },
            {
                "ip": "10.0.0.6",
                "port": 8443,
                "subject_cn": "old.local",
                "issuer_cn": "R3",
                "self_signed": False,
                "expired": True,
                "expires_in_days": -5,
                "not_after": "2026-07-01 0:00:00.0 +00:00:00",
                "negotiated_protocol": "TLSv1_3",
                "accepts_weak_protocols": [],
            },
        ],
        "findings": [],
    }
    rows = findings_from_pulse_tls(
        artifact, now=now, expiring_soon_days=30, max_targets=100
    )
    assert len(rows) == 2
    r0 = next(r for r in rows if r["host"] == "10.0.0.5")
    kinds = {i["kind"] for i in r0["issues"]}
    assert "self_signed" in kinds
    assert "cert_expiring_soon" in kinds
    assert "weak_protocol" in kinds
    assert r0["source"] == "pulse-tls"
    assert "TLSv1.0" in r0["accepts_weak_protocols"]

    r1 = next(r for r in rows if r["host"] == "10.0.0.6")
    assert any(i["kind"] == "cert_expired" for i in r1["issues"])


def test_check_tls_posture_uses_pulse_tls_before_probe(tmp_path: Path):
    nmap_dir = tmp_path / "nmap"
    nmap_dir.mkdir()
    pulse_dir = tmp_path / "pulse"
    pulse_dir.mkdir()
    (pulse_dir / "tls.json").write_text(
        json.dumps(
            {
                "schema": "octo.pulse_tls.v1",
                "tls": [
                    {
                        "ip": "10.1.2.3",
                        "port": 443,
                        "subject_cn": "x.example",
                        "issuer_cn": "R3",
                        "self_signed": False,
                        "expired": False,
                        "expires_in_days": 200,
                        "not_after": "2027-01-01 0:00:00.0 +00:00:00",
                        "negotiated_protocol": "TLSv1_3",
                        "accepts_weak_protocols": [],
                    }
                ],
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    cfg = TlsPostureConfig(enabled=True, probe_fallback=True)
    now = datetime(2026, 7, 29, tzinfo=timezone.utc)
    with patch("scanner.pipeline.tls_posture.probe_tls_endpoints") as mock_probe:
        result = check_tls_posture(
            nmap_dir,
            cfg,
            tmp_path,
            now=now,
            open_ports=["10.1.2.3:443/tcp"],
        )
    mock_probe.assert_not_called()
    assert result["source"] == "pulse-tls"
    assert result["checked_count"] == 1
    assert result["findings"][0]["source"] == "pulse-tls"
    assert result["findings"][0]["host"] == "10.1.2.3"
    assert (tmp_path / "tls_posture.json").exists()
    lines = (tmp_path / "tls_posture_findings.txt").read_text(encoding="utf-8").splitlines()
    # no issues → empty findings txt
    assert lines == []


def test_check_tls_posture_nmap_still_wins_over_pulse(tmp_path: Path):
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
    pulse_dir = tmp_path / "pulse"
    pulse_dir.mkdir()
    (pulse_dir / "tls.json").write_text(
        json.dumps({"tls": [{"ip": "10.0.0.1", "port": 443, "self_signed": True}]}),
        encoding="utf-8",
    )
    cfg = TlsPostureConfig(enabled=True, probe_fallback=True)
    now = datetime(2026, 7, 22, tzinfo=timezone.utc)
    result = check_tls_posture(tmp_path / "nmap", cfg, tmp_path, now=now)
    assert result["source"] == "nmap-nse"
    assert result["findings"][0]["source"] == "nmap-nse"


def test_write_pulse_artifacts_emits_tls_json(tmp_path: Path):
    from scanner.pipeline.pulse_probe import write_pulse_artifacts

    write_pulse_artifacts(
        tmp_path,
        [],
        [],
        [],
        raw={
            "open": [],
            "tls": [
                {
                    "ip": "1.2.3.4",
                    "port": 443,
                    "subject_cn": "a",
                    "expired": False,
                }
            ],
            "findings": [
                {
                    "finding_class": "tls",
                    "ip": "1.2.3.4",
                    "port": 443,
                    "title": "TLS certificate self-signed (heuristic)",
                }
            ],
            "cves": [],
        },
    )
    data = json.loads((tmp_path / "pulse" / "tls.json").read_text(encoding="utf-8"))
    assert data["schema"] == "octo.pulse_tls.v1"
    assert data["count"] == 1
    assert len(data["findings"]) == 1
