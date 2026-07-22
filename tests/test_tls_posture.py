from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import quoteattr

from scanner.pipeline.config_schema import TlsPostureConfig
from scanner.pipeline.tls_posture import (
    _parse_ssl_cert_output,
    _parse_ssl_enum_ciphers_output,
    check_tls_posture,
)

VALID_CERT_OUTPUT = """Subject: commonName=example.com
Issuer: commonName=R3/organizationName=Let's Encrypt
Public Key type: rsa
Public Key bits: 2048
Signature Algorithm: sha256WithRSAEncryption
Not valid before: 2026-05-01T00:00:00
Not valid after:  2027-05-01T23:59:59
"""

EXPIRED_SELF_SIGNED_CERT_OUTPUT = """Subject: commonName=internal.local
Issuer: commonName=internal.local
Public Key type: rsa
Public Key bits: 1024
Signature Algorithm: sha1WithRSAEncryption
Not valid before: 2020-01-01T00:00:00
Not valid after:  2021-01-01T00:00:00
"""

WEAK_CIPHERS_OUTPUT = """TLSv1.0:
  ciphers:
    TLS_RSA_WITH_RC4_128_SHA (rsa 2048) - C
  least strength: C
TLSv1.2:
  ciphers:
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A
  least strength: A
"""


def _script_xml(script_id: str, output: str) -> str:
    return f'<script id="{script_id}" output={quoteattr(output)} />'


def _write_nmap_xml(
    path: Path,
    host: str,
    port: str,
    scripts: list[tuple[str, str]],
) -> None:
    script_nodes = "\n".join(_script_xml(sid, out) for sid, out in scripts)
    xml = f"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="{host}" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="{port}">
        <state state="open" />
        {script_nodes}
      </port>
    </ports>
  </host>
</nmaprun>
"""
    path.write_text(xml, encoding="utf-8")


ENABLED_CONFIG = TlsPostureConfig(enabled=True)


def test_disabled_config_writes_json_and_skips(tmp_path: Path):
    nmap_dir = tmp_path / "nmap"
    result = check_tls_posture(nmap_dir, TlsPostureConfig(enabled=False), tmp_path)
    assert result["skipped_reason"] == "tls_posture.disabled"
    assert (tmp_path / "tls_posture.json").exists()


def test_no_tls_endpoints_missing_nmap_dir(tmp_path: Path):
    nmap_dir = tmp_path / "does_not_exist"
    result = check_tls_posture(nmap_dir, ENABLED_CONFIG, tmp_path)
    assert result["skipped_reason"] == "no_tls_endpoints"


def test_no_tls_endpoints_empty_nmap_dir(tmp_path: Path):
    nmap_dir = tmp_path / "nmap"
    nmap_dir.mkdir()
    result = check_tls_posture(nmap_dir, ENABLED_CONFIG, tmp_path)
    assert result["skipped_reason"] == "no_tls_endpoints"


def test_valid_nonexpiring_cert_has_no_issues(tmp_path: Path):
    nmap_dir = tmp_path / "nmap" / "tcp"
    nmap_dir.mkdir(parents=True)
    _write_nmap_xml(
        nmap_dir / "host1.xml", "10.0.0.1", "443", [("ssl-cert", VALID_CERT_OUTPUT)]
    )
    now = datetime(2026, 7, 22, tzinfo=timezone.utc)
    result = check_tls_posture(tmp_path / "nmap", ENABLED_CONFIG, tmp_path, now=now)
    assert result["skipped_reason"] is None
    assert result["checked_count"] == 1
    finding = result["findings"][0]
    assert finding["issues"] == []

    lines = (tmp_path / "tls_posture_findings.txt").read_text(encoding="utf-8").splitlines()
    assert lines == []


def test_expired_self_signed_cert(tmp_path: Path):
    nmap_dir = tmp_path / "nmap" / "tcp"
    nmap_dir.mkdir(parents=True)
    _write_nmap_xml(
        nmap_dir / "host1.xml",
        "10.0.0.2",
        "8443",
        [("ssl-cert", EXPIRED_SELF_SIGNED_CERT_OUTPUT)],
    )
    now = datetime(2026, 7, 22, tzinfo=timezone.utc)
    result = check_tls_posture(tmp_path / "nmap", ENABLED_CONFIG, tmp_path, now=now)
    finding = result["findings"][0]
    kinds = {issue["kind"] for issue in finding["issues"]}
    assert "cert_expired" in kinds
    assert "self_signed" in kinds

    expired = next(i for i in finding["issues"] if i["kind"] == "cert_expired")
    assert expired["severity"] == "critical"
    self_signed = next(i for i in finding["issues"] if i["kind"] == "self_signed")
    assert self_signed["severity"] == "medium"
    assert self_signed["heuristic"] == "cn_match"

    lines = (tmp_path / "tls_posture_findings.txt").read_text(encoding="utf-8").splitlines()
    assert lines == ["10.0.0.2:8443:cert_expired,self_signed"]


def test_cert_expiring_soon(tmp_path: Path):
    now = datetime(2026, 7, 22, tzinfo=timezone.utc)
    not_after = now + timedelta(days=10)
    cert_output = (
        "Subject: commonName=soon.example.com\n"
        "Issuer: commonName=R3/organizationName=Let's Encrypt\n"
        "Public Key bits: 2048\n"
        "Signature Algorithm: sha256WithRSAEncryption\n"
        f"Not valid before: {(now - timedelta(days=80)).strftime('%Y-%m-%dT%H:%M:%S')}\n"
        f"Not valid after:  {not_after.strftime('%Y-%m-%dT%H:%M:%S')}\n"
    )
    nmap_dir = tmp_path / "nmap" / "tcp"
    nmap_dir.mkdir(parents=True)
    _write_nmap_xml(nmap_dir / "host1.xml", "10.0.0.3", "443", [("ssl-cert", cert_output)])

    result = check_tls_posture(
        tmp_path / "nmap", TlsPostureConfig(enabled=True, expiring_soon_days=30), tmp_path, now=now
    )
    finding = result["findings"][0]
    expiring = next(i for i in finding["issues"] if i["kind"] == "cert_expiring_soon")
    assert expiring["severity"] == "medium"
    assert expiring["days"] == 9 or expiring["days"] == 10


def test_weak_cipher_blob_flags_weak_and_not_strong(tmp_path: Path):
    nmap_dir = tmp_path / "nmap" / "tcp"
    nmap_dir.mkdir(parents=True)
    _write_nmap_xml(
        nmap_dir / "host1.xml",
        "10.0.0.4",
        "443",
        [("ssl-enum-ciphers", WEAK_CIPHERS_OUTPUT)],
    )
    result = check_tls_posture(tmp_path / "nmap", ENABLED_CONFIG, tmp_path)
    finding = result["findings"][0]
    kinds_by_version = {}
    for issue in finding["issues"]:
        kinds_by_version.setdefault(issue.get("version"), set()).add(issue["kind"])

    assert "weak_protocol" in kinds_by_version["TLSv1.0"]
    assert "weak_cipher_grade" in kinds_by_version["TLSv1.0"]
    assert "weak_cipher_name" in kinds_by_version["TLSv1.0"]
    assert "TLSv1.2" not in kinds_by_version


def test_port_with_unrelated_script_excluded(tmp_path: Path):
    nmap_dir = tmp_path / "nmap" / "tcp"
    nmap_dir.mkdir(parents=True)
    _write_nmap_xml(
        nmap_dir / "host1.xml",
        "10.0.0.5",
        "80",
        [("http-title", "Site Title Here")],
    )
    result = check_tls_posture(tmp_path / "nmap", ENABLED_CONFIG, tmp_path)
    assert result["skipped_reason"] == "no_tls_endpoints"
    assert result["findings"] == []


def test_garbage_cert_output_parse_fails_gracefully(tmp_path: Path):
    nmap_dir = tmp_path / "nmap" / "tcp"
    nmap_dir.mkdir(parents=True)
    _write_nmap_xml(
        nmap_dir / "host1.xml",
        "10.0.0.6",
        "443",
        [("ssl-cert", "not a certificate at all, just noise\nno fields here\n")],
    )
    result = check_tls_posture(tmp_path / "nmap", ENABLED_CONFIG, tmp_path)
    finding = result["findings"][0]
    assert finding["cert"]["parse_ok"] is False
    assert finding["issues"] == []


def test_malformed_xml_file_alongside_valid_one(tmp_path: Path):
    nmap_dir = tmp_path / "nmap" / "tcp"
    nmap_dir.mkdir(parents=True)
    (nmap_dir / "broken.xml").write_text("<nmaprun><host><ports", encoding="utf-8")
    _write_nmap_xml(
        nmap_dir / "good.xml", "10.0.0.7", "443", [("ssl-cert", VALID_CERT_OUTPUT)]
    )
    result = check_tls_posture(tmp_path / "nmap", ENABLED_CONFIG, tmp_path)
    hosts = {(f["host"], f["port"]) for f in result["findings"]}
    assert ("10.0.0.7", "443") in hosts


def test_max_targets_truncation(tmp_path: Path):
    nmap_dir = tmp_path / "nmap" / "tcp"
    nmap_dir.mkdir(parents=True)
    for i in range(5):
        _write_nmap_xml(
            nmap_dir / f"host{i}.xml",
            f"10.0.0.{10 + i}",
            "443",
            [("ssl-cert", VALID_CERT_OUTPUT)],
        )
    result = check_tls_posture(
        tmp_path / "nmap", TlsPostureConfig(enabled=True, max_targets=2), tmp_path
    )
    assert result["targets_considered"] == 5
    assert result["truncated"] is True
    assert result["checked_count"] == 2


def test_persisted_json_matches_returned_result(tmp_path: Path):
    nmap_dir = tmp_path / "nmap" / "tcp"
    nmap_dir.mkdir(parents=True)
    _write_nmap_xml(
        nmap_dir / "host1.xml", "10.0.0.8", "443", [("ssl-cert", VALID_CERT_OUTPUT)]
    )
    now = datetime(2026, 7, 22, tzinfo=timezone.utc)
    result = check_tls_posture(tmp_path / "nmap", ENABLED_CONFIG, tmp_path, now=now)
    saved = json.loads((tmp_path / "tls_posture.json").read_text(encoding="utf-8"))
    assert saved["findings"] == result["findings"]


# --- Direct unit tests of the low-level parsers -----------------------------


def test_parse_ssl_cert_output_valid():
    parsed = _parse_ssl_cert_output(VALID_CERT_OUTPUT)
    assert parsed["subject"] == "commonName=example.com"
    assert parsed["issuer"] == "commonName=R3/organizationName=Let's Encrypt"
    assert parsed["signature_algorithm"] == "sha256WithRSAEncryption"
    assert parsed["public_key_bits"] == 2048
    assert parsed["not_before"] == "2026-05-01T00:00:00+00:00"
    assert parsed["not_after"] == "2027-05-01T23:59:59+00:00"
    assert parsed["parse_ok"] is True


def test_parse_ssl_cert_output_expired_self_signed():
    parsed = _parse_ssl_cert_output(EXPIRED_SELF_SIGNED_CERT_OUTPUT)
    assert parsed["subject"] == "commonName=internal.local"
    assert parsed["issuer"] == "commonName=internal.local"
    assert parsed["not_before"] == "2020-01-01T00:00:00+00:00"
    assert parsed["not_after"] == "2021-01-01T00:00:00+00:00"
    assert parsed["public_key_bits"] == 1024
    assert parsed["parse_ok"] is True


def test_parse_ssl_enum_ciphers_output():
    versions = _parse_ssl_enum_ciphers_output(WEAK_CIPHERS_OUTPUT)
    assert len(versions) == 2

    tls10 = next(v for v in versions if v["version"] == "TLSv1.0")
    assert tls10["least_strength"] == "C"
    assert tls10["ciphers"] == [{"name": "TLS_RSA_WITH_RC4_128_SHA", "grade": "C"}]

    tls12 = next(v for v in versions if v["version"] == "TLSv1.2")
    assert tls12["least_strength"] == "A"
    assert tls12["ciphers"] == [
        {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "grade": "A"}
    ]
