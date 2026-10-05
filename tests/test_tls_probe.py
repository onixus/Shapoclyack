"""Unit tests for direct TLS probe (Phase 4) — no live network."""

from __future__ import annotations

import json
import ssl
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from scanner.pipeline.config_schema import TlsPostureConfig
from scanner.pipeline.tls_posture import check_tls_posture
from scanner.pipeline.tls_probe import (
    _classify_from_cert,
    _parse_tls_endpoints,
    _server_refusal,
    _trust_from_verify_error,
    _trust_store_gap,
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


# --- DQ2: what a failed handshake does and does not establish ----------------


def _ssl_error(reason: str) -> ssl.SSLError:
    exc = ssl.SSLError(1, f"[SSL: {reason}]")
    exc.reason = reason
    return exc


def test_server_refusal_is_an_alert_or_a_hang_up():
    for exc in (
        _ssl_error("TLSV1_ALERT_PROTOCOL_VERSION"),
        _ssl_error("SSLV3_ALERT_HANDSHAKE_FAILURE"),
        _ssl_error("UNSUPPORTED_PROTOCOL"),
        _ssl_error("WRONG_VERSION_NUMBER"),
        ssl.SSLEOFError(8, "EOF occurred in violation of protocol"),
        ConnectionResetError(54, "Connection reset by peer"),
    ):
        assert _server_refusal(exc) is not None, exc


def test_local_handshake_abort_is_not_a_server_refusal():
    """OpenSSL refusing the server's parameters says nothing about whether the
    server accepts the version -- reporting it as "rejected" would be a check
    that did not run, reported as a negative."""
    for exc in (
        _ssl_error("NO_SUITABLE_SIGNATURE_ALGORITHM"),
        _ssl_error("UNSAFE_LEGACY_RENEGOTIATION_DISABLED"),
        _ssl_error("DH_KEY_TOO_SMALL"),
        ValueError("check_hostname requires server_hostname"),
    ):
        assert _server_refusal(exc) is None, exc


def test_empty_trust_store_is_not_used_to_judge_chains(tmp_path: Path, monkeypatch):
    """No anchors at all would make every public certificate "untrusted"."""
    empty_dir = tmp_path / "certs"
    empty_dir.mkdir()
    monkeypatch.setattr(
        "scanner.pipeline.tls_probe.ssl.get_default_verify_paths",
        lambda: ssl.DefaultVerifyPaths(None, str(empty_dir), "", "", "", ""),
    )
    bare = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    assert _trust_store_gap(bare) is not None

    # A hashed CA directory (Debian's /etc/ssl/certs) is read on demand and
    # never shows up in cert_store_stats -- its entries count.
    (empty_dir / "4042bcee.0").write_text("", encoding="utf-8")
    assert _trust_store_gap(bare) is None


def _verify_error(code: int, message: str) -> ssl.SSLCertVerificationError:
    exc = ssl.SSLCertVerificationError(1, f"[SSL: CERTIFICATE_VERIFY_FAILED] {message}")
    exc.verify_code = code
    exc.verify_message = message
    return exc


def test_only_trust_failures_make_a_chain_untrusted():
    """Expiry is cert_expired's finding and key size weak_key's: a verification
    that stopped on either has not said whether the chain reaches an anchor."""
    for code, message in (
        (10, "certificate has expired"),
        (9, "certificate is not yet valid"),
        (66, "EE certificate key too weak"),
        (68, "CA signature digest algorithm too weak"),
    ):
        assert _trust_from_verify_error(_verify_error(code, message))["status"] == "inconclusive"

    for code, message in (
        (18, "self-signed certificate"),
        (19, "self-signed certificate in certificate chain"),
        (20, "unable to get local issuer certificate"),
    ):
        trust = _trust_from_verify_error(_verify_error(code, message))
        assert trust == {"status": "untrusted", "detail": message, "verify_code": code}
