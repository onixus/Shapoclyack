"""Unit tests for direct TLS probe (Phase 4) — no live network."""

from __future__ import annotations

import json
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from scanner.pipeline.cert_strength import weak_signature_issue
from scanner.pipeline.config_schema import TlsPostureConfig
from scanner.pipeline.tls_posture import check_tls_posture
from scanner.pipeline.tls_probe import (
    _classify_from_cert,
    _parse_tls_endpoints,
    ProbeContexts,
    _Attempt,
    _is_public_peer,
    _handshake,
    _legacy_status,
    _ServerRecords,
    _trust_from_verify_error,
    _strength_fields,
    _trust_skip,
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


def test_check_tls_posture_hands_the_dq2_settings_to_the_probe(tmp_path: Path):
    """The probe's defaults are the config's defaults, so only non-default
    values show whether the stage passes them on at all."""
    cfg = TlsPostureConfig(
        enabled=True,
        probe_fallback=True,
        probe_legacy_protocols=False,
        ca_bundle="/etc/shapoclyack/corp-ca.pem",
        chain_trust="always",
    )
    with patch("scanner.pipeline.tls_posture.probe_tls_endpoints", return_value=[]) as mock_probe:
        check_tls_posture(tmp_path / "nmap", cfg, tmp_path, open_ports=["10.0.0.9:443/tcp"])
    kwargs = mock_probe.call_args.kwargs
    assert kwargs["probe_legacy_protocols"] is False
    assert kwargs["ca_bundle"] == "/etc/shapoclyack/corp-ca.pem"
    assert kwargs["chain_trust"] == "always"


def test_chain_trust_is_judged_on_public_addresses_only_by_default():
    """The scanner's one definition of "public" (safe_http), NAT64 included: an
    IPv6-only sensor reaches 10.0.0.5 as 64:ff9b::a00:5."""
    for peer in ("8.8.8.8", "2001:4860:4860::8888", "64:ff9b::808:808"):
        assert _is_public_peer(peer), peer
    for peer in ("10.0.0.5", "127.0.0.1", "192.168.1.10", "64:ff9b::a00:5", "fe80::1%en0", "", "not-an-ip"):
        assert not _is_public_peer(peer), peer

    base = {"collect": ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), "verify": ssl.create_default_context()}
    public_only = ProbeContexts(**base)
    assert _trust_skip(public_only, "8.8.8.8", True) is None
    skipped = _trust_skip(public_only, "10.0.0.5", False)
    assert skipped["status"] == "not_evaluated"
    assert skipped["reason"] == "internal_address"
    # A configured bundle is the operator saying which CAs are theirs.
    assert _trust_skip(ProbeContexts(**base, ca_bundle_configured=True), "10.0.0.5", False) is None
    assert _trust_skip(ProbeContexts(**base, chain_trust="always"), "10.0.0.5", False) is None
    off = _trust_skip(ProbeContexts(**base, chain_trust="off"), "8.8.8.8", True)
    assert off["status"] == "not_evaluated"
    assert off["reason"] == "disabled"


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


def _record(content_type: int, body: bytes) -> bytes:
    return bytes([content_type]) + b"\x03\x01" + len(body).to_bytes(2, "big") + body


def _handshake_message(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def _server_hello(version: int, supported_version: int | None = None) -> bytes:
    body = version.to_bytes(2, "big") + bytes(32) + b"\x00" + b"\xc0\x2f" + b"\x00"
    if supported_version is not None:
        ext = (43).to_bytes(2, "big") + (2).to_bytes(2, "big") + supported_version.to_bytes(2, "big")
        body += len(ext).to_bytes(2, "big") + ext
    return _record(22, _handshake_message(2, body))


def _alert(description: int) -> bytes:
    return _record(21, bytes([2, description]))


def _attempt(server_bytes: bytes, error: BaseException | None) -> _Attempt:
    records = _ServerRecords()
    records.feed(server_bytes)
    return _Attempt(records=records, error=error)


def test_server_records_read_the_version_the_server_hello_chose():
    records = _ServerRecords()
    records.feed(_server_hello(0x0303, supported_version=0x0304) + _alert(40))
    assert records.server_hello_version == "TLSv1.3"
    # Past a TLS 1.3 ServerHello everything is encrypted: no plaintext alert.
    assert records.alert is None

    records = _ServerRecords()
    hello = _server_hello(0x0301)
    for i in range(len(hello)):  # arrives a byte at a time
        records.feed(hello[i : i + 1])
    assert records.server_hello_version == "TLSv1.0"

    records = _ServerRecords()
    records.feed(b"HTTP/1.0 400 Bad Request\r\n\r\n")
    assert records.not_tls and not records.tls_seen


def test_only_version_specific_answers_are_rejections():
    rejected = [
        _attempt(_alert(70), _ssl_error("TLSV1_ALERT_PROTOCOL_VERSION")),
        _attempt(_server_hello(0x0301), _ssl_error("UNSUPPORTED_PROTOCOL")),
    ]
    statuses = [_legacy_status(attempt, "TLSv1.1") for attempt in rejected]
    assert [s["status"] for s in statuses] == ["rejected", "rejected"]
    assert statuses[1]["server_hello_version"] == "TLSv1.0"


def test_answers_that_do_not_name_a_version_are_inconclusive():
    """A handshake_failure alert before the ServerHello is what a server with
    no cipher in common sends too; a reset is what a connection limit does; a
    local abort says nothing about the server. None of them is a "no" to the
    version."""
    cases = {
        "handshake_failure": _attempt(_alert(40), _ssl_error("SSLV3_ALERT_HANDSHAKE_FAILURE")),
        "reset": _attempt(b"", ConnectionResetError(54, "Connection reset by peer")),
        "eof": _attempt(b"", ssl.SSLEOFError(8, "EOF occurred in violation of protocol")),
        "timeout": _attempt(b"", TimeoutError("handshake timed out")),
        "local": _attempt(_server_hello(0x0301), _ssl_error("NO_SUITABLE_SIGNATURE_ALGORITHM")),
        "not_tls": _attempt(b"HTTP/1.0 400 Bad Request\r\n\r\n", _ssl_error("WRONG_VERSION_NUMBER")),
    }
    for name, attempt in cases.items():
        assert _legacy_status(attempt, "TLSv1.0")["status"] == "inconclusive", name


def _warning(description: int) -> bytes:
    return _record(21, bytes([1, description]))


def test_the_fatal_alert_is_the_servers_verdict():
    """A warning (unrecognized_name for an SNI it does not know) may come
    before the fatal alert that refuses the version, and a close_notify may
    follow it; neither is the answer."""
    for stream in (_warning(112) + _alert(70), _alert(70) + _warning(0)):
        attempt = _attempt(stream, _ssl_error("TLSV1_ALERT_PROTOCOL_VERSION"))
        assert _legacy_status(attempt, "TLSv1.0") == {"status": "rejected", "detail": "protocol_version alert"}


def test_openssl_version_reason_decides_when_the_records_named_no_version():
    """The server answered in TLS records that carried neither a ServerHello
    nor an alert; OpenSSL's own WRONG_VERSION_NUMBER is then the only signal,
    and it is version-specific."""
    attempt = _attempt(_record(23, bytes(16)), _ssl_error("WRONG_VERSION_NUMBER"))
    assert _legacy_status(attempt, "TLSv1.0") == {"status": "rejected", "detail": "WRONG_VERSION_NUMBER"}
    reset = _attempt(_record(23, bytes(16)), ConnectionResetError(54, "Connection reset by peer"))
    assert _legacy_status(reset, "TLSv1.0")["status"] == "inconclusive"


def test_client_certificate_request_is_recorded_not_read_as_a_refusal():
    attempt = _attempt(
        _server_hello(0x0301) + _record(22, _handshake_message(13, b"\x01\x01\x00\x00")) + _alert(40),
        _ssl_error("SSLV3_ALERT_HANDSHAKE_FAILURE"),
    )
    check = _legacy_status(attempt, "TLSv1.0")
    assert check["status"] == "inconclusive"
    assert check["client_cert_requested"] is True
    assert check["server_hello_version"] == "TLSv1.0"


def test_local_policy_ending_a_handshake_the_server_accepted_is_not_performed():
    """OpenSSL 3.0 (Ubuntu 24.04) at security level 1 still builds a TLS 1.0
    ClientHello, the server chooses TLS 1.0, and then the local stack refuses
    the SHA-1 signature it would have to accept. The server said yes; the
    scanner host could not finish -- the check was not performed, it is not
    an inconclusive answer from the server."""
    for reason in ("LEGACY_SIGALG_DISALLOWED_OR_UNSUPPORTED", "DH_KEY_TOO_SMALL"):
        attempt = _attempt(_server_hello(0x0301), _ssl_error(reason))
        check = _legacy_status(attempt, "TLSv1.0")
        assert check["status"] == "not_performed"
        assert check["server_hello_version"] == "TLSv1.0"
        assert reason in check["detail"]
    other = _attempt(_server_hello(0x0301), _ssl_error("SSLV3_ALERT_HANDSHAKE_FAILURE"))
    assert _legacy_status(other, "TLSv1.0")["status"] == "inconclusive"


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


def test_md_family_and_oiw_sha1_signature_oids_are_named_for_the_strength_check():
    """cryptography calls md2/md4WithRSAEncryption and the OIW sha1WithRSA
    "Unknown OID"; left as a dotted string they would never read as weak."""
    from cryptography import x509

    from tests.test_tls_probe_live import _certificate, _der, _rsa_key

    issuer_key = _rsa_key()
    ca = _certificate("Probe MD CA", issuer_key, ca=True)
    cert = _certificate("md.example.test", _rsa_key(), issuer=ca, issuer_key=issuer_key)
    tbs = cert.tbs_certificate_bytes
    assert tbs[1] == 0x82  # two-byte length: the content starts at offset 4
    sha256_alg = _der(0x30, bytes.fromhex("06092a864886f70d01010b") + b"\x05\x00")
    for oid_hex, expected in (
        ("06092a864886f70d010102", "md2WithRSAEncryption"),
        ("06092a864886f70d010103", "md4WithRSAEncryption"),
        ("06092a864886f70d010104", "md5WithRSAEncryption"),
        ("06052b0e03021d", "sha1WithRSA"),
    ):
        alg = _der(0x30, bytes.fromhex(oid_hex) + b"\x05\x00")
        new_tbs = _der(0x30, tbs[4:].replace(sha256_alg, alg))
        leaf = x509.load_der_x509_certificate(_der(0x30, new_tbs + alg + _der(0x03, b"\x00" + bytes(256))))
        fields = _strength_fields(leaf)
        assert fields["signature_algorithm"] == expected
        assert weak_signature_issue(fields["signature_algorithm"]) is not None, expected


class _AlwaysWantRead:
    """A TLS object that keeps asking for data, EOF or not."""

    def do_handshake(self) -> None:
        raise ssl.SSLWantReadError("want read")

    def version(self) -> None:
        return None

    def cipher(self) -> None:
        return None


class _WantReadContext:
    verify_mode = ssl.CERT_NONE

    def wrap_bio(self, incoming, outgoing, server_side=False, server_hostname=None):
        return _AlwaysWantRead()


def test_handshake_ends_at_eof_even_if_the_tls_stack_keeps_asking_for_data():
    """OpenSSL 3.5/3.6 raise SSLEOFError once EOF is written to the BIO; a
    stack that answered WANT_READ instead would make the loop read an empty
    socket again and again until the deadline. The EOF check ends it at once."""
    ours, peer = socket.socketpair()
    peer.close()
    started = time.monotonic()
    with ours:
        attempt = _handshake(ours, _WantReadContext(), "x.test", 3.0)
    assert isinstance(attempt.error, ConnectionAbortedError)
    assert time.monotonic() - started < 1.0
