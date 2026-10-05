"""The stdlib TLS probe against real TLS servers on loopback (DQ2).

Every server here is a Python ``ssl`` server thread on 127.0.0.1 with a
certificate generated for the test -- the same OpenSSL handshake a scanned
host would do, with nothing mocked between the probe and the server. That is
the point: the probe used to say it tried legacy versions and did not, and
only a server that actually accepts TLS 1.0 shows the difference.

OpenSSL 3 refuses TLS 1.0/1.1 and sub-2048-bit keys above security level 0,
on the server side too, so the test servers run at ``@SECLEVEL=0``. A host
whose OpenSSL cannot complete such a handshake at all (a build without TLS
1.0, a crypto policy that forbids SHA-1) skips the test with the reason
instead of passing it without having tested anything.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import ssl
import sys
import threading
import warnings
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from scanner.pipeline.tls_probe import probe_tls_endpoints
from tests.mtls_pki import CA

LEGACY_CIPHERS = "DEFAULT:@SECLEVEL=0"

# sha256WithRSAEncryption and sha1WithRSAEncryption: same length, so the
# algorithm in a to-be-signed certificate can be swapped in place.
_SHA256_RSA_OID = bytes.fromhex("06092a864886f70d01010b")
_SHA1_RSA_OID = bytes.fromhex("06092a864886f70d010105")


# --------------------------------------------------------------------------
# certificates
# --------------------------------------------------------------------------


def _rsa_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _certificate(
    common_name: str,
    key,
    *,
    issuer: x509.Certificate | None = None,
    issuer_key=None,
    ca: bool = False,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    organization: str | None = None,
) -> x509.Certificate:
    """A leaf for 127.0.0.1, self-signed unless ``issuer`` is given."""
    now = datetime.now(UTC)
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if organization:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    subject = x509.Name(attributes)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer is not None else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - timedelta(days=1))
        .not_valid_after(not_after or now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]
            ),
            critical=False,
        )
    return builder.sign(issuer_key or key, hashes.SHA256())


def _der_length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(body)) + body


def _resign_with_sha1(cert: x509.Certificate, issuer_key: rsa.RSAPrivateKey) -> x509.Certificate:
    """The same certificate signed with sha1WithRSAEncryption.

    ``cryptography`` no longer signs X.509 with SHA-1, and the openssl CLI is
    not on every CI image, so the signature algorithm in the TBS is swapped
    and the TBS signed with the raw RSA primitive.
    """
    tbs = cert.tbs_certificate_bytes
    assert tbs.count(_SHA256_RSA_OID) == 1
    tbs = tbs.replace(_SHA256_RSA_OID, _SHA1_RSA_OID)
    signature = issuer_key.sign(tbs, padding.PKCS1v15(), hashes.SHA1())
    algorithm = _der(0x30, _SHA1_RSA_OID + b"\x05\x00")
    der = _der(0x30, tbs + algorithm + _der(0x03, b"\x00" + signature))
    return x509.load_der_x509_certificate(der)


def _write(directory: Path, name: str, cert: x509.Certificate, key) -> tuple[Path, Path]:
    cert_path = directory / f"{name}.crt"
    key_path = directory / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def _self_signed(directory: Path, name: str, bits: int = 2048) -> tuple[Path, Path]:
    key = _rsa_key(bits)
    return _write(directory, name, _certificate("legacy.example.test", key), key)


# --------------------------------------------------------------------------
# servers
# --------------------------------------------------------------------------


@contextmanager
def _tls_server(
    cert_path: Path,
    key_path: Path,
    *,
    minimum: ssl.TLSVersion | None = None,
    maximum: ssl.TLSVersion | None = None,
) -> Iterator[int]:
    """A TLS server on 127.0.0.1 that handshakes every connection; yields its port."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.set_ciphers(LEGACY_CIPHERS)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        if minimum is not None:
            ctx.minimum_version = minimum
        if maximum is not None:
            ctx.maximum_version = maximum
    try:
        ctx.load_cert_chain(cert_path, key_path)
    except ssl.SSLError as exc:
        pytest.skip(f"local OpenSSL will not serve this certificate: {exc}")

    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(0.2)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            conn.settimeout(5)
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except (OSError, ssl.SSLError):
                pass  # pinned versions and failed verification hang up mid-handshake
            finally:
                conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        stop.set()
        thread.join(timeout=2)
        listener.close()


def _require_handshake(port: int, version: ssl.TLSVersion, label: str) -> None:
    """Skip unless this host's OpenSSL can complete a ``label`` handshake at all.

    Uses a plain ``ssl`` client, not the probe: the question is whether the
    platform can do it, so that a probe reporting nothing means something.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers(LEGACY_CIPHERS)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            with ctx.wrap_socket(sock) as tls:
                assert tls.version() in (label, label.replace(".0", ""))
    except (OSError, ssl.SSLError, ValueError) as exc:
        pytest.skip(f"local OpenSSL cannot complete a {label} handshake on loopback: {exc}")


def _has_trust_store() -> bool:
    """Whether this host has system trust anchors, checked without the probe's own guard."""
    if ssl.create_default_context().cert_store_stats()["x509_ca"]:
        return True
    capath = ssl.get_default_verify_paths().capath
    return bool(capath) and any(re.match(r"^[0-9a-f]{8}\.\d+$", name) for name in os.listdir(capath))


def _require_trust_store() -> None:
    """Skip the chain-trust tests on a host with no system CA store at all.

    The probe declines to judge trust there (every public certificate would
    read as untrusted), so these tests would have nothing to observe.
    """
    if not _has_trust_store():
        pytest.skip("chain trust needs system trust anchors (no CA file or hashed CA directory)")


def _probe(port: int, **kwargs) -> dict:
    rows = probe_tls_endpoints(
        [f"127.0.0.1:{port}/tcp"],
        tls_ports={port},
        timeout_seconds=5.0,
        concurrency=1,
        **kwargs,
    )
    assert len(rows) == 1, rows
    return rows[0]


def _issues(row: dict, kind: str) -> list[dict]:
    return [issue for issue in row["issues"] if issue["kind"] == kind]


# --------------------------------------------------------------------------
# legacy protocols
# --------------------------------------------------------------------------


def test_server_that_also_speaks_tls13_is_caught_accepting_tls10(tmp_path: Path):
    """The default handshake negotiates TLS 1.3 here; only a ClientHello pinned
    to TLS 1.0 shows the server still takes it."""
    cert, key = _self_signed(tmp_path, "wide")
    with _tls_server(cert, key, minimum=ssl.TLSVersion.TLSv1) as port:
        _require_handshake(port, ssl.TLSVersion.TLSv1, "TLSv1.0")
        row = _probe(port)

    assert row["negotiated_protocol"] == "TLSv1.3"
    assert row["accepted_protocols"] == ["TLSv1.0", "TLSv1.1", "TLSv1.3"]
    assert row["checks"]["protocols"]["TLSv1.0"] == {"status": "accepted"}
    weak = {issue["version"]: issue for issue in _issues(row, "weak_protocol")}
    assert set(weak) == {"TLSv1.0", "TLSv1.1"}
    assert weak["TLSv1.0"]["severity"] == "high"


def test_tls10_only_server_is_reported_not_dropped(tmp_path: Path):
    """A server whose highest version is TLS 1.0 used to fail the probe's only
    handshake and vanish from the results."""
    cert, key = _self_signed(tmp_path, "old")
    with _tls_server(cert, key, minimum=ssl.TLSVersion.TLSv1, maximum=ssl.TLSVersion.TLSv1) as port:
        _require_handshake(port, ssl.TLSVersion.TLSv1, "TLSv1.0")
        row = _probe(port)

    assert row["negotiated_protocol"] == "TLSv1.0"
    assert row["accepted_protocols"] == ["TLSv1.0"]
    assert [issue["version"] for issue in _issues(row, "weak_protocol")] == ["TLSv1.0"]
    # Answered with TLS 1.0 to a TLS 1.1 ClientHello: the server said no.
    assert row["checks"]["protocols"]["TLSv1.1"]["status"] == "rejected"
    # The certificate still came through the TLS 1.0 handshake.
    assert row["cert"]["subject_cn"] == "legacy.example.test"


def test_tls12_only_server_is_clean_and_the_legacy_checks_ran(tmp_path: Path):
    cert, key = _self_signed(tmp_path, "modern")
    with _tls_server(cert, key, minimum=ssl.TLSVersion.TLSv1_2) as port:
        row = _probe(port)

    assert _issues(row, "weak_protocol") == []
    assert row["accepted_protocols"] == ["TLSv1.3"]
    protocols = row["checks"]["protocols"]
    # "rejected" is a server answer, not the absence of a check.
    assert protocols["TLSv1.0"]["status"] == "rejected"
    assert protocols["TLSv1.1"]["status"] == "rejected"
    assert protocols["SSLv3"]["status"] == "not_testable"
    assert protocols["SSLv2"]["status"] == "not_testable"


def test_local_stack_that_cannot_offer_tls10_reports_not_performed(tmp_path: Path, monkeypatch):
    """At security level 1 OpenSSL 3 will not build a TLS 1.0 ClientHello -- the
    position a scanner host with a strict crypto policy is in. The server does
    accept TLS 1.0; the probe must say it did not check, not that it was refused."""
    monkeypatch.setattr("scanner.pipeline.tls_probe._ASSESSMENT_CIPHERS", "DEFAULT:@SECLEVEL=1")
    cert, key = _self_signed(tmp_path, "wide")
    with _tls_server(cert, key, minimum=ssl.TLSVersion.TLSv1) as port:
        _require_handshake(port, ssl.TLSVersion.TLSv1, "TLSv1.0")
        row = _probe(port)

    for label in ("TLSv1.0", "TLSv1.1"):
        check = row["checks"]["protocols"][label]
        assert check["status"] == "not_performed"
        assert "NO_PROTOCOLS_AVAILABLE" in check["detail"]
    assert _issues(row, "weak_protocol") == []


def test_legacy_switch_off_records_the_checks_as_not_performed(tmp_path: Path):
    cert, key = _self_signed(tmp_path, "wide")
    with _tls_server(cert, key, minimum=ssl.TLSVersion.TLSv1) as port:
        row = _probe(port, probe_legacy_protocols=False)

    assert row["accepted_protocols"] == ["TLSv1.3"]
    check = row["checks"]["protocols"]["TLSv1.0"]
    assert check["status"] == "not_performed"
    assert "probe_legacy_protocols" in check["detail"]


# --------------------------------------------------------------------------
# certificate strength
# --------------------------------------------------------------------------


def test_1024_bit_rsa_key_is_a_weak_key(tmp_path: Path):
    cert, key = _self_signed(tmp_path, "small", bits=1024)
    with _tls_server(cert, key) as port:
        row = _probe(port)

    assert row["cert"]["public_key_type"] == "rsa"
    assert row["cert"]["public_key_bits"] == 1024
    weak = _issues(row, "weak_key")
    assert len(weak) == 1
    assert weak[0]["severity"] == "medium"
    assert weak[0]["bits"] == 1024
    assert row["checks"]["cert_strength"] == {"status": "performed"}
    # Above security level 0 OpenSSL stops at "EE key too weak" before it says
    # anything about trust; the weak key must not hide the self-signed chain.
    if _has_trust_store():
        assert row["checks"]["chain_trust"]["status"] == "untrusted"


def test_sha1_signed_leaf_is_a_weak_signature(tmp_path: Path):
    ca_key = _rsa_key()
    ca_cert = _certificate("Probe SHA-1 CA", ca_key, ca=True)
    leaf_key = _rsa_key()
    leaf = _resign_with_sha1(
        _certificate("sha1.example.test", leaf_key, issuer=ca_cert, issuer_key=ca_key), ca_key
    )
    assert leaf.signature_hash_algorithm.name == "sha1"
    cert, key = _write(tmp_path, "sha1", leaf, leaf_key)
    with _tls_server(cert, key) as port:
        row = _probe(port)

    weak = _issues(row, "weak_signature")
    assert len(weak) == 1
    assert weak[0]["algorithm"] == "sha1WithRSAEncryption"
    assert _issues(row, "weak_key") == []


def test_strength_check_without_cryptography_is_not_performed(tmp_path: Path, monkeypatch):
    cert, key = _self_signed(tmp_path, "small", bits=1024)
    with _tls_server(cert, key) as port:
        # The scanner image does not install cryptography (requirements.txt).
        monkeypatch.setitem(sys.modules, "cryptography", None)
        row = _probe(port)

    assert _issues(row, "weak_key") == []
    check = row["checks"]["cert_strength"]
    assert check["status"] == "not_performed"
    assert "cryptography" in check["detail"]


# --------------------------------------------------------------------------
# chain trust
# --------------------------------------------------------------------------


def test_chain_from_an_unknown_ca_is_untrusted(tmp_path: Path):
    _require_trust_store()
    ca = CA("Probe Test CA")
    cert, key = ca.server("127.0.0.1").write(tmp_path, "leaf")
    with _tls_server(cert, key) as port:
        row = _probe(port)

    untrusted = _issues(row, "cert_untrusted")
    assert len(untrusted) == 1
    assert untrusted[0]["severity"] == "medium"
    assert untrusted[0]["detail"] == "unable to get local issuer certificate"
    assert row["checks"]["chain_trust"]["status"] == "untrusted"
    assert _issues(row, "self_signed") == []


def test_ca_bundle_makes_an_internal_chain_trusted(tmp_path: Path):
    _require_trust_store()
    ca = CA("Probe Test CA")
    cert, key = ca.server("127.0.0.1").write(tmp_path, "leaf")
    bundle, _ = ca.write(tmp_path, "internal-ca")
    with _tls_server(cert, key) as port:
        row = _probe(port, ca_bundle=str(bundle))

    assert _issues(row, "cert_untrusted") == []
    assert row["checks"]["chain_trust"] == {"status": "trusted"}
    # Verified, so the stdlib decoded the certificate itself.
    assert row["cert"]["subject_cn"] == "127.0.0.1"


def test_verified_chain_silences_the_self_signed_heuristic(tmp_path: Path):
    """CA and leaf share a commonName (not the whole name -- OpenSSL itself
    treats a leaf whose subject equals its issuer as self-signed): the
    heuristic cannot tell that from a self-signed certificate, a verified
    chain can."""
    _require_trust_store()
    ca_key = _rsa_key()
    ca_cert = _certificate("shared.example.test", ca_key, ca=True, organization="Probe Root")
    leaf_key = _rsa_key()
    leaf = _certificate("shared.example.test", leaf_key, issuer=ca_cert, issuer_key=ca_key)
    cert, key = _write(tmp_path, "leaf", leaf, leaf_key)
    bundle, _ = _write(tmp_path, "internal-ca", ca_cert, ca_key)
    with _tls_server(cert, key) as port:
        trusted = _probe(port, ca_bundle=str(bundle))
        unverified = _probe(port)

    assert _issues(trusted, "self_signed") == []
    assert [i["kind"] for i in unverified["issues"] if i["kind"] in ("self_signed", "cert_untrusted")] == [
        "self_signed",
        "cert_untrusted",
    ]


def test_expired_leaf_of_a_trusted_ca_is_expired_not_untrusted(tmp_path: Path):
    _require_trust_store()
    ca = CA("Probe Test CA")
    now = datetime.now(UTC)
    leaf_key = _rsa_key()
    leaf = _certificate(
        "expired.example.test",
        leaf_key,
        issuer=ca.cert,
        issuer_key=ca.key,
        not_before=now - timedelta(days=400),
        not_after=now - timedelta(days=3),
    )
    cert, key = _write(tmp_path, "expired", leaf, leaf_key)
    bundle, _ = ca.write(tmp_path, "internal-ca")
    with _tls_server(cert, key) as port:
        row = _probe(port, ca_bundle=str(bundle))

    assert row["checks"]["chain_trust"] == {"status": "trusted"}
    assert _issues(row, "cert_untrusted") == []
    assert len(_issues(row, "cert_expired")) == 1


def test_unreadable_ca_bundle_does_not_flag_every_endpoint(tmp_path: Path):
    """Judging an internal PKI against the system store alone would mark all of
    it untrusted: a bundle that fails to load turns the trust check off."""
    _require_trust_store()
    ca = CA("Probe Test CA")
    cert, key = ca.server("127.0.0.1").write(tmp_path, "leaf")
    with _tls_server(cert, key) as port:
        row = _probe(port, ca_bundle=str(tmp_path / "missing.pem"))

    assert _issues(row, "cert_untrusted") == []
    trust = row["checks"]["chain_trust"]
    assert trust["status"] == "not_performed"
    assert "missing.pem" in trust["detail"]


def test_plain_tcp_listener_yields_no_row(tmp_path: Path):
    """Not TLS at all: no row, as before, and no legacy findings invented."""
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def answer() -> None:
        for _ in range(4):
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            with conn:
                conn.sendall(b"HTTP/1.0 400 Bad Request\r\n\r\n")

    thread = threading.Thread(target=answer, daemon=True)
    thread.start()
    try:
        rows = probe_tls_endpoints(
            [f"127.0.0.1:{port}/tcp"], tls_ports={port}, timeout_seconds=3.0, concurrency=1
        )
    finally:
        listener.close()
        thread.join(timeout=2)
    assert rows == []
