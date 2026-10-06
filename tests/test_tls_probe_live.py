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

127.0.0.1 is not a public address, so under the default ``chain_trust:
public_only`` the probe does not judge chains here; the trust tests either
pass ``chain_trust="always"`` or configure a ``ca_bundle``, as an operator
would.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import ssl
import sys
import threading
import time
import warnings
from collections.abc import Callable, Iterator
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

# A fatal handshake_failure alert, as a version-intolerant server sends it.
_HANDSHAKE_FAILURE_ALERT = bytes.fromhex("15030100020228")


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


def _write(
    directory: Path, name: str, cert: x509.Certificate, key, chain: tuple[x509.Certificate, ...] = ()
) -> tuple[Path, Path]:
    """Write a PEM certificate (followed by ``chain``) and its key."""
    cert_path = directory / f"{name}.crt"
    key_path = directory / f"{name}.key"
    cert_path.write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in (cert, *chain)))
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


def _rsa_ca(directory: Path, name: str = "Probe Root") -> tuple[x509.Certificate, rsa.RSAPrivateKey, Path]:
    """A self-signed RSA CA and the PEM bundle that trusts it."""
    key = _rsa_key()
    cert = _certificate(name, key, ca=True, organization="Probe Test")
    bundle = directory / f"{name.replace(' ', '-').lower()}.pem"
    bundle.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert, key, bundle


# --------------------------------------------------------------------------
# servers
# --------------------------------------------------------------------------


def _offered_max_version(record: bytes) -> int:
    """The highest version a ClientHello record offers (supported_versions, else client_version)."""
    hello = record[9:]  # record header (5) + handshake header (4)
    best = int.from_bytes(hello[0:2], "big")
    pos = 2 + 32
    pos += 1 + hello[pos]  # session id
    pos += 2 + int.from_bytes(hello[pos : pos + 2], "big")  # cipher suites
    pos += 1 + hello[pos]  # compression methods
    end = pos + 2 + int.from_bytes(hello[pos : pos + 2], "big")
    pos += 2
    while pos + 4 <= end:
        ext_type = int.from_bytes(hello[pos : pos + 2], "big")
        ext_len = int.from_bytes(hello[pos + 2 : pos + 4], "big")
        if ext_type == 43:  # supported_versions
            listed = hello[pos + 5 : pos + 4 + ext_len]
            best = max(int.from_bytes(listed[i : i + 2], "big") for i in range(0, len(listed), 2))
        pos += 4 + ext_len
    return best


def _peek_record(conn: socket.socket) -> bytes:
    """The client's first TLS record, read without consuming it."""
    data = b""
    for _ in range(100):
        data = conn.recv(65536, socket.MSG_PEEK)
        if len(data) >= 5 and len(data) >= 5 + int.from_bytes(data[3:5], "big"):
            return data
        time.sleep(0.01)
    return data


@contextmanager
def _listening(handle: Callable[[socket.socket], None]) -> Iterator[int]:
    """Accept on 127.0.0.1 in a thread and hand each connection to ``handle``.

    Yields the port. The thread is stopped and joined before the test returns
    -- the suite fails a test whose threads outlive it, and closing a listener
    does not wake a thread blocked in ``accept()`` on Linux -- so accept polls
    a stop event, and a connection still open at teardown is shut down so a
    handler blocked on it returns.
    """
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(0.2)
    stop = threading.Event()
    lock = threading.Lock()
    open_conns: set[socket.socket] = set()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            conn.settimeout(5)
            with lock:
                open_conns.add(conn)
            try:
                handle(conn)
            except (OSError, ssl.SSLError, ValueError, IndexError):
                pass  # pinned versions and failed verification hang up mid-handshake
            finally:
                with lock:
                    open_conns.discard(conn)
                conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        stop.set()
        with lock:
            for conn in open_conns:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass  # the client already closed it
        thread.join(timeout=10)
        listener.close()
        assert not thread.is_alive(), "test server thread did not stop"


@contextmanager
def _tls_server(
    cert_path: Path,
    key_path: Path,
    *,
    minimum: ssl.TLSVersion | None = None,
    maximum: ssl.TLSVersion | None = None,
    ciphers: str = LEGACY_CIPHERS,
    client_ca: Path | None = None,
    accept_limit: int | None = None,
    intolerant_above: int | None = None,
    connections: list[int] | None = None,
) -> Iterator[int]:
    """A TLS server on 127.0.0.1 that handshakes every connection; yields its port.

    ``client_ca`` requires a client certificate from that CA. ``accept_limit``
    resets every connection after the first N, as a per-source connection
    limiter does. ``intolerant_above`` answers a ClientHello offering anything
    newer than that version with a handshake_failure alert, as old
    version-intolerant stacks did.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.set_ciphers(ciphers)
    except ssl.SSLError as exc:
        pytest.skip(f"local OpenSSL has no cipher {ciphers!r}: {exc}")
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
    if client_ca is not None:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=str(client_ca))

    accepted = [0]

    def handle(conn: socket.socket) -> None:
        accepted[0] += 1
        if connections is not None:
            connections[0] += 1
        if accept_limit is not None and accepted[0] > accept_limit:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, (1).to_bytes(4, "little") + bytes(4))
            return
        if intolerant_above is not None:
            record = _peek_record(conn)
            if len(record) > 9 and _offered_max_version(record) > intolerant_above:
                conn.sendall(_HANDSHAKE_FAILURE_ALERT)
                return
        with ctx.wrap_socket(conn, server_side=True) as tls:
            tls.recv(1)

    with _listening(handle) as port:
        yield port


def _client_handshake(
    port: int, version: ssl.TLSVersion, *, cert: tuple[Path, Path] | None = None
) -> str | None:
    """A plain ``ssl`` client pinned to ``version``: the negotiated version."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers(LEGACY_CIPHERS)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = version
        ctx.maximum_version = version
    if cert is not None:
        ctx.load_cert_chain(*cert)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        with ctx.wrap_socket(sock) as tls:
            tls.sendall(b"x")  # a server that wanted a certificate says so by now
            return tls.version()


def _require_handshake(
    port: int, version: ssl.TLSVersion, label: str, *, cert: tuple[Path, Path] | None = None
) -> None:
    """Skip unless this host's OpenSSL can complete a ``label`` handshake at all.

    Uses a plain ``ssl`` client, not the probe: the question is whether the
    platform can do it, so that a probe reporting nothing means something.
    """
    try:
        negotiated = _client_handshake(port, version, cert=cert)
    except (OSError, ssl.SSLError, ValueError) as exc:
        pytest.skip(f"local OpenSSL cannot complete a {label} handshake on loopback: {exc}")
    assert negotiated in (label, label.replace(".0", ""))


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
    # Answered a TLS 1.1 ClientHello with a TLS 1.0 ServerHello: the server said no.
    tls11 = row["checks"]["protocols"]["TLSv1.1"]
    assert tls11["status"] == "rejected"
    assert tls11["server_hello_version"] == "TLSv1.0"
    # The certificate still came through the TLS 1.0 handshake.
    assert row["cert"]["subject_cn"] == "legacy.example.test"


def test_tls10_only_server_is_found_with_the_legacy_checks_off(tmp_path: Path):
    """The main handshake reaches as low as the local OpenSSL goes, so the
    switch that saves two connections does not hide a TLS 1.0-only server."""
    cert, key = _self_signed(tmp_path, "old")
    with _tls_server(cert, key, minimum=ssl.TLSVersion.TLSv1, maximum=ssl.TLSVersion.TLSv1) as port:
        _require_handshake(port, ssl.TLSVersion.TLSv1, "TLSv1.0")
        row = _probe(port, probe_legacy_protocols=False)

    assert row["accepted_protocols"] == ["TLSv1.0"]
    assert row["checks"]["protocols"]["TLSv1.0"]["status"] == "accepted"
    assert row["checks"]["protocols"]["TLSv1.1"]["status"] == "not_evaluated"
    assert [issue["version"] for issue in _issues(row, "weak_protocol")] == ["TLSv1.0"]


def test_version_intolerant_server_is_judged_by_its_pinned_handshakes(tmp_path: Path):
    """An old stack that answers a modern ClientHello with handshake_failure but
    takes one offering TLS 1.1 at most: the main handshake fails, the pinned
    ones complete, and the row reports the best version a client got."""
    cert, key = _self_signed(tmp_path, "intolerant")
    with _tls_server(
        cert, key, minimum=ssl.TLSVersion.TLSv1, maximum=ssl.TLSVersion.TLSv1_1, intolerant_above=0x0302
    ) as port:
        _require_handshake(port, ssl.TLSVersion.TLSv1_1, "TLSv1.1")
        row = _probe(port)

    assert row["accepted_protocols"] == ["TLSv1.0", "TLSv1.1"]
    assert row["negotiated_protocol"] == "TLSv1.1"
    assert {issue["version"] for issue in _issues(row, "weak_protocol")} == {"TLSv1.0", "TLSv1.1"}
    assert row["cert"]["subject_cn"] == "legacy.example.test"


def test_tls12_only_server_is_clean_and_the_legacy_checks_ran(tmp_path: Path):
    cert, key = _self_signed(tmp_path, "modern")
    with _tls_server(cert, key, minimum=ssl.TLSVersion.TLSv1_2) as port:
        row = _probe(port)

    assert _issues(row, "weak_protocol") == []
    assert row["accepted_protocols"] == ["TLSv1.3"]
    protocols = row["checks"]["protocols"]
    # "rejected" is a server answer (a protocol_version alert), not the absence of a check.
    assert protocols["TLSv1.0"] == {"status": "rejected", "detail": "protocol_version alert"}
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


def test_legacy_switch_off_records_the_checks_as_not_evaluated(tmp_path: Path):
    """Switched off by configuration is a choice, like chain_trust: off -- not
    a check that failed, which would keep the TLS control from ever being ok."""
    cert, key = _self_signed(tmp_path, "wide")
    with _tls_server(cert, key, minimum=ssl.TLSVersion.TLSv1) as port:
        row = _probe(port, probe_legacy_protocols=False)

    assert row["accepted_protocols"] == ["TLSv1.3"]
    check = row["checks"]["protocols"]["TLSv1.0"]
    assert check["status"] == "not_evaluated"
    assert check["reason"] == "disabled"
    assert "probe_legacy_protocols" in check["detail"]


def test_server_wanting_a_client_certificate_is_not_reported_as_refusing_tls10(tmp_path: Path):
    """The server chooses TLS 1.0 and then asks for a certificate the probe does
    not have. That is not a "no" to TLS 1.0 -- a client with a certificate gets
    in -- so the check says it could not tell, and why."""
    client_ca = CA("Probe Client CA")
    client_ca_path, _ = client_ca.write(tmp_path, "client-ca")
    client_cert = client_ca.plain_client().write(tmp_path, "client")
    cert, key = _self_signed(tmp_path, "mtls")
    with _tls_server(cert, key, minimum=ssl.TLSVersion.TLSv1, client_ca=client_ca_path) as port:
        _require_handshake(port, ssl.TLSVersion.TLSv1, "TLSv1.0", cert=client_cert)
        row = _probe(port)

    tls10 = row["checks"]["protocols"]["TLSv1.0"]
    assert tls10["status"] == "inconclusive"
    assert tls10["client_cert_requested"] is True
    assert tls10["server_hello_version"] == "TLSv1.0"
    assert row["client_cert_requested"] is True
    assert "TLSv1.0" not in [issue.get("version") for issue in _issues(row, "weak_protocol")]


def test_connection_limit_is_not_read_as_a_refusal(tmp_path: Path):
    """A limiter that resets every connection after the first: the legacy
    checks could not run, which is not the server refusing TLS 1.0."""
    cert, key = _self_signed(tmp_path, "limited")
    with _tls_server(cert, key, minimum=ssl.TLSVersion.TLSv1, accept_limit=1) as port:
        row = _probe(port)

    assert row["accepted_protocols"] == ["TLSv1.3"]
    for label in ("TLSv1.0", "TLSv1.1"):
        assert row["checks"]["protocols"][label]["status"] == "inconclusive"


def test_failed_second_connection_keeps_what_the_first_one_showed(tmp_path: Path):
    """Verification stops the first handshake at the certificate; the limiter
    resets the second. The certificate and the verdict on it stay."""
    cert, key = _self_signed(tmp_path, "limited")
    with _tls_server(cert, key, accept_limit=1) as port:
        row = _probe(port, chain_trust="always")

    assert row["cert"]["subject_cn"] == "legacy.example.test"
    assert row["checks"]["chain_trust"]["status"] == "untrusted"
    assert len(_issues(row, "self_signed")) == 1
    assert row["accepted_protocols"] == []


def test_tls10_server_without_a_common_cipher_still_yields_a_row(tmp_path: Path):
    """A TLS 1.0 server whose only suite OpenSSL's DEFAULT list does not offer
    answers the pinned ClientHello with handshake_failure: it speaks TLS 1.0,
    the probe cannot tell a refused cipher list from a refused version, and the
    endpoint is reported (nothing accepted, no certificate) instead of dropped.
    The server runs at security level 0 like the other legacy servers here;
    above it OpenSSL 3 would not speak TLS 1.0 at all."""
    cert, key = _self_signed(tmp_path, "ancient")
    with _tls_server(
        cert,
        key,
        minimum=ssl.TLSVersion.TLSv1,
        maximum=ssl.TLSVersion.TLSv1,
        ciphers="AECDH-AES128-SHA:@SECLEVEL=0",
    ) as port:
        row = _probe(port)

    assert row["accepted_protocols"] == []
    assert row["negotiated_protocol"] is None
    tls10 = row["checks"]["protocols"]["TLSv1.0"]
    assert tls10["status"] == "inconclusive"
    assert "handshake_failure" in tls10["detail"]
    assert row["checks"]["cert_fields"] == {"status": "not_performed", "detail": "no certificate received"}
    assert row["cert"] is None


# --------------------------------------------------------------------------
# certificate strength
# --------------------------------------------------------------------------


def test_1024_bit_rsa_key_is_a_weak_key(tmp_path: Path):
    cert, key = _self_signed(tmp_path, "small", bits=1024)
    with _tls_server(cert, key) as port:
        row = _probe(port, chain_trust="always")

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
        assert row["checks"]["chain_trust"]["verify_code"] == 18


def test_sha1_signed_leaf_is_a_weak_signature(tmp_path: Path):
    ca_cert, ca_key, _bundle = _rsa_ca(tmp_path, "Probe SHA-1 CA")
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
        monkeypatch.setitem(sys.modules, "cryptography", None)
        row = _probe(port)

    assert _issues(row, "weak_key") == []
    check = row["checks"]["cert_strength"]
    assert check["status"] == "not_performed"
    assert "cryptography" in check["detail"]
    # Names and dates come from the stdlib, with or without cryptography.
    assert row["checks"]["cert_fields"] == {"status": "performed"}
    assert row["cert"]["subject_cn"] == "legacy.example.test"


# --------------------------------------------------------------------------
# chain trust
# --------------------------------------------------------------------------


def test_internal_address_chain_is_not_judged_by_default(tmp_path: Path):
    """An intranet's own CA is not a finding until the operator names it: on
    a non-public address and without ca_bundle the chain is not judged."""
    cert, key = CA("Probe Test CA").server("127.0.0.1").write(tmp_path, "leaf")
    with _tls_server(cert, key) as port:
        row = _probe(port)

    trust = row["checks"]["chain_trust"]
    assert trust["status"] == "not_evaluated"
    assert trust["reason"] == "internal_address"
    assert _issues(row, "cert_untrusted") == []


def test_chain_from_an_unknown_ca_is_untrusted(tmp_path: Path):
    _require_trust_store()
    cert, key = CA("Probe Test CA").server("127.0.0.1").write(tmp_path, "leaf")
    with _tls_server(cert, key) as port:
        row = _probe(port, chain_trust="always")

    untrusted = _issues(row, "cert_untrusted")
    assert len(untrusted) == 1
    assert untrusted[0]["severity"] == "medium"
    assert untrusted[0]["detail"] == "unable to get local issuer certificate"
    assert row["checks"]["chain_trust"]["status"] == "untrusted"
    assert _issues(row, "self_signed") == []


def test_self_signed_leaf_is_one_certain_finding(tmp_path: Path):
    """Verification code 18 is the self_signed heuristic made certain: one
    finding, not self_signed plus cert_untrusted -- and no weak_signature for a
    SHA-1 self-signature that no client verifies."""
    _require_trust_store()
    key = _rsa_key()
    leaf = _resign_with_sha1(_certificate("self.example.test", key), key)
    cert, key_path = _write(tmp_path, "self", leaf, key)
    with _tls_server(cert, key_path) as port:
        row = _probe(port, chain_trust="always")

    kinds = sorted(issue["kind"] for issue in row["issues"])
    assert kinds == ["self_signed"]
    assert row["issues"][0]["heuristic"] is False
    assert row["checks"]["chain_trust"]["verify_code"] == 18


def test_ca_bundle_makes_an_internal_chain_trusted(tmp_path: Path):
    _require_trust_store()
    ca = CA("Probe Test CA")
    cert, key = ca.server("127.0.0.1").write(tmp_path, "leaf")
    bundle, _ = ca.write(tmp_path, "internal-ca")
    with _tls_server(cert, key) as port:
        row = _probe(port, ca_bundle=str(bundle))

    assert _issues(row, "cert_untrusted") == []
    assert row["checks"]["chain_trust"] == {
        "status": "trusted",
        "store": "system+ca_bundle",
        "validity_checked": True,
    }
    assert row["cert"]["subject_cn"] == "127.0.0.1"


def test_ca_bundle_is_used_on_a_host_without_system_anchors(tmp_path: Path, monkeypatch):
    """The operator named the CAs to trust; an empty system store must not
    switch the check off."""
    monkeypatch.setattr(
        "scanner.pipeline.tls_probe._trust_store_gap", lambda ctx: "no system trust anchors (test)"
    )
    ca = CA("Probe Test CA")
    cert, key = ca.server("127.0.0.1").write(tmp_path, "leaf")
    bundle, _ = ca.write(tmp_path, "internal-ca")
    with _tls_server(cert, key) as port:
        with_bundle = _probe(port, ca_bundle=str(bundle))
        without = _probe(port, chain_trust="always")

    assert with_bundle["checks"]["chain_trust"]["status"] == "trusted"
    assert with_bundle["checks"]["chain_trust"]["store"] == "ca_bundle"
    assert without["checks"]["chain_trust"]["status"] == "not_performed"


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
        unverified = _probe(port, chain_trust="always")

    assert _issues(trusted, "self_signed") == []
    assert [i["kind"] for i in unverified["issues"] if i["kind"] in ("self_signed", "cert_untrusted")] == [
        "self_signed",
        "cert_untrusted",
    ]


def test_expired_leaf_of_a_trusted_ca_is_expired_not_untrusted(tmp_path: Path):
    _require_trust_store()
    ca_cert, ca_key, bundle = _rsa_ca(tmp_path)
    now = datetime.now(UTC)
    leaf_key = _rsa_key()
    leaf = _certificate(
        "expired.example.test",
        leaf_key,
        issuer=ca_cert,
        issuer_key=ca_key,
        not_before=now - timedelta(days=400),
        not_after=now - timedelta(days=3),
    )
    cert, key = _write(tmp_path, "expired", leaf, leaf_key)
    with _tls_server(cert, key) as port:
        row = _probe(port, ca_bundle=str(bundle))

    trust = row["checks"]["chain_trust"]
    assert trust["status"] == "trusted"
    assert _issues(row, "cert_untrusted") == []
    assert len(_issues(row, "cert_expired")) == 1
    # Every CA certificate of the re-verified chain is in its window: the time
    # failure was the leaf's own, and the chain counts as checked.
    assert trust["validity_checked"] is True
    assert _issues(row, "cert_chain_expired") == []


def test_expired_leaf_under_an_expired_intermediate_is_said_undecidable(tmp_path: Path):
    """Leaf and intermediate both out of their windows: the untimed
    verification may have picked a twin a client would not, so the chain
    validity is reported as not checked rather than guessed."""
    _require_trust_store()
    now = datetime.now(UTC)
    root, root_key, bundle = _rsa_ca(tmp_path)
    inter_key = _rsa_key()
    inter = _certificate(
        "Probe Intermediate", inter_key, issuer=root, issuer_key=root_key, ca=True,
        not_before=now - timedelta(days=400), not_after=now - timedelta(days=10),
    )
    leaf_key = _rsa_key()
    leaf = _certificate(
        "app.example.test", leaf_key, issuer=inter, issuer_key=inter_key,
        not_before=now - timedelta(days=300), not_after=now - timedelta(days=5),
    )
    cert, key = _write(tmp_path, "leaf", leaf, leaf_key, chain=(inter,))
    with _tls_server(cert, key) as port:
        row = _probe(port, ca_bundle=str(bundle))

    trust = row["checks"]["chain_trust"]
    assert trust["status"] == "trusted"
    assert trust["validity_checked"] is False
    assert len(_issues(row, "cert_expired")) == 1


def test_expired_intermediate_is_found(tmp_path: Path):
    """Trust is judged with OpenSSL's time check off; a client that keeps it on
    rejects this chain ("certificate has expired"), so the probe checks every
    CA certificate of the verified chain itself."""
    _require_trust_store()
    now = datetime.now(UTC)
    root, root_key, bundle = _rsa_ca(tmp_path)
    inter_key = _rsa_key()
    inter = _certificate(
        "Probe Intermediate",
        inter_key,
        issuer=root,
        issuer_key=root_key,
        ca=True,
        not_before=now - timedelta(days=400),
        not_after=now - timedelta(days=10),
    )
    leaf_key = _rsa_key()
    leaf = _certificate("app.example.test", leaf_key, issuer=inter, issuer_key=inter_key)
    cert, key = _write(tmp_path, "leaf", leaf, leaf_key, chain=(inter,))
    connections = [0]
    with _tls_server(cert, key, connections=connections) as port:
        row = _probe(port, ca_bundle=str(bundle))

    assert row["checks"]["chain_trust"]["status"] == "trusted"
    expired = _issues(row, "cert_chain_expired")
    assert len(expired) == 1
    assert expired[0]["severity"] == "high"
    assert expired[0]["depth"] == 1
    assert "Probe Intermediate" in expired[0]["subject"]
    assert _issues(row, "cert_expired") == []
    # Protocol and cipher come from the completed untimed re-verification.
    assert row["accepted_protocols"] == ["TLSv1.3"]
    assert row["negotiated_cipher"]
    # The documented ceiling: timed verification, untimed re-verification and
    # two pinned handshakes -- the collect handshake is not run on this path.
    assert connections[0] == 4


def test_untrusted_chain_costs_at_most_four_connections(tmp_path: Path):
    _require_trust_store()
    cert, key = CA("Probe Test CA").server("127.0.0.1").write(tmp_path, "leaf")
    connections = [0]
    with _tls_server(cert, key, connections=connections) as port:
        row = _probe(port, chain_trust="always")

    assert row["checks"]["chain_trust"]["status"] == "untrusted"
    assert connections[0] == 4  # verify, collect, TLS 1.0, TLS 1.1


def test_expired_intermediate_behind_a_connection_limiter_is_still_found(tmp_path: Path):
    """The limiter resets the untimed re-verification. OpenSSL checks time only
    on a chain it built to a trust anchor (an unanchored one fails with code 20
    first), so a time failure with the leaf in its window already names a CA
    certificate -- found without a depth, not lost."""
    _require_trust_store()
    now = datetime.now(UTC)
    root, root_key, bundle = _rsa_ca(tmp_path)
    inter_key = _rsa_key()
    inter = _certificate(
        "Probe Intermediate", inter_key, issuer=root, issuer_key=root_key, ca=True,
        not_before=now - timedelta(days=400), not_after=now - timedelta(days=10),
    )
    leaf_key = _rsa_key()
    leaf = _certificate("app.example.test", leaf_key, issuer=inter, issuer_key=inter_key)
    cert, key = _write(tmp_path, "leaf", leaf, leaf_key, chain=(inter,))
    with _tls_server(cert, key, accept_limit=1) as port:
        row = _probe(port, ca_bundle=str(bundle))

    assert row["checks"]["chain_trust"]["status"] == "inconclusive"
    expired = _issues(row, "cert_chain_expired")
    assert len(expired) == 1
    assert expired[0]["severity"] == "high"
    assert "certificate has expired" in expired[0]["detail"]
    assert "depth" not in expired[0]
    assert row["negotiated_protocol"] == "TLSv1.3"  # from the main ServerHello


def test_leaf_not_yet_valid_is_found(tmp_path: Path):
    _require_trust_store()
    now = datetime.now(UTC)
    ca_cert, ca_key, bundle = _rsa_ca(tmp_path)
    leaf_key = _rsa_key()
    leaf = _certificate(
        "future.example.test",
        leaf_key,
        issuer=ca_cert,
        issuer_key=ca_key,
        not_before=now + timedelta(days=2),
        not_after=now + timedelta(days=90),
    )
    cert, key = _write(tmp_path, "future", leaf, leaf_key)
    with _tls_server(cert, key) as port:
        row = _probe(port, ca_bundle=str(bundle))

    assert row["checks"]["chain_trust"]["status"] == "trusted"
    assert [issue["severity"] for issue in _issues(row, "cert_not_yet_valid")] == ["medium"]


def test_unreadable_ca_bundle_does_not_flag_every_endpoint(tmp_path: Path):
    """Judging an internal PKI against the system store alone would mark all of
    it untrusted: a bundle that fails to load turns the trust check off."""
    _require_trust_store()
    cert, key = CA("Probe Test CA").server("127.0.0.1").write(tmp_path, "leaf")
    with _tls_server(cert, key) as port:
        row = _probe(port, ca_bundle=str(tmp_path / "missing.pem"))

    assert _issues(row, "cert_untrusted") == []
    trust = row["checks"]["chain_trust"]
    assert trust["status"] == "not_performed"
    assert "missing.pem" in trust["detail"]


def _expired_intermediate_chain(tmp_path: Path, *, renewed_first: bool | None) -> tuple[Path, Path, Path]:
    """Leaf under an intermediate that expired 10 days ago; with ``renewed_first``
    set, the server also sends the re-issued intermediate (same subject, same
    key), after (False) or before (True) the expired one."""
    now = datetime.now(UTC)
    root, root_key, bundle = _rsa_ca(tmp_path)
    inter_key = _rsa_key()
    expired = _certificate(
        "Probe Intermediate", inter_key, issuer=root, issuer_key=root_key, ca=True,
        not_before=now - timedelta(days=400), not_after=now - timedelta(days=10),
    )
    chain: tuple[x509.Certificate, ...] = (expired,)
    if renewed_first is not None:
        renewed = _certificate(
            "Probe Intermediate", inter_key, issuer=root, issuer_key=root_key, ca=True,
            not_before=now - timedelta(days=30), not_after=now + timedelta(days=700),
        )
        chain = (renewed, expired) if renewed_first else (expired, renewed)
    leaf_key = _rsa_key()
    # Both intermediates carry the same subject and key, so either signs the leaf.
    leaf = _certificate("app.example.test", leaf_key, issuer=expired, issuer_key=inter_key)
    cert, key = _write(tmp_path, "leaf", leaf, leaf_key, chain=chain)
    return cert, key, bundle


def test_stale_duplicate_intermediate_is_not_an_expired_chain(tmp_path: Path):
    """A server that still sends the expired intermediate next to its
    re-issued twin (same subject, same key) -- stale fullchain files do -- is
    accepted by an ordinary client. With the expired one listed first, a
    verification without the time check picked it; the probe now checks time
    the way a client does first."""
    _require_trust_store()
    cert, key, bundle = _expired_intermediate_chain(tmp_path, renewed_first=False)
    with _tls_server(cert, key) as port:
        ctx = ssl.create_default_context(cafile=str(bundle))
        ctx.check_hostname = False
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            with ctx.wrap_socket(sock):
                pass  # an ordinary client accepts this chain
        row = _probe(port, ca_bundle=str(bundle))

    assert row["checks"]["chain_trust"] == {"status": "trusted", "store": "system+ca_bundle", "validity_checked": True}
    assert _issues(row, "cert_chain_expired") == []


def test_chain_validity_without_a_verified_chain_is_said_not_assumed(tmp_path: Path, monkeypatch):
    """When this Python cannot hand back the verified chain, the expired
    intermediate cannot be named: validity_checked is false, not true."""
    _require_trust_store()
    monkeypatch.setattr("scanner.pipeline.tls_probe._verified_chain", lambda tls: None)
    cert, key, bundle = _expired_intermediate_chain(tmp_path, renewed_first=None)
    with _tls_server(cert, key) as port:
        row = _probe(port, ca_bundle=str(bundle))

    trust = row["checks"]["chain_trust"]
    assert trust["status"] == "trusted"
    assert trust["validity_checked"] is False
    assert "verified chain" in trust["validity_detail"]
    assert _issues(row, "cert_chain_expired") == []


def test_intermediate_not_yet_valid_is_found(tmp_path: Path):
    _require_trust_store()
    now = datetime.now(UTC)
    root, root_key, bundle = _rsa_ca(tmp_path)
    inter_key = _rsa_key()
    inter = _certificate(
        "Probe Future Intermediate", inter_key, issuer=root, issuer_key=root_key, ca=True,
        not_before=now + timedelta(days=3), not_after=now + timedelta(days=700),
    )
    leaf_key = _rsa_key()
    leaf = _certificate("app.example.test", leaf_key, issuer=inter, issuer_key=inter_key)
    cert, key = _write(tmp_path, "leaf", leaf, leaf_key, chain=(inter,))
    with _tls_server(cert, key) as port:
        row = _probe(port, ca_bundle=str(bundle))

    future = _issues(row, "cert_not_yet_valid")
    assert [(issue["depth"], issue["severity"]) for issue in future] == [(1, "medium")]
    assert _issues(row, "cert_chain_expired") == []


def test_server_that_hangs_up_at_once_costs_no_timeout(tmp_path: Path):
    """A clean close before any TLS byte ends each handshake at once; it must
    not spin until the deadline."""
    with _listening(lambda conn: None) as port:  # _listening closes it at once
        started = time.monotonic()
        rows = probe_tls_endpoints(
            [f"127.0.0.1:{port}/tcp"], tls_ports={port}, timeout_seconds=4.0, concurrency=1
        )
    assert rows == []
    assert time.monotonic() - started < 3.0


def test_plain_tcp_listener_yields_no_row(tmp_path: Path):
    """Not TLS at all: no row, as before, no legacy findings invented -- and
    no pinned ClientHellos sent after the first answer showed it is not TLS."""
    connections = [0]

    def answer(conn: socket.socket) -> None:
        connections[0] += 1
        conn.sendall(b"HTTP/1.0 400 Bad Request\r\n\r\n")

    with _listening(answer) as port:
        rows = probe_tls_endpoints(
            [f"127.0.0.1:{port}/tcp"], tls_ports={port}, timeout_seconds=3.0, concurrency=1
        )
    assert rows == []
    assert connections[0] == 1


def test_expired_leaf_behind_a_connection_limiter_is_not_an_expired_chain(tmp_path: Path):
    """Same limiter, but the leaf is the certificate out of its window: the
    time failure is the leaf's own (cert_expired), not a CA certificate's."""
    _require_trust_store()
    now = datetime.now(UTC)
    ca_cert, ca_key, bundle = _rsa_ca(tmp_path)
    leaf_key = _rsa_key()
    leaf = _certificate(
        "expired.example.test", leaf_key, issuer=ca_cert, issuer_key=ca_key,
        not_before=now - timedelta(days=400), not_after=now - timedelta(days=3),
    )
    cert, key = _write(tmp_path, "expired", leaf, leaf_key)
    with _tls_server(cert, key, accept_limit=1) as port:
        row = _probe(port, ca_bundle=str(bundle))

    assert row["checks"]["chain_trust"]["status"] == "inconclusive"
    assert len(_issues(row, "cert_expired")) == 1
    assert _issues(row, "cert_chain_expired") == []
