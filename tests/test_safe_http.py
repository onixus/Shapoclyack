"""SSRF boundary for scanner-side outbound HTTPS (org_profile M1, #182)."""

from __future__ import annotations

import http.client
import io
import ipaddress
import socket
import ssl
import time

import pytest

from scanner.pipeline import safe_http
from scanner.pipeline.safe_http import SafeHttpError, UnsafeTargetError


class _FakeSocket:
    timeout = None

    def settimeout(self, value):
        self.timeout = value


class _FakeRaw:
    def __init__(self):
        self._sock = _FakeSocket()


class _FakeFp(io.BytesIO):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.raw = _FakeRaw()


class _FakeResponse:
    """Just enough of http.client.HTTPResponse for _read_body / _request_once."""

    def __init__(self, status: int, headers: dict[str, str], body: bytes):
        self.status = status
        self._headers = headers
        self.fp = _FakeFp(body)

    def getheaders(self):
        return list(self._headers.items())

    def read(self, amount: int) -> bytes:
        return self.fp.read(amount)


def _pin_resolution(monkeypatch, mapping: dict[str, list[str]]) -> None:
    def _resolve(hostname: str):
        return [ipaddress.ip_address(addr) for addr in mapping.get(hostname, [])]

    monkeypatch.setattr("scanner.pipeline.safe_http._resolve", _resolve)


def _serve(monkeypatch, responses: list[_FakeResponse]) -> list[tuple[str, str, str]]:
    """Answer each _request_once with the next canned response.

    Returns the log of (connect_address, hostname, request_target) so a test
    can assert the socket dialled the validated IP rather than the name.
    """
    calls: list[tuple[str, str, str]] = []
    queue = list(responses)

    def _fake_request_once(target, address, headers, *, deadline, max_bytes):
        calls.append((str(address), target.hostname, target.request_target))
        response = queue.pop(0)
        body, truncated = safe_http._read_body(response, deadline=deadline, max_bytes=max_bytes)
        return response.status, {k.lower(): v for k, v in response.getheaders()}, body, truncated

    monkeypatch.setattr("scanner.pipeline.safe_http._request_once", _fake_request_once)
    return calls


def test_rejects_http_scheme():
    with pytest.raises(UnsafeTargetError, match="must be https"):
        safe_http.validate_url("http://rdap.example.com/domain/example.com")


def test_rejects_userinfo(monkeypatch):
    _pin_resolution(monkeypatch, {"rdap.example.com": ["93.184.216.34"]})
    with pytest.raises(UnsafeTargetError, match="userinfo"):
        safe_http.validate_url("https://user:pass@rdap.example.com/domain/example.com")


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "224.0.0.1"],
)
def test_rejects_non_public_address(monkeypatch, address: str):
    _pin_resolution(monkeypatch, {"rdap.example.com": [address]})
    with pytest.raises(UnsafeTargetError, match="non-public address"):
        safe_http.validate_url("https://rdap.example.com/domain/example.com")


def test_rejects_when_any_address_is_private(monkeypatch):
    # A public A record plus a loopback AAAA is still rejected: which address
    # the connection would pick is not this code's decision.
    _pin_resolution(monkeypatch, {"rdap.example.com": ["93.184.216.34", "::1"]})
    with pytest.raises(UnsafeTargetError, match="non-public address"):
        safe_http.validate_url("https://rdap.example.com/domain/example.com")


def test_unresolvable_host_is_not_a_policy_error(monkeypatch):
    _pin_resolution(monkeypatch, {})
    with pytest.raises(SafeHttpError, match="DNS resolution failed"):
        safe_http.validate_url("https://rdap.example.com/domain/example.com")


def test_get_dials_validated_ip_and_returns_body(monkeypatch):
    _pin_resolution(monkeypatch, {"rdap.example.com": ["93.184.216.34"]})
    calls = _serve(monkeypatch, [_FakeResponse(200, {"Content-Type": "application/json"}, b'{"a":1}')])

    resp = safe_http.get("https://rdap.example.com/domain/example.com", timeout_seconds=5)

    assert resp.status == 200
    assert resp.truncated is False
    assert safe_http.json_body(resp) == {"a": 1}
    assert calls == [("93.184.216.34", "rdap.example.com", "/domain/example.com")]


def test_get_follows_redirect_and_revalidates_target(monkeypatch):
    _pin_resolution(
        monkeypatch,
        {"rdap.org": ["93.184.216.34"], "rdap.registry.example": ["199.7.83.42"]},
    )
    calls = _serve(
        monkeypatch,
        [
            _FakeResponse(302, {"Location": "https://rdap.registry.example/domain/example.com"}, b""),
            _FakeResponse(200, {}, b'{"ldhName":"example.com"}'),
        ],
    )

    resp = safe_http.get("https://rdap.org/domain/example.com", timeout_seconds=5, max_redirects=3)

    assert resp.status == 200
    assert resp.url == "https://rdap.registry.example/domain/example.com"
    assert [call[0] for call in calls] == ["93.184.216.34", "199.7.83.42"]


def test_redirect_downgrade_to_http_is_refused(monkeypatch):
    _pin_resolution(monkeypatch, {"rdap.org": ["93.184.216.34"]})
    _serve(monkeypatch, [_FakeResponse(302, {"Location": "http://rdap.org/domain/example.com"}, b"")])

    with pytest.raises(UnsafeTargetError, match="must be https"):
        safe_http.get("https://rdap.org/domain/example.com", timeout_seconds=5, max_redirects=3)


def test_redirect_to_private_address_is_refused(monkeypatch):
    _pin_resolution(monkeypatch, {"rdap.org": ["93.184.216.34"], "metadata.internal": ["169.254.169.254"]})
    _serve(monkeypatch, [_FakeResponse(302, {"Location": "https://metadata.internal/latest/meta-data/"}, b"")])

    with pytest.raises(UnsafeTargetError, match="non-public address"):
        safe_http.get("https://rdap.org/domain/example.com", timeout_seconds=5, max_redirects=3)


def test_redirect_budget_is_finite(monkeypatch):
    _pin_resolution(monkeypatch, {"rdap.org": ["93.184.216.34"]})
    _serve(
        monkeypatch,
        [_FakeResponse(302, {"Location": "https://rdap.org/hop"}, b"") for _ in range(4)],
    )

    with pytest.raises(SafeHttpError, match="too many redirects"):
        safe_http.get("https://rdap.org/domain/example.com", timeout_seconds=5, max_redirects=3)


def test_body_is_cut_at_the_cap(monkeypatch):
    _pin_resolution(monkeypatch, {"rdap.example.com": ["93.184.216.34"]})
    _serve(monkeypatch, [_FakeResponse(200, {}, b"x" * 5000)])

    resp = safe_http.get("https://rdap.example.com/big", timeout_seconds=5, max_bytes=1024)

    assert resp.truncated is True
    assert len(resp.body) == 1024


def test_json_body_refuses_a_truncated_response(monkeypatch):
    _pin_resolution(monkeypatch, {"rdap.example.com": ["93.184.216.34"]})
    _serve(monkeypatch, [_FakeResponse(200, {}, b'{"padding":"' + b"x" * 5000 + b'"}')])

    resp = safe_http.get("https://rdap.example.com/big", timeout_seconds=5, max_bytes=64)

    with pytest.raises(SafeHttpError, match="exceeded the size cap"):
        safe_http.json_body(resp)


def test_read_body_stops_when_the_deadline_passes():
    response = _FakeResponse(200, {}, b"x" * 5000)
    with pytest.raises(SafeHttpError, match="deadline exceeded"):
        safe_http._read_body(response, deadline=0.0, max_bytes=4096)


def test_read_body_pushes_the_remaining_budget_onto_the_socket():
    """The deadline is only real if it reaches the socket.

    _read_body checks the clock between chunks, but a peer that opens the
    connection and then goes silent never returns from read(). Without
    settimeout the read blocks past the deadline forever, so assert the budget
    was actually pushed down rather than merely computed.
    """
    response = _FakeResponse(200, {}, b"x" * 100)
    deadline = time.perf_counter() + 5.0

    body, truncated = safe_http._read_body(response, deadline=deadline, max_bytes=4096)

    assert body == b"x" * 100
    assert truncated is False
    pushed = response.fp.raw._sock.timeout
    assert pushed is not None, "remaining budget was never pushed onto the socket"
    assert 0 < pushed <= 5.0


def test_pinned_context_verifies_the_certificate():
    """Pinning the address is worthless if the certificate is not checked.

    _PinnedHTTPSConnection dials an IP and passes the hostname as SNI; the only
    thing that stops an interceptor at that IP from answering is the default
    context's verification. Assert it, so swapping in an unverified context
    cannot pass the suite.
    """
    connection = safe_http._PinnedHTTPSConnection(
        connect_host="93.184.216.34",
        server_hostname="rdap.example.com",
        port=443,
        timeout=5.0,
    )

    assert connection._context.check_hostname is True
    assert connection._context.verify_mode is ssl.CERT_REQUIRED


def test_redirect_chain_shares_one_deadline(monkeypatch):
    """One budget covers every hop -- a redirect does not buy a fresh timeout.

    Each hop here burns more than half the budget, so a chain that reset the
    deadline per hop would complete and this test would not.
    """
    _pin_resolution(
        monkeypatch,
        {"rdap.example.com": ["93.184.216.34"], "second.example.com": ["93.184.216.35"]},
    )
    hops: list[str] = []

    class _SlowConnection:
        def __init__(self, *, connect_host, server_hostname, port, timeout):
            self._hostname = server_hostname
            self.sock = None

        def request(self, method, target, headers=None):
            hops.append(self._hostname)
            time.sleep(0.6)

        def getresponse(self):
            if self._hostname == "rdap.example.com":
                return _FakeResponse(302, {"Location": "https://second.example.com/next"}, b"")
            return _FakeResponse(200, {}, b"{}")

        def close(self):
            pass

    monkeypatch.setattr("scanner.pipeline.safe_http._PinnedHTTPSConnection", _SlowConnection)

    with pytest.raises(SafeHttpError, match="deadline exceeded"):
        safe_http.get(
            "https://rdap.example.com/domain/example.com",
            timeout_seconds=1,
            max_redirects=1,
        )

    assert hops == ["rdap.example.com", "second.example.com"]


def test_malformed_url_is_an_unsafe_target_not_a_crash():
    """urlsplit raises a bare ValueError on a broken IPv6 literal.

    The next hop is named by the remote side (the IANA bootstrap document, or
    the cached copy of it), and a bare ValueError escapes SAFE_HTTP_ERRORS --
    which would take the whole run down from inside a fail-soft stage.
    """
    with pytest.raises(UnsafeTargetError, match="malformed"):
        safe_http.validate_url("https://rdap.[bad].example/v1/")


def test_all_addresses_unreachable_is_reported(monkeypatch):
    _pin_resolution(monkeypatch, {"rdap.example.com": ["93.184.216.34", "93.184.216.35"]})

    def _boom(target, address, headers, *, deadline, max_bytes):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr("scanner.pipeline.safe_http._request_once", _boom)

    with pytest.raises(SafeHttpError, match="could be reached"):
        safe_http.get("https://rdap.example.com/domain/example.com", timeout_seconds=5)


def test_pinned_connection_dials_the_ip_but_verifies_the_name(monkeypatch):
    captured: dict[str, object] = {}

    class _Sock:
        pass

    def _create_connection(address, timeout, source_address):
        captured["dialled"] = address
        return _Sock()

    monkeypatch.setattr("scanner.pipeline.safe_http.socket.create_connection", _create_connection)
    connection = safe_http._PinnedHTTPSConnection(
        connect_host="93.184.216.34",
        server_hostname="rdap.example.com",
        port=443,
        timeout=5.0,
    )
    monkeypatch.setattr(
        connection._context,
        "wrap_socket",
        lambda sock, server_hostname: captured.setdefault("sni", server_hostname) or sock,
    )
    connection.connect()

    assert captured["dialled"] == ("93.184.216.34", 443)
    assert captured["sni"] == "rdap.example.com"
    assert isinstance(connection, http.client.HTTPSConnection)


def test_resolve_accepts_a_literal_and_survives_a_dns_failure(monkeypatch):
    assert safe_http._resolve("93.184.216.34") == [ipaddress.ip_address("93.184.216.34")]
    assert safe_http._resolve("[::1]") == [ipaddress.ip_address("::1")]

    def _boom(*args, **kwargs):
        raise socket.gaierror("nope")

    monkeypatch.setattr("scanner.pipeline.safe_http.socket.getaddrinfo", _boom)
    assert safe_http._resolve("nowhere.example") == []


def test_resolve_deduplicates_getaddrinfo_entries(monkeypatch):
    monkeypatch.setattr(
        "scanner.pipeline.safe_http.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("93.184.216.34", 0)),
            (2, 2, 17, "", ("93.184.216.34", 0)),
            (30, 1, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0)),
        ],
    )
    assert safe_http._resolve("example.test") == [
        ipaddress.ip_address("93.184.216.34"),
        ipaddress.ip_address("2606:2800:220:1:248:1893:25c8:1946"),
    ]


def test_request_once_sends_the_host_header_of_the_dns_name(monkeypatch):
    sent: dict[str, object] = {}

    class _FakeConnection:
        sock = None

        def __init__(self, **kwargs):
            sent["init"] = kwargs

        def request(self, method, target, headers):
            sent["request"] = (method, target, dict(headers))

        def getresponse(self):
            return _FakeResponse(200, {"Content-Type": "application/rdap+json"}, b"{}")

        def close(self):
            sent["closed"] = True

    monkeypatch.setattr("scanner.pipeline.safe_http._PinnedHTTPSConnection", _FakeConnection)
    _pin_resolution(monkeypatch, {"rdap.example.com": ["93.184.216.34"]})
    target = safe_http._parse_target("https://rdap.example.com:8443/domain/example.com?x=1")

    status, headers, body, truncated = safe_http._request_once(
        target,
        ipaddress.ip_address("93.184.216.34"),
        {"Accept": "application/rdap+json"},
        deadline=safe_http.time.perf_counter() + 5,
        max_bytes=1024,
    )

    assert status == 200
    assert body == b"{}"
    assert truncated is False
    assert headers["content-type"] == "application/rdap+json"
    assert sent["init"]["connect_host"] == "93.184.216.34"
    assert sent["init"]["server_hostname"] == "rdap.example.com"
    method, request_target, request_headers = sent["request"]
    assert (method, request_target) == ("GET", "/domain/example.com?x=1")
    # Non-default port belongs in the Host header, and the header carries the
    # name, never the pinned IP.
    assert request_headers["Host"] == "rdap.example.com:8443"
    assert sent["closed"] is True


def test_request_once_refuses_a_deadline_already_spent(monkeypatch):
    _pin_resolution(monkeypatch, {"rdap.example.com": ["93.184.216.34"]})
    target = safe_http._parse_target("https://rdap.example.com/domain/example.com")
    with pytest.raises(SafeHttpError, match="before connect"):
        safe_http._request_once(
            target,
            ipaddress.ip_address("93.184.216.34"),
            {},
            deadline=0.0,
            max_bytes=1024,
        )


def test_json_body_rejects_a_non_json_payload():
    response = safe_http.SafeResponse(
        url="https://rdap.example.com/domain/example.com",
        status=200,
        headers={},
        body=b"<html>not rdap</html>",
        truncated=False,
    )
    with pytest.raises(SafeHttpError, match="not valid JSON"):
        safe_http.json_body(response)
