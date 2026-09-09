"""Corporate egress: proxy, internal CA and the upload shaper (#359).

The agent lives on a network where nothing leaves without a proxy and TLS is
re-signed by an internal root, so these pin the three things that decide
whether it can reach the API at all: which proxy a URL goes through, what the
trust store ends up containing, and that ``OCTO_NO_PROXY`` is honoured. The
API's copy of the same rules is pinned against the agent's here too — the two
are deliberately separate modules (the agent ships without the ``api``
package), and two answers to "does NO_PROXY cover this host" is a support call
neither side can reproduce.
"""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest

from agent import egress as agent_egress
from agent import worker
from api.services import egress as api_egress

MODULES = pytest.mark.parametrize(
    "module", [agent_egress, api_egress], ids=["agent", "api"]
)

# A throwaway self-signed root, so the CA-bundle assertions load a real PEM
# rather than a file whose only property is existing.
_CA_PEM = """-----BEGIN CERTIFICATE-----
MIIBVDCB+6ADAgECAhRw9pq+m4ceVoTuobKYpylcKJaXfTAKBggqhkjOPQQDAjAg
MR4wHAYDVQQDDBVTaGFwb2NseWFjayBUZXN0IFJvb3QwHhcNMjYwMTAxMDAwMDAw
WhcNNDYwMTAxMDAwMDAwWjAgMR4wHAYDVQQDDBVTaGFwb2NseWFjayBUZXN0IFJv
b3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQu5hspivYRN+ufQJKd3UjMdxbw
XbTPU+mHTNDIGqhWlj9oXLlus4hhybEN3L4W4YbQA1MyMkOm3OjOc1fncQC1oxMw
ETAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIBnLXmke+QOr8CBo
JZnHDzgGSiLp2Ee2MxZ2eGdsjjxlAiEAsoWTINRB1Avqip3PQNHVlQhThD3wcvXJ
hI9wUJJl/QA=
-----END CERTIFICATE-----
"""


@pytest.fixture(autouse=True)
def _clean_proxy_env(monkeypatch):
    """No test inherits the developer's own proxy, and none leaks one."""
    for name in (
        "OCTO_HTTP_PROXY",
        "OCTO_HTTPS_PROXY",
        "OCTO_NO_PROXY",
        "OCTO_CA_BUNDLE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
    ):
        monkeypatch.delenv(name, raising=False)


# --------------------------------------------------------------------------- #
# Which proxy a URL goes through
# --------------------------------------------------------------------------- #


@MODULES
def test_no_proxy_variables_means_a_direct_dial(module):
    assert module.proxy_for_url("https://api.example.com/api/agent/register") is None


@MODULES
def test_the_https_proxy_is_used_for_https(module, monkeypatch):
    monkeypatch.setenv("OCTO_HTTPS_PROXY", "http://proxy.corp:3128")
    proxy = module.proxy_for_url("https://api.example.com/api/agent/register")
    assert proxy is not None
    assert (proxy.scheme, proxy.host, proxy.port) == ("http", "proxy.corp", 3128)


@MODULES
def test_the_http_proxy_is_used_for_http(module, monkeypatch):
    monkeypatch.setenv("OCTO_HTTP_PROXY", "proxy.corp:8080")
    monkeypatch.setenv("OCTO_HTTPS_PROXY", "http://tls-proxy.corp:3128")
    assert module.proxy_for_url("http://api.example.com/x").authority == "proxy.corp:8080"
    assert (
        module.proxy_for_url("https://api.example.com/x").authority == "tls-proxy.corp:3128"
    )


@MODULES
def test_the_octo_variable_wins_over_the_ambient_one(module, monkeypatch):
    """A pod inherits a cluster-wide HTTPS_PROXY meant for something else."""
    monkeypatch.setenv("HTTPS_PROXY", "http://ambient.corp:3128")
    monkeypatch.setenv("OCTO_HTTPS_PROXY", "http://ours.corp:3128")
    assert module.proxy_for_url("https://api.example.com/x").host == "ours.corp"


@MODULES
def test_the_ambient_variable_is_the_fallback(module, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://ambient.corp:3128")
    assert module.proxy_for_url("https://api.example.com/x").host == "ambient.corp"


@MODULES
def test_the_lowercase_http_proxy_is_not_read(module, monkeypatch):
    """httpoxy: in a CGI-shaped environment lowercase ``http_proxy`` is the
    caller's own ``Proxy:`` header, and this process reads request headers from
    untrusted callers."""
    monkeypatch.setenv("http_proxy", "http://attacker.example:3128")
    assert module.proxy_for_url("http://api.example.com/x") is None


@MODULES
@pytest.mark.parametrize(
    ("no_proxy", "url", "bypassed"),
    [
        ("*", "https://api.example.com/x", True),
        ("example.com", "https://api.example.com/x", True),
        (".example.com", "https://api.example.com/x", True),
        ("example.com", "https://example.com/x", True),
        ("example.com", "https://notexample.com/x", False),
        ("other.com,example.com", "https://api.example.com/x", True),
        ("api.example.com:8443", "https://api.example.com:8443/x", True),
        ("api.example.com:8443", "https://api.example.com/x", False),
        ("10.0.0.0/8", "https://10.1.2.3/x", True),
        ("10.0.0.0/8", "https://11.1.2.3/x", False),
    ],
)
def test_no_proxy_dialect(module, monkeypatch, no_proxy, url, bypassed):
    monkeypatch.setenv("OCTO_HTTPS_PROXY", "http://proxy.corp:3128")
    monkeypatch.setenv("OCTO_NO_PROXY", no_proxy)
    assert (module.proxy_for_url(url) is None) is bypassed


@MODULES
def test_a_proxy_url_that_is_not_http_is_refused(module, monkeypatch):
    monkeypatch.setenv("OCTO_HTTPS_PROXY", "socks5://proxy.corp:1080")
    with pytest.raises(module.EgressConfigError, match="http or https"):
        module.proxy_for_url("https://api.example.com/x")


@MODULES
def test_proxy_credentials_stay_out_of_the_loggable_form(module, monkeypatch):
    monkeypatch.setenv("OCTO_HTTPS_PROXY", "http://svc:s3cret@proxy.corp:3128")
    proxy = module.proxy_for_url("https://api.example.com/x")
    assert "s3cret" not in proxy.authority
    assert proxy.authority == "proxy.corp:3128"
    assert module.proxy_headers(proxy) == {"Proxy-Authorization": "Basic c3ZjOnMzY3JldA=="}


def _fields(proxy) -> tuple | None:
    if proxy is None:
        return None
    return (proxy.scheme, proxy.host, proxy.port, proxy.username, proxy.password)


def test_the_two_modules_agree_on_every_proxy_decision(monkeypatch):
    """The agent ships without the ``api`` package, so these rules are written
    twice. Two answers to "is this host proxied" is a support call neither side
    can reproduce from the other's logs."""
    cases = [
        ({"OCTO_HTTPS_PROXY": "http://p:3128"}, "https://a.example.com/x"),
        ({"HTTPS_PROXY": "http://p:3128"}, "https://a.example.com/x"),
        ({"http_proxy": "http://p:3128"}, "http://a.example.com/x"),
        (
            {"OCTO_HTTPS_PROXY": "http://p:3128", "OCTO_NO_PROXY": ".example.com"},
            "https://a.example.com/x",
        ),
        (
            {"OCTO_HTTPS_PROXY": "http://p:3128", "OCTO_NO_PROXY": "10.0.0.0/8"},
            "https://10.1.2.3/x",
        ),
        ({"OCTO_HTTP_PROXY": "p.corp"}, "http://a.example.com:8080/x"),
    ]
    for env, url in cases:
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        # Compared field by field: the two dataclasses are deliberately
        # distinct types, so ``==`` between them is always False.
        assert _fields(agent_egress.proxy_for_url(url)) == _fields(
            api_egress.proxy_for_url(url)
        ), url
        for name in env:
            monkeypatch.delenv(name)


# --------------------------------------------------------------------------- #
# The CA bundle
# --------------------------------------------------------------------------- #


@MODULES
def test_without_a_bundle_the_context_is_the_system_default(module):
    context = module.ssl_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


@MODULES
def test_the_ca_bundle_is_added_to_the_system_store(module, monkeypatch, tmp_path: Path):
    """*Added*, not substituted: a fleet behind an inspecting proxy still
    reaches receivers that are not behind it."""
    system_roots = len(ssl.create_default_context().get_ca_certs())
    bundle = tmp_path / "corp-root.pem"
    bundle.write_text(_CA_PEM, encoding="utf-8")
    monkeypatch.setenv("OCTO_CA_BUNDLE", str(bundle))

    context = module.ssl_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert len(context.get_ca_certs()) == system_roots + 1


@MODULES
def test_a_missing_ca_bundle_is_an_error_not_a_silent_fallback(module, monkeypatch, tmp_path):
    monkeypatch.setenv("OCTO_CA_BUNDLE", str(tmp_path / "absent.pem"))
    with pytest.raises(module.EgressConfigError, match="not a readable file"):
        module.ssl_context()


@MODULES
def test_a_ca_bundle_that_is_not_pem_is_an_error(module, monkeypatch, tmp_path: Path):
    bundle = tmp_path / "corp-root.pem"
    bundle.write_bytes(b"this is not a certificate")
    monkeypatch.setenv("OCTO_CA_BUNDLE", str(bundle))
    with pytest.raises(module.EgressConfigError, match="not a usable PEM bundle"):
        module.ssl_context()


@MODULES
def test_the_opener_carries_the_proxy_and_the_context(module, monkeypatch, tmp_path: Path):
    import urllib.request

    bundle = tmp_path / "corp-root.pem"
    bundle.write_text(_CA_PEM, encoding="utf-8")
    monkeypatch.setenv("OCTO_CA_BUNDLE", str(bundle))
    monkeypatch.setenv("OCTO_HTTPS_PROXY", "http://proxy.corp:3128")

    opener = module.build_opener("https://api.example.com/x")
    proxy_handlers = [h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert proxy_handlers and proxy_handlers[0].proxies == {
        "http": "http://proxy.corp:3128",
        "https": "http://proxy.corp:3128",
    }


@MODULES
def test_a_bypassed_host_gets_an_opener_that_ignores_the_environment(module, monkeypatch):
    """``OCTO_NO_PROXY`` must beat the ambient ``HTTPS_PROXY``, and the only way
    to say that to ``urllib`` is to hand it a ``ProxyHandler`` of its own.

    Passing an empty one marks the class as supplied, so ``build_opener`` does
    not add the default that scans the environment — and then drops the empty
    instance, since it installs no ``*_open`` method. No ProxyHandler at all is
    therefore exactly the outcome wanted; without the explicit one, urllib's
    default would be here and would proxy this host.
    """
    import urllib.request

    monkeypatch.setenv("HTTPS_PROXY", "http://ambient.corp:3128")
    monkeypatch.setenv("OCTO_NO_PROXY", "api.example.com")
    opener = module.build_opener("https://api.example.com/x")
    assert [h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)] == []
    assert urllib.request.getproxies().get("https") == "http://ambient.corp:3128"


# --------------------------------------------------------------------------- #
# The agent's own wiring
# --------------------------------------------------------------------------- #


def test_the_agent_client_opens_through_the_configured_proxy(monkeypatch):
    import urllib.request

    monkeypatch.setenv("OCTO_HTTPS_PROXY", "http://proxy.corp:3128")
    client = worker.AgentClient("https://api.example.com", "token", timeout=1.0)
    proxy_handlers = [
        h for h in client._opener.handlers  # noqa: SLF001
        if isinstance(h, urllib.request.ProxyHandler)
    ]
    assert proxy_handlers and proxy_handlers[0].proxies["https"] == "http://proxy.corp:3128"


def test_the_nats_ca_bundle_rides_along_with_the_http_one(monkeypatch, tmp_path: Path):
    """One internal root, named once. Without this an operator sets
    OCTO_CA_BUNDLE, watches HTTP start working and NATS keep failing."""
    bundle = tmp_path / "corp-root.pem"
    bundle.write_text(_CA_PEM, encoding="utf-8")
    system_roots = len(ssl.create_default_context().get_ca_certs())
    monkeypatch.setenv("OCTO_CA_BUNDLE", str(bundle))

    options = worker.tls_connect_options()
    assert len(options["tls"].get_ca_certs()) == system_roots + 1


def test_a_websocket_nats_url_without_aiohttp_says_what_to_install(monkeypatch):
    """nats-py implements ws:// through aiohttp, which the agent image does not
    carry. Without the preflight the failure is an ImportError from inside a
    background event-loop thread, minutes after start."""
    import builtins

    real_import = builtins.__import__

    def _no_aiohttp(name, *args, **kwargs):
        if name == "aiohttp":
            raise ImportError("no module named aiohttp")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_aiohttp)
    with pytest.raises(RuntimeError, match="aiohttp"):
        worker.check_nats_transport("wss://nats.example.com:443")


@pytest.mark.parametrize("url", ["nats://nats:4222", "tls://nats.example.com:443", ""])
def test_a_tcp_nats_url_needs_no_websocket_dependency(url):
    worker.check_nats_transport(url)


# --------------------------------------------------------------------------- #
# OCTO_AGENT_UPLOAD_RATE_LIMIT_KBPS
# --------------------------------------------------------------------------- #


class _FakeClock:
    """A clock that only moves when something sleeps, so a shaped read is
    measured rather than waited for."""

    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def test_the_upload_is_unshaped_by_default():
    bucket = worker.TokenBucket(0)
    assert bucket.enabled is False
    bucket.consume(10 * 1024 * 1024)  # returns without sleeping or it hangs the suite


def test_the_token_bucket_holds_a_stream_to_the_configured_rate():
    clock = _FakeClock()
    bucket = worker.TokenBucket(64, monotonic=clock.monotonic, sleep=clock.sleep)

    # The first second's worth is the burst the bucket starts full with; the
    # next four seconds' worth has to be waited for.
    for _ in range(5):
        bucket.consume(64 * 1024)

    assert sum(clock.slept) == pytest.approx(4.0, abs=0.01)


def test_a_chunk_larger_than_the_bucket_still_drains(monkeypatch):
    """A read bigger than one second's allowance would never be granted in
    full — the bucket never holds more than its capacity — and the upload would
    hang forever instead of going slowly."""
    clock = _FakeClock()
    bucket = worker.TokenBucket(8, monotonic=clock.monotonic, sleep=clock.sleep)
    bucket.consume(64 * 1024)
    assert sum(clock.slept) > 0


def test_the_upload_body_streams_the_archive_at_the_configured_rate(tmp_path: Path):
    archive = tmp_path / "run.tar.gz"
    archive.write_bytes(b"\x00" * (256 * 1024))
    clock = _FakeClock()
    body = worker._ThrottledBody(  # noqa: SLF001
        b"--boundary\r\n",
        archive,
        b"\r\n--boundary--\r\n",
        bucket=worker.TokenBucket(64, monotonic=clock.monotonic, sleep=clock.sleep),
    )

    read = 0
    while True:
        chunk = body.read(65536)
        if not chunk:
            break
        read += len(chunk)

    assert read == len(body) == 256 * 1024 + len(b"--boundary\r\n") + len(b"\r\n--boundary--\r\n")
    # 256 KiB at 64 KiB/s is four seconds, less the bucketful it starts with.
    assert sum(clock.slept) == pytest.approx(3.0, abs=0.05)


def test_the_upload_body_reproduces_the_multipart_byte_for_byte(tmp_path: Path):
    """Streaming must not change what the server parses: the archive is read
    from disk mid-body, which is the one place an off-by-one is invisible until
    a real upload is rejected as a malformed multipart."""
    archive = tmp_path / "run.tar.gz"
    archive.write_bytes(bytes(range(256)) * 40)
    prefix, suffix = b"--b\r\nfields\r\n", b"\r\n--b--\r\n"
    body = worker._ThrottledBody(  # noqa: SLF001
        prefix, archive, suffix, bucket=worker.TokenBucket(0), chunk_size=97
    )

    chunks = []
    while True:
        chunk = body.read(4096)
        if not chunk:
            break
        chunks.append(chunk)
    assert b"".join(chunks) == prefix + archive.read_bytes() + suffix
    assert max(len(chunk) for chunk in chunks) <= 97


def test_the_upload_body_rewinds_for_a_retry(tmp_path: Path):
    """``_request`` retries a 503. A stream already read to its end would post
    an empty body on the retry and look like the scan produced nothing."""
    archive = tmp_path / "run.tar.gz"
    archive.write_bytes(b"payload" * 100)
    body = worker._ThrottledBody(  # noqa: SLF001
        b"--b\r\n", archive, b"\r\n--b--\r\n", bucket=worker.TokenBucket(0)
    )

    first = b""
    while chunk := body.read(4096):
        first += chunk
    assert body.read(4096) == b""

    body.reset()
    second = b""
    while chunk := body.read(4096):
        second += chunk
    assert second == first


def test_the_upload_declares_a_content_length(monkeypatch, tmp_path: Path):
    """The results route reads Content-Length before it buffers the multipart
    and answers 411 without one, so a streamed body must not fall through to
    urllib's chunked encoding."""
    archive = tmp_path / "run.tar.gz"
    archive.write_bytes(b"x" * 4096)
    seen: dict[str, object] = {}

    class _Resp:
        status = 200

        def read(self) -> bytes:
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def _open(req, timeout):
        seen["length"] = req.get_header("Content-length")
        seen["body"] = req.data.read(-1) if hasattr(req.data, "read") else req.data
        return _Resp()

    client = worker.AgentClient("http://127.0.0.1:8080", "token", timeout=1.0)
    monkeypatch.setattr(client._opener, "open", _open)  # noqa: SLF001
    client.upload_results(
        "job-1",
        agent_id="agent-1",
        exit_code=0,
        run_id="run-1",
        error=None,
        archive_path=archive,
    )

    assert seen["length"] is not None
    assert int(seen["length"]) > 4096
