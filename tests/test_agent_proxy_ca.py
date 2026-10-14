"""Sensor HTTP wiring, NATS trust and result upload shaping contracts."""

from __future__ import annotations

import ssl
import urllib.error
from pathlib import Path

import pytest

from agent import worker
from tests.egress_test_support import _CA_PEM

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


def test_the_api_side_nats_connection_reads_the_same_ca_bundle(monkeypatch, tmp_path: Path):
    """``OCTO_CA_BUNDLE`` is documented as "API **and** agent", and the API's
    NATS client is the end that used to ignore it: the agent trusted the
    internal root, the API did not, and the broker behind the same
    cert-manager issuer answered one of them."""
    from api.services import nats_bus

    bundle = tmp_path / "corp-root.pem"
    bundle.write_text(_CA_PEM, encoding="utf-8")
    system_roots = len(ssl.create_default_context().get_ca_certs())
    monkeypatch.setenv("OCTO_CA_BUNDLE", str(bundle))
    for name in ("OCTO_NATS_TLS_CA", "OCTO_NATS_TLS_CERT", "OCTO_NATS_TLS_HOSTNAME"):
        monkeypatch.delenv(name, raising=False)

    options = nats_bus.tls_connect_options()
    assert len(options["tls"].get_ca_certs()) == system_roots + 1


def test_the_api_side_nats_connection_stays_default_without_any_variable(monkeypatch):
    """A `nats://` deployment with nothing set must keep connecting in the
    clear, not acquire a TLS context because the bundle lookup ran."""
    from api.services import nats_bus

    for name in (
        "OCTO_CA_BUNDLE",
        "OCTO_NATS_TLS_CA",
        "OCTO_NATS_TLS_CERT",
        "OCTO_NATS_TLS_KEY",
        "OCTO_NATS_TLS_HOSTNAME",
    ):
        monkeypatch.delenv(name, raising=False)
    assert nats_bus.tls_connect_options() == {}


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


def test_a_body_cut_off_mid_upload_is_not_re_sent(monkeypatch, tmp_path: Path):
    """``OCTO_AGENT_RESULTS_MAX_BODY_BYTES`` is answered on ``Content-Length``,
    so the API never drains the multipart and the status line is lost with the
    socket — the agent only sees a broken pipe. Retrying that spends the
    branch office's uplink twice more to be refused three times."""
    archive = tmp_path / "run.tar.gz"
    archive.write_bytes(b"x" * 4096)
    attempts = []

    def _open(req, timeout):
        attempts.append(req)
        raise urllib.error.URLError(BrokenPipeError(32, "Broken pipe"))

    monkeypatch.setattr(worker.time, "sleep", lambda seconds: pytest.fail("no backoff wanted"))
    client = worker.AgentClient("http://127.0.0.1:8080", "token", timeout=1.0)
    monkeypatch.setattr(client._opener, "open", _open)  # noqa: SLF001

    with pytest.raises(RuntimeError, match="OCTO_AGENT_RESULTS_MAX_BODY_BYTES"):
        client.upload_results(
            "job-1",
            agent_id="agent-1",
            exit_code=0,
            run_id="run-1",
            error=None,
            archive_path=archive,
        )
    assert len(attempts) == 1


def test_a_transport_error_that_is_not_a_cut_off_body_still_retries(monkeypatch, tmp_path: Path):
    """The narrow rule must stay narrow: an upload that never reached the API
    at all is the case retries exist for."""
    archive = tmp_path / "run.tar.gz"
    archive.write_bytes(b"x" * 4096)
    attempts = []

    def _open(req, timeout):
        attempts.append(req)
        raise urllib.error.URLError(ConnectionRefusedError(61, "Connection refused"))

    monkeypatch.setattr(worker.time, "sleep", lambda seconds: None)
    client = worker.AgentClient("http://127.0.0.1:8080", "token", timeout=1.0)
    monkeypatch.setattr(client._opener, "open", _open)  # noqa: SLF001

    with pytest.raises(RuntimeError, match="network error"):
        client.upload_results(
            "job-1",
            agent_id="agent-1",
            exit_code=0,
            run_id="run-1",
            error=None,
            archive_path=archive,
        )
    assert len(attempts) == 3


# --------------------------------------------------------------------------- #
# The pipeline's own lookups (RIPEstat, S3/GCS/Azure)
# --------------------------------------------------------------------------- #


def test_the_pipeline_lookups_are_unconfigured_by_default():
    """No variables, no keyword arguments: ``httpx`` keeps its own defaults
    rather than being handed ``proxy=None`` and ``verify=None``."""
    from scanner.pipeline.egress_env import httpx_kwargs

    assert httpx_kwargs() == {}


def test_the_pipeline_lookups_go_through_the_proxy_and_the_internal_root(
    monkeypatch, tmp_path: Path
):
    """``asn_discovery`` asks RIPEstat and ``cloud_discovery`` asks S3, GCS and
    Azure — always-external services, on a network whose only way out is the
    proxy. Both stages failed there without naming a setting."""
    from scanner.pipeline.egress_env import httpx_kwargs

    bundle = tmp_path / "corp-root.pem"
    bundle.write_text(_CA_PEM, encoding="utf-8")
    monkeypatch.setenv("OCTO_HTTPS_PROXY", "proxy.corp:3128")
    monkeypatch.setenv("OCTO_CA_BUNDLE", str(bundle))

    assert httpx_kwargs() == {"proxy": "http://proxy.corp:3128", "verify": str(bundle)}


def test_a_missing_pipeline_ca_bundle_is_an_error_not_a_silent_fallback(monkeypatch, tmp_path):
    from scanner.pipeline.egress_env import httpx_kwargs

    monkeypatch.setenv("OCTO_CA_BUNDLE", str(tmp_path / "absent.pem"))
    with pytest.raises(ValueError, match="not a readable file"):
        httpx_kwargs()
