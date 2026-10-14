"""Canonical stdlib egress contracts and compatibility transport smoke tests."""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest

from agent import egress as agent_egress
from agent.runtime import egress
from api.services import egress as api_egress
from tests.egress_test_support import _CA_PEM

MODULES = pytest.mark.parametrize("module", [egress], ids=["runtime"])


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
def test_the_uppercase_http_proxy_is_not_read(module, monkeypatch):
    """httpoxy, in the direction it actually runs.

    A CGI-shaped environment derives ``HTTP_PROXY`` from an incoming ``Proxy:``
    request header — uppercase, prefixed, underscored — so the *uppercase*
    spelling is the one an untrusted caller can write. curl reads only the
    lowercase name for exactly this reason, and this reads it the same way.
    """
    monkeypatch.setenv("HTTP_PROXY", "http://attacker.example:3128")
    assert module.proxy_for_url("http://api.example.com/x") is None


@MODULES
def test_the_lowercase_http_proxy_is_the_ambient_fallback(module, monkeypatch):
    """The other half of the same rule: ``http_proxy`` is the conventional name
    no request header can spell, so it is the one honoured."""
    monkeypatch.setenv("http_proxy", "http://ambient.corp:3128")
    assert module.proxy_for_url("http://api.example.com/x").host == "ambient.corp"


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
    with pytest.raises(module.EgressConfigError, match="must be http"):
        module.proxy_for_url("https://api.example.com/x")


@MODULES
def test_an_https_proxy_url_is_refused_rather_than_downgraded(module, monkeypatch):
    """Accepting ``https://`` was a promise the client does not keep: the hop
    to the proxy is a plaintext ``CONNECT`` carrying ``Proxy-Authorization:
    Basic``, so the credentials would go out in the clear under a scheme that
    says they do not."""
    monkeypatch.setenv("OCTO_HTTPS_PROXY", "https://svc:s3cret@proxy.corp:3128")
    with pytest.raises(module.EgressConfigError, match="must be http://"):
        module.proxy_for_url("https://api.example.com/x")


@MODULES
def test_a_bare_proxy_authority_is_read_as_http(module, monkeypatch):
    monkeypatch.setenv("OCTO_HTTPS_PROXY", "proxy.corp")
    proxy = module.proxy_for_url("https://api.example.com/x")
    assert (proxy.scheme, proxy.host, proxy.port) == ("http", "proxy.corp", 80)


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
    """Compatibility entry points resolve the same policy implementation."""
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




def test_entrypoints_reexport_canonical_contracts():
    for module in (agent_egress, api_egress):
        for name in (
            "Proxy", "EgressConfigError", "parse_proxy", "proxy_for_url",
            "proxy_for", "matches_no_proxy", "ssl_context", "ca_bundle",
            "proxy_headers", "describe",
        ):
            assert getattr(module, name) is getattr(egress, name)


@pytest.mark.parametrize("module", [egress, agent_egress, api_egress])
def test_empty_overrides_keep_first_nonempty_fallback(module, monkeypatch):
    monkeypatch.setenv("OCTO_HTTPS_PROXY", "  ")
    monkeypatch.setenv("HTTPS_PROXY", "")
    monkeypatch.setenv("https_proxy", "http://fallback:3128")
    monkeypatch.setenv("OCTO_NO_PROXY", "")
    monkeypatch.setenv("NO_PROXY", " .internal.example ")
    assert module.proxy_for_url("https://a.internal.example") is None
    assert module.proxy_for_url("https://public.example").host == "fallback"


@pytest.mark.parametrize(
    "host,port,entry,matched",
    [
        ("2001:db8::1", 443, "2001:db8::/32", True),
        ("2001:db9::1", 443, "2001:db8::/32", False),
        ("[2001:db8::1]", 443, "2001:db8::1", True),
        ("2001:db8::1", 8443, "[2001:db8::1]:8443", False),
        ("2001:db8::1", 443, "[2001:db8::1]:8443", False),
        ("127.0.0.1", 8080, "127.0.0.1:8080", True),
        ("127.0.0.1", 80, "127.0.0.1:8080", False),
        ("notexample.com", 443, ".example.com", False),
    ],
)
def test_ip_and_host_port_bypass_contract(host, port, entry, matched):
    assert egress.matches_no_proxy(host, port, entry) is matched


def test_ipv6_proxy_authority_and_target_bypass(monkeypatch):
    monkeypatch.setenv("OCTO_HTTPS_PROXY", "http://svc:secret@[2001:db8::2]:3128")
    proxy = egress.proxy_for_url("https://[2001:db9::1]:8443/payload")
    assert proxy.host == "2001:db8::2"
    assert proxy.authority == "[2001:db8::2]:3128"
    assert proxy.proxy_url() == "http://svc:secret@[2001:db8::2]:3128"
    monkeypatch.setenv("OCTO_NO_PROXY", "2001:db9::/32")
    assert egress.proxy_for_url("https://[2001:db9::1]:8443/payload") is None
    assert egress.proxy_for_url("https://[2001:db8::1]:8443/payload") is not None


@pytest.mark.parametrize(
    "raw",
    [
        "http://svc:secret@proxy:bad",
        "http://svc:secret@[invalid]",
        "http://svc:secret@proxy\uff1a3128",
    ],
)
def test_invalid_proxy_reports_configuration_error_without_credentials(raw):
    import traceback

    with pytest.raises(egress.EgressConfigError) as caught:
        egress.parse_proxy(raw)
    diagnostic = "".join(traceback.format_exception(caught.value))
    assert "secret" not in diagnostic
    assert "svc" not in diagnostic


def test_proxy_diagnostics_never_include_credentials(monkeypatch):
    monkeypatch.setenv("OCTO_HTTPS_PROXY", "http://svc:s3cret@proxy.corp:3128")
    proxy = egress.proxy_for_url("https://api.example")
    for diagnostic in (egress.describe("https://api.example"), repr(proxy), proxy.authority):
        assert "s3cret" not in diagnostic
        assert "svc" not in diagnostic


@pytest.fixture
def local_transport(tmp_path):
    """Real HTTP, HTTPS and CONNECT proxy; every owned thread is joined."""
    import contextlib
    import http.server
    import select
    import socket
    import threading

    from tests.mtls_pki import CA

    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            seen.append((self.path, self.headers.get("Proxy-Authorization")))
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/payload")
                self.end_headers()
                return
            payload = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_CONNECT(self):
            seen.append((self.path, self.headers.get("Proxy-Authorization")))
            # This test proxy tunnels only to its own local TLS fixture.
            if self.path != f"127.0.0.1:{tls_server.server_port}":
                self.send_error(403)
                return
            with socket.create_connection(tls_server.server_address, timeout=2) as upstream:
                self.send_response(200)
                self.end_headers()
                self.wfile.flush()
                sockets = (self.connection, upstream)
                while True:
                    readable, _, _ = select.select(sockets, (), (), 2)
                    if not readable:
                        return
                    for source in readable:
                        data = source.recv(65536)
                        if not data:
                            return
                        target = upstream if source is self.connection else self.connection
                        target.sendall(data)

    @contextlib.contextmanager
    def serving(tls_context=None):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = False
        if tls_context is not None:
            server.socket = tls_context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
            assert not thread.is_alive()

    ca = CA()
    ca_path, _ = ca.write(tmp_path)
    cert_path, key_path = ca.server().write(tmp_path, "server")
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(cert_path, key_path)
    with serving(tls_context) as tls_server, serving() as plain_server, serving() as proxy_server:
        yield {
            "http": f"http://127.0.0.1:{plain_server.server_port}",
            "https": f"https://127.0.0.1:{tls_server.server_port}",
            "proxy": f"http://svc:s3cret@127.0.0.1:{proxy_server.server_port}",
            "ca": str(ca_path),
            "seen": seen,
        }


@pytest.mark.parametrize("module", [agent_egress, api_egress], ids=["sensor", "api"])
def test_real_http_proxy_route_and_bypass(module, local_transport, monkeypatch):
    url = "http://unresolvable.invalid/payload"
    monkeypatch.setenv("OCTO_HTTP_PROXY", local_transport["proxy"])
    with module.build_opener(url).open(url, timeout=2) as response:
        assert response.read() == b'{"ok":true}'
    assert local_transport["seen"] == [(url, "Basic c3ZjOnMzY3JldA==")]
    monkeypatch.setenv("OCTO_NO_PROXY", "127.0.0.0/8")
    direct = local_transport["http"] + "/payload"
    with module.build_opener(direct).open(direct, timeout=2) as response:
        assert response.read() == b'{"ok":true}'
    assert local_transport["seen"][-1] == ("/payload", None)


@pytest.mark.parametrize("module", [agent_egress, api_egress], ids=["sensor", "api"])
@pytest.mark.parametrize("proxied", [False, True], ids=["direct", "connect"])
def test_real_https_requires_valid_added_ca(module, proxied, local_transport, monkeypatch):
    url = local_transport["https"] + "/payload"
    if proxied:
        monkeypatch.setenv("OCTO_HTTPS_PROXY", local_transport["proxy"])
    import urllib.error
    with pytest.raises(urllib.error.URLError) as caught:
        module.build_opener(url).open(url, timeout=2)
    assert isinstance(caught.value.reason, ssl.SSLCertVerificationError)
    monkeypatch.setenv("OCTO_CA_BUNDLE", local_transport["ca"])
    with module.build_opener(url).open(url, timeout=2) as response:
        assert response.read() == b'{"ok":true}'
    assert local_transport["seen"][-1] == ("/payload", None)
    if proxied:
        assert local_transport["seen"][-2][1] == "Basic c3ZjOnMzY3JldA=="


def test_api_real_advisory_fetch_uses_shared_added_ca(local_transport, monkeypatch):
    from api.services.advisories import fetch
    monkeypatch.setenv("OCTO_CA_BUNDLE", local_transport["ca"])
    assert fetch.fetch_json(local_transport["https"] + "/payload", timeout=2) == {"ok": True}


def test_sensor_redirect_is_rejected_while_api_compatibility_remains(local_transport):
    import urllib.error
    url = local_transport["http"] + "/redirect"
    with pytest.raises(urllib.error.HTTPError) as caught:
        agent_egress.build_opener(url).open(url, timeout=2)
    assert caught.value.code == 302
    caught.value.close()
    assert local_transport["seen"] == [("/redirect", None)]
    with api_egress.build_opener(url).open(url, timeout=2) as response:
        assert response.read() == b'{"ok":true}'
    assert local_transport["seen"][-1] == ("/payload", None)


def test_sensor_egress_imports_without_control_plane_or_site_packages(tmp_path):
    import json
    import shutil
    import subprocess
    import sys
    # Copy only the sensor's actual stdlib dependency graph, then isolate Python.
    source = Path(__file__).resolve().parents[1]
    for relative in ("agent/__init__.py", "agent/egress.py", "agent/runtime/__init__.py", "agent/runtime/egress.py"):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, destination)
    script = (
        "import sys,json; sys.path.insert(0,sys.argv[1]); "
        "from agent import egress; "
        "assert egress.proxy_for_url('https://example.com') is None; "
        "assert egress.ssl_context().check_hostname; "
        "print(json.dumps(sorted(sys.modules)))"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script, str(tmp_path)],
        check=True, capture_output=True, text=True, timeout=10,
    )
    modules = json.loads(result.stdout)
    assert "agent.runtime.egress" in modules
    assert not any(name.split(".")[0] in {"api", "fastapi", "sqlalchemy"} for name in modules)
