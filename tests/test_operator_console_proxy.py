"""The development ingress is a bounded fixed target, not an open proxy."""
from contextlib import contextmanager
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
from pathlib import Path
from threading import Thread

import pytest

spec = importlib.util.spec_from_file_location("operator_console_proxy", Path(__file__).parents[1] / "scripts/operator-console-proxy.py")
proxy_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy_module)


@contextmanager
def serving(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def ingress():
    calls = []

    class Upstream(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"fixed-upstream")

        def log_message(self, *_args):
            pass

    with serving(Upstream) as upstream:
        class FixedProxy(proxy_module.Proxy):
            pass
        FixedProxy.upstream = upstream
        with serving(FixedProxy) as address:
            yield address, calls


def send(ingress, path="/health", method="GET", headers=None):
    connection = HTTPConnection(*ingress[0], timeout=3)
    try:
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


@pytest.mark.parametrize("origin", ["https://external.invalid", "null", "https://localhost:8083",
                                   "http://localhost:9999", "http://localhost:8083.attacker.invalid"])
def test_foreign_browser_origins_never_reach_upstream(ingress, origin):
    assert send(ingress, headers={"Origin": origin})[0] == 403
    assert not ingress[1]


@pytest.mark.parametrize("target", ["https://external.invalid/secret", "//external.invalid/path"])
def test_absolute_targets_cannot_retarget_upstream(ingress, target):
    assert send(ingress, target)[0] == 400
    assert not ingress[1]


def test_local_origin_uses_fixed_target(ingress):
    assert send(ingress, headers={"Origin": "http://127.0.0.1:8083"}) == (200, b"fixed-upstream")
    assert ingress[1] == ["/health"]


def test_imported_workstation_uses_deployment_owned_origin_port(ingress, monkeypatch):
    monkeypatch.setenv("OCTO_OPERATOR_CONSOLE_PORT", "8085")
    configured = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(configured)
    monkeypatch.setattr(proxy_module, "LOCAL_ORIGINS", configured.LOCAL_ORIGINS)
    assert send(ingress, headers={"Origin": "http://127.0.0.1:8085"}) == (200, b"fixed-upstream")
    assert send(ingress, headers={"Origin": "https://127.0.0.1:8085"})[0] == 403
    assert send(ingress, headers={"Origin": "http://127.0.0.1:8086"})[0] == 403


@pytest.mark.parametrize("port", ["0", "80", "65536", "8085/path", "8085,9999", "٨٠٨٥"])
def test_invalid_deployment_origin_port_rejected(monkeypatch, port):
    monkeypatch.setenv("OCTO_OPERATOR_CONSOLE_PORT", port)
    with pytest.raises(ValueError, match="deployment-owned"):
        spec.loader.exec_module(importlib.util.module_from_spec(spec))


def test_cli_without_browser_origin_uses_fixed_target(ingress):
    assert send(ingress) == (200, b"fixed-upstream")
    assert ingress[1] == ["/health"]


@pytest.mark.parametrize("headers,status", [({"Transfer-Encoding": "chunked"}, 400),
    ({"Content-Length": "-1"}, 413), ({"Content-Length": "999999999"}, 413),
    ({"Content-Length": "invalid"}, 400)])
def test_body_smuggling_and_unbounded_lengths_denied_before_read(ingress, headers, status):
    assert send(ingress, method="POST", headers=headers)[0] == status
    assert not ingress[1]


def test_connect_cannot_create_a_tunnel(ingress):
    assert send(ingress, "external.invalid:443", method="CONNECT")[0] == 501
    assert not ingress[1]
