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
        connection.request(method, path, headers={"Host": "127.0.0.1:8083", **(headers or {})})
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


@pytest.mark.parametrize("host", ["attacker.invalid", "127.0.0.1", "127.0.0.1:9999", "localhost:8083.attacker.invalid",
                                  "127.0.0.1:8083, attacker.invalid"])
def test_foreign_host_header_never_reaches_upstream(ingress, host):
    assert send(ingress, headers={"Host": host})[0] == 421
    assert not ingress[1]


@pytest.mark.parametrize("host", ["127.0.0.1:8083", "LOCALHOST:8083", "127.0.0.1:8082", "localhost:8084"])
def test_loopback_hosts_are_served(ingress, host):
    assert send(ingress, headers={"Host": host})[0] == 200


def test_missing_host_header_is_refused(ingress):
    connection = HTTPConnection(*ingress[0], timeout=3)
    try:
        connection.putrequest("GET", "/health", skip_host=True)
        connection.endheaders()
        assert connection.getresponse().status == 421
    finally:
        connection.close()
    assert not ingress[1]


@pytest.fixture
def model_ingress(ingress, monkeypatch):
    monkeypatch.setattr(proxy_module.Proxy, "allowed_paths", proxy_module.MODEL_PATHS)
    return ingress


@pytest.mark.parametrize("path", ["/health", "/v1/models", "/v1/models?x=1"])
def test_model_proxy_serves_the_read_endpoints(model_ingress, path):
    assert send(model_ingress, path)[0] == 200
    assert model_ingress[1] == [path]


@pytest.mark.parametrize("path", ["/v1/chat/completions", "/v1/embeddings"])
def test_model_proxy_lets_the_post_endpoints_through_to_the_upstream(model_ingress, path):
    # Reached the stub upstream, which implements GET only: 501 rather than the proxy's 404.
    assert send(model_ingress, path, method="POST", headers={"Content-Length": "0"})[0] == 501


@pytest.mark.parametrize("name", ["inference", "embeddings"])
def test_selecting_a_model_target_installs_the_path_allowlist(monkeypatch, name):
    monkeypatch.setattr(proxy_module.Proxy, "upstream", ("api", 8080))
    monkeypatch.setattr(proxy_module.Proxy, "allowed_paths", None)
    proxy_module.select_model_target(name)
    assert proxy_module.Proxy.allowed_paths == proxy_module.MODEL_PATHS
    assert proxy_module.Proxy.upstream == proxy_module.MODEL_TARGETS[name]
    assert set(proxy_module.MODEL_PATHS) == {"/health", "/v1/models", "/v1/chat/completions", "/v1/embeddings"}


@pytest.mark.parametrize("path,method", [("/props", "GET"), ("/slots", "GET"), ("/metrics", "GET"), ("/tokenize", "POST"),
                                         ("/v1/completions", "POST"), ("/health/../props", "GET"), ("/v1/chat/completions", "GET"),
                                         ("/v1/embeddings", "DELETE"), ("/", "GET"), ("/v1/models/", "GET")])
def test_model_proxy_refuses_other_llama_server_routes_and_methods(model_ingress, path, method):
    assert send(model_ingress, path, method=method)[0] == 404
    assert not model_ingress[1]


def test_api_ingress_keeps_serving_console_paths(ingress):
    assert send(ingress, "/operator")[0] == 200 and ingress[1] == ["/operator"]
