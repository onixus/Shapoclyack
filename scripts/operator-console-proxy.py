"""Loopback development ingress to the fixed isolated API, never an open proxy."""
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import sys
from urllib.parse import urlsplit

HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailer", "transfer-encoding", "upgrade"}
LOCAL_ORIGINS = {"http://127.0.0.1:8082", "http://localhost:8082",
                 "http://127.0.0.1:8083", "http://localhost:8083"}
if port := os.environ.get("OCTO_OPERATOR_CONSOLE_PORT"):
    if not port.isascii() or not port.isdecimal() or not 1024 <= int(port) <= 65535:
        raise ValueError("Invalid deployment-owned console port")
    LOCAL_ORIGINS.update({f"http://127.0.0.1:{int(port)}", f"http://localhost:{int(port)}"})
# Only these loopback authorities may address the ingress; any other Host
# header (DNS rebinding from a hostile page) is refused before forwarding.
ALLOWED_HOSTS = {origin.removeprefix("http://") for origin in LOCAL_ORIGINS} | {"127.0.0.1:8084", "localhost:8084"}
# The model targets expose nothing but the endpoints the operator uses; the
# llama.cpp server's other routes (slots, props, metrics, tokenize, ...) stay
# unreachable through this proxy. The API ingress (None) serves the console.
MODEL_PATHS = {"/health": {"GET", "HEAD"}, "/v1/models": {"GET", "HEAD"},
               "/v1/chat/completions": {"POST"}, "/v1/embeddings": {"POST"}}


class Proxy(BaseHTTPRequestHandler):
    upstream = ("api", 8080)
    allowed_paths = None

    def authority_allowed(self):
        hosts = self.headers.get_all("Host", [])
        return len(hosts) == 1 and hosts[0].lower() in ALLOWED_HOSTS

    def path_allowed(self):
        if self.allowed_paths is None:
            return True
        methods = self.allowed_paths.get(urlsplit(self.path).path)
        return methods is not None and (self.command in methods or self.command == "OPTIONS")

    def forward(self):
        if not self.authority_allowed():
            self.send_error(421)
            return
        # Reject browser requests from unrelated sites before they reach the
        # local model's permissive CORS handler or authenticated console API.
        origins = self.headers.get_all("Origin", [])
        if origins and (len(origins) != 1 or origins[0] not in LOCAL_ORIGINS):
            self.send_error(403)
            return
        # BaseHTTPRequestHandler normalizes a network-path reference's leading
        # // to / before dispatch; inspect the original request target too.
        target = self.requestline.split()[1]
        if not target.startswith("/") or target.startswith("//"):
            self.send_error(400)
            return
        if not self.path_allowed():
            self.send_error(404)
            return
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") or len(lengths) > 1:
            self.send_error(400)
            return
        try:
            length = int(lengths[0]) if lengths else 0
        except ValueError:
            self.send_error(400)
            return
        if not 0 <= length <= 8 * 1024 * 1024:
            self.send_error(413)
            return
        connection = HTTPConnection(*self.upstream, timeout=130)
        started = False
        try:
            self.connection.settimeout(15)
            headers = {key: value for key, value in self.headers.items() if key.lower() not in HOP_HEADERS}
            connection.request(self.command, self.path, self.rfile.read(length), headers)
            response = connection.getresponse()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in HOP_HEADERS:
                    self.send_header(key, value)
            self.send_header("Connection", "close")
            self.end_headers()
            started = True
            if self.command != "HEAD":
                while chunk := response.read(65536):
                    self.wfile.write(chunk)
        except (OSError, TimeoutError):
            # Upstream addresses, payloads and authentication headers stay out
            # of local logs; unavailable backend is an explicit HTTP failure.
            if started:
                self.close_connection = True
            else:
                self.send_error(502)
        finally:
            connection.close()

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = forward

    def log_message(self, *_args):
        pass


MODEL_TARGETS = {"inference": ("172.30.83.2", 8082), "embeddings": ("172.30.83.5", 8084)}


def select_model_target(name):
    """Point the proxy at one fixed model server and restrict it to the operator endpoints."""
    Proxy.upstream = MODEL_TARGETS[name]
    Proxy.allowed_paths = MODEL_PATHS


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if len(sys.argv) != 2 or sys.argv[1] not in MODEL_TARGETS:
            raise SystemExit("Only fixed model targets may be selected")
        select_model_target(sys.argv[1])
    ThreadingHTTPServer(("0.0.0.0", 8080), Proxy).serve_forever()
