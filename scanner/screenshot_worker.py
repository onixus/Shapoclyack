"""Isolated screenshot worker (``python -m scanner.screenshot_worker``).

Loopback HTTP by default. The scanner stage posts already-open web URLs;
this process is the only one that imports Playwright or launches Chromium.
It returns redacted PNG bytes and does not write the run directory.

``SCREENSHOT_WORKER_BIND`` (default ``127.0.0.1``) and
``SCREENSHOT_WORKER_PORT`` (default ``8077``) select the listen address.
``SCREENSHOT_WORKER_BIND=0.0.0.0`` is for the container, which has no other
listeners. ``SCREENSHOT_WORKER_NO_SANDBOX=1`` adds ``--no-sandbox`` — only
inside the container's own seccomp/user-namespace story. Do not add
raw-socket capabilities.

HONESTY: redaction covers obvious form fields only (the shared
``REDACT_SCRIPT``). Unredacted pixels are never returned. Errors are the
fixed token ``capture_failed`` — never exception text, response bodies, or
cookies.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import urlsplit

from scanner.pipeline.screenshots import REDACT_SCRIPT

LOG = logging.getLogger("shapoclyack.screenshot_worker")

DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 8077
VIEWPORT = {"width": 1280, "height": 720}
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_NO_SANDBOX_ENV = "SCREENSHOT_WORKER_NO_SANDBOX"
_MAX_BODY = 64 * 1024

CaptureFn = Callable[[str, float, bool], tuple[bytes, int]]

_capture_lock = threading.Lock()


class WorkerError(Exception):
    """Request rejected before navigation. ``code`` is an HTTP status."""

    def __init__(self, code: int, error: str) -> None:
        super().__init__(error)
        self.code = code
        self.error = error


def bind_address() -> str:
    raw = os.environ.get("SCREENSHOT_WORKER_BIND", DEFAULT_BIND).strip()
    return raw or DEFAULT_BIND


def bind_port() -> int:
    raw = os.environ.get("SCREENSHOT_WORKER_PORT", str(DEFAULT_PORT)).strip()
    try:
        port = int(raw)
    except ValueError:
        return DEFAULT_PORT
    if port < 1 or port > 65535:
        return DEFAULT_PORT
    return port


def no_sandbox() -> bool:
    return os.environ.get(_NO_SANDBOX_ENV, "").strip() == "1"


def chromium_args() -> list[str]:
    """Headless launch args. ``--no-sandbox`` only when the container asks."""
    args = ["--disable-dev-shm-usage"]
    if no_sandbox():
        args.append("--no-sandbox")
    return args


def validate_capture_url(url: str) -> str:
    """Accept only http(s) URLs with no userinfo. Reject everything else."""
    if (
        not isinstance(url, str)
        or not url
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in url)
    ):
        raise WorkerError(400, "invalid_url")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise WorkerError(400, "invalid_url") from exc
    if parts.scheme not in ("http", "https"):
        raise WorkerError(400, "invalid_url")
    if parts.username is not None or parts.password is not None:
        raise WorkerError(400, "invalid_url")
    if not parts.hostname:
        raise WorkerError(400, "invalid_url")
    return url


def _timeout_seconds(raw: Any) -> float:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise WorkerError(400, "invalid_request")
    timeout = float(raw)
    if timeout <= 0 or timeout > 120:
        raise WorkerError(400, "invalid_request")
    return timeout


def _verify_tls(raw: Any) -> bool:
    if not isinstance(raw, bool):
        raise WorkerError(400, "invalid_request")
    return raw


def parse_capture_request(body: bytes) -> tuple[str, float, bool]:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerError(400, "invalid_request") from exc
    if not isinstance(payload, dict):
        raise WorkerError(400, "invalid_request")
    url = validate_capture_url(payload.get("url", ""))
    timeout = _timeout_seconds(payload.get("timeout_seconds", 15))
    verify = _verify_tls(payload.get("verify_tls", False))
    return url, timeout, verify


def encode_png(png: bytes, redacted_fields: int) -> dict[str, Any]:
    if not png or not png.startswith(PNG_MAGIC):
        raise WorkerError(200, "capture_failed")
    if redacted_fields < 0:
        raise WorkerError(200, "capture_failed")
    encoded = base64.standard_b64encode(png).decode("ascii")
    if "\n" in encoded or "\r" in encoded:
        raise WorkerError(200, "capture_failed")
    return {"png_base64": encoded, "redacted_fields": int(redacted_fields)}


def _playwright_capture(
    url: str, timeout: float, verify_tls: bool
) -> tuple[bytes, int]:
    """Navigate, redact, screenshot. Playwright is imported only here."""
    from playwright.sync_api import sync_playwright

    timeout_ms = int(timeout * 1000)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, args=chromium_args())
        try:
            page = browser.new_page(
                ignore_https_errors=not verify_tls,
                viewport=VIEWPORT,
            )
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            redacted = int(page.evaluate(REDACT_SCRIPT) or 0)
            png = page.screenshot(full_page=False, type="png")
        finally:
            browser.close()
    if not isinstance(png, (bytes, bytearray)) or not png:
        raise WorkerError(200, "capture_failed")
    return bytes(png), redacted


def handle_capture(
    body: bytes,
    capture: CaptureFn | None = None,
) -> tuple[int, dict[str, Any]]:
    """Validate one request and shape the JSON the scanner expects.

    Navigation, timeout, and empty-page failures are ``200``
    ``{"error": "capture_failed"}``. Exception text never leaves this
    function. ``capture`` is the test seam; production uses Playwright.
    """
    try:
        url, timeout, verify_tls = parse_capture_request(body)
    except WorkerError as exc:
        return exc.code, {"error": exc.error}
    fn = capture or _playwright_capture
    try:
        with _capture_lock:
            png, redacted = fn(url, timeout, verify_tls)
        body_out = encode_png(png, int(redacted))
    except WorkerError as exc:
        return exc.code, {"error": "capture_failed"}
    except Exception:
        LOG.debug("screenshot capture failed")
        return 200, {"error": "capture_failed"}
    return 200, body_out


def browser_can_launch() -> bool:
    """True when Playwright imports and a Chromium binary is on disk.

    ``GET /healthz`` is a kubelet probe, so this must not start the Playwright
    driver or a browser. A missing binary still fails the first capture as
    ``capture_failed``; the probe only answers "is this process the worker,
    and can it see Chromium".
    """
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False
    root = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "").strip()
    if not root:
        # Local dev, where Playwright keeps browsers under its own cache.
        # The image always sets PLAYWRIGHT_BROWSERS_PATH.
        return True
    base = Path(root)
    if not base.is_dir():
        return False
    return any(
        path.is_file() and os.access(path, os.X_OK) and path.name == "chrome"
        for path in base.rglob("chrome")
    )


def make_handler(
    *,
    capture: CaptureFn | None = None,
    health: Callable[[], bool] | None = None,
) -> type[BaseHTTPRequestHandler]:
    health_fn = health if health is not None else browser_can_launch

    class Handler(BaseHTTPRequestHandler):
        server_version = "shapoclyack-screenshot-worker"

        def _send_json(self, code: int, payload: dict[str, Any]) -> None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            self.close_connection = True

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            path = self.path.split("?", 1)[0]
            if path != "/healthz":
                self._send_json(404, {"error": "not_found"})
                return
            if health_fn():
                self._send_json(200, {"status": "ok"})
                return
            self._send_json(503, {"status": "unavailable"})

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            path = self.path.split("?", 1)[0]
            if path != "/capture":
                self._send_json(404, {"error": "not_found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_json(400, {"error": "invalid_request"})
                return
            if length < 0 or length > _MAX_BODY:
                self._send_json(400, {"error": "invalid_request"})
                return
            raw = self.rfile.read(length) if length else b""
            code, payload = handle_capture(raw, capture=capture)
            self._send_json(code, payload)

        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002
            # Never log the request target: it is a scanned URL.
            LOG.debug("screenshot worker %s", self.command)

    return Handler


class WorkerServer:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        capture: CaptureFn | None = None,
        health: Callable[[], bool] | None = None,
    ) -> None:
        self._httpd = ThreadingHTTPServer(
            (host, port), make_handler(capture=capture, health=health)
        )
        self._httpd.daemon_threads = True

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    def serve_forever(self) -> None:
        self._httpd.serve_forever()

    def shutdown(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")
    host, port = bind_address(), bind_port()
    LOG.info("screenshot worker listening on %s:%s", host, port)
    WorkerServer(host, port).serve_forever()


if __name__ == "__main__":
    main()
