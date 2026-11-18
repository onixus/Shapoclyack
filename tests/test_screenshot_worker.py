"""Screenshot worker request validation. Chromium is never launched."""

from __future__ import annotations

import base64
import json
import threading
import types
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from scanner.pipeline.screenshots import REDACT_SCRIPT
from scanner.screenshot_worker import (
    PNG_MAGIC,
    WorkerError,
    WorkerServer,
    _playwright_capture,
    browser_can_launch,
    encode_png,
    handle_capture,
    same_navigation_target,
    validate_capture_url,
)

PNG = PNG_MAGIC + b"redacted-bytes"
TOKEN = "test-screenshot-token"


def _body(**overrides: object) -> bytes:
    payload = {
        "url": "https://203.0.113.10/",
        "timeout_seconds": 15,
        "verify_tls": False,
    }
    payload.update(overrides)
    return json.dumps(payload).encode("utf-8")


def _auth_headers(**extra: str) -> dict[str, str]:
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"}
    headers.update(extra)
    return headers


def test_redact_script_is_the_stage_script():
    assert "data-shapoclyack-redact" in REDACT_SCRIPT
    assert "querySelectorAll" in REDACT_SCRIPT


@pytest.mark.parametrize(
    "url",
    [
        "ftp://203.0.113.10/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "https://user:secret@203.0.113.10/",
        "https://user@203.0.113.10/",
        "http://",
        "",
        "https://203.0.113.10/\n",
    ],
)
def test_rejects_non_http_and_userinfo(url: str):
    with pytest.raises(Exception) as caught:
        validate_capture_url(url)
    assert getattr(caught.value, "error", "") == "invalid_url"


def test_accepts_http_and_https():
    assert (
        validate_capture_url("http://203.0.113.10:8080/login")
        == "http://203.0.113.10:8080/login"
    )
    assert validate_capture_url("https://[2001:db8::1]/") == "https://[2001:db8::1]/"


@pytest.mark.parametrize(
    ("requested", "candidate", "ok"),
    [
        ("http://203.0.113.10/", "http://203.0.113.10/login", True),
        # Scheme may flip only when the numeric port stays the same.
        ("http://203.0.113.10:8443/", "https://203.0.113.10:8443/login", True),
        ("http://203.0.113.10:443/", "https://203.0.113.10/", True),
        ("https://203.0.113.10:80/", "http://203.0.113.10/", True),
        # Default http:80 vs https:443 is a port change → reject.
        ("http://203.0.113.10/", "https://203.0.113.10/login", False),
        ("https://203.0.113.10/", "http://203.0.113.10/", False),
        ("http://203.0.113.10:8080/", "http://203.0.113.10:8080/a", True),
        ("http://203.0.113.10/", "http://169.254.169.254/", False),
        ("http://203.0.113.10/", "http://127.0.0.1/", False),
        ("http://203.0.113.10:8080/", "http://203.0.113.10/", False),
        ("http://203.0.113.10/", "http://203.0.113.10:8443/", False),
        ("http://[2001:db8::1]:8443/", "https://[2001:db8::1]:8443/", True),
        ("http://[2001:db8::1]/", "http://[2001:db8::2]/", False),
    ],
)
def test_same_navigation_target_pins_host_and_port(
    requested: str, candidate: str, ok: bool
):
    assert same_navigation_target(requested, candidate) is ok


def test_off_host_redirect_is_capture_failed(monkeypatch):
    """A 302 that lands off-host must not return pixels (SSRF guard)."""

    class _Request:
        url = "http://169.254.169.254/latest/meta-data/"

        def is_navigation_request(self) -> bool:
            return True

    class _Route:
        def __init__(self) -> None:
            self.request = _Request()
            self.aborted = False
            self.continued = False

        def abort(self) -> None:
            self.aborted = True

        def continue_(self) -> None:
            self.continued = True

    class _Response:
        url = "http://169.254.169.254/latest/meta-data/"

    class _Page:
        url = "http://169.254.169.254/latest/meta-data/"

        def route(self, pattern, handler) -> None:
            route = _Route()
            handler(route)
            assert route.aborted is True
            assert route.continued is False

        def goto(self, url, wait_until, timeout):
            del url, wait_until, timeout
            return _Response()

        def evaluate(self, script):
            del script
            return 0

        def screenshot(self, full_page, type):  # noqa: A002
            del full_page, type
            return PNG

    class _Browser:
        def new_page(self, ignore_https_errors, viewport):
            del ignore_https_errors, viewport
            return _Page()

        def close(self) -> None:
            return None

    class _Chromium:
        def launch(self, headless, args):
            del headless, args
            return _Browser()

    class _Playwright:
        chromium = _Chromium()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    fake = types.ModuleType("playwright.sync_api")
    fake.sync_playwright = lambda: _Playwright()
    monkeypatch.setitem(__import__("sys").modules, "playwright", types.ModuleType("playwright"))
    monkeypatch.setitem(__import__("sys").modules, "playwright.sync_api", fake)

    with pytest.raises(WorkerError) as caught:
        _playwright_capture("http://203.0.113.10/", 5.0, False)
    assert caught.value.error == "capture_failed"

    code, payload = handle_capture(
        _body(url="http://203.0.113.10/"), capture=_playwright_capture
    )
    assert code == 200
    assert payload == {"error": "capture_failed"}


def test_capture_failed_has_no_exception_text():
    def boom(url: str, timeout: float, verify_tls: bool) -> tuple[bytes, int]:
        del url, timeout, verify_tls
        raise RuntimeError("secret page body and Set-Cookie=session")

    code, payload = handle_capture(_body(), capture=boom)
    assert code == 200
    assert payload == {"error": "capture_failed"}
    rendered = json.dumps(payload)
    assert "secret" not in rendered
    assert "Set-Cookie" not in rendered
    assert "RuntimeError" not in rendered


def test_success_is_standard_base64_png():
    def ok(url: str, timeout: float, verify_tls: bool) -> tuple[bytes, int]:
        assert url == "https://203.0.113.10/"
        assert timeout == 15
        assert verify_tls is False
        return PNG, 2

    code, payload = handle_capture(_body(), capture=ok)
    assert code == 200
    assert payload["redacted_fields"] == 2
    assert "\n" not in payload["png_base64"]
    assert base64.standard_b64decode(payload["png_base64"]) == PNG


def test_empty_and_non_png_are_capture_failed():
    def empty(url: str, timeout: float, verify_tls: bool) -> tuple[bytes, int]:
        del url, timeout, verify_tls
        return b"", 0

    def junk(url: str, timeout: float, verify_tls: bool) -> tuple[bytes, int]:
        del url, timeout, verify_tls
        return b"GIF89a", 1

    assert handle_capture(_body(), capture=empty) == (200, {"error": "capture_failed"})
    assert handle_capture(_body(), capture=junk) == (200, {"error": "capture_failed"})
    with pytest.raises(Exception):
        encode_png(b"not-a-png", 0)


def test_invalid_json_and_types():
    assert handle_capture(b"not-json")[0] == 400
    assert handle_capture(_body(timeout_seconds=0))[0] == 400
    assert handle_capture(_body(timeout_seconds="15"))[0] == 400
    assert handle_capture(_body(verify_tls="false"))[0] == 400
    code, payload = handle_capture(_body(url="https://user@203.0.113.10/"))
    assert code == 400
    assert payload == {"error": "invalid_url"}


def test_http_server_health_and_capture_with_fake_browser(monkeypatch):
    monkeypatch.setenv("OCTO_SCREENSHOT_WORKER_TOKEN", TOKEN)

    def ok(url: str, timeout: float, verify_tls: bool) -> tuple[bytes, int]:
        del url, timeout, verify_tls
        return PNG, 1

    server = WorkerServer("127.0.0.1", 0, capture=ok, health=lambda: True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.port}"
    try:
        with urlopen(base + "/healthz", timeout=2) as response:
            assert response.status == 200
            assert json.loads(response.read()) == {"status": "ok"}
        request = Request(
            base + "/capture",
            data=_body(),
            headers=_auth_headers(),
            method="POST",
        )
        with urlopen(request, timeout=2) as response:
            payload = json.loads(response.read())
        assert base64.standard_b64decode(payload["png_base64"]) == PNG
        assert payload["redacted_fields"] == 1
        with pytest.raises(HTTPError) as caught:
            urlopen(
                Request(
                    base + "/capture",
                    data=b'{"url":"ftp://x"}',
                    headers=_auth_headers(),
                    method="POST",
                ),
                timeout=2,
            )
        assert caught.value.code == 400
        assert json.loads(caught.value.read()) == {"error": "invalid_url"}
    finally:
        server.shutdown()
        thread.join(timeout=3)


def test_capture_requires_matching_token(monkeypatch):
    monkeypatch.setenv("OCTO_SCREENSHOT_WORKER_TOKEN", TOKEN)

    def ok(url: str, timeout: float, verify_tls: bool) -> tuple[bytes, int]:
        del url, timeout, verify_tls
        return PNG, 0

    server = WorkerServer("127.0.0.1", 0, capture=ok, health=lambda: True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.port}"
    try:
        with pytest.raises(HTTPError) as missing:
            urlopen(
                Request(
                    base + "/capture",
                    data=_body(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                ),
                timeout=2,
            )
        assert missing.value.code == 401
        assert json.loads(missing.value.read()) == {"error": "unauthorized"}

        with pytest.raises(HTTPError) as wrong:
            urlopen(
                Request(
                    base + "/capture",
                    data=_body(),
                    headers=_auth_headers(Authorization="Bearer wrong"),
                    method="POST",
                ),
                timeout=2,
            )
        assert wrong.value.code == 401

        alt = Request(
            base + "/capture",
            data=_body(),
            headers={
                "Content-Type": "application/json",
                "X-Screenshot-Token": TOKEN,
            },
            method="POST",
        )
        with urlopen(alt, timeout=2) as response:
            assert response.status == 200
            assert "png_base64" in json.loads(response.read())
    finally:
        server.shutdown()
        thread.join(timeout=3)


def test_capture_refuses_when_token_unset(monkeypatch):
    monkeypatch.delenv("OCTO_SCREENSHOT_WORKER_TOKEN", raising=False)
    server = WorkerServer(
        "127.0.0.1", 0, capture=lambda *a: (PNG, 0), health=lambda: True
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(HTTPError) as caught:
            urlopen(
                Request(
                    f"http://127.0.0.1:{server.port}/capture",
                    data=_body(),
                    headers=_auth_headers(),
                    method="POST",
                ),
                timeout=2,
            )
        assert caught.value.code == 401
        assert json.loads(caught.value.read()) == {"error": "unauthorized"}
    finally:
        server.shutdown()
        thread.join(timeout=3)


def test_health_checks_chromium_on_disk_without_launching(monkeypatch, tmp_path: Path):
    """A kubelet probe must not start the Playwright driver or a browser."""
    import builtins
    import types as types_mod

    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path))
    real_import = builtins.__import__

    def importable(name, *args, **kwargs):
        if name == "playwright" or name.startswith("playwright."):
            return types_mod.ModuleType(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", importable)
    assert browser_can_launch() is False
    chrome = tmp_path / "chromium" / "chrome"
    chrome.parent.mkdir()
    chrome.write_bytes(b"#!/bin/sh\n")
    chrome.chmod(0o755)
    assert browser_can_launch() is True

    def missing(name, *args, **kwargs):
        if name == "playwright" or name.startswith("playwright."):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing)
    assert browser_can_launch() is False


def test_healthz_unavailable_when_browser_cannot_launch():
    server = WorkerServer("127.0.0.1", 0, health=lambda: False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(HTTPError) as caught:
            urlopen(f"http://127.0.0.1:{server.port}/healthz", timeout=2)
        assert caught.value.code == 503
        assert json.loads(caught.value.read()) == {"status": "unavailable"}
    finally:
        server.shutdown()
        thread.join(timeout=3)
