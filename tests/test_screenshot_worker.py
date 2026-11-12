"""Screenshot worker request validation. Chromium is never launched."""

from __future__ import annotations

import base64
import json
import threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from scanner.pipeline.screenshots import REDACT_SCRIPT
from scanner.screenshot_worker import (
    PNG_MAGIC,
    WorkerServer,
    browser_can_launch,
    encode_png,
    handle_capture,
    validate_capture_url,
)

PNG = PNG_MAGIC + b"redacted-bytes"


def _body(**overrides: object) -> bytes:
    payload = {
        "url": "https://203.0.113.10/",
        "timeout_seconds": 15,
        "verify_tls": False,
    }
    payload.update(overrides)
    return json.dumps(payload).encode("utf-8")


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


def test_http_server_health_and_capture_with_fake_browser():
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
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=2) as response:
            payload = json.loads(response.read())
        assert base64.standard_b64decode(payload["png_base64"]) == PNG
        assert payload["redacted_fields"] == 1
        with pytest.raises(HTTPError) as caught:
            urlopen(
                Request(base + "/capture", data=b'{"url":"ftp://x"}', method="POST"),
                timeout=2,
            )
        assert caught.value.code == 400
        assert json.loads(caught.value.read()) == {"error": "invalid_url"}
    finally:
        server.shutdown()
        thread.join(timeout=3)


def test_health_checks_chromium_on_disk_without_launching(monkeypatch, tmp_path: Path):
    """A kubelet probe must not start the Playwright driver or a browser."""
    import builtins
    import types

    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path))
    real_import = builtins.__import__

    def importable(name, *args, **kwargs):
        if name == "playwright" or name.startswith("playwright."):
            return types.ModuleType(name)
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
