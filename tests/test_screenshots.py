"""Web screenshots (P4.4 / Phase 9.3).

Capture is delegated to the isolated worker. These tests inject the capture
callable, so Playwright is not imported and Chromium is not launched.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from scanner.pipeline.config_schema import ScreenshotConfig
from scanner.pipeline.screenshots import (
    REDACT_SELECTOR,
    capture_screenshots_sync,
    screenshot_filename,
)


PNG = b"\x89PNG\r\n\x1a\nredacted-bytes"


def _capture_ok(url: str, timeout: float, verify_tls: bool) -> tuple[bytes, int]:
    del timeout, verify_tls
    # Two "form fields" redacted, same contract as Playwright evaluate().
    return PNG + url.encode("ascii"), 2


def test_disabled_writes_manifest_and_no_pixels(tmp_path: Path):
    result = capture_screenshots_sync(
        ["10.0.0.1:80/tcp"], ScreenshotConfig(enabled=False), tmp_path
    )
    assert result["skipped_reason"] == "screenshots.disabled"
    assert result["captured_count"] == 0
    saved = json.loads((tmp_path / "screenshots.json").read_text(encoding="utf-8"))
    assert saved["skipped_reason"] == "screenshots.disabled"
    assert not (tmp_path / "screenshots").exists()


def test_no_web_ports(tmp_path: Path):
    result = capture_screenshots_sync(
        ["10.0.0.1:22/tcp"],
        ScreenshotConfig(enabled=True),
        tmp_path,
        capture=_capture_ok,
    )
    assert result["skipped_reason"] == "no_web_ports"
    assert not (tmp_path / "screenshots").exists()


def test_worker_unavailable_skips_without_pixels(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("SCREENSHOT_WORKER_URL", raising=False)
    monkeypatch.setattr(
        "scanner.pipeline.screenshots._worker_reachable", lambda timeout: False
    )
    result = capture_screenshots_sync(
        ["10.0.0.1:80/tcp"], ScreenshotConfig(enabled=True), tmp_path
    )
    assert result["skipped_reason"] == "worker.unavailable"
    assert result["captured_count"] == 0
    assert result["findings"] == []
    assert not (tmp_path / "screenshots").exists()


def test_empty_worker_url_is_unavailable(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SCREENSHOT_WORKER_URL", "  ")
    result = capture_screenshots_sync(
        ["10.0.0.1:80/tcp"], ScreenshotConfig(enabled=True), tmp_path
    )
    assert result["skipped_reason"] == "worker.unavailable"
    assert result["captured_count"] == 0
    assert not (tmp_path / "screenshots").exists()


def test_worker_png_is_written(tmp_path: Path, monkeypatch):
    png = PNG + b"from-worker"
    captured: list[tuple[str, float, bool]] = []

    class _Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            url = captured[-1][0]
            body = {
                "png_base64": base64.standard_b64encode(
                    png + url.encode("ascii")
                ).decode("ascii"),
                "redacted_fields": 2,
            }
            return json.dumps(body).encode("utf-8")

    def fake_urlopen(request, timeout):
        assert request.full_url == "http://127.0.0.1:8077/capture"
        assert timeout == 15 + 5
        payload = json.loads(request.data.decode("utf-8"))
        captured.append(
            (payload["url"], payload["timeout_seconds"], payload["verify_tls"])
        )
        return _Response()

    monkeypatch.delenv("SCREENSHOT_WORKER_URL", raising=False)
    monkeypatch.setattr(
        "scanner.pipeline.screenshots._worker_reachable", lambda timeout: True
    )
    monkeypatch.setattr("scanner.pipeline.screenshots.urlopen", fake_urlopen)
    result = capture_screenshots_sync(
        ["203.0.113.10:443/tcp"], ScreenshotConfig(enabled=True), tmp_path
    )
    assert result["skipped_reason"] is None
    assert result["captured_count"] == 1
    assert result["redacted_fields"] == 2
    assert captured == [("https://203.0.113.10:443/", 15.0, False)]
    name = screenshot_filename("203.0.113.10", 443, "https")
    on_disk = (tmp_path / "screenshots" / name).read_bytes()
    assert on_disk.startswith(PNG)
    assert b"203.0.113.10" in on_disk


def test_worker_bad_base64_is_capture_failed(tmp_path: Path, monkeypatch):
    class _Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"png_base64": "!!!!not-base64!!!!", "redacted_fields": 0}'

    monkeypatch.setattr(
        "scanner.pipeline.screenshots._worker_reachable", lambda timeout: True
    )
    monkeypatch.setattr(
        "scanner.pipeline.screenshots.urlopen", lambda request, timeout: _Response()
    )
    result = capture_screenshots_sync(
        ["10.0.0.1:80/tcp"], ScreenshotConfig(enabled=True), tmp_path
    )
    assert result["skipped_reason"] is None
    assert result["captured_count"] == 0
    assert result["findings"][0]["error"] == "capture_failed"
    assert list((tmp_path / "screenshots").glob("*.png")) == []


def test_worker_capture_failed_does_not_fail_the_scan(tmp_path: Path, monkeypatch):
    class _Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"error": "capture_failed"}'

    monkeypatch.setattr(
        "scanner.pipeline.screenshots._worker_reachable", lambda timeout: True
    )
    monkeypatch.setattr(
        "scanner.pipeline.screenshots.urlopen", lambda request, timeout: _Response()
    )
    result = capture_screenshots_sync(
        ["10.0.0.1:80/tcp"], ScreenshotConfig(enabled=True), tmp_path
    )
    assert result["skipped_reason"] is None
    assert result["captured_count"] == 0
    assert result["findings"][0]["error"] == "capture_failed"
    assert list((tmp_path / "screenshots").glob("*.png")) == []


def test_forward_name_is_opened_instead_of_the_address(tmp_path: Path):
    seen: list[str] = []

    def capture(url: str, timeout: float, verify_tls: bool) -> tuple[bytes, int]:
        seen.append(url)
        return PNG, 0

    result = capture_screenshots_sync(
        ["203.0.113.10:443/tcp"],
        ScreenshotConfig(enabled=True),
        tmp_path,
        capture=capture,
        hostnames={"203.0.113.10": {"forward": ["onixus.ru", "onixus.duckdns.org"]}},
    )
    assert seen == [
        "https://onixus.ru:443/",
        "https://onixus.duckdns.org:443/",
    ]
    assert result["captured_count"] == 2
    assert [item["host"] for item in result["findings"]] == [
        "onixus.ru",
        "onixus.duckdns.org",
    ]
    assert {item["address"] for item in result["findings"]} == {"203.0.113.10"}


def test_capture_writes_only_what_capture_returned(tmp_path: Path):
    result = capture_screenshots_sync(
        ["203.0.113.10:443/tcp"],
        ScreenshotConfig(enabled=True),
        tmp_path,
        capture=_capture_ok,
    )
    assert result["skipped_reason"] is None
    assert result["captured_count"] == 1
    assert result["redacted_fields"] == 2
    finding = result["findings"][0]
    assert finding["host"] == "203.0.113.10"
    assert finding["port"] == 443
    assert finding["scheme"] == "https"
    assert finding["error"] is None
    assert finding["redacted_fields"] == 2
    name = screenshot_filename("203.0.113.10", 443, "https")
    assert finding["file"] == f"screenshots/{name}"
    on_disk = (tmp_path / "screenshots" / name).read_bytes()
    # Disk holds the post-redaction bytes the capture function returned —
    # there is no second unredacted file next to it.
    assert on_disk.startswith(b"\x89PNG")
    assert on_disk.startswith(PNG)
    assert b"203.0.113.10" in on_disk
    assert list((tmp_path / "screenshots").iterdir()) == [
        tmp_path / "screenshots" / name
    ]


def test_filename_is_stable_hash_not_raw_host():
    name = screenshot_filename("login.example.com", 443, "https")
    assert name.endswith(".png")
    assert "login" not in name
    assert "example" not in name
    assert screenshot_filename("login.example.com", 443, "https") == name
    assert screenshot_filename("login.example.com", 80, "http") != name


def test_truncates_at_max_targets(tmp_path: Path):
    calls: list[str] = []

    def capture(url: str, timeout: float, verify_tls: bool) -> tuple[bytes, int]:
        del timeout, verify_tls
        calls.append(url)
        return PNG, 0

    result = capture_screenshots_sync(
        ["10.0.0.1:80/tcp", "10.0.0.2:443/tcp", "10.0.0.3:8080/tcp"],
        ScreenshotConfig(enabled=True, max_targets=1),
        tmp_path,
        capture=capture,
    )
    assert result["truncated"] is True
    assert result["targets_considered"] == 3
    assert result["captured_count"] == 1
    assert len(calls) == 1


def test_capture_failure_is_fail_soft(tmp_path: Path):
    def boom(url: str, timeout: float, verify_tls: bool) -> tuple[bytes, int]:
        del url, timeout, verify_tls
        raise RuntimeError("browser crashed")

    result = capture_screenshots_sync(
        ["10.0.0.1:80/tcp"],
        ScreenshotConfig(enabled=True),
        tmp_path,
        capture=boom,
    )
    assert result["captured_count"] == 0
    assert result["findings"][0]["error"] == "capture_failed"
    assert list((tmp_path / "screenshots").glob("*.png")) == []


def test_empty_capture_does_not_write_png(tmp_path: Path):
    def empty(url: str, timeout: float, verify_tls: bool) -> tuple[bytes, int]:
        del url, timeout, verify_tls
        return b"", 0

    result = capture_screenshots_sync(
        ["10.0.0.1:80/tcp"],
        ScreenshotConfig(enabled=True),
        tmp_path,
        capture=empty,
    )
    assert result["findings"][0]["error"] == "empty_capture"
    assert list((tmp_path / "screenshots").glob("*.png")) == []


def test_redact_selector_covers_obvious_credential_fields():
    lowered = REDACT_SELECTOR.lower()
    for needle in ("password", "token", "ssn", "credit", "one-time-code", "cc-number"):
        assert needle in lowered
