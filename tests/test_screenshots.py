"""Web screenshots (P4.4 / Phase 9.3). Playwright is not required — capture is injected."""

from __future__ import annotations

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


def test_playwright_missing_skips_without_pixels(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "scanner.pipeline.screenshots._playwright_available", lambda: False
    )
    result = capture_screenshots_sync(
        ["10.0.0.1:80/tcp"], ScreenshotConfig(enabled=True), tmp_path
    )
    assert result["skipped_reason"] == "playwright.unavailable"
    assert result["captured_count"] == 0
    assert not (tmp_path / "screenshots").exists()


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
    assert list((tmp_path / "screenshots").iterdir()) == [tmp_path / "screenshots" / name]


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
