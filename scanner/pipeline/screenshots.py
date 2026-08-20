"""Web screenshots with DOM redaction (P4.4 / Phase 9.3).

Reuses already-open web ports — the same candidate selection as
``fingerprint.py``. No new port scan, no extra GET that expands scope.

SAFETY: disabled by default (``screenshots.enabled = false``). Capped by
``max_targets`` / ``concurrency`` / ``timeout_seconds``. Findings live under
``screenshots/`` plus ``screenshots.json``. Capture needs Playwright; when it
is not installed the stage writes ``skipped_reason: playwright.unavailable``
and no pixels.

HONESTY: redaction covers *obvious form fields* (password, token, SSN,
card, OTP, …) by painting a black overlay on their bounding boxes in the
live DOM, then taking the screenshot. A name in a heading, a session token
in a URL bar we do not capture, or text that is not a form control is
**not** redacted. That is why retention and operator-only access exist —
the PNG can still hold personal data.

Unredacted bytes are never written to disk.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from pathlib import Path
from typing import Any, Callable

from .config_schema import ScreenshotConfig
from .fingerprint import _build_url, _candidate_endpoints
from .utils import save_json

LOG = logging.getLogger("shapoclyack.screenshots")

#: CSS selector for form controls we will black out before capture.
REDACT_SELECTOR = ",".join(
    (
        'input[type="password"]',
        'input[type="email"]',
        'input[autocomplete="current-password"]',
        'input[autocomplete="new-password"]',
        'input[autocomplete="cc-number"]',
        'input[autocomplete="cc-csc"]',
        'input[autocomplete="one-time-code"]',
        'input[name*="password" i]',
        'input[name*="passwd" i]',
        'input[name*="secret" i]',
        'input[name*="token" i]',
        'input[name*="ssn" i]',
        'input[name*="credit" i]',
        'input[id*="password" i]',
        'input[id*="token" i]',
    )
)

REDACT_SCRIPT = f"""() => {{
  const nodes = Array.from(document.querySelectorAll({REDACT_SELECTOR!r}));
  let covered = 0;
  for (const el of nodes) {{
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) continue;
    const cover = document.createElement("div");
    cover.setAttribute("data-shapoclyack-redact", "1");
    cover.style.cssText = [
      "position:fixed",
      "left:" + r.left + "px",
      "top:" + r.top + "px",
      "width:" + r.width + "px",
      "height:" + r.height + "px",
      "background:#000",
      "z-index:2147483647",
      "pointer-events:none",
    ].join(";");
    document.documentElement.appendChild(cover);
    if ("value" in el) try {{ el.value = ""; }} catch (e) {{}}
    covered += 1;
  }}
  return covered;
}}"""

CaptureFn = Callable[[str, float, bool], tuple[bytes, int]]


def screenshot_filename(host: str, port: int, scheme: str) -> str:
    material = f"{host}:{port}:{scheme}".encode("utf-8")
    return f"{hashlib.sha256(material).hexdigest()[:16]}.png"


def _playwright_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        return False
    return True


def _playwright_capture(url: str, timeout: float, verify_tls: bool) -> tuple[bytes, int]:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            page = browser.new_page(ignore_https_errors=not verify_tls, viewport={"width": 1280, "height": 720})
            page.goto(url, wait_until="domcontentloaded", timeout=int(timeout * 1000))
            redacted = int(page.evaluate(REDACT_SCRIPT) or 0)
            png = page.screenshot(full_page=False, type="png")
        finally:
            browser.close()
    return png, redacted


async def capture_screenshots(
    open_ports: list[str],
    config: ScreenshotConfig,
    output_dir: Path,
    *,
    capture: CaptureFn | None = None,
) -> dict[str, Any]:
    shot_dir = output_dir / "screenshots"
    result: dict[str, Any] = {
        "targets_considered": 0,
        "captured_count": 0,
        "redacted_fields": 0,
        "findings": [],
        "truncated": False,
        "skipped_reason": None,
    }
    if not config.enabled:
        result["skipped_reason"] = "screenshots.disabled"
        save_json(output_dir / "screenshots.json", result)
        return result

    capture_fn = capture or _playwright_capture
    if capture is None and not _playwright_available():
        result["skipped_reason"] = "playwright.unavailable"
        save_json(output_dir / "screenshots.json", result)
        return result

    candidates = _candidate_endpoints(
        open_ports, set(config.http_ports), set(config.https_ports)
    )
    result["targets_considered"] = len(candidates)
    if not candidates:
        result["skipped_reason"] = "no_web_ports"
        save_json(output_dir / "screenshots.json", result)
        return result

    truncated = len(candidates) > config.max_targets
    candidates = candidates[: config.max_targets]
    shot_dir.mkdir(parents=True, exist_ok=True)
    semaphore = asyncio.Semaphore(config.concurrency)
    timeout = float(config.timeout_seconds)

    async def _one(host: str, port: int, scheme: str) -> dict[str, Any]:
        url = _build_url(host, port, scheme)
        name = screenshot_filename(host, port, scheme)
        outcome: dict[str, Any] = {
            "host": host,
            "port": port,
            "scheme": scheme,
            "url": url,
            "file": f"screenshots/{name}",
            "redacted_fields": 0,
            "error": None,
        }
        async with semaphore:
            try:
                png, redacted = await asyncio.to_thread(
                    capture_fn, url, timeout, config.verify_tls
                )
            except Exception as exc:  # noqa: BLE001
                LOG.debug("screenshot failed for %s: %s", url, exc)
                outcome["error"] = "capture_failed"
                return outcome
        if not png:
            outcome["error"] = "empty_capture"
            return outcome
        (shot_dir / name).write_bytes(png)
        outcome["redacted_fields"] = int(redacted)
        return outcome

    findings = await asyncio.gather(*(_one(h, p, s) for h, p, s in candidates))
    result["findings"] = list(findings)
    result["captured_count"] = sum(1 for f in findings if not f["error"])
    result["redacted_fields"] = sum(int(f["redacted_fields"] or 0) for f in findings)
    result["truncated"] = truncated
    save_json(output_dir / "screenshots.json", result)
    LOG.info(
        "screenshots: %d endpoint(s) -> %d captured, %d field(s) redacted%s",
        len(findings),
        result["captured_count"],
        result["redacted_fields"],
        " [truncated]" if truncated else "",
    )
    return result


def capture_screenshots_sync(
    open_ports: list[str],
    config: ScreenshotConfig,
    output_dir: Path,
    *,
    capture: CaptureFn | None = None,
) -> dict[str, Any]:
    return asyncio.run(capture_screenshots(open_ports, config, output_dir, capture=capture))
