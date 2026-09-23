#!/usr/bin/env python3
"""Launch the image's bundled Chromium and prove it can emit a PNG.

This is intentionally network-free. Docker builds execute it after switching to
the final non-root runtime user, which catches a browser downloaded into root's
private cache, missing shared libraries, and unreadable executable bits before
an operator enables the screenshot stage in production.
"""

from __future__ import annotations

from playwright.sync_api import sync_playwright

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def main() -> int:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": 320, "height": 180})
            page.set_content(
                "<!doctype html><title>Shapoclyack browser smoke</title>"
                "<main><h1>browser ready</h1></main>",
                wait_until="domcontentloaded",
            )
            png = page.screenshot(type="png", full_page=False)
        finally:
            browser.close()

    if not png.startswith(PNG_SIGNATURE):
        raise RuntimeError("Playwright returned a non-PNG screenshot")
    print(f"playwright chromium: OK ({len(png)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
