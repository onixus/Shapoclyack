"""Screenshot stage: already-open web ports, pixels from an isolated worker.

Capture is delegated to ``python -m scanner.screenshot_worker``. This module
does not import or launch Playwright. Published scanner images stay
browser-free; capture works only when ``SCREENSHOT_WORKER_URL`` answers and
``screenshots.enabled`` is true.

Reuses already-open web ports — the same candidate selection as
``fingerprint.py``. No new port scan, no extra GET that expands scope.

SAFETY: disabled by default (``screenshots.enabled = false``). Capped by
``max_targets`` / ``concurrency`` / ``timeout_seconds``. Findings live under
``screenshots/`` plus ``screenshots.json``. A missing, empty, or unreachable
worker writes ``skipped_reason: worker.unavailable`` and no pixels. A per-URL
failure stays ``error: capture_failed`` and does not fail the scan.

HONESTY: redaction covers *obvious form fields* (password, token, SSN,
card, OTP, …) by painting a black overlay on their bounding boxes in the
live DOM, then taking the screenshot. A name in a heading, a session token
in a URL bar we do not capture, or text that is not a form control is
**not** redacted. That is why retention and operator-only access exist —
the PNG can still hold personal data.

Unredacted bytes are never written to disk. The worker runs the same
``REDACT_SCRIPT`` before it returns pixels.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Callable
from urllib.error import URLError
from urllib.request import Request, urlopen

from .config_schema import ScreenshotConfig
from .fingerprint import _build_url, _candidate_endpoints
from .utils import save_json

LOG = logging.getLogger("shapoclyack.screenshots")

DEFAULT_WORKER_URL = "http://127.0.0.1:8077"
_WORKER_URL_ENV = "SCREENSHOT_WORKER_URL"
_CLIENT_GRACE_SECONDS = 5.0
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

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


def worker_url() -> str:
    """Configured worker base URL. Empty means no worker is configured."""
    return os.environ.get(_WORKER_URL_ENV, DEFAULT_WORKER_URL).strip()


def _decode_worker_png(payload: dict[str, Any]) -> tuple[bytes, int]:
    if payload.get("error"):
        raise RuntimeError("capture_failed")
    encoded = payload.get("png_base64")
    if not isinstance(encoded, str) or not encoded:
        raise RuntimeError("capture_failed")
    try:
        png = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("capture_failed") from exc
    if not png.startswith(PNG_MAGIC):
        raise RuntimeError("capture_failed")
    redacted = payload.get("redacted_fields", 0)
    if isinstance(redacted, bool) or not isinstance(redacted, int) or redacted < 0:
        raise RuntimeError("capture_failed")
    return png, redacted


def _worker_capture(url: str, timeout: float, verify_tls: bool) -> tuple[bytes, int]:
    """POST one URL to the isolated worker. Raises if it is unreachable.

    The client timeout is the capture timeout plus a small grace so the
    worker's own timeout wins and comes back as ``capture_failed``.
    """
    base = worker_url()
    if not base:
        raise ConnectionError("worker.unavailable")
    endpoint = base.rstrip("/") + "/capture"
    body = json.dumps(
        {"url": url, "timeout_seconds": timeout, "verify_tls": verify_tls},
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    client_timeout = float(timeout) + _CLIENT_GRACE_SECONDS
    try:
        with urlopen(request, timeout=client_timeout) as response:  # noqa: S310 - worker URL is operator config
            raw = response.read()
    except (URLError, TimeoutError, OSError) as exc:
        raise ConnectionError("worker.unavailable") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("capture_failed") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("capture_failed")
    return _decode_worker_png(payload)


def _worker_reachable(timeout: float) -> bool:
    """False when the URL is empty or ``/healthz`` does not answer 200."""
    base = worker_url()
    if not base:
        return False
    request = Request(base.rstrip("/") + "/healthz", method="GET")
    try:
        with urlopen(request, timeout=min(float(timeout), 5.0)) as response:  # noqa: S310
            if getattr(response, "status", 200) != 200:
                return False
            raw = response.read()
    except (URLError, TimeoutError, OSError, ValueError):
        return False
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(payload, dict) and payload.get("status") == "ok"


def _capture_hosts(address: str, hostnames: dict[str, Any] | None) -> list[str]:
    """Names to open for one address.

    A bare IP is what the port list carries, but a name-based site answers
    ``ERR_SSL_PROTOCOL_ERROR`` (or the wrong vhost) when Chromium dials the
    address. Prefer the forward names this run already resolved. Never PTR:
    a reverse name is not evidence the service is that host. Cap the list so
    one address with many names cannot spend the whole ``max_targets`` budget.
    """
    entry = (hostnames or {}).get(address)
    forward = entry.get("forward") if isinstance(entry, dict) else None
    names: list[str] = []
    if isinstance(forward, list):
        for raw in forward:
            name = str(raw).strip().rstrip(".").lower()
            if name and name not in names:
                names.append(name)
            if len(names) == 4:
                break
    return names or [address]


async def capture_screenshots(
    open_ports: list[str],
    config: ScreenshotConfig,
    output_dir: Path,
    *,
    capture: CaptureFn | None = None,
    hostnames: dict[str, Any] | None = None,
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

    capture_fn = capture if capture is not None else _worker_capture
    if capture is None and not await asyncio.to_thread(
        _worker_reachable, float(config.timeout_seconds)
    ):
        result["skipped_reason"] = "worker.unavailable"
        save_json(output_dir / "screenshots.json", result)
        return result

    candidates = [
        (name, port, scheme, address)
        for address, port, scheme in _candidate_endpoints(
            open_ports, set(config.http_ports), set(config.https_ports)
        )
        for name in _capture_hosts(address, hostnames)
    ]
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
    worker_down = False

    async def _one(host: str, port: int, scheme: str, address: str) -> dict[str, Any]:
        nonlocal worker_down
        url = _build_url(host, port, scheme)
        name = screenshot_filename(host, port, scheme)
        outcome: dict[str, Any] = {
            "host": host,
            "address": address,
            "port": port,
            "scheme": scheme,
            "url": url,
            "file": f"screenshots/{name}",
            "redacted_fields": 0,
            "error": None,
        }
        if worker_down:
            outcome["error"] = "capture_failed"
            return outcome
        async with semaphore:
            if worker_down:
                outcome["error"] = "capture_failed"
                return outcome
            try:
                png, redacted = await asyncio.to_thread(
                    capture_fn, url, timeout, config.verify_tls
                )
            except ConnectionError:
                LOG.debug("screenshot worker unavailable for %s", url)
                worker_down = True
                outcome["error"] = "capture_failed"
                return outcome
            except Exception as exc:  # noqa: BLE001
                LOG.debug("screenshot failed for %s: %s", url, exc)
                outcome["error"] = "capture_failed"
                return outcome
        if not png or not png.startswith(PNG_MAGIC):
            outcome["error"] = "empty_capture" if not png else "capture_failed"
            return outcome
        (shot_dir / name).write_bytes(png)
        outcome["redacted_fields"] = int(redacted)
        return outcome

    findings = await asyncio.gather(*(_one(h, p, s, a) for h, p, s, a in candidates))
    if (
        capture is None
        and findings
        and all(f["error"] == "capture_failed" for f in findings)
        and worker_down
    ):
        # Health passed, then every capture lost the worker: no pixels, skip.
        result["skipped_reason"] = "worker.unavailable"
        result["findings"] = []
        result["targets_considered"] = len(candidates)
        save_json(output_dir / "screenshots.json", result)
        return result
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
    hostnames: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return asyncio.run(
        capture_screenshots(
            open_ports, config, output_dir, capture=capture, hostnames=hostnames
        )
    )
