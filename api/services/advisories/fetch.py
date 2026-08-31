"""Opt-in, bounded refresh of the advisory datasets. **Off by default.**

Nothing on a request path ever calls into this module. The API reads whatever
JSON is on disk (``api/services/advisories/base.py``); this is the separate step
that puts it there, and it exists so an operator who *can* reach the internet
has a supported way to refresh without hand-assembling the file.

Three properties, all of them deliberate:

* **Opt-in.** ``OCTO_ADVISORY_FETCH_ENABLED`` defaults to false and
  :func:`refresh` refuses without it. An installation that never sets it never
  makes an outbound connection because of this feature.
* **Bounded.** Every request has a connect/read timeout and a hard byte ceiling,
  enforced while streaming rather than after: the Debian tracker JSON is tens of
  megabytes and a hostile or broken origin must not be able to fill the disk or
  hang a process.
* **Atomic.** The dataset is written to a temporary file and renamed, the same
  way ``scripts/fetch-cvss4-db.py`` does, because the API polls the directory
  and must never parse a half-written file.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable

from api.services.advisories import debian, ubuntu

LOG = logging.getLogger("shapoclyack.advisories.fetch")

DEBIAN_TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
UBUNTU_USN_URL = "https://usn.ubuntu.com/usn-db/database.json"

#: Ceiling on a single download. The Debian tracker JSON is ~50 MB uncompressed.
DEFAULT_MAX_BYTES = 128 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 60.0

#: dataset name → (url, normalizer, default output path, source label).
SOURCES: dict[str, tuple[str, Callable[[Any], Iterable[dict[str, Any]]], str, str]] = {
    "debian": (
        DEBIAN_TRACKER_URL,
        debian.normalize_tracker_json,
        debian.DebianAdvisoryProvider.default_path,
        debian.DebianAdvisoryProvider.name,
    ),
    "ubuntu": (
        UBUNTU_USN_URL,
        ubuntu.normalize_usn_json,
        ubuntu.UbuntuAdvisoryProvider.default_path,
        ubuntu.UbuntuAdvisoryProvider.name,
    ),
}


class FetchDisabledError(RuntimeError):
    """``refresh()`` was called without the opt-in flag set."""


class FetchTooLargeError(RuntimeError):
    """The response exceeded the byte ceiling and was abandoned mid-stream."""


def fetch_enabled() -> bool:
    return os.environ.get("OCTO_ADVISORY_FETCH_ENABLED", "false").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def fetch_json(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = DEFAULT_MAX_BYTES,
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> Any:
    """GET ``url`` and parse it as JSON, refusing to read past ``max_bytes``.

    ``opener`` is injectable so the bound can be tested without a network.
    """
    request = urllib.request.Request(url, headers={"User-Agent": "shapoclyack-advisories"})
    chunks: list[bytes] = []
    total = 0
    with opener(request, timeout=timeout) as response:  # noqa: S310 - https URLs from SOURCES
        while True:
            chunk = response.read(1024 * 256)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise FetchTooLargeError(
                    f"{url} exceeded the {max_bytes} byte ceiling; aborted"
                )
            chunks.append(chunk)
    return json.loads(b"".join(chunks).decode("utf-8"))


def build_dataset(
    entries: Iterable[dict[str, Any]], *, source: str, origin_url: str
) -> dict[str, Any]:
    """Wrap normalized entries in the same envelope every overlay uses."""
    return {
        "version": 1,
        "source": source,
        "origin_url": origin_url,
        "updated": datetime.now(UTC).date().isoformat(),
        "entries": list(entries),
    }


def write_dataset(path: Path, dataset: dict[str, Any]) -> int:
    """Write-then-rename, so a reader never sees a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(dataset, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    tmp.replace(path)
    return len(dataset.get("entries") or ())


def refresh(
    name: str,
    *,
    path: Path | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = DEFAULT_MAX_BYTES,
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> int:
    """Download, normalize and write one advisory dataset. Returns the entry count.

    Refuses unless ``OCTO_ADVISORY_FETCH_ENABLED`` is set — the flag is checked
    here rather than at the call site so no future caller can skip it.
    """
    if not fetch_enabled():
        raise FetchDisabledError(
            "advisory fetching is off by default; set OCTO_ADVISORY_FETCH_ENABLED=true to allow it"
        )
    if name not in SOURCES:
        raise ValueError(f"unknown advisory dataset: {name!r} (known: {sorted(SOURCES)})")
    url, normalize, default_path, source = SOURCES[name]
    payload = fetch_json(url, timeout=timeout, max_bytes=max_bytes, opener=opener)
    dataset = build_dataset(normalize(payload), source=source, origin_url=url)
    written = write_dataset(Path(path) if path else Path(default_path), dataset)
    LOG.info("advisories: refreshed %s (%d entries) from %s", name, written, url)
    return written
