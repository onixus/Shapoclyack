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

from api.services import egress
from api.services.advisories import debian, msrc, ubuntu

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
    opener: Callable[..., Any] | None = None,
    headers: dict[str, str] | None = None,
) -> Any:
    """GET ``url`` and parse it as JSON, refusing to read past ``max_bytes``.

    ``opener`` is injectable so the bound can be tested without a network.
    Unset, it is this installation's egress opener — advisory feeds are the one
    egress path that always goes to the public internet, so behind a corporate
    proxy they are the first thing to stop working (#359).
    """
    if opener is None:
        opener = egress.build_opener(url).open
    # `Accept` matters for at least one feed: Microsoft's Security Update Guide
    # serves CVRF as XML unless JSON is asked for, and the parse failure that
    # follows reads as "the feed is broken" rather than "we asked for the wrong
    # representation".
    request_headers = {"User-Agent": "shapoclyack-advisories"}
    request_headers.update(headers or {})
    request = urllib.request.Request(url, headers=request_headers)
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
    opener: Callable[..., Any] | None = None,
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


MSRC_INDEX_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"

#: How many monthly CVRF documents to merge by default.
#:
#: Windows servicing is cumulative, so one month's remediations already describe
#: the state of a fully patched host — but only for the builds that month
#: shipped a fix for. A host on a build whose last fix was two months ago has no
#: statement at all in the newest document and would match as "unknown build".
#: Twelve months covers a year of service and is about eighty thousand
#: statements: enough that a host which has not been patched in a year still has
#: something said about it, and small enough to ship in the image.
MSRC_DEFAULT_MONTHS = 12

#: A CVRF month is ~16 MB of JSON.
MSRC_MAX_BYTES = 64 * 1024 * 1024

#: The Update Guide serves CVRF as XML by default. Without this the download
#: succeeds and the parse fails, which reads as a broken feed.
MSRC_HEADERS = {"Accept": "application/json"}


def refresh_msrc(
    *,
    path: Path | None = None,
    months: int = MSRC_DEFAULT_MONTHS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = MSRC_MAX_BYTES,
    opener: Callable[..., Any] | None = None,
) -> int:
    """Merge the last ``months`` Security Update Guide documents into one dataset.

    Not part of :data:`SOURCES` because it is not the same shape: the others are
    one URL and one normalizer, and this is an index followed by a document per
    month. Bending it into that table would mean either a fake URL or a
    normalizer that fetches, and a normalizer that opens sockets is exactly what
    the separation in this module exists to prevent.

    Newest first, and a month that fails is skipped rather than failing the run:
    a single 500 from the index's oldest entry must not cost eleven good months.
    A run that recovers *nothing* still raises, because writing an empty dataset
    over a populated one would turn every Windows host clean.
    """
    if not fetch_enabled():
        raise FetchDisabledError(
            "advisory fetching is off by default; set OCTO_ADVISORY_FETCH_ENABLED=true to allow it"
        )

    index = fetch_json(
        MSRC_INDEX_URL,
        timeout=timeout,
        max_bytes=DEFAULT_MAX_BYTES,
        opener=opener,
        headers=MSRC_HEADERS,
    )
    documents = index.get("value") if isinstance(index, dict) else index
    if not isinstance(documents, list) or not documents:
        raise RuntimeError(f"{MSRC_INDEX_URL} listed no documents")

    # Sorted by release date, not taken from the end of the list: the index is
    # not in chronological order -- September's document was listed after
    # May's, whose CurrentReleaseDate is later still -- so "the last twelve
    # entries" is not "the last twelve months".
    usable = [doc for doc in documents if isinstance(doc, dict) and doc.get("CvrfUrl")]
    usable.sort(key=lambda doc: str(doc.get("InitialReleaseDate") or ""))
    wanted = usable[-max(1, months):]

    entries: dict[tuple[str, str, str], dict[str, Any]] = {}
    recovered = 0
    for doc in reversed(wanted):
        url = str(doc["CvrfUrl"])
        try:
            payload = fetch_json(
                url,
                timeout=timeout,
                max_bytes=max_bytes,
                opener=opener,
                headers=MSRC_HEADERS,
            )
        except Exception as exc:  # noqa: BLE001 - one bad month must not cost the rest
            LOG.warning("msrc: skipping %s: %s", url, exc)
            continue
        recovered += 1
        for entry in msrc.normalize_cvrf(payload):
            # Newest month wins on a collision: Microsoft re-publishes a
            # remediation when it revises one, and the later document is the
            # current statement.
            entries.setdefault(
                (entry["cve_id"], entry["fixed_build"], entry["kb"]), entry
            )

    if recovered == 0:
        raise RuntimeError("no Security Update Guide document could be fetched")

    dataset = build_dataset(
        sorted(entries.values(), key=lambda e: (e["cve_id"], e["fixed_build"])),
        source=msrc.PROVIDER_NAME,
        origin_url=MSRC_INDEX_URL,
    )
    written = write_dataset(
        Path(path) if path else Path(msrc.DEFAULT_DATASET), dataset
    )
    LOG.info(
        "advisories: refreshed msrc (%d statements from %d of %d months)",
        written,
        recovered,
        len(wanted),
    )
    return written
