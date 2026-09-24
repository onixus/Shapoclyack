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

Every upstream URL can be pointed at a mirror (#339): ``DEBIAN_TRACKER_URL``,
``UBUNTU_USN_URL`` and ``MSRC_CVRF_BASE_URL`` here, ``NVD_API_URL`` in
``api/services/cpe_ranges_fetch.py``. The names are the ones the feed scripts
read (``scripts/feed_fetch.py``), because an operator sets them once for the
refresh job and expects every fetcher to follow. docs/air-gap.md has the table.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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


#: dataset name → the variable that points it at a mirror (#339).
URL_VARIABLES: dict[str, str] = {
    "debian": "DEBIAN_TRACKER_URL",
    "ubuntu": "UBUNTU_USN_URL",
}

#: Schemes a feed URL may use; ``file`` is a mirror mounted into the pod. The
#: same list as ``scripts/feed_fetch.py``.
ALLOWED_SCHEMES = ("https", "http", "file")

#: Query parameters whose values are credentials (see ``redact_url``). The same
#: pattern as ``scripts/feed_fetch.py`` — tests/test_air_gap_feeds.py holds the
#: two together, because a URL one of them prints and the other redacts is a
#: licence key in a log.
_SECRET_PARAM = re.compile(r"key|token|secret|passw|signature|sig$|auth", re.IGNORECASE)


class FetchDisabledError(RuntimeError):
    """``refresh()`` was called without the opt-in flag set."""


class FeedURLError(ValueError):
    """A mirror override names a URL no fetcher here may open."""


def redact_url(url: str) -> str:
    """``url`` with userinfo dropped and credential query values blanked.

    What goes into a log line and into a dataset's ``origin_url``: a mirror URL
    can carry basic-auth credentials, and a MaxMind one carries a licence key.
    """
    parts = urlsplit((url or "").strip())
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = f"{host}:{port}" if port else host
    query = urlencode(
        [
            (name, "REDACTED" if _SECRET_PARAM.search(name) else value)
            for name, value in parse_qsl(parts.query, keep_blank_values=True)
        ]
    )
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def feed_url(variable: str, default: str) -> str:
    """``$variable`` when set, else ``default``; refused if not http(s)/file.

    Read at call time rather than import, so a process that was started before
    the operator pointed it at a mirror still honours the mirror on its next
    refresh.
    """
    raw = os.environ.get(variable, "").strip()
    url = raw or default
    scheme = urlsplit(url).scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise FeedURLError(
            f"{variable}={redact_url(url)}: unsupported scheme {scheme or '(none)'!r}; "
            f"a feed URL must be one of {', '.join(ALLOWED_SCHEMES)}"
        )
    return url


def source_url(name: str) -> str:
    """Where ``refresh(name)`` downloads from: the mirror if one is set."""
    return feed_url(URL_VARIABLES[name], SOURCES[name][0])


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
                    f"{redact_url(url)} exceeded the {max_bytes} byte ceiling; aborted"
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
    _, normalize, default_path, source = SOURCES[name]
    url = source_url(name)
    payload = fetch_json(url, timeout=timeout, max_bytes=max_bytes, opener=opener)
    dataset = build_dataset(normalize(payload), source=source, origin_url=redact_url(url))
    written = write_dataset(Path(path) if path else Path(default_path), dataset)
    LOG.info("advisories: refreshed %s (%d entries) from %s", name, written, redact_url(url))
    return written


#: The Security Update Guide's CVRF API. The index lists one document per month
#: and names each by an absolute URL under this base.
MSRC_API_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"
MSRC_INDEX_URL = f"{MSRC_API_BASE}/updates"
#: Mirror override (#339): a base URL, not the index, because the documents the
#: index lists live under it too — see ``msrc_document_url``.
MSRC_BASE_URL_VARIABLE = "MSRC_CVRF_BASE_URL"


def msrc_base_url() -> str:
    """The CVRF API base this run reads: the mirror if one is set."""
    return feed_url(MSRC_BASE_URL_VARIABLE, MSRC_API_BASE).rstrip("/")


def msrc_document_url(listed: str, base: str) -> str | None:
    """Where to fetch a month the index lists as ``listed``, or ``None``.

    The index names every document by an absolute ``api.msrc.microsoft.com``
    URL, so a mirror of the index alone would still send twelve requests a run
    to Microsoft. With a mirror configured, a document under the upstream base
    is read from the same path under the mirror, one already under the mirror
    is read as is, and anything else is skipped rather than fetched: an
    air-gapped refresh must not reach for a host the operator never named.
    """
    if base == MSRC_API_BASE:
        return listed
    if listed.startswith(f"{MSRC_API_BASE}/"):
        return f"{base}{listed[len(MSRC_API_BASE):]}"
    if listed.startswith(f"{base}/"):
        return listed
    return None

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

    base = msrc_base_url()
    index_url = f"{base}/updates"
    index = fetch_json(
        index_url,
        timeout=timeout,
        max_bytes=DEFAULT_MAX_BYTES,
        opener=opener,
        headers=MSRC_HEADERS,
    )
    documents = index.get("value") if isinstance(index, dict) else index
    if not isinstance(documents, list) or not documents:
        raise RuntimeError(f"{redact_url(index_url)} listed no documents")

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
        url = msrc_document_url(str(doc["CvrfUrl"]), base)
        if url is None:
            LOG.warning(
                "msrc: skipping %s: not under the configured mirror %s",
                redact_url(str(doc["CvrfUrl"])),
                redact_url(base),
            )
            continue
        try:
            payload = fetch_json(
                url,
                timeout=timeout,
                max_bytes=max_bytes,
                opener=opener,
                headers=MSRC_HEADERS,
            )
        except Exception as exc:  # noqa: BLE001 - one bad month must not cost the rest
            LOG.warning("msrc: skipping %s: %s", redact_url(url), exc)
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
        origin_url=redact_url(index_url),
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
