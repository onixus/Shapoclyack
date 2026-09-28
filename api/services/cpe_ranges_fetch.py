"""Opt-in, bounded refresh of the NVD CPE-range dataset. **Off by default.**

Nothing on a request path calls into this module; the API reads whatever file
is on disk (``api/services/cpe_ranges.py``). This is the step that writes it,
from the NVD CVE API 2.0, for an installation that can reach the internet and
has said so — the same three properties as ``advisories/fetch.py``:

* **Opt-in.** ``OCTO_NVD_CPE_FETCH_ENABLED`` defaults to false and
  :func:`harvest` refuses without it; the check is here so no caller can skip
  it.
* **Bounded.** Every page is read through ``advisories.fetch.fetch_json``, with
  a socket timeout and a byte ceiling enforced while streaming. Requests are
  paced to NVD's published limits — 5 per 30 s anonymous, 50 with
  ``NVD_API_KEY`` — and a 429/503 backs off instead of failing the run.
* **Atomic.** The dataset is written to a temporary file and renamed
  (``advisories.fetch.write_dataset``); the API polls by mtime and must never
  parse half a file.

**What is kept from a CVE.** Every ``cpeMatch`` with ``vulnerable: true`` whose
criteria is an application (part ``a``; ``o``/``h`` on request), reduced to a
product key and a version window. A criteria that names a version is an exact
statement; one with ``*`` needs at least one ``versionStart*``/``versionEnd*``
bound, and without one it is dropped — "every version" is not something a
banner can be matched against honestly. The configuration's AND/OR structure is
not kept: a node that says "this application, *running on* Windows" becomes a
statement about the application alone. That over-reports on the platform side
and is written down in docs/retro-cve-matching.md.

**Full and incremental.** A full harvest pages the whole corpus (~250k CVEs;
minutes with a key, hours without) and replaces the dataset. An incremental one
asks for CVEs modified in the last N days (at most 120, NVD's own cap) and
merges them: every statement of a harvested CVE is replaced by what NVD says now,
so a narrowed range narrows here too, and every other CVE is left alone.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterable

from api.services import cpe_ranges
from api.services.advisories import fetch as advisory_fetch
from api.services.retro_match import parse_cpe

LOG = logging.getLogger("shapoclyack.cpe-ranges.fetch")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
#: Mirror override (#339). The same variable scripts/fetch-cvss4-db.py reads:
#: both talk to the CVE API 2.0, and a mirror of it serves both.
NVD_URL_VARIABLE = "NVD_API_URL"
#: NVD's documented maximum page for the CVE API.
PAGE_SIZE = 2000
#: A 2000-CVE page with configurations is ~15-30 MB of JSON.
PAGE_MAX_BYTES = 64 * 1024 * 1024
#: Spacing between request starts: NVD asks for 6 s anonymous, 0.6 s keyed.
SLEEP_ANONYMOUS = 6.5
SLEEP_KEYED = 0.8
#: ``lastModStartDate``/``lastModEndDate`` windows are capped at 120 days.
MAX_LAST_MOD_DAYS = 120
DEFAULT_PARTS = ("a",)
_RETRYABLE = (429, 503, 504)
_ORDER = ("cve", *cpe_ranges.RANGE_KEYS)


class FetchDisabledError(RuntimeError):
    """A harvest was attempted without the opt-in flag."""


def fetch_enabled() -> bool:
    return os.environ.get("OCTO_NVD_CPE_FETCH_ENABLED", "false").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def nvd_url() -> str:
    """The CVE API endpoint a harvest reads: ``$NVD_API_URL`` or NVD itself."""
    return advisory_fetch.feed_url(NVD_URL_VARIABLE, NVD_URL)


# --------------------------------------------------------------------------
# Normalisation — pure, and what the tests pin
# --------------------------------------------------------------------------


def _severity_and_score(metrics: dict[str, Any]) -> tuple[str | None, float | None]:
    """NVD's primary base score: v3.1, then v3.0, then v4.0, then v2."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if not rows:
            continue
        primary = next((r for r in rows if r.get("type") == "Primary"), rows[0])
        data = primary.get("cvssData") or {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or primary.get("baseSeverity")
        if score is None:
            continue
        return (str(severity).strip().lower() if severity else None), float(score)
    return None, None


def normalize_cve(item: dict[str, Any], *, parts: Iterable[str] = DEFAULT_PARTS) -> tuple[
    str, dict[str, Any], list[tuple[str, dict[str, str]]]
] | None:
    """One ``vulnerabilities[]`` element → ``(cve, info, [(product key, statement)])``."""
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict):
        return None
    cve_id = str(cve.get("id") or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return None
    if str(cve.get("vulnStatus") or "").strip().lower() == "rejected":
        return cve_id, {}, []
    wanted = set(parts)
    statements: list[tuple[str, dict[str, str]]] = []
    seen: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
    for configuration in cve.get("configurations") or []:
        for node in (configuration or {}).get("nodes") or []:
            for cpe_match in (node or {}).get("cpeMatch") or []:
                if not isinstance(cpe_match, dict) or not cpe_match.get("vulnerable"):
                    continue
                parsed = parse_cpe(str(cpe_match.get("criteria") or ""))
                if parsed is None:
                    continue
                key, version = parsed
                if key.split(":", 1)[0] not in wanted:
                    continue
                statement: dict[str, str] = {"cve": cve_id}
                if version:
                    statement["v"] = version
                else:
                    for short, name in (
                        ("si", "versionStartIncluding"),
                        ("se", "versionStartExcluding"),
                        ("ei", "versionEndIncluding"),
                        ("ee", "versionEndExcluding"),
                    ):
                        value = str(cpe_match.get(name) or "").strip()
                        if value:
                            statement[short] = value
                    if len(statement) == 1:
                        # "*" with no bound: every version. Dropped — see the
                        # module docstring.
                        continue
                identity = (key, tuple(sorted(statement.items())))
                if identity in seen:
                    continue
                seen.add(identity)
                statements.append((key, statement))
    severity, score = _severity_and_score(cve.get("metrics") or {})
    info: dict[str, Any] = {}
    if score is not None:
        info["cvss"] = score
    if severity:
        info["severity"] = severity
    published = str(cve.get("published") or "").strip()
    if published:
        info["published"] = published[:10]
    return cve_id, info, statements


@dataclass
class Harvest:
    """What one harvest collected, keyed by CVE so a merge can replace a CVE whole."""

    statements: dict[str, list[tuple[str, dict[str, str]]]] = field(default_factory=dict)
    info: dict[str, dict[str, Any]] = field(default_factory=dict)
    complete: bool = True
    pages: int = 0
    #: The last modification time this harvest vouches for (see :func:`harvest`).
    covered_until: datetime | None = None
    #: Where the pages came from, redacted — NVD or the mirror in ``NVD_API_URL``.
    origin_url: str = NVD_URL

    def add_page(self, payload: dict[str, Any], *, parts: Iterable[str]) -> None:
        for item in payload.get("vulnerabilities") or []:
            normalized = normalize_cve(item, parts=parts)
            if normalized is None:
                continue
            cve_id, info, statements = normalized
            self.statements[cve_id] = statements
            if info:
                self.info[cve_id] = info
        self.pages += 1


def merge(existing: dict[str, Any] | None, harvest: Harvest, *, replace: bool) -> dict[str, Any]:
    """The new dataset: ``harvest`` over ``existing`` (or alone, with ``replace``).

    Per CVE, not per statement: every statement a harvested CVE had is dropped
    and its new ones added, so NVD narrowing a range (it does, when a vendor
    corrects an advisory) narrows it here. A rejected CVE harvests no
    statements and so disappears.
    """
    entries: dict[str, list[dict[str, str]]] = {}
    cves: dict[str, dict[str, Any]] = {}
    if existing and not replace:
        for key, statements in (existing.get("entries") or {}).items():
            kept = [s for s in statements if isinstance(s, dict) and s.get("cve") not in harvest.statements]
            if kept:
                entries[key] = kept
        cves = {
            cve: info
            for cve, info in (existing.get("cves") or {}).items()
            if cve not in harvest.statements
        }
    for cve_id, statements in harvest.statements.items():
        for key, statement in statements:
            entries.setdefault(key, []).append(statement)
        if statements and cve_id in harvest.info:
            cves[cve_id] = harvest.info[cve_id]
    referenced = {s["cve"] for statements in entries.values() for s in statements}
    # What the file can vouch for, not when it was written: a merge that ran
    # today over an eight-day window after a month offline must not read as
    # fresh (the next increment starts from here, see increment_window).
    covered = harvest.covered_until or datetime.now(UTC)
    return {
        "version": 1,
        "source": cpe_ranges.SOURCE,
        "origin_url": harvest.origin_url,
        "updated": covered.date().isoformat(),
        "covered_until": covered.astimezone(UTC).isoformat(timespec="seconds"),
        "parts": sorted({key.split(":", 1)[0] for key in entries}) or list(DEFAULT_PARTS),
        "cves": {cve: cves[cve] for cve in sorted(cves) if cve in referenced},
        # Sorted within each product too, so the file is the same bytes for the
        # same content whatever order the harvest arrived in.
        "entries": {
            key: sorted(entries[key], key=lambda s: tuple(str(s.get(k) or "") for k in _ORDER))
            for key in sorted(entries)
        },
    }


# --------------------------------------------------------------------------
# The network half
# --------------------------------------------------------------------------


def _fetch_page(
    params: dict[str, Any],
    *,
    base_url: str,
    api_key: str | None,
    timeout: float,
    opener: Callable[..., Any] | None,
    retries: int,
) -> dict[str, Any] | None:
    url = f"{base_url}?{urllib.parse.urlencode(params)}"
    shown = advisory_fetch.redact_url(url)
    headers = {"apiKey": api_key} if api_key else None
    backoff = 8.0
    for attempt in range(retries + 1):
        try:
            payload = advisory_fetch.fetch_json(
                url, timeout=timeout, max_bytes=PAGE_MAX_BYTES, opener=opener, headers=headers
            )
        except urllib.error.HTTPError as exc:
            if exc.code in _RETRYABLE and attempt < retries:
                LOG.warning("nvd-cpe: HTTP %s, retrying in %.0fs", exc.code, backoff)
                time.sleep(backoff)
                backoff = min(backoff * 2, 120.0)
                continue
            LOG.warning("nvd-cpe: HTTP %s for %s", exc.code, shown)
            return None
        except (OSError, ValueError, advisory_fetch.FetchTooLargeError) as exc:
            if attempt < retries:
                LOG.warning("nvd-cpe: %s, retrying in %.0fs", exc, backoff)
                time.sleep(backoff)
                backoff = min(backoff * 2, 120.0)
                continue
            LOG.warning("nvd-cpe: giving up on %s: %s", shown, exc)
            return None
        return payload if isinstance(payload, dict) else None
    return None


def harvest(
    *,
    window: tuple[datetime, datetime] | None = None,
    parts: Iterable[str] = DEFAULT_PARTS,
    api_key: str | None = None,
    sleep_seconds: float | None = None,
    timeout: float = advisory_fetch.DEFAULT_TIMEOUT_SECONDS,
    opener: Callable[..., Any] | None = None,
    retries: int = 5,
    now: datetime | None = None,
) -> Harvest:
    """Page through NVD: CVEs last modified inside ``window``, or all of them.

    Serial on purpose: the anonymous limit leaves no room to overlap requests,
    and with a key a daily incremental is a handful of pages. The harvest is
    marked incomplete — and ``scripts/fetch-nvd-cpe.py`` then refuses to
    publish it — whenever what came back cannot be the whole answer:

    * a page failed after its retries;
    * a page carried no ``totalResults`` (an error body with a 200);
    * a page answered for a different ``startIndex`` than was asked;
    * a page came back empty while ``totalResults`` says there is more.

    ``covered_until`` is what the result can vouch for: the window's end, or
    for a full harvest the moment it started (a CVE modified while the pages
    were being read may be on a page already passed; the next increment,
    which starts there, catches it).
    """
    if not fetch_enabled():
        raise FetchDisabledError(
            "NVD CPE fetching is off by default; set OCTO_NVD_CPE_FETCH_ENABLED=true to allow it"
        )
    parts = tuple(parts)
    # Resolved once, before the first request: a mistyped mirror is a
    # configuration error, and the retry loop below would back off from it
    # for minutes instead of saying so.
    base_url = nvd_url()
    if api_key and urllib.parse.urlsplit(base_url).scheme != "https":
        # The key is a credential; a plain-http mirror would carry it in the
        # clear. Anonymous and slower beats disclosed (review of #339).
        LOG.warning(
            "nvd-cpe: NVD_API_KEY not sent to %s: not https", advisory_fetch.redact_url(base_url)
        )
        api_key = None
    if sleep_seconds is None:
        sleep_seconds = SLEEP_KEYED if api_key else SLEEP_ANONYMOUS
    base: dict[str, Any] = {"resultsPerPage": PAGE_SIZE}
    started = now or datetime.now(UTC)
    result = Harvest(covered_until=started, origin_url=advisory_fetch.redact_url(base_url))
    if window is not None:
        start, end = window
        if end - start > timedelta(days=MAX_LAST_MOD_DAYS):
            raise ValueError(
                f"a lastMod window cannot exceed {MAX_LAST_MOD_DAYS} days (NVD API limit)"
            )
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        base.update({"lastModStartDate": start.strftime(fmt), "lastModEndDate": end.strftime(fmt)})
        result.covered_until = end

    start_index = 0
    total: int | None = None
    while total is None or start_index < total:
        if start_index:
            time.sleep(max(0.0, sleep_seconds))
        payload = _fetch_page(
            {**base, "startIndex": start_index},
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            opener=opener,
            retries=retries,
        )
        if payload is None or "totalResults" not in payload:
            result.complete = False
            break
        echoed = payload.get("startIndex")
        if echoed is not None and int(echoed) != start_index:
            LOG.warning("nvd-cpe: asked for startIndex %d, got %s", start_index, echoed)
            result.complete = False
            break
        if total is None:
            total = int(payload.get("totalResults") or 0)
            LOG.info("nvd-cpe: %d CVEs to read (%d pages)", total, -(-total // PAGE_SIZE))
        result.add_page(payload, parts=parts)
        returned = len(payload.get("vulnerabilities") or [])
        if not returned:
            if start_index < total:
                # An empty page before the end is an outage, not the end: the
                # CVEs on the pages not read would be missing from a dataset
                # that says it is complete.
                LOG.warning(
                    "nvd-cpe: empty page at startIndex %d of %d; harvest incomplete",
                    start_index,
                    total,
                )
                result.complete = False
            break
        start_index += returned
    return result


#: Overlap with the previous window, so a CVE modified in the last minutes
#: before the previous run's end is not lost to clock skew or NVD's indexing lag.
WINDOW_OVERLAP = timedelta(days=1)


class WindowError(ValueError):
    """No incremental window can be honest: the caller must run ``--full``."""


def covered_until(existing: dict[str, Any] | None) -> datetime | None:
    """How far an existing dataset's NVD content reaches.

    ``covered_until`` when a harvest wrote it; else ``updated`` (a seed or an
    older file) read as the start of that day, which errs towards fetching
    more rather than less.
    """
    if not existing:
        return None
    for key in ("covered_until", "updated"):
        value = str(existing.get(key) or "").strip()
        if not value:
            continue
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def increment_window(
    existing: dict[str, Any] | None,
    *,
    now: datetime,
    last_mod_days: int | None = None,
) -> tuple[datetime, datetime]:
    """The ``lastMod`` window that continues ``existing`` without a hole.

    From where the file's coverage ends (less :data:`WINDOW_OVERLAP`) to now.
    A fixed eight-day window lost everything NVD changed while the job was
    down longer than that, and stamped the result as today's. Refuses when
    no window can close the gap: nothing to continue, or more than NVD's
    120-day limit behind. ``last_mod_days`` asks for an explicit window and is
    refused if it would start after the coverage ends.
    """
    reach = covered_until(existing)
    if reach is None:
        raise WindowError("there is no dataset to continue; run --full to build one")
    start = reach - WINDOW_OVERLAP
    if last_mod_days is not None:
        asked = now - timedelta(days=last_mod_days)
        if asked > start:
            raise WindowError(
                f"--last-mod-days {last_mod_days} starts at {asked:%Y-%m-%d}, after the dataset's "
                f"coverage ends ({reach:%Y-%m-%d}); the CVEs modified in between would be lost. "
                "Omit it to continue from the coverage, or run --full"
            )
        start = asked
    if now - start > timedelta(days=MAX_LAST_MOD_DAYS):
        raise WindowError(
            f"the dataset's coverage ends {reach:%Y-%m-%d}, more than {MAX_LAST_MOD_DAYS} days ago "
            "(NVD's limit for one lastMod window); run --full to rebuild it"
        )
    return start, now


def load_existing(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def write_dataset(path: Path, dataset: dict[str, Any]) -> int:
    """Write-then-rename; returns the product count the manifest floors on."""
    advisory_fetch.write_dataset(path, dataset)
    return len(dataset.get("entries") or {})
