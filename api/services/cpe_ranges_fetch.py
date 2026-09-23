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


class FetchDisabledError(RuntimeError):
    """A harvest was attempted without the opt-in flag."""


def fetch_enabled() -> bool:
    return os.environ.get("OCTO_NVD_CPE_FETCH_ENABLED", "false").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


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
    return {
        "version": 1,
        "source": cpe_ranges.SOURCE,
        "origin_url": NVD_URL,
        "updated": datetime.now(UTC).date().isoformat(),
        "parts": sorted({key.split(":", 1)[0] for key in entries}) or list(DEFAULT_PARTS),
        "cves": {cve: cves[cve] for cve in sorted(cves) if cve in referenced},
        "entries": {key: entries[key] for key in sorted(entries)},
    }


# --------------------------------------------------------------------------
# The network half
# --------------------------------------------------------------------------


def _fetch_page(
    params: dict[str, Any],
    *,
    api_key: str | None,
    timeout: float,
    opener: Callable[..., Any] | None,
    retries: int,
) -> dict[str, Any] | None:
    url = f"{NVD_URL}?{urllib.parse.urlencode(params)}"
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
            LOG.warning("nvd-cpe: HTTP %s for %s", exc.code, url)
            return None
        except (OSError, ValueError, advisory_fetch.FetchTooLargeError) as exc:
            if attempt < retries:
                LOG.warning("nvd-cpe: %s, retrying in %.0fs", exc, backoff)
                time.sleep(backoff)
                backoff = min(backoff * 2, 120.0)
                continue
            LOG.warning("nvd-cpe: giving up on %s: %s", url, exc)
            return None
        return payload if isinstance(payload, dict) else None
    return None


def harvest(
    *,
    last_mod_days: int | None = None,
    parts: Iterable[str] = DEFAULT_PARTS,
    api_key: str | None = None,
    sleep_seconds: float | None = None,
    timeout: float = advisory_fetch.DEFAULT_TIMEOUT_SECONDS,
    opener: Callable[..., Any] | None = None,
    retries: int = 5,
    now: datetime | None = None,
) -> Harvest:
    """Page through NVD. ``last_mod_days`` None is the whole corpus.

    Serial on purpose: the anonymous limit leaves no room to overlap requests,
    and with a key a daily incremental is a handful of pages. A page that fails
    after its retries marks the harvest incomplete; the caller decides whether
    to publish (``scripts/fetch-nvd-cpe.py`` does not).
    """
    if not fetch_enabled():
        raise FetchDisabledError(
            "NVD CPE fetching is off by default; set OCTO_NVD_CPE_FETCH_ENABLED=true to allow it"
        )
    parts = tuple(parts)
    if sleep_seconds is None:
        sleep_seconds = SLEEP_KEYED if api_key else SLEEP_ANONYMOUS
    base: dict[str, Any] = {"resultsPerPage": PAGE_SIZE}
    if last_mod_days:
        if last_mod_days > MAX_LAST_MOD_DAYS:
            raise ValueError(f"last_mod_days cannot exceed {MAX_LAST_MOD_DAYS} (NVD API limit)")
        end = now or datetime.now(UTC)
        start = end - timedelta(days=last_mod_days)
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        base.update({"lastModStartDate": start.strftime(fmt), "lastModEndDate": end.strftime(fmt)})

    result = Harvest()
    start_index = 0
    total: int | None = None
    while total is None or start_index < total:
        if start_index:
            time.sleep(max(0.0, sleep_seconds))
        payload = _fetch_page(
            {**base, "startIndex": start_index},
            api_key=api_key,
            timeout=timeout,
            opener=opener,
            retries=retries,
        )
        if payload is None:
            result.complete = False
            break
        if total is None:
            total = int(payload.get("totalResults") or 0)
            LOG.info("nvd-cpe: %d CVEs to read (%d pages)", total, -(-total // PAGE_SIZE))
        result.add_page(payload, parts=parts)
        returned = len(payload.get("vulnerabilities") or [])
        if not returned:
            break
        start_index += returned
    return result


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
