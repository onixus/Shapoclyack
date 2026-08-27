#!/usr/bin/env python3
"""Build a local CVE → CVSS v4 JSON database from NVD API 2.0.

Requires network access. Optional NVD_API_KEY improves rate limits
(5 req/30s anonymous → 50 req/30s keyed) and is what makes --full practical.

Three modes:

  --full          Walk the entire NVD corpus and keep every CVE that carries a
                  genuine CVSS v4 metric. This is how the committed baseline
                  scanner/data/cvss4/cvss4.json is produced; it is slow (see
                  --sleep) and meant to be run rarely, by hand or in CI.
  --last-mod-days Incremental refresh: only CVEs modified in the last N days.
                  This is the daily-CronJob path (scripts/fetch-enrichment.sh).
  --cves          Explicit CVE list, for spot checks.

All modes MERGE into the existing output file — a CVE already in the database
is never dropped because a later run did not see it.

Usage:
  python3 scripts/fetch-cvss4-db.py --full -o scanner/data/cvss4/cvss4.json
  python3 scripts/fetch-cvss4-db.py --last-mod-days 8
  python3 scripts/fetch-cvss4-db.py --cves CVE-2021-44228,CVE-2014-0160

Note on filtering: NVD's own cvssV4Severity filter cannot be used to select
v4-scored CVEs — it reports a handful of results against a corpus where ~34% of
recent CVEs carry cvssMetricV40 — so --full pages through everything and
filters client-side via _extract_cvss4().
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from concurrent import futures
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Run as a script, sys.path[0] is scripts/ — not the repo root — so the scanner
# package sitting beside it is not importable and this file dies on the next
# line before parsing a single argument. Every documented invocation is
# `python3 scripts/fetch-cvss4-db.py …`, including the one in the image build,
# where the failure showed up only as "==> cvss4: FAILED (continuing)" and was
# read as one more casualty of the 403s (#246). Fix it here rather than asking
# each caller for a PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.pipeline.cvss4 import extract_nvd_cwes  # noqa: E402 - needs the path above

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD's documented maximum for the CVE API.
PAGE_SIZE = 2000

# NVD asks for >=6s between anonymous requests (5 req/30s) and tolerates ~0.6s
# with a key (50 req/30s). Both are padded slightly: a 429 costs far more than
# the padding does, and --full issues ~190 requests back to back.
SLEEP_ANONYMOUS = 6.5
SLEEP_KEYED = 0.8

# lastModStartDate/lastModEndDate ranges are capped at 120 days by the API.
MAX_LAST_MOD_DAYS = 120

# Concurrent pages when a key is present. Wall-clock is dominated by NVD's
# ~20s to render a 2000-CVE page rather than by the rate limit, so overlapping
# pages is the only real lever. Kept well below the 50-req/30s ceiling: at 8 in
# flight NVD stopped sending body bytes entirely after a few minutes (no 429 --
# it just throttles), so 4 trades some speed for a run that finishes.
WORKERS_KEYED = 4

# Per-operation socket timeout, and a hard ceiling on one full response body.
# Both are needed: the first catches a dead connection, the second catches a
# live one that has been throttled to a trickle. See _read_bounded().
SOCKET_TIMEOUT = 60
REQUEST_DEADLINE = 120.0


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _extract_cvss4(metrics: dict) -> dict | None:
    for key in ("cvssMetricV40", "cvssMetricV4", "cvssMetricV31", "cvssMetricV30"):
        rows = metrics.get(key) or []
        if not rows:
            continue
        primary = next((r for r in rows if r.get("type") == "Primary"), rows[0])
        data = primary.get("cvssData") or {}
        score = data.get("baseScore")
        if score is None:
            continue
        vector = data.get("vectorString") or ""
        version = str(data.get("version") or "")
        if not version.startswith("4") and key.startswith("cvssMetricV3"):
            # Prefer true v4; skip v3 when scanning for v4-only build unless no v4.
            continue
        return {
            "score": float(score),
            "vector": vector,
            "severity": _severity_from_score(float(score)),
            "version": version or ("4.0" if "V40" in key or "V4" in key else ""),
        }
    # Fallback: any *actual* v4 metric under a key we didn't already check above
    # (e.g. a future/alternate NVD key name). Do NOT fall back to v3.x here --
    # this database's "score"/"vector" are consumed downstream as genuine CVSS
    # v4 (scanner/pipeline/cvss4.py overrides "severity" from them), so a v3.x
    # score would be silently mislabeled as v4.
    for key, rows in metrics.items():
        if key in ("cvssMetricV40", "cvssMetricV4", "cvssMetricV31", "cvssMetricV30"):
            continue
        if not isinstance(rows, list) or not rows:
            continue
        data = (rows[0].get("cvssData") or {})
        score = data.get("baseScore")
        version = str(data.get("version") or "")
        if score is None or not version.startswith("4"):
            continue
        return {
            "score": float(score),
            "vector": data.get("vectorString") or "",
            "severity": _severity_from_score(float(score)),
            "version": version,
        }
    return None


def fetch_cve(cve_id: str, api_key: str | None, *, retries: int = 5) -> dict | None:
    params = urllib.parse.urlencode({"cveId": cve_id})
    req = urllib.request.Request(f"{NVD_URL}?{params}")
    req.add_header("User-Agent", "shapoclyack-cvss4-fetch/1.0")
    if api_key:
        req.add_header("apiKey", api_key)
    # NVD's anonymous rate limit is 5 req/30s (50/30s with an API key) -- a
    # 429 here isn't a permanent failure like a 404, so back off and retry
    # instead of dropping the CVE (this is what silently lost ~80% of a
    # 150-CVE batch before this fix).
    backoff = 8.0
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
                break
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt < retries:
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                delay = float(retry_after) if retry_after else backoff
                print(f"warn: {cve_id}: HTTP 429, retrying in {delay:.0f}s (attempt {attempt + 1}/{retries})",
                      file=sys.stderr)
                time.sleep(delay)
                backoff = min(backoff * 2, 60.0)
                continue
            print(f"warn: {cve_id}: HTTP {exc.code}", file=sys.stderr)
            return None
        except Exception as exc:  # noqa: BLE001
            print(f"warn: {cve_id}: {exc}", file=sys.stderr)
            return None
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        if str(cve.get("id", "")).upper() != cve_id.upper():
            continue
        entry = _extract_cvss4(cve.get("metrics") or {})
        if entry:
            cwes = extract_nvd_cwes(cve)
            if cwes:
                entry["cwe"] = cwes
            return entry
    return None


def _read_bounded(resp, max_seconds: float = REQUEST_DEADLINE) -> bytes:
    """Read a response body under a wall-clock deadline.

    A socket timeout is per-operation, so it cannot catch a server that trickles
    the body: every few bytes reset the clock and the read blocks forever while
    transferring nothing. NVD does exactly this when it decides to throttle a
    client — connections stay ESTABLISHED with byte counters frozen, no 429, no
    close — which once wedged this script for over an hour with no output. Bound
    the whole body instead, so a starved read fails, is retried on a fresh
    connection, and the run keeps moving.
    """
    deadline = time.monotonic() + max_seconds
    chunks: list[bytes] = []
    while True:
        chunk = resp.read(65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        if time.monotonic() > deadline:
            raise TimeoutError(
                f"response body exceeded {max_seconds:.0f}s "
                f"({sum(len(c) for c in chunks)} bytes read)"
            )


def _request_json(url: str, api_key: str | None, *, retries: int = 6) -> dict | None:
    """GET a NVD URL with the same 429/transient backoff fetch_cve() uses.

    Returns None once retries are exhausted so the caller can decide whether a
    partial result is still worth keeping.
    """
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "shapoclyack-cvss4-fetch/1.0")
    if api_key:
        req.add_header("apiKey", api_key)
    backoff = 8.0
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=SOCKET_TIMEOUT) as resp:
                return json.loads(_read_bounded(resp).decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # 503/504 show up during NVD maintenance windows and are as
            # retryable as 429 for our purposes.
            if exc.code in (429, 503, 504) and attempt < retries:
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                delay = float(retry_after) if retry_after else backoff
                print(f"warn: HTTP {exc.code}, retrying in {delay:.0f}s "
                      f"(attempt {attempt + 1}/{retries})", file=sys.stderr)
                time.sleep(delay)
                backoff = min(backoff * 2, 120.0)
                continue
            print(f"warn: HTTP {exc.code} for {url}", file=sys.stderr)
            return None
        except Exception as exc:  # noqa: BLE001
            if attempt < retries:
                print(f"warn: {exc}, retrying in {backoff:.0f}s "
                      f"(attempt {attempt + 1}/{retries})", file=sys.stderr)
                time.sleep(backoff)
                backoff = min(backoff * 2, 120.0)
                continue
            print(f"warn: {exc} for {url}", file=sys.stderr)
            return None
    return None


class _Pacer:
    """Global minimum spacing between request starts, shared across workers.

    Concurrency and rate limiting are independent knobs here: workers bound how
    many pages are in flight (NVD takes ~20s to render a 2000-CVE page, so the
    win is overlapping that latency), while this bounds how fast we may *start*
    requests. Without it, N workers would fire N requests at once on startup and
    trip the 50-req/30s ceiling regardless of how slow each one then is.
    """

    def __init__(self, min_interval: float) -> None:
        self._min_interval = max(0.0, min_interval)
        self._lock = threading.Lock()
        self._next_at = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delay = max(0.0, self._next_at - now)
            self._next_at = max(now, self._next_at) + self._min_interval
        if delay:
            time.sleep(delay)


def _scan_page(payload: dict) -> dict:
    entries: dict = {}
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cve_id = str(cve.get("id") or "").upper()
        if not cve_id:
            continue
        entry = _extract_cvss4(cve.get("metrics") or {})
        if entry:
            published = str(cve.get("published") or "").strip()
            if published:
                entry["published"] = published[:10]
            cwes = extract_nvd_cwes(cve)
            if cwes:
                entry["cwe"] = cwes
            entries[cve_id] = entry
    return entries


def harvest(
    base_params: dict,
    api_key: str | None,
    sleep_seconds: float,
    *,
    label: str,
    workers: int = 1,
) -> tuple[dict, bool]:
    """Page through a CVE query, keeping only CVEs that carry a real v4 metric.

    Returns (entries, complete). `complete` is False when any page failed, which
    the caller uses to refuse a destructive overwrite from partial data.
    """
    pacer = _Pacer(sleep_seconds)

    def fetch_at(start_index: int) -> dict | None:
        params = dict(base_params)
        params.update({"resultsPerPage": PAGE_SIZE, "startIndex": start_index})
        pacer.wait()
        return _request_json(f"{NVD_URL}?{urllib.parse.urlencode(params)}", api_key)

    # The first page is fetched alone: totalResults is what tells us how many
    # pages exist, and there is nothing to parallelise until we know that.
    first = fetch_at(0)
    if first is None:
        print(f"warn: {label}: first page failed, harvested nothing", file=sys.stderr)
        return {}, False

    total = int(first.get("totalResults") or 0)
    page_count = (total + PAGE_SIZE - 1) // PAGE_SIZE
    print(f"==> {label}: {total} CVEs to scan ({page_count} pages, "
          # flush: this runs for many minutes with stdout redirected to a log
          # or captured by kubectl, where block buffering would hide progress
          # until the very end and make a slow run look like a hung one.
          f"{workers} in flight)", flush=True)

    entries = _scan_page(first)
    complete = True
    done_pages = 1
    lock = threading.Lock()

    def run_page(start_index: int) -> tuple[dict | None, int]:
        return fetch_at(start_index), start_index

    offsets = [i * PAGE_SIZE for i in range(1, page_count)]
    if offsets:
        with futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            for payload, start_index in pool.map(run_page, offsets):
                with lock:
                    done_pages += 1
                    if payload is None:
                        print(f"warn: {label}: page at startIndex={start_index} "
                              f"failed after retries", file=sys.stderr)
                        complete = False
                        continue
                    entries.update(_scan_page(payload))
                    print(f"    {label}: {done_pages}/{page_count} pages, "
                          f"{len(entries)} with CVSS v4", flush=True)

    return entries, complete


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("scanner/data/cvss4/cvss4.json"),
        help="Output JSON path",
    )
    parser.add_argument(
        "--cves",
        default="",
        help="Comma-separated CVE list (default: refresh the existing keys)",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Rebuild from the entire NVD corpus (slow; produces the committed baseline)",
    )
    parser.add_argument(
        "--last-mod-days",
        type=int,
        default=0,
        help=f"Incremental: only CVEs modified in the last N days (max {MAX_LAST_MOD_DAYS})",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=None,
        help="Minimum spacing between request starts "
             "(default: 6.5s anonymous, 0.8s with NVD_API_KEY)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Pages to fetch concurrently (default: 4 with NVD_API_KEY, 1 without)",
    )
    parser.add_argument(
        "--seed",
        type=Path,
        default=None,
        help="Baseline database to union in for CVEs the output is missing",
    )
    args = parser.parse_args()

    api_key = os.environ.get("NVD_API_KEY")
    sleep_seconds = args.sleep if args.sleep is not None else (
        SLEEP_KEYED if api_key else SLEEP_ANONYMOUS
    )
    # Anonymous stays strictly serial: at 5 req/30s there is no headroom to
    # overlap anything, and concurrent workers would just race into 429s.
    workers = args.workers if args.workers is not None else (WORKERS_KEYED if api_key else 1)
    workers = max(1, workers)
    if not api_key:
        if args.workers is not None and args.workers > 1:
            print("note: ignoring --workers > 1 without NVD_API_KEY "
                  "(anonymous limit is 5 req/30s)", file=sys.stderr)
        workers = 1
        if args.full or args.last_mod_days:
            print("note: no NVD_API_KEY set — anonymous 5 req/30s, serial. A key "
                  "enables concurrent pages and cuts a --full run to minutes.",
                  file=sys.stderr)
    existing: dict = {}
    if args.output.exists():
        try:
            existing = json.loads(args.output.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = {}

    entries = dict(existing.get("entries") or {})
    before = len(entries)

    # Union in the image's committed baseline for anything the output lacks.
    # Without this a shipped baseline can never reach a volume that already has
    # a database on it: the seed "floor" in fetch-enrichment.sh only fires when
    # the file is absent, and an incremental run only adds recently-modified
    # CVEs. A cluster upgraded to an image with a larger baseline would keep its
    # old, smaller database forever. Existing entries win — they are at least as
    # fresh as the baked-in copy.
    if args.seed and args.seed != args.output:
        try:
            seed_doc = json.loads(args.seed.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"warn: could not read seed {args.seed}: {exc}", file=sys.stderr)
        else:
            added = 0
            for cve_id, entry in (seed_doc.get("entries") or {}).items():
                if cve_id not in entries:
                    entries[cve_id] = entry
                    added += 1
            if added:
                print(f"seeded {added} entries from baseline {args.seed}", flush=True)

    def _store(cve_id: str, entry: dict) -> None:
        entries[cve_id] = {
            "score": entry["score"],
            "vector": entry["vector"],
            "severity": entry["severity"],
        }
        if entry.get("version"):
            entries[cve_id]["version"] = entry["version"]
        if entry.get("published"):
            entries[cve_id]["published"] = entry["published"]
        if entry.get("cwe"):
            entries[cve_id]["cwe"] = entry["cwe"]

    if args.full or args.last_mod_days:
        if args.last_mod_days > MAX_LAST_MOD_DAYS:
            print(f"error: --last-mod-days cannot exceed {MAX_LAST_MOD_DAYS} "
                  f"(NVD API limit); use --full to rebuild", file=sys.stderr)
            return 2
        params: dict = {}
        label = "full"
        if args.last_mod_days:
            now = datetime.now(timezone.utc)
            start = now - timedelta(days=args.last_mod_days)
            fmt = "%Y-%m-%dT%H:%M:%S.000"
            params = {
                "lastModStartDate": start.strftime(fmt),
                "lastModEndDate": now.strftime(fmt),
            }
            label = f"last {args.last_mod_days}d"

        harvested, complete = harvest(
            params, api_key, sleep_seconds, label=label, workers=workers
        )

        # A full rebuild that came back empty means the run failed, not that NVD
        # dropped every v4 score overnight. Refuse to publish it over a database
        # that has content -- an empty cvss4.json silently disables v4 scoring
        # everywhere downstream, which is exactly the failure this guard exists
        # to stop from reaching the shared enrichment volume.
        if not harvested and before:
            print("error: harvested 0 entries but the existing database has "
                  f"{before} — refusing to overwrite it", file=sys.stderr)
            return 1
        if args.full and not complete:
            print("error: --full did not complete (a page failed after retries); "
                  "refusing to publish a partial rebuild", file=sys.stderr)
            return 1
        for cve_id, entry in harvested.items():
            _store(cve_id, entry)
    else:
        cve_ids = [c.strip().upper() for c in args.cves.split(",") if c.strip()]
        if not cve_ids:
            cve_ids = sorted(entries.keys())
        if not cve_ids:
            print("error: nothing to fetch — the database is empty and no --cves "
                  "given. Use --full to build it.", file=sys.stderr)
            return 2
        for cve_id in cve_ids:
            print(f"fetch {cve_id}…")
            entry = fetch_cve(cve_id, api_key)
            if entry:
                _store(cve_id, entry)
            time.sleep(max(0.0, sleep_seconds))

    out = {
        "version": "4.0",
        "source": "nvd-api-2.0",
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "entries": dict(sorted(entries.items())),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Write-then-rename: the daily CronJob rewrites this file on a volume the API
    # replicas poll by mtime, so a reader must never observe a half-written file.
    tmp = args.output.with_suffix(args.output.suffix + ".tmp")
    tmp.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    tmp.replace(args.output)
    print(f"wrote {len(entries)} entries (+{len(entries) - before}) → {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
