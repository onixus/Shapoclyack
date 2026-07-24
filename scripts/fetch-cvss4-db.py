#!/usr/bin/env python3
"""Build a local CVE → CVSS v4 JSON database from NVD API 2.0.

Requires network access. Optional NVD_API_KEY improves rate limits.

Usage:
  python3 scripts/fetch-cvss4-db.py -o scanner/data/cvss4/cvss4.json
  python3 scripts/fetch-cvss4-db.py --cves CVE-2021-44228,CVE-2014-0160
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


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
    # Fallback: any metric with a base score
    for key, rows in metrics.items():
        if not isinstance(rows, list) or not rows:
            continue
        data = (rows[0].get("cvssData") or {})
        score = data.get("baseScore")
        if score is None:
            continue
        return {
            "score": float(score),
            "vector": data.get("vectorString") or "",
            "severity": _severity_from_score(float(score)),
            "version": str(data.get("version") or ""),
        }
    return None


def fetch_cve(cve_id: str, api_key: str | None, *, retries: int = 5) -> dict | None:
    params = urllib.parse.urlencode({"cveId": cve_id})
    req = urllib.request.Request(f"{NVD_URL}?{params}")
    req.add_header("User-Agent", "octo-man-cvss4-fetch/1.0")
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
            return entry
    return None


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
        help="Comma-separated CVE list (default: merge into existing seed keys)",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.7,
        help="Delay between NVD requests (seconds)",
    )
    args = parser.parse_args()

    api_key = os.environ.get("NVD_API_KEY")
    existing: dict = {}
    if args.output.exists():
        try:
            existing = json.loads(args.output.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = {}

    entries = dict(existing.get("entries") or {})
    if args.cves.strip():
        cve_ids = [c.strip().upper() for c in args.cves.split(",") if c.strip()]
    else:
        cve_ids = sorted(entries.keys()) or [
            "CVE-2014-0160",
            "CVE-2017-0144",
            "CVE-2019-0708",
            "CVE-2021-44228",
            "CVE-2023-44487",
            "CVE-2024-3094",
        ]

    for cve_id in cve_ids:
        print(f"fetch {cve_id}…")
        entry = fetch_cve(cve_id, api_key)
        if entry:
            entries[cve_id] = {
                "score": entry["score"],
                "vector": entry["vector"],
                "severity": entry["severity"],
            }
            if entry.get("version"):
                entries[cve_id]["version"] = entry["version"]
        time.sleep(max(0.0, args.sleep))

    out = {
        "version": "4.0",
        "source": "nvd-api-2.0",
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "entries": dict(sorted(entries.items())),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(entries)} entries → {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
