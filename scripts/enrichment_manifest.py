#!/usr/bin/env python3
"""Record what each enrichment dataset in a data directory actually holds.

``scripts/fetch-enrichment.sh`` keeps going when a third-party feed is down —
that is deliberate, a foreign server having a bad day must not fail a build.
The defect that motivated this module (#246) is that the resulting image was
then indistinguishable from one built with fresh data: the fetches printed
``FAILED (continuing)``, the build stayed green, and nothing downstream could
tell a freshly-pulled EPSS corpus from the committed baseline.

So every refresh writes a manifest next to the data recording, per dataset,
where it came from, what date the feed itself stamped on it, and how many
entries it has. ``GET /api/system`` reads it back
(``api/services/system_status.py``), which is what makes the difference visible
from outside the image instead of only in a build log nobody reads.

The same pass answers the build's other question: is this dataset *usable*, or
is it a demo stub? "Source unreachable" is a warning — the previous data is
still in place and still good. "No usable data" is a different failure, and it
is the one that must stop a release image from shipping (see ``verdict()``).

Usage::

    python3 scripts/enrichment_manifest.py --dir scanner/data
    python3 scripts/enrichment_manifest.py --dir /data --refreshed epss,kev
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

# Datasets the risk model reads, with the path each one lives at under the
# enrichment directory and the floor that separates a real corpus from the
# handful-of-CVEs demo stub this repo used to ship.
#
# The floors are deliberately an order of magnitude below the real feeds
# (EPSS ~365k, KEV ~1.7k, CVSS4 ~32k, exploit ~26k as of 2026-08): they are
# there to catch "this is a placeholder", not to police day-to-day drift, which
# is what ``stale``/``age_days`` in the system status already covers.
_JSON_DATASETS: dict[str, tuple[str, int]] = {
    "cvss4": ("cvss4/cvss4.json", 1000),
    "epss": ("epss/epss-overlay.json", 1000),
    "kev": ("kev/kev-overlay.json", 100),
    "exploit": ("exploit/exploit-overlay.json", 1000),
}

# Vendor advisory datasets for software→CVE matching (ROADMAP Track E M1).
# Same JSON envelope and the same provenance question as the overlays above, but
# **not required**: the image ships a committed seed of a few dozen real
# advisories, not a feed dump, so a floor in the thousands would fail every
# build. An installation that wants real coverage refreshes them with the
# opt-in fetcher (api/services/advisories/fetch.py) — see
# docs/software-cve-matching.md.
_OPTIONAL_JSON_DATASETS: dict[str, tuple[str, int]] = {
    "advisories_debian": ("advisories/debian-advisories.json", 1),
    "advisories_ubuntu": ("advisories/ubuntu-advisories.json", 1),
}

# GeoIP/ASN are MaxMind-format .mmdb blobs, not JSON overlays: there is no
# redistributable seed for them (see fetch-enrichment.sh's header), so they are
# reported but never required — an image without them behaves exactly like one
# with no database configured, which is a supported configuration.
_BINARY_DATASETS: dict[str, str] = {
    "geoip": "geoip/geoip.mmdb",
    "asn": "asn/asn.mmdb",
}

MANIFEST_NAME = "enrichment-manifest.json"

# Exit codes, consumed by fetch-enrichment.sh and in turn by the Dockerfiles.
EXIT_OK = 0
EXIT_DEGRADED = 1  # a source was unreachable; existing data is still usable
EXIT_NO_DATA = 2  # a required dataset is missing or is a stub


def _count_entries(payload: object) -> int | None:
    """Number of CVEs in an overlay, across the two shapes we publish.

    KEV is a list of ids, EPSS/CVSS4/exploit are id → value maps. Anything else
    is a file we do not recognise, which is reported as ``None`` rather than
    guessed at.
    """
    if not isinstance(payload, dict):
        return None
    entries = payload.get("entries")
    if isinstance(entries, (dict, list)):
        return len(entries)
    return None


def inspect_json_dataset(path: Path, min_entries: int) -> dict:
    """Provenance and usability of one JSON overlay.

    Unreadable and unparsable are kept distinct from absent in ``error`` — an
    operator debugging a mounted volume needs to know which of the three it is
    — but all three land on ``usable: False`` the same way.
    """
    record: dict = {
        "present": False,
        "usable": False,
        "source": None,
        "updated": None,
        "entries": None,
        "min_entries": min_entries,
        "error": None,
    }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        record["error"] = "missing"
        return record
    except OSError as exc:
        record["error"] = f"unreadable: {exc}"
        return record
    except json.JSONDecodeError as exc:
        record["present"] = True
        record["error"] = f"invalid JSON: {exc}"
        return record

    record["present"] = True
    if isinstance(payload, dict):
        record["source"] = payload.get("source") or None
        record["updated"] = str(payload.get("updated") or "") or None
    count = _count_entries(payload)
    record["entries"] = count
    if count is None:
        record["error"] = "no entries map"
    elif count < min_entries:
        record["error"] = f"only {count} entries (expected at least {min_entries})"
    else:
        record["usable"] = True
    return record


def inspect_binary_dataset(path: Path, source: str | None) -> dict:
    """Presence of one .mmdb database. Never required — see _BINARY_DATASETS."""
    try:
        size = path.stat().st_size
    except OSError:
        return {"present": False, "usable": False, "source": source, "size_bytes": None}
    return {"present": True, "usable": size > 0, "source": source, "size_bytes": size}


def build_manifest(
    data_dir: Path,
    *,
    refreshed: set[str],
    failed: set[str],
    sources: dict[str, str] | None = None,
) -> dict:
    """Inspect every dataset under ``data_dir`` and describe what is there.

    ``refreshed``/``failed`` come from the fetch run that just happened, which
    is the only place that knows whether a file is the feed's current content or
    whatever was left behind — the bytes on disk look identical either way.
    ``origin`` is the field that carries that distinction outward.
    """
    sources = sources or {}
    datasets: dict[str, dict] = {}
    for name, (relative, min_entries) in _JSON_DATASETS.items():
        record = inspect_json_dataset(data_dir / relative, min_entries)
        record["required"] = True
        record["path"] = str(data_dir / relative)
        datasets[name] = record
    for name, (relative, min_entries) in _OPTIONAL_JSON_DATASETS.items():
        record = inspect_json_dataset(data_dir / relative, min_entries)
        record["required"] = False
        record["path"] = str(data_dir / relative)
        datasets[name] = record
    for name, relative in _BINARY_DATASETS.items():
        record = inspect_binary_dataset(data_dir / relative, sources.get(name))
        record["required"] = False
        record["path"] = str(data_dir / relative)
        datasets[name] = record

    for name, record in datasets.items():
        if sources.get(name):
            record["source"] = sources[name]
        if name in refreshed:
            record["origin"] = "fetch"
        elif name in failed:
            # The fetch was attempted and failed, so whatever is on disk is the
            # seed or the last good refresh — precisely the case the build log
            # used to swallow.
            record["origin"] = "stale" if record["present"] else "missing"
        else:
            record["origin"] = "seed" if record["present"] else "missing"

    # An absent advisory dataset is a supported configuration, not a degraded
    # build: the matcher answers "unknown" without one, which is the honest
    # result, and no seed for it existed before Track E. A *failed refresh* of
    # one still degrades, because that is the case #246 exists to make visible.
    for name in _OPTIONAL_JSON_DATASETS:
        record = datasets.get(name) or {}
        if record.get("origin") == "missing":
            record["degrades"] = False

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "datasets": datasets,
    }


def verdict(manifest: dict) -> int:
    """Exit code for a manifest: ok, degraded, or no-data.

    The three-way split is the whole point of #246. A build may legitimately
    ship data it could not refresh today; it may not ship data that is not
    there at all.
    """
    datasets = manifest.get("datasets") or {}
    if any(rec.get("required") and not rec.get("usable") for rec in datasets.values()):
        return EXIT_NO_DATA
    if any(
        rec.get("origin") in ("stale", "missing") and rec.get("degrades", True)
        for rec in datasets.values()
    ):
        return EXIT_DEGRADED
    return EXIT_OK


def _summarize(manifest: dict) -> list[str]:
    lines = []
    for name, record in sorted((manifest.get("datasets") or {}).items()):
        detail = record.get("error") or ""
        entries = record.get("entries")
        if entries is not None:
            detail = detail or f"{entries} entries"
        parts = [f"origin={record.get('origin')}"]
        if record.get("source"):
            parts.append(f"source={record['source']}")
        if record.get("updated"):
            parts.append(f"updated={record['updated']}")
        if detail:
            parts.append(detail)
        lines.append(f"    {name}: {', '.join(parts)}")
    return lines


def _split(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", type=Path, default=Path("scanner/data"), help="Enrichment data directory")
    parser.add_argument("--refreshed", default="", help="Comma-separated datasets this run fetched successfully")
    parser.add_argument("--failed", default="", help="Comma-separated datasets whose fetch failed")
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="NAME=LABEL",
        help="Override the recorded source label for a dataset (repeatable)",
    )
    args = parser.parse_args()

    sources: dict[str, str] = {}
    for item in args.source:
        name, _, label = item.partition("=")
        if name.strip() and label.strip():
            sources[name.strip()] = label.strip()

    manifest = build_manifest(
        args.dir,
        refreshed=_split(args.refreshed),
        failed=_split(args.failed),
        sources=sources,
    )
    out = args.dir / MANIFEST_NAME
    out.parent.mkdir(parents=True, exist_ok=True)
    # Write-then-rename, like fetch-cvss4-db.py: the API polls this directory
    # and must never read a half-written manifest.
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(out)

    print(f"==> enrichment manifest → {out}")
    for line in _summarize(manifest):
        print(line)
    return verdict(manifest)


if __name__ == "__main__":
    raise SystemExit(main())
