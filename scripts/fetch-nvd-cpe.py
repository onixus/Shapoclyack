#!/usr/bin/env python3
"""Refresh the NVD CPE-range dataset behind retro CVE matching.

Requires network access and the opt-in flag: ``api/services/cpe_ranges_fetch.py``
refuses unless ``OCTO_NVD_CPE_FETCH_ENABLED=true``, and the check lives there so
no caller can skip it. ``NVD_API_KEY`` is optional and turns a full harvest from
hours into minutes (5 → 50 requests per 30 s). See docs/retro-cve-matching.md.

Two modes:

  --full           Page the whole NVD corpus and *replace* the dataset. Slow,
                   meant to be run by hand once (and after a long outage), like
                   ``fetch-cvss4-db.py --full``. Refused unless the result
                   clears the dataset's floor in scripts/enrichment_manifest.py.
  --last-mod-days  Incremental (the default, 8 days): CVEs NVD modified in the
                   window, *merged* into the existing file. This is what
                   scripts/fetch-enrichment.sh runs daily. Refused if the
                   existing file is there but unreadable — merging a week of
                   NVD over nothing would publish it as the whole dataset.

Either way the download lands on a staging path beside the destination and is
promoted by a rename only once it passes, and a harvest with a failed page is
never published.

Exit codes (the same contract as fetch-advisories.py):

  0  the dataset was refreshed
  1  the fetch failed or the result was refused; whatever was on disk is intact
  3  fetching is disabled (``OCTO_NVD_CPE_FETCH_ENABLED`` unset)

Usage:
  OCTO_NVD_CPE_FETCH_ENABLED=true python3 scripts/fetch-nvd-cpe.py --full
  OCTO_NVD_CPE_FETCH_ENABLED=true python3 scripts/fetch-nvd-cpe.py --last-mod-days 8 \\
      -o /data/nvd-cpe/nvd-cpe-ranges.json
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Run as a script, sys.path[0] is scripts/ — not the repo root. Same fix, and
# the same reason, as fetch-advisories.py.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))
sys.path.insert(0, str(_HERE))

from api.services import cpe_ranges, cpe_ranges_fetch  # noqa: E402 - needs the path above

# The manifest owns the floor, so the number this refuses at and the number
# GET /api/system reports ``usable`` against are one number.
import enrichment_manifest  # noqa: E402 - needs the path above

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_DISABLED = 3

MANIFEST_KEY = "nvd_cpe"


def default_floor() -> int:
    record = enrichment_manifest._JSON_DATASETS.get(MANIFEST_KEY)
    return record[1] if record else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--full", action="store_true", help="Harvest the whole corpus and replace the dataset")
    mode.add_argument(
        "--last-mod-days",
        type=int,
        default=8,
        help=f"Incremental window in days (default 8, max {cpe_ranges_fetch.MAX_LAST_MOD_DAYS})",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path(cpe_ranges.DEFAULT_PATH),
        help=f"Destination file (default {cpe_ranges.DEFAULT_PATH})",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=None,
        help="Spacing between requests (default 6.5s anonymous, 0.8s with NVD_API_KEY)",
    )
    parser.add_argument(
        "--min-products",
        type=int,
        default=None,
        help="--full only: refuse a result with fewer products than this "
        "(default: the dataset's floor in scripts/enrichment_manifest.py)",
    )
    args = parser.parse_args()

    # Applications only: the matcher never reads an o/h statement (a service's
    # platform CPE is the host, not the listener — see retro_match.product_keys),
    # and the operating-system half of NVD would double the file for nothing.
    parts = cpe_ranges_fetch.DEFAULT_PARTS
    output: Path = args.output
    staging = output.with_suffix(output.suffix + ".fetch")
    api_key = os.environ.get("NVD_API_KEY") or None
    existing = None if args.full else cpe_ranges_fetch.load_existing(output)
    if not args.full and existing is None and output.exists():
        # An incremental merge over a file it could not read would publish
        # eight days of NVD as the whole dataset.
        print(f"error: {output} exists but is not readable JSON; refusing to merge over it "
              "(run --full to rebuild it)", file=sys.stderr)
        return EXIT_FAILED
    before = len((existing or {}).get("entries") or {})

    label = "full" if args.full else f"last {args.last_mod_days}d"
    print(f"==> nvd-cpe ({label}, parts={','.join(parts)}, key={'yes' if api_key else 'no'})", flush=True)
    try:
        harvest = cpe_ranges_fetch.harvest(
            last_mod_days=None if args.full else args.last_mod_days,
            parts=parts,
            api_key=api_key,
            sleep_seconds=args.sleep,
        )
    except cpe_ranges_fetch.FetchDisabledError as exc:
        print(f"skipped: {exc}", file=sys.stderr)
        return EXIT_DISABLED
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILED

    if not harvest.complete:
        print(
            f"error: a page failed after retries ({harvest.pages} read); refusing to publish "
            f"a partial harvest over {output}",
            file=sys.stderr,
        )
        return EXIT_FAILED

    dataset = cpe_ranges_fetch.merge(existing, harvest, replace=args.full)
    products = len(dataset["entries"])
    if args.full:
        floor = args.min_products if args.min_products is not None else default_floor()
        if products < floor:
            print(
                f"error: full harvest produced {products} products (expected at least {floor}) "
                f"— refusing to publish over {output}",
                file=sys.stderr,
            )
            return EXIT_FAILED

    try:
        cpe_ranges_fetch.write_dataset(staging, dataset)
        staging.replace(output)
    except OSError as exc:
        staging.unlink(missing_ok=True)
        print(f"error: could not write {output}: {exc}", file=sys.stderr)
        return EXIT_FAILED
    statements = sum(len(v) for v in dataset["entries"].values())
    print(
        f"wrote {products} products / {statements} statements "
        f"({len(harvest.statements)} CVEs harvested, {products - before:+d} products) → {output}"
    )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
