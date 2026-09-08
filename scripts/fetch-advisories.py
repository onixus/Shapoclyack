#!/usr/bin/env python3
"""Refresh one vendor advisory dataset from its upstream feed.

Requires network access and the opt-in flag: ``api/services/advisories/fetch.py``
refuses unless ``OCTO_ADVISORY_FETCH_ENABLED=true``, and the check lives there
rather than here so no caller can skip it.

This is a thin wrapper. Everything that decides *what* is fetched, *how* it is
normalized and *where* it is written is in the service module; the script's own
job is argument parsing, an exit code a shell can branch on, and one guard the
service deliberately does not have: a feed that answers with an empty document
must not replace a dataset that has content. The download therefore lands on a
staging path next to the destination and is promoted only once it is big enough
to be real — the same shape as ``scripts/fetch-cvss4-db.py``'s refusal to
publish an empty rebuild over a populated database.

Exit codes (``scripts/fetch-enrichment.sh`` reads them):

  0  the dataset was refreshed
  1  the fetch failed, or came back too small to publish; whatever was on disk
     is still there
  3  fetching is disabled (``OCTO_ADVISORY_FETCH_ENABLED`` unset). Kept distinct
     from a failure because "off by default" is not a broken feed.

Usage:
  python3 scripts/fetch-advisories.py debian
  python3 scripts/fetch-advisories.py ubuntu -o /data/advisories/ubuntu-advisories.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Run as a script, sys.path[0] is scripts/ — not the repo root — so `api` beside
# it is not importable. Same fix, and the same reason, as fetch-cvss4-db.py.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.services.advisories import fetch  # noqa: E402 - needs the path above

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_DISABLED = 3


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("dataset", choices=sorted(fetch.SOURCES), help="Which vendor feed to refresh")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Destination file (default: the provider's own path under scanner/data/advisories/)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=fetch.DEFAULT_TIMEOUT_SECONDS,
        help=f"Per-operation socket timeout in seconds (default {fetch.DEFAULT_TIMEOUT_SECONDS:g})",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=fetch.DEFAULT_MAX_BYTES,
        help="Hard ceiling on the download, enforced while streaming "
        f"(default {fetch.DEFAULT_MAX_BYTES})",
    )
    parser.add_argument(
        "--min-entries",
        type=int,
        default=1,
        help="Refuse to publish a dataset with fewer entries than this (default 1). "
        "A feed that answers 200 with an empty document is an outage, not a day "
        "with no advisories",
    )
    args = parser.parse_args()

    url, _, default_path, _ = fetch.SOURCES[args.dataset]
    output = args.output or Path(default_path)
    # Staged beside the destination so the promotion below is a rename on the
    # same filesystem, and so a failed run leaves the live dataset untouched.
    staging = output.with_suffix(output.suffix + ".fetch")

    print(f"==> {args.dataset}: {url}", flush=True)
    try:
        written = fetch.refresh(
            args.dataset, path=staging, timeout=args.timeout, max_bytes=args.max_bytes
        )
    except fetch.FetchDisabledError as exc:
        print(f"skipped: {exc}", file=sys.stderr)
        return EXIT_DISABLED
    # urllib's URLError/HTTPError are OSError subclasses, so the network,
    # the disk and a feed that is not JSON all land here — every one of them
    # leaves the live dataset alone, which is the only behaviour a caller cares about.
    except (fetch.FetchTooLargeError, OSError, json.JSONDecodeError) as exc:
        staging.unlink(missing_ok=True)
        print(f"error: {args.dataset} fetch failed: {exc}", file=sys.stderr)
        return EXIT_FAILED

    if written < args.min_entries:
        staging.unlink(missing_ok=True)
        print(
            f"error: {args.dataset} normalized to {written} entries "
            f"(expected at least {args.min_entries}) — refusing to publish over {output}",
            file=sys.stderr,
        )
        return EXIT_FAILED

    output.parent.mkdir(parents=True, exist_ok=True)
    staging.replace(output)
    print(f"wrote {written} entries → {output}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
