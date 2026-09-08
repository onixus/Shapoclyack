#!/usr/bin/env python3
"""Refresh one vendor advisory dataset from its upstream feed.

Requires network access and the opt-in flag: ``api/services/advisories/fetch.py``
refuses unless ``OCTO_ADVISORY_FETCH_ENABLED=true``, and the check lives there
rather than here so no caller can skip it.

This is a thin wrapper. Everything that decides *what* is fetched, *how* it is
normalized and *where* it is written is in the service module; the script's own
job is argument parsing, an exit code a caller can branch on, and one guard the
service deliberately does not have: a feed that answers with a *short* document
must not replace a dataset that has content. The download therefore lands on a
staging path next to the destination and is promoted only once it is big enough
to be real — the same shape as ``scripts/fetch-cvss4-db.py``'s refusal to
publish an empty rebuild over a populated database.

"Big enough" defaults to the same floor ``scripts/enrichment_manifest.py`` keeps
for the dataset, because that is already the number this project uses to tell a
corpus from a stub, and there is no reason for a second opinion. A floor of one
would only catch the literally empty document; a tracker answering 200 with a
truncated one normalizes to a dozen statements, clears it, and replaces four
hundred thousand.

Exit codes:

  0  the dataset was refreshed
  1  the fetch failed, or came back too small to publish; whatever was on disk
     is still there
  3  fetching is disabled (``OCTO_ADVISORY_FETCH_ENABLED`` unset). Kept distinct
     from a failure because "off by default" is not a broken feed.

``scripts/fetch-enrichment.sh`` branches on zero versus non-zero and never sees
3: it tests the same flag itself, before calling this, so that a run nobody
opted into is recorded as neither a refresh nor a failure rather than as one of
them. 3 is for a direct invocation — the by-hand form in docs/configuration.md.

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
# scripts/ goes on explicitly too: sys.path[0] carries it only when this file is
# the entry point, and it is also loaded by path from tests.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))
sys.path.insert(0, str(_HERE))

from api.services.advisories import fetch  # noqa: E402 - needs the path above

# The manifest module beside this one owns the per-dataset floors; see the
# module docstring for why this script does not keep a second opinion.
import enrichment_manifest  # noqa: E402 - needs the path above

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_DISABLED = 3

#: CLI dataset name → the key it is filed under in the manifest.
_MANIFEST_KEYS = {name: f"advisories_{name}" for name in fetch.SOURCES}


def default_min_entries(dataset: str) -> int:
    """The floor below which publishing ``dataset`` would overwrite a corpus.

    Straight out of ``enrichment_manifest._JSON_DATASETS`` so the number the
    fetch refuses at and the number the manifest reports ``usable`` against are
    one number. Falls back to 1 for a dataset the manifest does not track, which
    is the old behaviour and the most this script can say about a feed nothing
    has sized.
    """
    key = _MANIFEST_KEYS.get(dataset, "")
    record = enrichment_manifest._JSON_DATASETS.get(key)
    return record[1] if record else 1


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
        default=None,
        help="Refuse to publish a dataset with fewer entries than this (default: the "
        "dataset's floor in scripts/enrichment_manifest.py). A feed that answers 200 "
        "with an empty or truncated document is an outage, not a day with no advisories",
    )
    args = parser.parse_args()
    min_entries = args.min_entries if args.min_entries is not None else default_min_entries(args.dataset)

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

    if written < min_entries:
        staging.unlink(missing_ok=True)
        print(
            f"error: {args.dataset} normalized to {written} entries "
            f"(expected at least {min_entries}) — refusing to publish over {output}",
            file=sys.stderr,
        )
        return EXIT_FAILED

    output.parent.mkdir(parents=True, exist_ok=True)
    staging.replace(output)
    print(f"wrote {written} entries → {output}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
