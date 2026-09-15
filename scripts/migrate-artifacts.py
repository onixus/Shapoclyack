#!/usr/bin/env python3
"""Copy scan artifacts from the filesystem into the configured artifact store (#336).

Run once, when an installation moves from ``OCTO_ARTIFACT_BACKEND=local`` to
``s3``. Everything an existing installation holds on its volume is walked and
uploaded under the same keys new artifacts get: run directories, generated
reports and the input files of jobs that have not finished. Materialised
wordlists are not copied -- they are a pod-local scratch copy of a row the
database already holds, and nothing would ever read the copy in the bucket.

    OCTO_ARTIFACT_BACKEND=s3 OCTO_ARTIFACT_S3_BUCKET=... \\
      python3 scripts/migrate-artifacts.py --output-dir scanner/output \\
                                           --state-dir scanner/state

Deliberately conservative about the source:

* Nothing is deleted. The volume is the only copy until the migration is
  verified, and the operator removes it themselves afterwards (``--summary``
  says how much is there). A migration that tidied up after itself would make
  "did everything arrive?" unanswerable at the exact moment it matters.
* An object that is already in the store is left alone unless ``--overwrite``
  is given, so the script is safe to re-run after an interruption and safe to
  run against a store that is already taking new artifacts.
* ``--dry-run`` reports what would move without touching anything.

Ordering: run this **before** pointing the API at the new backend if the
installation can be stopped, or after if it cannot -- the store is additive, so
a run written by the new API while this is walking an old directory is not
disturbed. What must not happen is deleting the volume before the counts have
been checked.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.services import artifact_store  # noqa: E402
from api.settings import load_settings  # noqa: E402

#: Which directories hold which family, relative to the two roots.
_FAMILIES = (
    ("output", "runs", artifact_store.keys.RUNS),
    ("output", "reports", artifact_store.keys.REPORTS),
    ("state", "job_inputs", artifact_store.keys.JOB_INPUTS),
)


def _iter_files(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            yield path


def migrate(
    store: artifact_store.ArtifactStore,
    *,
    output_dir: Path,
    state_dir: Path,
    dry_run: bool,
    overwrite: bool,
) -> dict[str, dict[str, int]]:
    roots = {"output": output_dir, "state": state_dir}
    report: dict[str, dict[str, int]] = {}
    for root_name, subdir, family in _FAMILIES:
        base = roots[root_name] / subdir
        counts = {"copied": 0, "skipped": 0, "bytes": 0, "errors": 0}
        report[family] = counts
        if not base.is_dir():
            continue
        for path in _iter_files(base):
            key = f"{family}/{path.relative_to(base).as_posix()}"
            try:
                if not overwrite and store.exists(key):
                    counts["skipped"] += 1
                    continue
                size = path.stat().st_size
                if not dry_run:
                    store.put_bytes(key, path.read_bytes())
                counts["copied"] += 1
                counts["bytes"] += size
            except (OSError, artifact_store.ArtifactStoreError) as exc:
                counts["errors"] += 1
                print(f"  ! {key}: {exc}", file=sys.stderr)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default=os.environ.get("OCTO_OUTPUT_DIR", "scanner/output"),
        help="Where run directories and reports are now (default: $OCTO_OUTPUT_DIR)",
    )
    parser.add_argument(
        "--state-dir",
        default=os.environ.get("OCTO_STATE_DIR", "scanner/state"),
        help="Where job inputs and wordlists are now (default: $OCTO_STATE_DIR)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Report, copy nothing")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace objects that are already in the store (default: leave them)",
    )
    args = parser.parse_args()

    settings = load_settings()
    store = artifact_store.get_store(settings)
    if store.backend == artifact_store.BACKEND_LOCAL:
        # The destination is the source. Refused rather than made a no-op:
        # somebody ran this to move their artifacts, and a silent success would
        # have them delete the volume afterwards.
        print(
            "OCTO_ARTIFACT_BACKEND is 'local' -- the destination store is the same "
            "filesystem this would read from. Set the object-storage settings "
            "(OCTO_ARTIFACT_BACKEND=s3, OCTO_ARTIFACT_S3_BUCKET=...) and run again.",
            file=sys.stderr,
        )
        return 2

    ok, detail = store.healthy()
    if not ok:
        print(f"Artifact store is not usable: {detail}", file=sys.stderr)
        return 2

    report = migrate(
        store,
        output_dir=Path(args.output_dir),
        state_dir=Path(args.state_dir),
        dry_run=args.dry_run,
        overwrite=args.overwrite,
    )

    total_errors = sum(counts["errors"] for counts in report.values())
    verb = "would copy" if args.dry_run else "copied"
    for family, counts in report.items():
        print(
            f"{family:<12} {verb} {counts['copied']:>6} file(s), "
            f"{counts['bytes'] / 1_048_576:.1f} MiB, "
            f"{counts['skipped']} already there, {counts['errors']} error(s)"
        )
    if total_errors:
        print(
            f"\n{total_errors} file(s) did not move. The originals are untouched; "
            "fix the cause and re-run -- what already arrived is skipped.",
            file=sys.stderr,
        )
        return 1
    if not args.dry_run:
        print(
            "\nNothing was deleted. Check the console reads the runs and reports "
            "you expect, then remove the old directories yourself."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
