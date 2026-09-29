#!/usr/bin/env python3
"""Build a shadow evidence sidecar from existing run artifacts, without scanning."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scanner.pipeline.evidence_artifacts import write_evidence_artifact  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("--tenant-id", required=True, help="Explicit context, not an authorization grant")
    parser.add_argument("--run-id", required=True, help="Stable ID of the original run, not today's date")
    args = parser.parse_args()
    try:
        result = write_evidence_artifact(args.run_directory, tenant_id=args.tenant_id, run_id=args.run_id)
    except (OSError, ValueError):
        print("Cannot build evidence: check the run directory and explicit context.", file=sys.stderr)
        return 2
    print(f"Shadow projection: {result['finding_count']} groups, {result['observation_count']} observations; "
          "coverage unknown; no tracker updates.")
    if result["projection_incomplete"]:
        print("Projection incomplete: see finding_evidence.json diagnostics.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
