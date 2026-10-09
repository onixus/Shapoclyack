#!/usr/bin/env python3
"""Gap report between the recorded Nmap and Pulse corpus (#541). Offline.

Usage:
  scripts/compare-nmap-pulse-corpus.py                 # table
  scripts/compare-nmap-pulse-corpus.py --json          # full report (per endpoint)
  scripts/compare-nmap-pulse-corpus.py --corpus DIR    # a corpus recorded elsewhere

Reads tests/fixtures/nmap_pulse_corpus/{nmap,pulse}; needs neither tool nor a
network. To re-record the corpus see tests/fixtures/nmap_pulse_corpus/record.sh.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))  # `scanner` package; `pulse_corpus` is next to this file

from pulse_corpus import compare_corpus, format_table  # noqa: E402

DEFAULT_CORPUS = ROOT / "tests" / "fixtures" / "nmap_pulse_corpus"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    ap.add_argument("--json", action="store_true", help="print the full JSON report")
    args = ap.parse_args()
    report = compare_corpus(args.corpus)
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else format_table(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
