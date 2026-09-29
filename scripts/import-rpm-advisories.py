#!/usr/bin/env python3
"""Import local RHEL/SLES CSAF or ALAS updateinfo into an offline dataset."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from defusedxml.common import DefusedXmlException  # noqa: E402
from xml.etree.ElementTree import ParseError  # noqa: E402
from api.services.advisories.rpm_import import import_manifest  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="operator-verified local source manifest")
    parser.add_argument("-o", "--output", required=True, type=Path)
    parser.add_argument("--min-entries", type=int, default=1)
    parser.add_argument("--allow-shrink", action="store_true", help="explicitly permit reduced existing coverage")
    args = parser.parse_args()
    try:
        result = import_manifest(args.manifest, args.output, min_entries=args.min_entries,
                                 allow_shrink=args.allow_shrink)
    except (OSError, ValueError, UnicodeError, RecursionError, EOFError, ParseError, DefusedXmlException) as exc:
        parser.exit(1, f"RPM advisory import refused: {exc}\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
