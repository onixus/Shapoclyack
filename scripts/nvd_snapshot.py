#!/usr/bin/env python3
"""Park or verify the versioned NVD CVSS4 snapshot used by image builds."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import date
from pathlib import Path


def inspect(data: bytes) -> dict:
    doc = json.loads(data)
    if not isinstance(doc, dict) or doc.get("source") != "nvd-api-2.0" or doc.get("version") != "4.0":
        raise ValueError("expected an NVD CVSS4 snapshot")
    date.fromisoformat(doc["updated"])
    entries = doc.get("entries")
    if not isinstance(entries, dict) or len(entries) < 1000:
        raise ValueError("NVD snapshot must contain at least 1000 entries")
    return doc


def verify(path: Path) -> dict:
    data = path.read_bytes()
    expected = path.with_suffix(".sha256").read_text().strip()
    if expected != hashlib.sha256(data).hexdigest():
        raise ValueError("NVD snapshot checksum mismatch")
    return inspect(data)


def park(source: Path, destination: Path) -> dict:
    data = source.read_bytes()
    doc = inspect(data)  # Validate before touching the previous snapshot.
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".json.tmp")
    temporary.write_bytes(data)
    temporary.replace(destination)
    checksum = destination.with_suffix(".sha256")
    temporary = checksum.with_suffix(".sha256.tmp")
    temporary.write_text(hashlib.sha256(data).hexdigest() + "\n")
    temporary.replace(checksum)
    return doc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("verify")
    check.add_argument("snapshot", type=Path)
    save = commands.add_parser("park")
    save.add_argument("source", type=Path)
    save.add_argument("snapshot", type=Path)
    args = parser.parse_args()
    try:
        doc = park(args.source, args.snapshot) if args.command == "park" else verify(args.snapshot)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"error: {error}\n")
    print(f"NVD snapshot: {len(doc['entries'])} entries, updated {doc['updated']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
