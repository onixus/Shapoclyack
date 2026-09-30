#!/usr/bin/env python3
"""Verify a Shapoclyack compliance evidence package offline (#356).

The embedded public key proves package integrity. For authenticity, pin the key
id obtained from a trusted deployment record with --key-id; otherwise replacing
both the package and its embedded public key would still verify cryptographically.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.services.compliance import evidence_package  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument(
        "--key-id",
        default=None,
        help="expected trusted signing-key fingerprint",
    )
    args = parser.parse_args(argv)
    try:
        raw = args.package.read_bytes()
        if len(raw) > 256 * 1024 * 1024:
            raise evidence_package.InvalidEvidencePackage("package exceeds 256 MiB")
        document = json.loads(raw)
        payload = evidence_package.verify(document, expected_key_id=args.key_id)
    except (
        OSError,
        ValueError,
        RecursionError,
        evidence_package.InvalidEvidencePackage,
    ) as exc:
        print(f"invalid evidence package: {exc}", file=sys.stderr)
        return 1
    signature = document["signature"]
    print(
        json.dumps(
            {
                "valid": True,
                "key_id": signature["key_id"],
                "payload_sha256": document["payload_sha256"],
                "tenant_id": payload.get("tenant_id"),
                "framework_id": payload.get("framework_id"),
                "generated_at": payload.get("generated_at"),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
