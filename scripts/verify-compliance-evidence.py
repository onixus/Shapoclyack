#!/usr/bin/env python3
"""Verify a Shapoclyack compliance evidence package offline (#356).

The embedded public key proves package integrity. For authenticity, pin the key
id obtained from a trusted deployment record with --key-id; otherwise replacing
both the package and its embedded public key would still verify cryptographically.

Self-contained on purpose: an auditor runs this file with Python and the
``cryptography`` package, without the platform or its dependencies. The format
constants and the canonical form mirror ``api/services/compliance/
evidence_package.py``; ``tests/test_compliance_evidence_package.py`` holds the
two together.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FORMAT = "shapoclyack.compliance-evidence"
VERSION = 1
SIGNATURE_ALGORITHM = "Ed25519"
MAX_PACKAGE_BYTES = 256 * 1024 * 1024
_KEY_ID_DOMAIN = b"shapoclyack/compliance-evidence/ed25519/v1"


class InvalidEvidencePackage(ValueError):
    """An evidence package is malformed or does not verify."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def verify(package: Any, *, expected_key_id: str | None = None) -> dict[str, Any]:
    if (
        not isinstance(package, dict)
        or package.get("format") != FORMAT
        or package.get("version") != VERSION
    ):
        raise InvalidEvidencePackage("unsupported evidence package format")
    payload = package.get("payload")
    signature = package.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, dict):
        raise InvalidEvidencePackage("evidence package is missing payload or signature")
    if signature.get("algorithm") != SIGNATURE_ALGORITHM:
        raise InvalidEvidencePackage("unsupported evidence signature algorithm")
    try:
        public_raw = base64.b64decode(str(signature["public_key"]), validate=True)
        signed = base64.b64decode(str(signature["value"]), validate=True)
        public = Ed25519PublicKey.from_public_bytes(public_raw)
    except (KeyError, ValueError, binascii.Error) as exc:
        raise InvalidEvidencePackage("malformed evidence signature") from exc
    actual_key_id = hashlib.sha256(_KEY_ID_DOMAIN + public_raw).hexdigest()
    if signature.get("key_id") != actual_key_id:
        raise InvalidEvidencePackage("evidence signing key id does not match the embedded public key")
    if expected_key_id is not None and actual_key_id != expected_key_id:
        raise InvalidEvidencePackage(
            f"evidence package was signed by {actual_key_id}, expected {expected_key_id}"
        )
    body = canonical_bytes(payload)
    if package.get("payload_sha256") != hashlib.sha256(body).hexdigest():
        raise InvalidEvidencePackage("evidence payload SHA-256 does not match")
    try:
        public.verify(signed, body)
    except InvalidSignature as exc:
        raise InvalidEvidencePackage("evidence signature is invalid") from exc
    return payload


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
        if len(raw) > MAX_PACKAGE_BYTES:
            raise InvalidEvidencePackage("package exceeds 256 MiB")
        document = json.loads(raw)
        payload = verify(document, expected_key_id=args.key_id)
    except (OSError, ValueError, RecursionError) as exc:
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
