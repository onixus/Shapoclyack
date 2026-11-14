"""Argparse CLI for offline product-license generation."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from typing import Any, Sequence, TextIO

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from api.services.licensing.format import (
    SIGNING_KEY_ENV,
    build_payload,
    key_id_for_public,
    sign_license,
)


def _load_signing_seed(path: str | None) -> bytes:
    """Load a 32-byte Ed25519 seed from ``--signing-key`` or ``OCTO_LICENSE_SIGNING_KEY``."""
    if path:
        raw = Path(path).read_text(encoding="utf-8").strip()
        if not raw:
            raise SystemExit(f"signing key file is empty: {path}")
        return _decode_seed(raw, source=path)
    env_raw = (os.environ.get(SIGNING_KEY_ENV) or "").strip()
    if not env_raw:
        raise SystemExit(
            f"provide --signing-key PATH or set {SIGNING_KEY_ENV} "
            "(32-byte Ed25519 seed as base64 or hex)"
        )
    return _decode_seed(env_raw, source=SIGNING_KEY_ENV)


def _decode_seed(raw: str, *, source: str) -> bytes:
    value = raw.strip()
    candidate: bytes | None = None
    if len(value) == 64:
        try:
            candidate = bytes.fromhex(value)
        except ValueError:
            candidate = None
    if candidate is None:
        try:
            candidate = base64.b64decode(value, validate=True)
        except Exception:
            candidate = None
    if candidate is None or len(candidate) != 32:
        raise SystemExit(
            f"{source} must be a 32-byte Ed25519 seed as base64 or hex"
        )
    return candidate


def _emit(text: str, output: str | None, *, stream: TextIO | None = None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        out = stream or sys.stdout
        out.write(text)
        if not text.endswith("\n"):
            out.write("\n")


def generate_keypair(*, output: str | None = None) -> dict[str, str]:
    """Create a fresh Ed25519 seed + public key for vendor ops."""
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes_raw()
    public = key.public_key()
    public_b64 = base64.b64encode(public.public_bytes_raw()).decode("ascii")
    seed_b64 = base64.b64encode(seed).decode("ascii")
    kid = key_id_for_public(public)
    payload = {
        "signing_key_base64": seed_b64,
        "public_key_base64": public_b64,
        "key_id": kid,
        "env_hint": {
            SIGNING_KEY_ENV: seed_b64,
            "OCTO_LICENSE_PUBLIC_KEY": public_b64,
        },
    }
    _emit(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", output)
    return payload


def print_public_key(*, signing_key: str | None, output: str | None = None) -> dict[str, str]:
    """Derive the public key and key id from a signing seed (bootstrap pinning)."""
    seed = _load_signing_seed(signing_key)
    key = Ed25519PrivateKey.from_private_bytes(seed)
    public = key.public_key()
    public_b64 = base64.b64encode(public.public_bytes_raw()).decode("ascii")
    kid = key_id_for_public(public)
    payload = {
        "public_key_base64": public_b64,
        "key_id": kid,
        "env_hint": {"OCTO_LICENSE_PUBLIC_KEY": public_b64},
    }
    _emit(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", output)
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tools.license_gen",
        description=(
            "Offline Shapoclyack product-license generator. "
            "Signs shapoclyack-license v1 documents with an Ed25519 seed that "
            "never ships in the product image."
        ),
    )
    parser.add_argument(
        "--customer",
        metavar="NAME",
        help="Customer / installation name (required unless --generate-keypair / --print-public-key)",
    )

    duration = parser.add_mutually_exclusive_group()
    duration.add_argument("--days", type=int, metavar="N", help="Term length in days")
    duration.add_argument(
        "--months", type=int, metavar="N", help="Term length in calendar months"
    )
    duration.add_argument(
        "--years", type=int, metavar="N", help="Term length in calendar years"
    )
    duration.add_argument(
        "--until",
        metavar="ISO8601",
        help="Absolute expiry (UTC ISO-8601)",
    )

    parser.add_argument(
        "--valid-from",
        metavar="ISO8601",
        dest="valid_from",
        help="License start (UTC ISO-8601); default: now",
    )
    parser.add_argument(
        "--lariska",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable Lariska (endpoint inventory); default: on",
    )
    parser.add_argument(
        "--brand-watch",
        action=argparse.BooleanOptionalAction,
        default=False,
        dest="brand_watch",
        help="Enable Brand Watch / domain-monitor; default: off",
    )
    parser.add_argument("--note", default="", metavar="TEXT", help="Optional note")
    parser.add_argument(
        "--license-id",
        metavar="UUID",
        dest="license_id",
        help="Stable license id (default: random UUID)",
    )
    parser.add_argument(
        "--signing-key",
        metavar="PATH",
        dest="signing_key",
        help=(
            f"Path to a file with the 32-byte Ed25519 seed (base64 or hex). "
            f"If omitted, reads {SIGNING_KEY_ENV}."
        ),
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="PATH",
        help="Write JSON to PATH instead of stdout",
    )
    parser.add_argument(
        "--print-public-key",
        action="store_true",
        dest="print_public_key",
        help=(
            "Print the public key (base64) and key id for the given signing key; "
            "pin as OCTO_LICENSE_PUBLIC_KEY in the product"
        ),
    )
    parser.add_argument(
        "--generate-keypair",
        action="store_true",
        dest="generate_keypair",
        help="Generate a fresh Ed25519 seed + public key (vendor ops); no --customer needed",
    )
    return parser


def _require_exactly_one_duration(args: argparse.Namespace) -> None:
    specified = sum(
        x is not None for x in (args.days, args.months, args.years, args.until)
    )
    if specified != 1:
        raise SystemExit(
            "set exactly one of --days, --months, --years, or --until for the license term"
        )


def generate_license_document(args: argparse.Namespace) -> dict[str, Any]:
    if not (args.customer or "").strip():
        raise SystemExit("--customer NAME is required to generate a license")
    _require_exactly_one_duration(args)
    seed = _load_signing_seed(args.signing_key)
    try:
        payload = build_payload(
            customer_name=args.customer,
            days=args.days,
            months=args.months,
            years=args.years,
            until=args.until,
            valid_from=args.valid_from,
            lariska=bool(args.lariska),
            brand_watch=bool(args.brand_watch),
            note=args.note or "",
            license_id=args.license_id,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    return sign_license(payload, private_key=seed)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.generate_keypair and args.print_public_key:
        parser.error("use only one of --generate-keypair or --print-public-key")

    if args.generate_keypair:
        generate_keypair(output=args.output)
        return 0

    if args.print_public_key:
        print_public_key(signing_key=args.signing_key, output=args.output)
        return 0

    document = generate_license_document(args)
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    _emit(text, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
