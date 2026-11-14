"""Signed ``shapoclyack-license`` v1 documents and the duration calculator.

The private key is for the offline generator only. The control plane pins the
matching public key via ``OCTO_LICENSE_PUBLIC_KEY`` and never needs to sign.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from api.services.licensing.errors import LicenseInvalid

FORMAT = "shapoclyack-license"
VERSION = 1
SIGNATURE_ALGORITHM = "Ed25519"
_KEY_BYTES = 32
_KEY_ID_DOMAIN = b"shapoclyack/product-license/ed25519/v1"
PUBLIC_KEY_ENV = "OCTO_LICENSE_PUBLIC_KEY"
SIGNING_KEY_ENV = "OCTO_LICENSE_SIGNING_KEY"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def parse_utc(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).replace(microsecond=0)


def to_iso(dt: datetime) -> str:
    return parse_utc(dt).isoformat().replace("+00:00", "Z")


def calculate_expiry(
    *,
    valid_from: datetime | None = None,
    days: int | None = None,
    months: int | None = None,
    years: int | None = None,
    until: datetime | str | None = None,
) -> tuple[datetime, datetime]:
    """Duration calculator used by the offline generator.

    Exactly one of ``days`` / ``months`` / ``years`` / ``until`` must be set.
    Months and years are calendar steps (day-of-month clamped), not 30-day
    approximations — renewals land on the same calendar date when possible.
    """
    start = parse_utc(valid_from or _now())
    specified = sum(x is not None for x in (days, months, years, until))
    if specified != 1:
        raise ValueError(
            "set exactly one of days, months, years, or until for the license term"
        )
    if until is not None:
        end = parse_utc(until)
    elif days is not None:
        if days < 1:
            raise ValueError("days must be >= 1")
        end = start + timedelta(days=int(days))
    elif months is not None:
        if months < 1:
            raise ValueError("months must be >= 1")
        end = _add_months(start, int(months))
    else:
        assert years is not None
        if years < 1:
            raise ValueError("years must be >= 1")
        end = _add_months(start, int(years) * 12)
    if end <= start:
        raise ValueError("expires_at must be after valid_from")
    return start, end


def _add_months(dt: datetime, months: int) -> datetime:
    year = dt.year + (dt.month - 1 + months) // 12
    month = (dt.month - 1 + months) % 12 + 1
    # Clamp day for shorter months (31 Jan + 1 month → 28/29 Feb).
    for day in range(dt.day, 0, -1):
        try:
            return dt.replace(year=year, month=month, day=day)
        except ValueError:
            continue
    raise ValueError("could not advance calendar months")


def _decode_key_material(raw: str, *, env_name: str) -> bytes:
    value = str(raw or "").strip()
    candidate: bytes | None = None
    if len(value) == _KEY_BYTES * 2:
        try:
            candidate = bytes.fromhex(value)
        except ValueError:
            candidate = None
    if candidate is None:
        try:
            candidate = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            candidate = None
    if candidate is None or len(candidate) != _KEY_BYTES:
        raise LicenseInvalid(
            f"{env_name} must be a 32-byte Ed25519 key as base64 or hex"
        )
    return candidate


def key_id_for_public(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes_raw()
    return hashlib.sha256(_KEY_ID_DOMAIN + raw).hexdigest()


@dataclass(frozen=True)
class Features:
    lariska: bool = True
    brand_watch: bool = False

    def as_dict(self) -> dict[str, bool]:
        return {"lariska": bool(self.lariska), "brand_watch": bool(self.brand_watch)}


@dataclass(frozen=True)
class LicensePayload:
    license_id: str
    customer_name: str
    issued_at: datetime
    valid_from: datetime
    expires_at: datetime
    features: Features
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "license_id": self.license_id,
            "customer_name": self.customer_name,
            "issued_at": to_iso(self.issued_at),
            "valid_from": to_iso(self.valid_from),
            "expires_at": to_iso(self.expires_at),
            "features": self.features.as_dict(),
            "note": self.note or "",
        }


def build_payload(
    *,
    customer_name: str,
    days: int | None = None,
    months: int | None = None,
    years: int | None = None,
    until: datetime | str | None = None,
    valid_from: datetime | str | None = None,
    lariska: bool = True,
    brand_watch: bool = False,
    note: str = "",
    license_id: str | None = None,
    issued_at: datetime | None = None,
) -> LicensePayload:
    start, end = calculate_expiry(
        valid_from=parse_utc(valid_from) if valid_from else None,
        days=days,
        months=months,
        years=years,
        until=until,
    )
    issued = parse_utc(issued_at or _now())
    name = (customer_name or "").strip()
    if not name:
        raise ValueError("customer_name is required")
    return LicensePayload(
        license_id=license_id or str(uuid.uuid4()),
        customer_name=name,
        issued_at=issued,
        valid_from=start,
        expires_at=end,
        features=Features(lariska=lariska, brand_watch=brand_watch),
        note=(note or "").strip(),
    )


def sign_license(
    payload: LicensePayload | dict[str, Any],
    *,
    private_key: bytes | str | None = None,
    environ: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Sign a payload. Used by the offline generator, not by the API."""
    body_dict = payload.as_dict() if isinstance(payload, LicensePayload) else dict(payload)
    raw = private_key
    if raw is None:
        env = os.environ if environ is None else environ
        raw = (env.get(SIGNING_KEY_ENV) or "").strip()
    if isinstance(raw, str):
        seed = _decode_key_material(raw, env_name=SIGNING_KEY_ENV)
    else:
        seed = raw
    if len(seed) != _KEY_BYTES:
        raise LicenseInvalid(f"{SIGNING_KEY_ENV} must be 32 bytes")
    key = Ed25519PrivateKey.from_private_bytes(seed)
    public = key.public_key()
    body = canonical_bytes(body_dict)
    return {
        "format": FORMAT,
        "version": VERSION,
        "payload_sha256": hashlib.sha256(body).hexdigest(),
        "payload": body_dict,
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "key_id": key_id_for_public(public),
            "public_key": base64.b64encode(public.public_bytes_raw()).decode("ascii"),
            "value": base64.b64encode(key.sign(body)).decode("ascii"),
        },
    }


def _pinned_public_key(
    *,
    expected_public_key: bytes | str | None = None,
    environ: dict[str, str] | None = None,
) -> Ed25519PublicKey | None:
    if expected_public_key is not None:
        raw = (
            _decode_key_material(expected_public_key, env_name=PUBLIC_KEY_ENV)
            if isinstance(expected_public_key, str)
            else expected_public_key
        )
        return Ed25519PublicKey.from_public_bytes(raw)
    env = os.environ if environ is None else environ
    pinned = (env.get(PUBLIC_KEY_ENV) or "").strip()
    if not pinned:
        return None
    return Ed25519PublicKey.from_public_bytes(
        _decode_key_material(pinned, env_name=PUBLIC_KEY_ENV)
    )


def verify_license(
    document: dict[str, Any],
    *,
    expected_public_key: bytes | str | None = None,
    environ: dict[str, str] | None = None,
    now: datetime | None = None,
) -> LicensePayload:
    """Verify signature and shape; does **not** enforce expiry by itself."""
    if not isinstance(document, dict):
        raise LicenseInvalid("license document must be a JSON object")
    if document.get("format") != FORMAT or document.get("version") != VERSION:
        raise LicenseInvalid("unsupported license format or version")
    payload = document.get("payload")
    signature = document.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, dict):
        raise LicenseInvalid("license is missing payload or signature")
    if signature.get("algorithm") != SIGNATURE_ALGORITHM:
        raise LicenseInvalid("unsupported license signature algorithm")
    try:
        public_raw = base64.b64decode(str(signature["public_key"]), validate=True)
        signed = base64.b64decode(str(signature["value"]), validate=True)
        public = Ed25519PublicKey.from_public_bytes(public_raw)
    except (KeyError, ValueError, binascii.Error) as exc:
        raise LicenseInvalid("malformed license signature") from exc
    actual_key_id = key_id_for_public(public)
    if signature.get("key_id") != actual_key_id:
        raise LicenseInvalid("license key id does not match the embedded public key")
    pinned = _pinned_public_key(
        expected_public_key=expected_public_key, environ=environ
    )
    if pinned is not None:
        if pinned.public_bytes_raw() != public_raw:
            raise LicenseInvalid("license was not signed by the pinned public key")
        if key_id_for_public(pinned) != actual_key_id:
            raise LicenseInvalid("license key id does not match the pinned public key")
    body = canonical_bytes(payload)
    digest = hashlib.sha256(body).hexdigest()
    if document.get("payload_sha256") != digest:
        raise LicenseInvalid("license payload SHA-256 does not match")
    try:
        public.verify(signed, body)
    except InvalidSignature as exc:
        raise LicenseInvalid("license signature is invalid") from exc

    try:
        features_raw = payload.get("features") or {}
        if not isinstance(features_raw, dict):
            raise LicenseInvalid("license features must be an object")
        features = Features(
            lariska=bool(features_raw.get("lariska", False)),
            brand_watch=bool(features_raw.get("brand_watch", False)),
        )
        parsed = LicensePayload(
            license_id=str(payload["license_id"]),
            customer_name=str(payload["customer_name"]).strip(),
            issued_at=parse_utc(str(payload["issued_at"])),
            valid_from=parse_utc(str(payload["valid_from"])),
            expires_at=parse_utc(str(payload["expires_at"])),
            features=features,
            note=str(payload.get("note") or ""),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise LicenseInvalid("license payload fields are incomplete or invalid") from exc
    if not parsed.customer_name:
        raise LicenseInvalid("license customer_name is empty")
    if parsed.expires_at <= parsed.valid_from:
        raise LicenseInvalid("license expires_at must be after valid_from")
    # ``now`` reserved for callers that want not-yet-valid checks at verify time.
    _ = now
    return parsed
