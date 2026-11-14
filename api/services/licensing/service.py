"""Persist and evaluate the installation's active product license."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update

from api.db import models
from api.db.engine import get_session
from api.services.licensing.errors import (
    LicenseExpired,
    LicenseFeatureDenied,
    LicenseInvalid,
    LicenseMissing,
)
from api.services.licensing.format import (
    Features,
    LicensePayload,
    parse_utc,
    to_iso,
    verify_license,
)
from api.settings import Settings

_log = logging.getLogger(__name__)

_settings: Settings | None = None


def configure(settings: Settings) -> None:
    """Pin the Postgres URL for entitlement reads (same pattern as audit/tenants)."""
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "licensing.configure() not called"
    return _settings


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


@dataclass(frozen=True)
class LicenseStatus:
    installed: bool
    active: bool
    enforcement_enabled: bool
    product_active: bool
    new_scans_allowed: bool
    lariska: bool
    brand_watch: bool
    license_id: str | None = None
    customer_name: str | None = None
    valid_from: str | None = None
    expires_at: str | None = None
    issued_at: str | None = None
    note: str | None = None
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "installed": self.installed,
            "active": self.active,
            "enforcement_enabled": self.enforcement_enabled,
            "product_active": self.product_active,
            "new_scans_allowed": self.new_scans_allowed,
            "features": {
                "lariska": self.lariska,
                "brand_watch": self.brand_watch,
            },
            "license_id": self.license_id,
            "customer_name": self.customer_name,
            "valid_from": self.valid_from,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "note": self.note,
            "reason": self.reason,
        }


def active_license(
    settings: Settings | None = None,
) -> models.ProductLicense | None:
    """Return the active license row, or ``None`` when none / no store.

    An empty ``postgres_url`` is treated as "no license installed" rather than
    raising: unit tests and no-infra CI exercise ``start_scan`` without Postgres,
    and the gate must not invent a hard dependency there. Enforcement still
    closes the product when ``license_enforcement_enabled`` is on and this
    returns ``None``.
    """
    cfg = settings if settings is not None else _require_settings()
    url = (cfg.postgres_url or "").strip()
    if not url:
        return None
    try:
        with get_session(url) as session:
            row = session.scalar(
                select(models.ProductLicense)
                .where(models.ProductLicense.active.is_(True))
                .order_by(models.ProductLicense.uploaded_at.desc())
                .limit(1)
            )
            if row is None:
                return None
            session.expunge(row)
            return row
    except Exception:  # noqa: BLE001 - fail-soft like system_status panels
        _log.warning("licensing: could not read product_licenses", exc_info=True)
        return None


def _payload_from_row(row: models.ProductLicense) -> LicensePayload:
    return LicensePayload(
        license_id=row.license_id,
        customer_name=row.customer_name,
        issued_at=parse_utc(row.issued_at),
        valid_from=parse_utc(row.valid_from),
        expires_at=parse_utc(row.expires_at),
        features=Features(
            lariska=bool(row.feature_lariska),
            brand_watch=bool(row.feature_brand_watch),
        ),
        note=row.note or "",
    )


def product_active(
    settings: Settings,
    *,
    now: datetime | None = None,
    row: models.ProductLicense | None = None,
) -> bool:
    """Whether the contracted product term is currently open."""
    moment = parse_utc(now or _now())
    license_row = row if row is not None else active_license(settings)
    if license_row is None:
        # No document: open only when enforcement is off (dev / grandfathered).
        return not settings.license_enforcement_enabled
    start = parse_utc(license_row.valid_from)
    end = parse_utc(license_row.expires_at)
    return start <= moment < end


def lariska_entitled(settings: Settings, *, now: datetime | None = None) -> bool:
    if not product_active(settings, now=now):
        return False
    row = active_license(settings)
    if row is None:
        # Grandfathered install: env flag remains authoritative.
        return bool(settings.endpoint_inventory_enabled)
    return bool(row.feature_lariska) and bool(settings.endpoint_inventory_enabled)


def brand_watch_entitled(settings: Settings, *, now: datetime | None = None) -> bool:
    if not product_active(settings, now=now):
        return False
    row = active_license(settings)
    if row is None:
        return False
    return bool(row.feature_brand_watch)


def license_status(
    settings: Settings, *, now: datetime | None = None
) -> LicenseStatus:
    moment = parse_utc(now or _now())
    row = active_license(settings)
    enforcement = bool(settings.license_enforcement_enabled)
    if row is None:
        active = not enforcement
        return LicenseStatus(
            installed=False,
            active=False,
            enforcement_enabled=enforcement,
            product_active=active,
            new_scans_allowed=active and bool(settings.allow_scan_start),
            lariska=bool(settings.endpoint_inventory_enabled) and active,
            brand_watch=False,
            reason=(
                "no license installed; enforcement requires one"
                if enforcement
                else "no license installed; enforcement disabled"
            ),
        )
    start = parse_utc(row.valid_from)
    end = parse_utc(row.expires_at)
    in_term = start <= moment < end
    reason = None
    if moment < start:
        reason = "license not yet valid"
    elif not in_term:
        reason = "license expired"
    return LicenseStatus(
        installed=True,
        active=True,
        enforcement_enabled=enforcement,
        product_active=in_term,
        new_scans_allowed=in_term and bool(settings.allow_scan_start),
        lariska=in_term and bool(row.feature_lariska) and bool(
            settings.endpoint_inventory_enabled
        ),
        brand_watch=in_term and bool(row.feature_brand_watch),
        license_id=row.license_id,
        customer_name=row.customer_name,
        valid_from=to_iso(start),
        expires_at=to_iso(end),
        issued_at=to_iso(parse_utc(row.issued_at)),
        note=row.note or None,
        reason=reason,
    )


def assert_new_scan_allowed(settings: Settings, *, now: datetime | None = None) -> None:
    """Hard gate for every new scan start path."""
    status = license_status(settings, now=now)
    if status.new_scans_allowed:
        return
    if not status.installed and status.enforcement_enabled:
        raise LicenseMissing("Scan start refused: no product license installed")
    if status.installed and not status.product_active:
        raise LicenseExpired(
            f"Scan start refused: product license expired"
            f"{f' at {status.expires_at}' if status.expires_at else ''}"
        )
    if not settings.allow_scan_start:
        raise LicenseExpired("Scan start disabled by OCTO_ALLOW_SCAN_START")
    raise LicenseMissing("Scan start refused: product license not active")


def assert_lariska(settings: Settings, *, now: datetime | None = None) -> None:
    if lariska_entitled(settings, now=now):
        return
    status = license_status(settings, now=now)
    if not status.product_active:
        if status.installed:
            raise LicenseExpired("Lariska refused: product license expired")
        raise LicenseMissing("Lariska refused: no active product license")
    raise LicenseFeatureDenied("Lariska is not enabled on the active license")


def assert_brand_watch(settings: Settings, *, now: datetime | None = None) -> None:
    if brand_watch_entitled(settings, now=now):
        return
    status = license_status(settings, now=now)
    if not status.product_active:
        if status.installed:
            raise LicenseExpired("Brand Watch refused: product license expired")
        raise LicenseMissing("Brand Watch refused: no active product license")
    raise LicenseFeatureDenied("Brand Watch is not enabled on the active license")


def brand_watch_overlay(
    settings: Settings,
    config_extra: dict[str, Any] | None = None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Deep-merge config extras with domain-monitor forced off when not entitled.

    Soft gate used by scan submission: a scan without Brand Watch still runs;
    only the Brand Watch / domain-monitor stage is stripped.
    """
    from api.services.scan_intents import merge_config_extras

    base = dict(config_extra or {})
    if brand_watch_entitled(settings, now=now):
        return base
    return (
        merge_config_extras(
            base,
            {"discovery": {"domain_monitor": {"enabled": False}}},
        )
        or {}
    )


def install_license(
    document: dict[str, Any] | str | bytes,
    *,
    settings: Settings,
    uploaded_by: str,
    now: datetime | None = None,
) -> LicenseStatus:
    """Verify and activate a license document, deactivating any previous one."""
    if isinstance(document, (bytes, bytearray)):
        try:
            document = json.loads(document.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LicenseInvalid("license file is not valid UTF-8 JSON") from exc
    elif isinstance(document, str):
        try:
            document = json.loads(document)
        except json.JSONDecodeError as exc:
            raise LicenseInvalid("license file is not valid JSON") from exc
    if not isinstance(document, dict):
        raise LicenseInvalid("license document must be a JSON object")

    pinned = (settings.license_public_key or "").strip() or None
    payload = verify_license(
        document,
        expected_public_key=pinned,
        environ=None if pinned else {},
    )
    moment = parse_utc(now or _now())
    raw_json = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.ProductLicense).values(active=False).where(
                models.ProductLicense.active.is_(True)
            )
        )
        existing = session.scalar(
            select(models.ProductLicense).where(
                models.ProductLicense.license_id == payload.license_id
            )
        )
        if existing is not None:
            existing.customer_name = payload.customer_name
            existing.issued_at = payload.issued_at.replace(tzinfo=None)
            existing.valid_from = payload.valid_from.replace(tzinfo=None)
            existing.expires_at = payload.expires_at.replace(tzinfo=None)
            existing.feature_lariska = payload.features.lariska
            existing.feature_brand_watch = payload.features.brand_watch
            existing.note = payload.note
            existing.document_json = raw_json
            existing.uploaded_at = moment.replace(tzinfo=None)
            existing.uploaded_by = uploaded_by
            existing.active = True
        else:
            session.add(
                models.ProductLicense(
                    license_id=payload.license_id,
                    customer_name=payload.customer_name,
                    issued_at=payload.issued_at.replace(tzinfo=None),
                    valid_from=payload.valid_from.replace(tzinfo=None),
                    expires_at=payload.expires_at.replace(tzinfo=None),
                    feature_lariska=payload.features.lariska,
                    feature_brand_watch=payload.features.brand_watch,
                    note=payload.note,
                    document_json=raw_json,
                    uploaded_at=moment.replace(tzinfo=None),
                    uploaded_by=uploaded_by,
                    active=True,
                )
            )
        session.commit()

    _log.info(
        "product license activated license_id=%s customer=%s expires_at=%s by=%s",
        payload.license_id,
        payload.customer_name,
        to_iso(payload.expires_at),
        uploaded_by,
    )
    return license_status(settings, now=moment)
