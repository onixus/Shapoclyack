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
    LicenseNotYetValid,
    LicenseStoreUnavailable,
)
from api.services.licensing.format import (
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
    if settings.license_enforcement_enabled and not (settings.license_public_key or "").strip():
        _log.error(
            "OCTO_LICENSE_ENFORCEMENT_ENABLED is on but OCTO_LICENSE_PUBLIC_KEY is empty; "
            "new scans and license uploads will be refused until a pin is configured"
        )


def _require_settings() -> Settings:
    assert _settings is not None, "licensing.configure() not called"
    return _settings


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _pin_required(settings: Settings) -> bool:
    return bool(settings.license_enforcement_enabled)


def _has_pin(settings: Settings) -> bool:
    return bool((settings.license_public_key or "").strip())


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


@dataclass(frozen=True)
class _LicenseLookup:
    """Result of reading the active row.

    ``unavailable`` is True only when a configured store failed — distinct from
    "no row" (grandfathered when enforcement is off) and from an empty
    ``postgres_url`` (no-infra / unit tests).
    """

    row: models.ProductLicense | None
    unavailable: bool = False


def _load_active(settings: Settings) -> _LicenseLookup:
    url = (settings.postgres_url or "").strip()
    if not url:
        return _LicenseLookup(row=None, unavailable=False)
    try:
        with get_session(url) as session:
            row = session.scalar(
                select(models.ProductLicense)
                .where(models.ProductLicense.active.is_(True))
                .order_by(models.ProductLicense.uploaded_at.desc())
                .limit(1)
            )
            if row is None:
                return _LicenseLookup(row=None, unavailable=False)
            session.expunge(row)
            return _LicenseLookup(row=row, unavailable=False)
    except Exception:  # noqa: BLE001 - classify, then fail closed at the gate
        _log.warning("licensing: could not read product_licenses", exc_info=True)
        return _LicenseLookup(row=None, unavailable=True)


def active_license(
    settings: Settings | None = None,
) -> models.ProductLicense | None:
    """Return the active license row, or ``None`` when none / no store / error.

    Prefer :func:`license_status` / :func:`assert_new_scan_allowed` for gates:
    a store error must fail closed, which this helper alone cannot express.
    """
    cfg = settings if settings is not None else _require_settings()
    return _load_active(cfg).row


def product_active(
    settings: Settings,
    *,
    now: datetime | None = None,
    row: models.ProductLicense | None = None,
    unavailable: bool = False,
) -> bool:
    """Whether the contracted product term is currently open (half-open interval)."""
    if unavailable:
        return False
    moment = parse_utc(now or _now())
    if row is None:
        # No document: open only when enforcement is off (dev / grandfathered).
        return not settings.license_enforcement_enabled
    start = parse_utc(row.valid_from)
    end = parse_utc(row.expires_at)
    return start <= moment < end


def lariska_entitled(
    settings: Settings,
    *,
    now: datetime | None = None,
    row: models.ProductLicense | None = None,
    unavailable: bool = False,
) -> bool:
    if unavailable:
        return False
    if row is None and now is None:
        lookup = _load_active(settings)
        row, unavailable = lookup.row, lookup.unavailable
        if unavailable:
            return False
    if not product_active(settings, now=now, row=row, unavailable=unavailable):
        return False
    if row is None:
        return bool(settings.endpoint_inventory_enabled)
    return bool(row.feature_lariska) and bool(settings.endpoint_inventory_enabled)


def brand_watch_entitled(
    settings: Settings,
    *,
    now: datetime | None = None,
    row: models.ProductLicense | None = None,
    unavailable: bool = False,
) -> bool:
    if unavailable:
        return False
    if row is None and now is None:
        lookup = _load_active(settings)
        row, unavailable = lookup.row, lookup.unavailable
        if unavailable:
            return False
    if not product_active(settings, now=now, row=row, unavailable=unavailable):
        return False
    if row is None:
        return False
    return bool(row.feature_brand_watch)


def license_status(
    settings: Settings, *, now: datetime | None = None
) -> LicenseStatus:
    moment = parse_utc(now or _now())
    enforcement = bool(settings.license_enforcement_enabled)
    if _pin_required(settings) and not _has_pin(settings):
        return LicenseStatus(
            installed=False,
            active=False,
            enforcement_enabled=enforcement,
            product_active=False,
            new_scans_allowed=False,
            lariska=False,
            brand_watch=False,
            reason="enforcement requires OCTO_LICENSE_PUBLIC_KEY",
        )

    lookup = _load_active(settings)
    if lookup.unavailable:
        # Commercial stop must not lift because Postgres blinked.
        return LicenseStatus(
            installed=False,
            active=False,
            enforcement_enabled=enforcement,
            product_active=False,
            new_scans_allowed=False,
            lariska=False,
            brand_watch=False,
            reason="license store unavailable",
        )

    row = lookup.row
    if row is None:
        open_without = not enforcement
        return LicenseStatus(
            installed=False,
            active=False,
            enforcement_enabled=enforcement,
            product_active=open_without,
            new_scans_allowed=open_without and bool(settings.allow_scan_start),
            lariska=bool(settings.endpoint_inventory_enabled) and open_without,
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
        # ``active`` means "this is the installation's current license row",
        # not that the commercial term is open — see ``product_active``.
        active=True,
        enforcement_enabled=enforcement,
        product_active=in_term,
        new_scans_allowed=in_term and bool(settings.allow_scan_start),
        lariska=in_term
        and bool(row.feature_lariska)
        and bool(settings.endpoint_inventory_enabled),
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
    if status.reason == "license store unavailable":
        raise LicenseStoreUnavailable(
            "Scan start refused: product license store unavailable"
        )
    if status.reason == "enforcement requires OCTO_LICENSE_PUBLIC_KEY":
        raise LicenseMissing(
            "Scan start refused: OCTO_LICENSE_PUBLIC_KEY required when enforcement is enabled"
        )
    if not status.installed and status.enforcement_enabled:
        raise LicenseMissing("Scan start refused: no product license installed")
    if status.installed and not status.product_active:
        if status.reason == "license not yet valid":
            raise LicenseNotYetValid(
                f"Scan start refused: product license not valid until {status.valid_from}"
            )
        raise LicenseExpired(
            f"Scan start refused: product license expired"
            f"{f' at {status.expires_at}' if status.expires_at else ''}"
        )
    if not settings.allow_scan_start:
        raise RuntimeError("Scan start disabled by OCTO_ALLOW_SCAN_START")
    raise LicenseMissing("Scan start refused: product license not active")


def assert_lariska(settings: Settings, *, now: datetime | None = None) -> None:
    lookup = _load_active(settings)
    if lookup.unavailable:
        raise LicenseStoreUnavailable(
            "Lariska refused: product license store unavailable"
        )
    if lariska_entitled(
        settings, now=now, row=lookup.row, unavailable=lookup.unavailable
    ):
        return
    status = license_status(settings, now=now)
    if status.reason == "enforcement requires OCTO_LICENSE_PUBLIC_KEY":
        raise LicenseMissing(
            "Lariska refused: OCTO_LICENSE_PUBLIC_KEY required when enforcement is enabled"
        )
    if not status.product_active:
        if status.reason == "license not yet valid":
            raise LicenseNotYetValid(
                f"Lariska refused: product license not valid until {status.valid_from}"
            )
        if status.installed:
            raise LicenseExpired("Lariska refused: product license expired")
        raise LicenseMissing("Lariska refused: no active product license")
    raise LicenseFeatureDenied("Lariska is not enabled on the active license")


def assert_brand_watch(settings: Settings, *, now: datetime | None = None) -> None:
    lookup = _load_active(settings)
    if lookup.unavailable:
        raise LicenseStoreUnavailable(
            "Brand Watch refused: product license store unavailable"
        )
    if brand_watch_entitled(
        settings, now=now, row=lookup.row, unavailable=lookup.unavailable
    ):
        return
    status = license_status(settings, now=now)
    if not status.product_active:
        if status.reason == "license not yet valid":
            raise LicenseNotYetValid(
                f"Brand Watch refused: product license not valid until {status.valid_from}"
            )
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
    lookup = _load_active(settings)
    if brand_watch_entitled(
        settings, now=now, row=lookup.row, unavailable=lookup.unavailable
    ):
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
    if _pin_required(settings) and not pinned:
        raise LicenseInvalid(
            "OCTO_LICENSE_PUBLIC_KEY is required when license enforcement is enabled"
        )

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
