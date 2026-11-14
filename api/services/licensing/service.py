"""Persist and evaluate the installation's active product license."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

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
    LicensePayload,
    parse_utc,
    to_iso,
    verify_license,
)
from api.settings import Settings

_log = logging.getLogger(__name__)

_settings: Settings | None = None
_PIN_REASON = "OCTO_LICENSE_PUBLIC_KEY is required"
_SIGNATURE_REASON = "license signature does not match the pinned public key"
_STORE_REASON = "license store unavailable"


def configure(settings: Settings) -> None:
    """Pin the Postgres URL for entitlement reads (same pattern as audit/tenants)."""
    global _settings
    _settings = settings
    if not (settings.license_public_key or "").strip():
        _log.error(
            "OCTO_LICENSE_PUBLIC_KEY is empty; license upload is refused and an "
            "installed document cannot be trusted until a pin is configured"
        )


def _require_settings() -> Settings:
    assert _settings is not None, "licensing.configure() not called"
    return _settings


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


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


def _verified_payload(settings: Settings, row: models.ProductLicense) -> LicensePayload:
    """Re-check the stored document. Columns are a cache, not the entitlement."""
    pinned = (settings.license_public_key or "").strip()
    if not pinned:
        raise LicenseInvalid(_PIN_REASON)
    try:
        document = json.loads(row.document_json)
    except json.JSONDecodeError as exc:
        raise LicenseInvalid("stored license document is not JSON") from exc
    if not isinstance(document, dict):
        raise LicenseInvalid("stored license document is not an object")
    return verify_license(document, expected_public_key=pinned, environ={})


def active_license(
    settings: Settings | None = None,
) -> models.ProductLicense | None:
    """Return the active license row, or ``None`` when none / no store / error.

    Prefer :func:`license_status` / :func:`assert_new_scan_allowed` for gates:
    a store error must fail closed, and a row is not an entitlement until its
    document verifies against the pinned key.
    """
    cfg = settings if settings is not None else _require_settings()
    return _load_active(cfg).row


def _closed(
    *,
    enforcement: bool,
    reason: str,
    installed: bool = False,
    license_id: str | None = None,
) -> LicenseStatus:
    return LicenseStatus(
        installed=installed,
        active=installed,
        enforcement_enabled=enforcement,
        product_active=False,
        new_scans_allowed=False,
        lariska=False,
        brand_watch=False,
        license_id=license_id,
        reason=reason,
    )


def license_status(
    settings: Settings, *, now: datetime | None = None
) -> LicenseStatus:
    moment = parse_utc(now or _now())
    enforcement = bool(settings.license_enforcement_enabled)
    lookup = _load_active(settings)
    if lookup.unavailable:
        # Commercial stop must not lift because Postgres blinked.
        return _closed(enforcement=enforcement, reason=_STORE_REASON)

    row = lookup.row
    if row is None:
        if enforcement and not _has_pin(settings):
            return _closed(enforcement=enforcement, reason=_PIN_REASON)
        open_without = not enforcement
        return LicenseStatus(
            installed=False,
            active=False,
            enforcement_enabled=enforcement,
            product_active=open_without,
            new_scans_allowed=open_without and bool(settings.allow_scan_start),
            lariska=bool(settings.endpoint_inventory_enabled) and open_without,
            # No document yet: the product stays open when enforcement is off,
            # including Brand Watch. An uploaded document replaces that.
            brand_watch=open_without,
            reason=(
                "no license installed; enforcement requires one"
                if enforcement
                else "no license installed; enforcement disabled"
            ),
        )

    if not _has_pin(settings):
        return _closed(
            enforcement=enforcement,
            reason=_PIN_REASON,
            installed=True,
            license_id=row.license_id,
        )
    try:
        payload = _verified_payload(settings, row)
    except LicenseInvalid as exc:
        _log.warning("licensing: active document failed verification: %s", exc)
        return _closed(
            enforcement=enforcement,
            reason=_SIGNATURE_REASON,
            installed=True,
            license_id=row.license_id,
        )
    except Exception:  # noqa: BLE001 - a corrupt row is not an open product
        _log.warning("licensing: could not verify active document", exc_info=True)
        return _closed(
            enforcement=enforcement,
            reason=_SIGNATURE_REASON,
            installed=True,
            license_id=row.license_id,
        )

    start = parse_utc(payload.valid_from)
    end = parse_utc(payload.expires_at)
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
        and bool(payload.features.lariska)
        and bool(settings.endpoint_inventory_enabled),
        brand_watch=in_term and bool(payload.features.brand_watch),
        license_id=payload.license_id,
        customer_name=payload.customer_name,
        valid_from=to_iso(start),
        expires_at=to_iso(end),
        issued_at=to_iso(parse_utc(payload.issued_at)),
        note=payload.note or None,
        reason=reason,
    )


def product_active(
    settings: Settings,
    *,
    now: datetime | None = None,
    row: models.ProductLicense | None = None,
    unavailable: bool = False,
) -> bool:
    """Whether the contracted product term is currently open (half-open interval)."""
    del row, unavailable
    return license_status(settings, now=now).product_active


def lariska_entitled(
    settings: Settings,
    *,
    now: datetime | None = None,
    row: models.ProductLicense | None = None,
    unavailable: bool = False,
) -> bool:
    del row, unavailable
    return license_status(settings, now=now).lariska


def brand_watch_entitled(
    settings: Settings,
    *,
    now: datetime | None = None,
    row: models.ProductLicense | None = None,
    unavailable: bool = False,
) -> bool:
    del row, unavailable
    return license_status(settings, now=now).brand_watch


def _refuse(status: LicenseStatus, what: str) -> None:
    if status.reason == _STORE_REASON:
        raise LicenseStoreUnavailable(f"{what} refused: product license store unavailable")
    if status.reason == _PIN_REASON:
        raise LicenseMissing(f"{what} refused: {_PIN_REASON}")
    if status.reason == _SIGNATURE_REASON:
        raise LicenseMissing(
            f"{what} refused: product license signature does not match the pinned public key"
        )
    if not status.product_active:
        if status.reason == "license not yet valid":
            raise LicenseNotYetValid(
                f"{what} refused: product license not valid until {status.valid_from}"
            )
        if status.installed:
            raise LicenseExpired(f"{what} refused: product license expired")
        raise LicenseMissing(f"{what} refused: no active product license")
    raise LicenseFeatureDenied(f"{what} is not enabled on the active license")


def assert_new_scan_allowed(settings: Settings, *, now: datetime | None = None) -> None:
    """Hard gate for every new scan start path."""
    status = license_status(settings, now=now)
    if status.new_scans_allowed:
        return
    if status.reason in {_STORE_REASON, _PIN_REASON, _SIGNATURE_REASON}:
        _refuse(status, "Scan start")
    if not status.installed and status.enforcement_enabled:
        raise LicenseMissing("Scan start refused: no product license installed")
    if status.installed and not status.product_active:
        _refuse(status, "Scan start")
    if not settings.allow_scan_start:
        raise RuntimeError("Scan start disabled by OCTO_ALLOW_SCAN_START")
    raise LicenseMissing("Scan start refused: product license not active")


def assert_lariska(settings: Settings, *, now: datetime | None = None) -> None:
    status = license_status(settings, now=now)
    if status.lariska:
        return
    _refuse(status, "Lariska")


def assert_brand_watch(settings: Settings, *, now: datetime | None = None) -> None:
    status = license_status(settings, now=now)
    if status.brand_watch:
        return
    _refuse(status, "Brand Watch")


def brand_watch_overlay(
    settings: Settings,
    config_extra: dict[str, Any] | None = None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Force ``discovery.domain_monitor`` off when Brand Watch is not entitled.

    Defense in depth for the scan pipeline. The product gate is
    :func:`assert_brand_watch` on the brand-watch API and dispatcher — this
    overlay does not implement that product.
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
    """Verify and activate a license document, deactivating any previous one.

    A repeat upload of the same ``license_id`` is a new row. The previous
    active row is kept, inactive, so a rewritten term cannot erase the
    document that was in force.
    """
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

    pinned = (settings.license_public_key or "").strip()
    if not pinned:
        raise LicenseInvalid(f"{_PIN_REASON} to upload a product license")

    payload = verify_license(document, expected_public_key=pinned, environ={})
    moment = parse_utc(now or _now())
    raw_json = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    url = (settings.postgres_url or "").strip()
    if not url:
        raise LicenseStoreUnavailable("license store is not configured")

    last_error: IntegrityError | None = None
    for _attempt in range(2):
        try:
            with get_session(url) as session:
                session.execute(
                    update(models.ProductLicense)
                    .values(active=False)
                    .where(models.ProductLicense.active.is_(True))
                )
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
                session.flush()
            last_error = None
            break
        except IntegrityError as exc:
            # The partial unique index lost a race with another upload.
            last_error = exc
    if last_error is not None:
        raise LicenseInvalid(
            "another license upload won the race; retry"
        ) from last_error

    _log.info(
        "product license activated license_id=%s customer=%s expires_at=%s by=%s",
        payload.license_id,
        payload.customer_name,
        to_iso(payload.expires_at),
        uploaded_by,
    )
    return license_status(settings, now=moment)


def reset_for_tests(settings: Settings) -> None:
    """Drop installation-wide license rows (test isolation only).

    The table has no tenant foreign key, so ``tenants.reset_for_tests`` does
    not cascade into it. A row left behind would gate every later test.
    """
    url = (settings.postgres_url or "").strip()
    if not url:
        return
    with get_session(url) as session:
        session.execute(delete(models.ProductLicense))
