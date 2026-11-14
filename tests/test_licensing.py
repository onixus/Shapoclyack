"""Product licensing: install, status, scan admission and Brand Watch soft-gate (ADR 0007)."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import delete

from api.db import models
from api.db.engine import get_session
from api.schemas import StartScanRequest
from api.services import jobs as jobs_service
from api.services import licensing
from api.services import tenants as tenants_service
from api.services.licensing import (
    LicenseExpired,
    LicenseMissing,
    LicenseNotYetValid,
    LicenseStoreUnavailable,
    build_payload,
    brand_watch_overlay,
    install_license,
    license_status,
    sign_license,
)
from api.settings import Settings
from tests.conftest import approve_scan_scope, make_settings, requires_postgres

pytestmark = requires_postgres


def _clear_licenses(settings: Settings) -> None:
    with get_session(settings.postgres_url) as session:
        session.execute(delete(models.ProductLicense))
        session.commit()


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    base = make_settings(
        tmp_path,
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "output",
        license_enforcement_enabled=False,
        license_public_key="",
        endpoint_inventory_enabled=True,
    )
    base.state_dir.mkdir(parents=True, exist_ok=True)
    base.output_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(base)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(base)
    licensing.configure(base)
    approve_scan_scope(base)
    _clear_licenses(base)
    return base


@pytest.fixture()
def signing_pair() -> tuple[bytes, str]:
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    public = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes_raw()
    )
    return seed, base64.b64encode(public).decode("ascii")


def _signed(
    seed: bytes,
    *,
    days: int = 30,
    lariska: bool = True,
    brand_watch: bool = False,
    valid_from: datetime | None = None,
    customer: str = "Test Customer",
) -> dict:
    payload = build_payload(
        customer_name=customer,
        days=days,
        lariska=lariska,
        brand_watch=brand_watch,
        valid_from=valid_from,
    )
    return sign_license(payload, private_key=seed)


def test_sign_install_status_roundtrip(settings: Settings, signing_pair: tuple[bytes, str]):
    seed, public_b64 = signing_pair
    settings.license_public_key = public_b64
    document = _signed(seed, days=30, lariska=True, brand_watch=True)

    status = install_license(document, settings=settings, uploaded_by="admin")

    assert status.installed is True
    assert status.product_active is True
    assert status.new_scans_allowed is True
    assert status.lariska is True
    assert status.brand_watch is True
    assert status.customer_name == "Test Customer"
    assert status.expires_at is not None

    again = license_status(settings)
    assert again.license_id == status.license_id
    assert again.as_dict()["features"]["brand_watch"] is True


def test_enforcement_on_without_license_raises_missing(
    settings: Settings, signing_pair: tuple[bytes, str]
):
    _, public_b64 = signing_pair
    settings.license_public_key = public_b64
    settings.license_enforcement_enabled = True
    status = license_status(settings)
    assert status.installed is False
    assert status.product_active is False
    assert status.new_scans_allowed is False

    with pytest.raises(LicenseMissing):
        licensing.assert_new_scan_allowed(settings)


def test_enforcement_requires_public_key_pin(settings: Settings):
    settings.license_enforcement_enabled = True
    settings.license_public_key = ""
    status = license_status(settings)
    assert status.new_scans_allowed is False
    assert status.reason == "enforcement requires OCTO_LICENSE_PUBLIC_KEY"
    with pytest.raises(LicenseMissing, match="OCTO_LICENSE_PUBLIC_KEY"):
        licensing.assert_new_scan_allowed(settings)


def test_enforcement_refuses_install_without_pin(
    settings: Settings, signing_pair: tuple[bytes, str]
):
    seed, _ = signing_pair
    settings.license_enforcement_enabled = True
    settings.license_public_key = ""
    with pytest.raises(licensing.LicenseInvalid, match="OCTO_LICENSE_PUBLIC_KEY"):
        install_license(_signed(seed, days=30), settings=settings, uploaded_by="admin")


def test_expired_license_blocks_start_scan(
    settings: Settings, signing_pair: tuple[bytes, str]
):
    seed, public_b64 = signing_pair
    settings.license_public_key = public_b64
    settings.license_enforcement_enabled = True

    past = datetime.now(UTC).replace(microsecond=0) - timedelta(days=60)
    document = _signed(seed, days=30, valid_from=past)
    install_license(document, settings=settings, uploaded_by="admin")

    with pytest.raises(LicenseExpired):
        licensing.assert_new_scan_allowed(settings)

    with pytest.raises(PermissionError):
        jobs_service.start_scan(
            settings, StartScanRequest(mode="balanced"), username="admin"
        )


def test_valid_license_allows_start_scan(
    settings: Settings, signing_pair: tuple[bytes, str]
):
    seed, public_b64 = signing_pair
    settings.license_public_key = public_b64
    settings.license_enforcement_enabled = True
    install_license(
        _signed(seed, days=30, lariska=True),
        settings=settings,
        uploaded_by="admin",
    )

    job = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced"), username="admin"
    )
    assert job.job_id


def test_brand_watch_overlay_forces_domain_monitor_off(
    settings: Settings, signing_pair: tuple[bytes, str]
):
    seed, public_b64 = signing_pair
    settings.license_public_key = public_b64
    install_license(
        _signed(seed, days=30, brand_watch=False),
        settings=settings,
        uploaded_by="admin",
    )
    assert licensing.brand_watch_entitled(settings) is False

    overlay = brand_watch_overlay(
        settings,
        {"discovery": {"domain_monitor": {"enabled": True}, "other": 1}},
    )
    assert overlay["discovery"]["domain_monitor"]["enabled"] is False
    assert overlay["discovery"]["other"] == 1


def test_brand_watch_entitled_keeps_overlay(
    settings: Settings, signing_pair: tuple[bytes, str]
):
    seed, public_b64 = signing_pair
    settings.license_public_key = public_b64
    install_license(
        _signed(seed, days=30, brand_watch=True),
        settings=settings,
        uploaded_by="admin",
    )
    assert licensing.brand_watch_entitled(settings) is True
    overlay = brand_watch_overlay(
        settings, {"discovery": {"domain_monitor": {"enabled": True}}}
    )
    assert overlay["discovery"]["domain_monitor"]["enabled"] is True


def test_grandfathered_no_license_when_enforcement_off(settings: Settings):
    """No row + enforcement off: product stays open (dev / upgrade path)."""
    status = license_status(settings)
    assert status.installed is False
    assert status.product_active is True
    assert status.new_scans_allowed is True
    licensing.assert_new_scan_allowed(settings)


def test_expired_license_blocks_even_when_enforcement_off(
    settings: Settings, signing_pair: tuple[bytes, str]
):
    """ADR: uploaded+expired is a hard stop regardless of the enforcement flag."""
    seed, public_b64 = signing_pair
    settings.license_public_key = public_b64
    settings.license_enforcement_enabled = False
    past = datetime.now(UTC).replace(microsecond=0) - timedelta(days=60)
    install_license(
        _signed(seed, days=30, valid_from=past),
        settings=settings,
        uploaded_by="admin",
    )
    with pytest.raises(LicenseExpired):
        licensing.assert_new_scan_allowed(settings)


def test_not_yet_valid_license_raises_not_yet_valid(
    settings: Settings, signing_pair: tuple[bytes, str]
):
    seed, public_b64 = signing_pair
    settings.license_public_key = public_b64
    settings.license_enforcement_enabled = True
    future = datetime.now(UTC).replace(microsecond=0) + timedelta(days=7)
    install_license(
        _signed(seed, days=30, valid_from=future),
        settings=settings,
        uploaded_by="admin",
    )
    with pytest.raises(LicenseNotYetValid, match="not valid until"):
        licensing.assert_new_scan_allowed(settings)


def test_store_unavailable_fails_closed(settings: Settings, monkeypatch: pytest.MonkeyPatch):
    """A Postgres blip must not reopen the product after an expired upload."""
    from api.services.licensing import service as licensing_service

    settings.license_enforcement_enabled = False

    def boom(_settings=None):
        return licensing_service._LicenseLookup(row=None, unavailable=True)

    monkeypatch.setattr(licensing_service, "_load_active", boom)
    status = license_status(settings)
    assert status.new_scans_allowed is False
    assert status.reason == "license store unavailable"
    with pytest.raises(LicenseStoreUnavailable):
        licensing.assert_new_scan_allowed(settings)
