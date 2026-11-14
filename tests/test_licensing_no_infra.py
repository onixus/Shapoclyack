"""Licensing gates that must work without Postgres (no-infra CI / unit paths)."""

from __future__ import annotations

from pathlib import Path

import pytest

from api.services import licensing
from tests.conftest import make_settings


def test_empty_postgres_url_is_grandfathered_without_querying(tmp_path: Path) -> None:
    """``start_scan`` unit tests have no ``OCTO_POSTGRES_URL``; licensing must not raise."""
    settings = make_settings(
        tmp_path,
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "output",
        postgres_url="",
        license_enforcement_enabled=False,
        allow_scan_start=True,
    )
    licensing.configure(settings)
    assert licensing.active_license(settings) is None
    status = licensing.license_status(settings)
    assert status.installed is False
    assert status.product_active is True
    licensing.assert_new_scan_allowed(settings)


def test_enforcement_on_empty_postgres_without_pin_refuses(tmp_path: Path) -> None:
    settings = make_settings(
        tmp_path,
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "output",
        postgres_url="",
        license_enforcement_enabled=True,
        license_public_key="",
        allow_scan_start=True,
    )
    licensing.configure(settings)
    with pytest.raises(licensing.LicenseMissing, match="OCTO_LICENSE_PUBLIC_KEY"):
        licensing.assert_new_scan_allowed(settings)
