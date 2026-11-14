"""Product licensing: signed entitlements for Lariska, Brand Watch, and term.

See docs/adr/0007-product-licensing.md. The offline generator lives under
``tools/license_gen``; this package verifies, stores, and answers entitlement
questions for the control plane.
"""

from __future__ import annotations

from api.services.licensing.errors import (
    LicenseError,
    LicenseExpired,
    LicenseFeatureDenied,
    LicenseInvalid,
    LicenseMissing,
)
from api.services.licensing.service import (
    LicenseStatus,
    active_license,
    assert_brand_watch,
    assert_lariska,
    assert_new_scan_allowed,
    brand_watch_entitled,
    brand_watch_overlay,
    configure,
    install_license,
    lariska_entitled,
    license_status,
    product_active,
)
from api.services.licensing.format import (
    FORMAT,
    VERSION,
    Features,
    LicensePayload,
    build_payload,
    calculate_expiry,
    sign_license,
    verify_license,
)

__all__ = [
    "FORMAT",
    "VERSION",
    "Features",
    "LicenseError",
    "LicenseExpired",
    "LicenseFeatureDenied",
    "LicenseInvalid",
    "LicenseMissing",
    "LicensePayload",
    "LicenseStatus",
    "active_license",
    "assert_brand_watch",
    "assert_lariska",
    "assert_new_scan_allowed",
    "brand_watch_entitled",
    "brand_watch_overlay",
    "build_payload",
    "calculate_expiry",
    "configure",
    "install_license",
    "lariska_entitled",
    "license_status",
    "product_active",
    "sign_license",
    "verify_license",
]
