"""License refusal exceptions.

``LicenseExpired`` and ``LicenseMissing`` are ``PermissionError`` subclasses so
routes that already map permission failures can reuse that path; the job
submission layer turns them into the same 403 style as ``allow_scan_start``.
"""

from __future__ import annotations


class LicenseError(Exception):
    """Base for every licensing refusal or verification failure."""


class LicenseInvalid(LicenseError, ValueError):
    """The document is malformed or the signature does not verify."""


class LicenseMissing(LicenseError, PermissionError):
    """Enforcement is on and no usable license is installed."""


class LicenseExpired(LicenseError, PermissionError):
    """The active license's product term has ended."""


class LicenseFeatureDenied(LicenseError, PermissionError):
    """The active license does not grant the requested feature."""
