"""Per-tenant report branding (Sprint 4).

An MSSP's deliverable carries the MSSP's name, not this platform's. Branding is
therefore a per-tenant row read at render time rather than an installation-wide
setting: one deployment serves many customers, and a global logo would put the
wrong one on every report but the first.

Validation happens on write, not on render. A malformed colour or an oversized
logo must fail the operator's PATCH — where somebody is looking — instead of
the quarterly render at 03:00 on the first of the month.
"""

from __future__ import annotations

import base64
import binascii
import re
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.settings import Settings

# 512 KiB of base64. A logo is a header image a few hundred pixels wide; the
# cap is what keeps a tenant from turning a JSON PATCH into a way to store a
# megabyte-per-row blob in the OLTP database.
MAX_LOGO_B64_BYTES = 512 * 1024

_HEX_COLOR = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

DEFAULT_PRIMARY = "#1e3a8a"
DEFAULT_ACCENT = "#3b82f6"


class BrandingError(ValueError):
    """Invalid branding input; surfaced as a 400 rather than a 500 at render."""


def _now() -> datetime:
    return datetime.now(UTC)


def _validate_color(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if not _HEX_COLOR.match(value):
        raise BrandingError(f"{field} must be a hex colour such as #1e3a8a")
    return value


def _validate_logo(value: str | None) -> str | None:
    """A base64 PNG, checked for being both base64 and a PNG.

    The magic-number check is not cosmetic: without it the field accepts any
    bytes an operator can base64, and the renderer would be handed something it
    hands straight to the PDF library."""

    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if len(value) > MAX_LOGO_B64_BYTES:
        raise BrandingError(f"logo_png exceeds {MAX_LOGO_B64_BYTES} base64 bytes")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BrandingError("logo_png must be base64-encoded") from exc
    if not raw.startswith(_PNG_MAGIC):
        raise BrandingError("logo_png must be a PNG image")
    return value


def _to_dict(row: models.TenantBranding | None, tenant_id: str) -> dict[str, Any]:
    if row is None:
        return {
            "tenant_id": tenant_id,
            "org_name": None,
            "primary_color": DEFAULT_PRIMARY,
            "accent_color": DEFAULT_ACCENT,
            "logo_png": None,
            "footer_text": None,
            "contact_email": None,
            "updated_at": None,
            "updated_by": None,
        }
    return {
        "tenant_id": row.tenant_id,
        "org_name": row.org_name,
        "primary_color": row.primary_color or DEFAULT_PRIMARY,
        "accent_color": row.accent_color or DEFAULT_ACCENT,
        "logo_png": row.logo_png,
        "footer_text": row.footer_text,
        "contact_email": row.contact_email,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "updated_by": row.updated_by,
    }


def get_branding(settings: Settings, *, tenant_id: str) -> dict[str, Any]:
    with get_session(settings.postgres_url) as session:
        row = session.execute(
            select(models.TenantBranding).where(models.TenantBranding.tenant_id == tenant_id)
        ).scalar_one_or_none()
        return _to_dict(row, tenant_id)


def set_branding(
    settings: Settings, *, tenant_id: str, actor: str | None = None, **fields: Any
) -> dict[str, Any]:
    """Upsert. Only the keys present in ``fields`` are written, so clearing the
    logo is an explicit ``logo_png=None`` and not a side effect of renaming."""

    updates: dict[str, Any] = {}
    if "primary_color" in fields:
        updates["primary_color"] = _validate_color(fields["primary_color"], "primary_color")
    if "accent_color" in fields:
        updates["accent_color"] = _validate_color(fields["accent_color"], "accent_color")
    if "logo_png" in fields:
        updates["logo_png"] = _validate_logo(fields["logo_png"])
    for key in ("org_name", "footer_text", "contact_email"):
        if key in fields:
            value = fields[key]
            updates[key] = value.strip() if isinstance(value, str) and value.strip() else None

    with get_session(settings.postgres_url) as session:
        row = session.execute(
            select(models.TenantBranding).where(models.TenantBranding.tenant_id == tenant_id)
        ).scalar_one_or_none()
        if row is None:
            row = models.TenantBranding(tenant_id=tenant_id, updated_at=_now())
            session.add(row)
        for key, value in updates.items():
            setattr(row, key, value)
        row.updated_at = _now()
        row.updated_by = actor
        session.commit()
        session.refresh(row)
        return _to_dict(row, tenant_id)
