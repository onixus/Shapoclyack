"""Provider-neutral identity mapping shared by SAML and LDAP (#317)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

_ROLE_RANK = {"viewer": 1, "operator": 2, "admin": 3}


@dataclass(frozen=True)
class FederatedIdentity:
    issuer: str
    subject: str
    username: str
    email: str | None
    email_verified: bool
    role: str
    tenant_id: str
    jit_enabled: bool
    groups: list[str] | None


def attribute_values(attributes: dict[str, Any], name: str) -> list[str] | None:
    if not name:
        return []
    if name not in attributes:
        return None
    raw = attributes[name]
    values = raw if isinstance(raw, (list, tuple)) else [raw]
    return [value.strip() for value in values if isinstance(value, str) and value.strip()]


def first_attribute(attributes: dict[str, Any], name: str) -> str:
    values = attribute_values(attributes, name) or []
    return values[0][:128] if values else ""


def role_for_groups(role_map: dict[str, str], groups: list[str] | None, default: str) -> str:
    mapped = [role_map[group] for group in groups or [] if group in role_map]
    return max(mapped, key=lambda role: _ROLE_RANK.get(role, 0)) if mapped else default


def listed_groups(groups: list[str] | None, *, required: bool) -> list[str] | None:
    return [] if groups is None and required else groups
