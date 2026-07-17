"""JWT encode/decode helpers (API gateway / agent exchange).

Secret resolution order:
  1. ``API_SECRET_KEY`` (plan name)
  2. ``OCTO_JWT_SECRET`` (existing Octo-man env)
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

DEFAULT_ALGORITHM = "HS256"
AGENT_TOKEN_TYP = "agent"
# Plan default for provisioning-key exchange TTL.
DEFAULT_EXCHANGE_TTL_MINUTES = 120


def get_api_secret_key() -> str:
    return (
        os.environ.get("API_SECRET_KEY", "").strip()
        or os.environ.get("OCTO_JWT_SECRET", "").strip()
        or "octo-man-dev-secret-change-me"
    )


def get_jwt_algorithm() -> str:
    return os.environ.get("OCTO_JWT_ALGORITHM", DEFAULT_ALGORITHM).strip() or DEFAULT_ALGORITHM


def encode_jwt(
    claims: dict[str, Any],
    *,
    secret: str | None = None,
    algorithm: str | None = None,
    expires_minutes: int = DEFAULT_EXCHANGE_TTL_MINUTES,
) -> str:
    """Encode claims into a signed JWT; adds ``iat`` / ``exp`` if missing."""
    payload = dict(claims)
    now = datetime.now(UTC)
    payload.setdefault("iat", now)
    if "exp" not in payload:
        payload["exp"] = now + timedelta(minutes=expires_minutes)
    return jwt.encode(
        payload,
        secret or get_api_secret_key(),
        algorithm=algorithm or get_jwt_algorithm(),
    )


def decode_jwt(
    token: str,
    *,
    secret: str | None = None,
    algorithm: str | None = None,
) -> dict[str, Any]:
    """Decode and verify a JWT; raises ``jwt.PyJWTError`` on failure."""
    return jwt.decode(
        token,
        secret or get_api_secret_key(),
        algorithms=[algorithm or get_jwt_algorithm()],
    )


def create_agent_exchange_token(
    *,
    tenant_id: str,
    agent_id: str,
    key_id: str | None = None,
    expires_minutes: int = DEFAULT_EXCHANGE_TTL_MINUTES,
    secret: str | None = None,
) -> str:
    """Short-lived agent JWT with ``tenant_id`` + ``agent_id`` (plan TASK 3)."""
    claims: dict[str, Any] = {
        "sub": agent_id,
        "typ": AGENT_TOKEN_TYP,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
    }
    if key_id:
        claims["key_id"] = key_id
    return encode_jwt(claims, secret=secret, expires_minutes=expires_minutes)
