"""JWT encode/decode helpers (API gateway / agent exchange).

Secret resolution order:
  1. ``API_SECRET_KEY`` (plan name)
  2. ``OCTO_JWT_SECRET`` (existing Shapoclyack env)

Operator tokens and agent tokens are signed with **different** keys
(:func:`derive_agent_jwt_secret`), so a token minted for one audience does not
verify for the other even before the ``typ`` claim is looked at.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from api.settings import DEFAULT_JWT_SECRET, ENV_DEV, ENV_PROD, InsecureConfigurationError, load_settings

DEFAULT_ALGORITHM = "HS256"
# HS256 only, for now. The set used to carry every RS/ES/HS variant PyJWT can
# verify, which is a promise this installation cannot keep: there is one shared
# symmetric secret and no key material, no ``kid`` and no rotation path for the
# asymmetric families, so naming them only widened what a forged ``alg`` header
# could talk the decoder into. Adding RS256/EdDSA is a key-management change
# (see #312), and this set is where it lands when it is made.
ALLOWED_ALGORITHMS = frozenset({DEFAULT_ALGORITHM})
AGENT_TOKEN_TYP = "agent"
# HKDF-SHA256 ``info`` for the agent signing key. Fixed forever: changing it
# rotates every agent token at once.
AGENT_JWT_HKDF_INFO = b"shapoclyack-agent-jwt"
# Domain-separated prefix of sha256 over the signing key, published as the
# ``kid`` header so a verifier knows which key of a rotation window signed a
# token before it tries any of them. Sixteen hex characters: wide enough that
# two keys in one window do not collide, short enough to read in a log. It is a
# digest, so it does not carry the key — but a *guessable* key is still
# recoverable from it, which is one more reason OCTO_JWT_SECRET is 32 random
# bytes rather than a phrase (#314).
JWT_KID_DOMAIN = b"shapoclyack-jwt-kid:"
JWT_KID_LENGTH = 16
# Plan default for provisioning-key exchange TTL.
DEFAULT_EXCHANGE_TTL_MINUTES = 120
DEFAULT_DECODE_LEEWAY_SECONDS = 10


def get_api_secret_key() -> str:
    """The operator-token signing secret, from the environment.

    There is deliberately no literal fallback any more (#312). The old one
    returned the development secret that is printed in this repository whenever
    neither variable was set, so an install that reached this helper before
    ``load_settings()`` had refused to start signed real tokens with a published
    key. ``prod`` now raises and ``dev`` falls back to exactly what
    ``Settings.jwt_secret`` defaults to, so the two agree on what "unset" means.
    """
    secret = (
        os.environ.get("API_SECRET_KEY", "").strip()
        or os.environ.get("OCTO_JWT_SECRET", "").strip()
    )
    if secret:
        return secret
    if os.environ.get("OCTO_ENV", ENV_PROD).strip().lower() == ENV_DEV:
        return DEFAULT_JWT_SECRET
    raise InsecureConfigurationError(
        "OCTO_JWT_SECRET (or API_SECRET_KEY) is unset, so no JWT can be signed.\n"
        "    Generate one with: openssl rand -hex 32\n"
        f"    Set OCTO_ENV={ENV_DEV} to allow the built-in development secret."
    )


def derive_agent_jwt_secret(operator_secret: str) -> str:
    """Agent signing key derived from the operator secret via HKDF-SHA256.

    Agent JWTs used to be signed with ``settings.jwt_secret``, the same key as
    console sessions (#312): one leaked secret minted both an admin session and
    an agent token for any tenant, and neither key could be rotated without the
    other. A separate ``OCTO_AGENT_JWT_SECRET`` is the explicit answer, but
    requiring it would break every existing install on upgrade, so an unset one
    is derived here instead — different key material, no new variable.

    HKDF (RFC 5869) rather than a plain hash of the secret: extract-then-expand
    with a domain-separating ``info`` means the result is unusable as the
    operator key even if it leaks, and a future second derived key gets its own
    ``info`` rather than a second guessable hash of the same input.
    """
    # Empty salt is the RFC 5869 default and is what makes the derivation
    # deterministic across replicas, which is required: every API pod must
    # arrive at the same agent key or tokens stop verifying between them.
    prk = hmac.new(b"\x00" * hashlib.sha256().digest_size, operator_secret.encode("utf-8"), hashlib.sha256).digest()
    okm = hmac.new(prk, AGENT_JWT_HKDF_INFO + b"\x01", hashlib.sha256).digest()
    return okm.hex()


def jwt_kid(secret: str) -> str:
    """The ``kid`` header for one signing key (#314).

    A pure function of the key, so every replica computes the same value with
    nothing to configure and nothing to keep in step — which is what makes a
    rotation window work across a rolling deploy.
    """
    return hashlib.sha256(JWT_KID_DOMAIN + secret.encode("utf-8")).hexdigest()[:JWT_KID_LENGTH]


def get_jwt_algorithm() -> str:
    """The single configured JWT algorithm.

    Used to read ``OCTO_JWT_ALGORITHM`` on its own while ``Settings`` ignored
    the variable entirely (#312). Two sources meant an operator who set it
    changed what this module signed with and nothing else, so a token minted
    here no longer verified in :mod:`api.auth`. ``Settings`` is now the only
    source and validates the value at startup.
    """
    return load_settings().jwt_algorithm


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
    algo = algorithm or get_jwt_algorithm()
    if algo not in ALLOWED_ALGORITHMS:
        raise ValueError(f"Insecure or unsupported JWT algorithm: {algo!r}")
    key = secret or get_api_secret_key()
    # ``kid`` on agent tokens too (#314), for the same reason as on console
    # ones: mid-rotation the verifier has more than one key and should not have
    # to try each of them.
    return jwt.encode(
        payload,
        key,
        algorithm=algo,
        headers={"kid": jwt_kid(key)},
    )


def decode_jwt(
    token: str,
    *,
    secret: str | None = None,
    algorithm: str | None = None,
    leeway: int = DEFAULT_DECODE_LEEWAY_SECONDS,
) -> dict[str, Any]:
    """Decode and verify a JWT; raises ``jwt.PyJWTError`` on failure."""
    algo = algorithm or get_jwt_algorithm()
    if algo not in ALLOWED_ALGORITHMS:
        raise ValueError(f"Insecure or unsupported JWT algorithm: {algo!r}")
    return jwt.decode(
        token,
        secret or get_api_secret_key(),
        algorithms=[algo],
        leeway=leeway,
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
