"""OpenID Connect (OIDC) authentication and JIT user provisioning service (Sprint 1 IAM)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

import httpx
from sqlalchemy import select

from api.db.engine import get_session
from api.db.models import OIDCIdentity, Tenant, User, UserTenant
from api.settings import Settings

logger = logging.getLogger(__name__)

# Discovery & JWKS cache: issuer -> (timestamp, discovery_dict)
_DISCOVERY_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}


def generate_pkce() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256)."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    return verifier, challenge


def generate_state(settings: Settings, redirect_to: str = "/") -> str:
    """Generate a signed state parameter to protect against CSRF."""
    payload = {
        "nonce": secrets.token_hex(16),
        "ts": int(time.time()),
        "redirect_to": redirect_to,
    }
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    sig = hmac.new(settings.jwt_secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    encoded_payload = base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")
    return f"{encoded_payload}.{sig}"


def verify_state(settings: Settings, state: str, max_age_seconds: int = 600) -> dict[str, Any] | None:
    """Verify signed state parameter and check freshness."""
    if not state or "." not in state:
        return None
    try:
        encoded_payload, sig = state.split(".", 1)
        # Pad base64 if needed
        padding = "=" * ((4 - len(encoded_payload) % 4) % 4)
        raw = base64.urlsafe_b64decode(encoded_payload + padding)
        expected_sig = hmac.new(settings.jwt_secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        payload = json.loads(raw.decode("utf-8"))
        age = time.time() - payload.get("ts", 0)
        if age < 0 or age > max_age_seconds:
            return None
        return payload
    except Exception as exc:
        logger.warning("Failed to verify OIDC state: %s", exc)
        return None


def fetch_discovery_document(settings: Settings) -> dict[str, Any]:
    """Fetch and cache OpenID discovery document."""
    issuer = settings.oidc_issuer_url.rstrip("/")
    if not issuer:
        raise ValueError("OCTO_OIDC_ISSUER_URL is not configured")

    now = time.time()
    if issuer in _DISCOVERY_CACHE:
        cached_ts, cached_doc = _DISCOVERY_CACHE[issuer]
        if now - cached_ts < settings.oidc_jwks_cache_ttl_seconds:
            return cached_doc

    discovery_url = f"{issuer}/.well-known/openid-configuration"
    logger.info("Fetching OIDC discovery from %s", discovery_url)
    with httpx.Client(timeout=10.0) as client:
        resp = client.get(discovery_url)
        resp.raise_for_status()
        doc = resp.json()
        _DISCOVERY_CACHE[issuer] = (now, doc)
        return doc


def build_authorization_url(
    settings: Settings,
    state: str,
    redirect_uri: str | None = None,
    code_challenge: str | None = None,
) -> str:
    """Construct authorization redirect URL for Identity Provider."""
    doc = fetch_discovery_document(settings)
    auth_endpoint = doc.get("authorization_endpoint")
    if not auth_endpoint:
        raise ValueError("OIDC discovery missing 'authorization_endpoint'")

    cb_url = redirect_uri or settings.oidc_redirect_uri
    params = {
        "client_id": settings.oidc_client_id,
        "response_type": "code",
        "scope": settings.oidc_scopes,
        "redirect_uri": cb_url,
        "state": state,
    }
    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"

    return f"{auth_endpoint}?{urlencode(params)}"


def exchange_code(
    settings: Settings,
    code: str,
    redirect_uri: str | None = None,
    code_verifier: str | None = None,
) -> dict[str, Any]:
    """Exchange authorization code for tokens and fetch user claims."""
    doc = fetch_discovery_document(settings)
    token_endpoint = doc.get("token_endpoint")
    if not token_endpoint:
        raise ValueError("OIDC discovery missing 'token_endpoint'")

    cb_url = redirect_uri or settings.oidc_redirect_uri
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": cb_url,
        "client_id": settings.oidc_client_id,
        "client_secret": settings.oidc_client_secret,
    }
    if code_verifier:
        data["code_verifier"] = code_verifier

    with httpx.Client(timeout=10.0) as client:
        token_resp = client.post(token_endpoint, data=data)
        if token_resp.status_code != 200:
            logger.error("OIDC token exchange failed (%s): %s", token_resp.status_code, token_resp.text)
            raise ValueError(f"OIDC token exchange failed: {token_resp.text}")
        token_data = token_resp.json()

        access_token = token_data.get("access_token")
        userinfo_endpoint = doc.get("userinfo_endpoint")

        claims: dict[str, Any] = {}
        # Parse id_token payload without verification for basic claims fallback
        id_token = token_data.get("id_token")
        if id_token and "." in id_token:
            try:
                parts = id_token.split(".")
                if len(parts) >= 2:
                    padding = "=" * ((4 - len(parts[1]) % 4) % 4)
                    claims = json.loads(base64.urlsafe_b64decode(parts[1] + padding).decode("utf-8"))
            except Exception as exc:
                logger.warning("Could not parse id_token payload: %s", exc)

        # Fetch full userinfo endpoint if available
        if userinfo_endpoint and access_token:
            try:
                userinfo_resp = client.get(
                    userinfo_endpoint,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                if userinfo_resp.status_code == 200:
                    claims.update(userinfo_resp.json())
            except Exception as exc:
                logger.warning("Could not fetch userinfo: %s", exc)

        return claims


def resolve_role_from_claims(claims: dict[str, Any], settings: Settings) -> str:
    """Map claims to a platform role ('admin' | 'operator' | 'viewer')."""
    role_claim_name = settings.oidc_role_claim
    raw_roles = claims.get(role_claim_name)

    roles_list: list[str] = []
    if isinstance(raw_roles, list):
        roles_list = [str(r).lower() for r in raw_roles]
    elif isinstance(raw_roles, str):
        roles_list = [r.strip().lower() for r in raw_roles.split(",")]

    # Check realm/resource roles (e.g. Keycloak structure: realm_access.roles)
    if "realm_access" in claims and isinstance(claims["realm_access"], dict):
        realm_roles = claims["realm_access"].get("roles", [])
        if isinstance(realm_roles, list):
            roles_list.extend([str(r).lower() for r in realm_roles])

    if any(r in roles_list for r in ("admin", "administrator", "shapoclyack_admin")):
        return "admin"
    if any(r in roles_list for r in ("operator", "secops", "shapoclyack_operator")):
        return "operator"
    if any(r in roles_list for r in ("viewer", "reader", "auditor", "shapoclyack_viewer")):
        return "viewer"

    return settings.oidc_default_role


def provision_or_get_user(claims: dict[str, Any], settings: Settings) -> dict[str, Any]:
    """Just-In-Time (JIT) provision or update user from OIDC claims."""
    issuer = settings.oidc_issuer_url.rstrip("/")
    sub = str(claims.get("sub") or "")
    if not sub:
        raise ValueError("OIDC claims missing 'sub'")

    email = claims.get("email") or ""
    preferred_username = claims.get("preferred_username") or email.split("@")[0] if email else f"oidc_{sub[:8]}"
    username = str(preferred_username).strip()
    role = resolve_role_from_claims(claims, settings)

    now = datetime.now(UTC)

    with get_session(settings.postgres_url) as session:
        # Check existing identity link
        identity = session.scalar(
            select(OIDCIdentity).where(
                OIDCIdentity.issuer == issuer,
                OIDCIdentity.subject == sub,
            )
        )

        user: User | None = None
        if identity:
            user = session.get(User, identity.username)
            identity.last_login_at = now
            identity.claims = claims
            if email:
                identity.email = str(email)
        else:
            # Check if user with this username exists
            user = session.get(User, username)
            if not user and settings.oidc_auto_provision:
                user = User(
                    username=username,
                    password_hash="",  # Disabled password login
                    role=role,
                    created_at=now,
                    updated_at=now,
                    disabled_at=None,
                    created_by="oidc",
                )
                session.add(user)
                session.flush()

                # Ensure default tenant membership
                default_tenant = session.get(Tenant, "default")
                if not default_tenant:
                    default_tenant = Tenant(
                        tenant_id="default",
                        name="Default Tenant",
                        status="active",
                        created_at=now,
                    )
                    session.add(default_tenant)
                    session.flush()

                user_tenant = UserTenant(
                    username=username,
                    tenant_id="default",
                    role=role,
                    created_at=now,
                    created_by="oidc",
                )
                session.add(user_tenant)

            if not user:
                raise PermissionError(f"User '{username}' does not exist and auto-provisioning is disabled")

            # Create OIDC link
            identity = OIDCIdentity(
                username=user.username,
                issuer=issuer,
                subject=sub,
                email=str(email) if email else None,
                claims=claims,
                created_at=now,
                last_login_at=now,
            )
            session.add(identity)

        if user.disabled_at is not None:
            raise PermissionError("Account is disabled")

        session.commit()
        return {
            "username": user.username,
            "role": user.role,
            "email": email,
        }
