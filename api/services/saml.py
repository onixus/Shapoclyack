"""SAML 2.0 service provider: metadata, signed SSO, encrypted assertions and SLO (#317)."""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from sqlalchemy import delete

from api.db import models
from api.db.engine import get_session
from api.services import egress
from api.services.federated import (
    FederatedIdentity,
    attribute_values,
    first_attribute,
    listed_groups,
    role_for_groups,
)
from api.settings import Settings

logger = logging.getLogger(__name__)
MAX_METADATA_BYTES = 2 * 1024 * 1024


class SamlError(Exception):
    pass


class SamlDisabledError(SamlError):
    pass


@dataclass(frozen=True)
class SamlLogin:
    authorization_url: str
    relay_state: str
    expires_in: int


@dataclass(frozen=True)
class CompletedSamlLogin:
    identity: FederatedIdentity
    next_url: str


@dataclass(frozen=True)
class _PendingRequest:
    request_id: str
    next_url: str
    expires_at: datetime


@dataclass
class _MetadataCache:
    value: dict[str, Any]
    fetched_at: float = field(default_factory=time.monotonic)


_cache_lock = threading.Lock()
_metadata_cache: dict[str, _MetadataCache] = {}


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def is_enabled(settings: Settings) -> bool:
    sources = bool(settings.saml_idp_metadata_url) ^ bool(settings.saml_idp_metadata_path)
    keys_ready = bool(settings.saml_sp_x509_cert and settings.saml_sp_private_key)
    needs_keys = settings.saml_require_encrypted_assertion or settings.saml_sign_requests
    return bool(settings.saml_sp_entity_id and sources and (keys_ready or not needs_keys))


def _https_url(value: str, *, what: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme == "https":
        return value
    if parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        return value
    raise SamlError(f"SAML {what} must be an https URL")


def acs_url(settings: Settings) -> str:
    if settings.saml_acs_url:
        return settings.saml_acs_url
    if not settings.public_base_url:
        raise SamlError("SAML ACS URL is not configured")
    return f"{settings.public_base_url.rstrip('/')}/api/auth/saml/acs"


def slo_url(settings: Settings) -> str:
    if settings.saml_slo_url:
        return settings.saml_slo_url
    if not settings.public_base_url:
        raise SamlError("SAML SLO URL is not configured")
    return f"{settings.public_base_url.rstrip('/')}/api/auth/saml/slo"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102, ANN001
        raise SamlError("SAML metadata endpoint returned a redirect")


def _http_get_metadata(url: str, *, timeout: int) -> bytes:
    request = urllib.request.Request(url, headers={"Accept": "application/xml, text/xml"})
    opener = egress.build_opener(url, _NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:  # nosec B310 - scheme checked by caller
            raw = response.read(MAX_METADATA_BYTES + 1)
    except (urllib.error.URLError, OSError) as exc:
        raise SamlError("SAML IdP metadata could not be fetched") from exc
    if len(raw) > MAX_METADATA_BYTES:
        raise SamlError("SAML IdP metadata is too large")
    return raw


def _metadata_source(settings: Settings) -> str:
    if settings.saml_idp_metadata_path:
        return str(Path(settings.saml_idp_metadata_path).resolve())
    return settings.saml_idp_metadata_url.strip()


def _read_metadata(settings: Settings) -> bytes:
    if settings.saml_idp_metadata_path:
        path = Path(settings.saml_idp_metadata_path)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise SamlError("SAML IdP metadata could not be read") from exc
        if len(raw) > MAX_METADATA_BYTES:
            raise SamlError("SAML IdP metadata is too large")
        return raw
    url = _https_url(settings.saml_idp_metadata_url, what="metadata URL")
    return _http_get_metadata(url, timeout=settings.saml_http_timeout_seconds)


def idp_metadata(settings: Settings, *, force_refresh: bool = False) -> dict[str, Any]:
    if not is_enabled(settings):
        raise SamlDisabledError("SAML single sign-on is not configured")
    source = _metadata_source(settings)
    ttl = max(60, settings.saml_metadata_cache_ttl_seconds)
    with _cache_lock:
        cached = _metadata_cache.get(source)
        if cached and not force_refresh and time.monotonic() - cached.fetched_at < ttl:
            return cached.value
    try:
        parsed = OneLogin_Saml2_IdPMetadataParser.parse(_read_metadata(settings))
    except Exception as exc:  # noqa: BLE001 - library exposes several XML/parser failures
        raise SamlError("SAML IdP metadata is invalid") from exc
    idp = parsed.get("idp")
    if not isinstance(idp, dict) or not idp.get("entityId"):
        raise SamlError("SAML IdP metadata has no entityId")
    sso = idp.get("singleSignOnService", {})
    _https_url(str(sso.get("url", "")), what="SSO URL")
    slo = idp.get("singleLogoutService", {})
    if slo:
        _https_url(str(slo.get("url", "")), what="SLO URL")
    with _cache_lock:
        _metadata_cache[source] = _MetadataCache(parsed)
    return parsed


def sp_settings(settings: Settings) -> dict[str, Any]:
    metadata = idp_metadata(settings)
    signed = settings.saml_sign_requests
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": settings.saml_sp_entity_id,
            "assertionConsumerService": {
                "url": acs_url(settings),
                "binding": OneLogin_Saml2_Constants.BINDING_HTTP_POST,
            },
            "singleLogoutService": {
                "url": slo_url(settings),
                "binding": OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT,
            },
            "NameIDFormat": OneLogin_Saml2_Constants.NAMEID_PERSISTENT,
            "x509cert": settings.saml_sp_x509_cert,
            "privateKey": settings.saml_sp_private_key,
        },
        "idp": metadata["idp"],
        "security": {
            "authnRequestsSigned": signed,
            "logoutRequestSigned": signed,
            "logoutResponseSigned": signed,
            "signMetadata": signed,
            "wantMessagesSigned": True,
            "wantAssertionsSigned": False,
            "wantAssertionsEncrypted": settings.saml_require_encrypted_assertion,
            "wantNameId": True,
            "wantAttributeStatement": False,
            "rejectDeprecatedAlgorithm": True,
            "signatureAlgorithm": OneLogin_Saml2_Constants.RSA_SHA256,
            "digestAlgorithm": OneLogin_Saml2_Constants.SHA256,
        },
    }


def request_data(
    settings: Settings,
    *,
    get_data: dict[str, Any] | None = None,
    post_data: dict[str, Any] | None = None,
    logout: bool = False,
) -> dict[str, Any]:
    """Build library request data from configured URLs, never the Host header."""
    parsed = urllib.parse.urlsplit(slo_url(settings) if logout else acs_url(settings))
    return {
        "https": "on" if parsed.scheme == "https" else "off",
        "http_host": parsed.netloc,
        "script_name": parsed.path,
        "get_data": get_data or {},
        "post_data": post_data or {},
    }


def _auth(settings: Settings, data: dict[str, Any]) -> OneLogin_Saml2_Auth:
    try:
        return OneLogin_Saml2_Auth(data, old_settings=sp_settings(settings))
    except Exception as exc:  # noqa: BLE001
        raise SamlError("SAML provider configuration is invalid") from exc


def metadata_xml(settings: Settings) -> str:
    try:
        document = OneLogin_Saml2_Settings(sp_settings(settings)).get_sp_metadata()
        return document.decode("utf-8") if isinstance(document, bytes) else document
    except Exception as exc:  # noqa: BLE001
        raise SamlError("SAML SP metadata could not be generated") from exc


def _relay_hash(relay_state: str) -> str:
    return hashlib.sha256(relay_state.encode("utf-8")).hexdigest()


def _store_request(
    settings: Settings, request_id: str, relay_state: str, *, kind: str, next_url: str = ""
) -> None:
    now = _now()
    if not request_id:
        raise SamlError("SAML request has no id")
    with get_session(settings.postgres_url) as session:
        session.execute(
            delete(models.SamlPendingRequest).where(models.SamlPendingRequest.expires_at <= now)
        )
        session.add(
            models.SamlPendingRequest(
                request_id=request_id,
                relay_state_hash=_relay_hash(relay_state),
                kind=kind,
                next_url=next_url,
                created_at=now,
                expires_at=now + timedelta(seconds=max(30, settings.saml_state_ttl_seconds)),
            )
        )


def _consume_request(settings: Settings, relay_state: str, *, kind: str) -> _PendingRequest:
    if not relay_state:
        raise SamlError("SAML response has no RelayState")
    with get_session(settings.postgres_url) as session:
        row = session.execute(
            delete(models.SamlPendingRequest)
            .where(
                models.SamlPendingRequest.relay_state_hash == _relay_hash(relay_state),
                models.SamlPendingRequest.kind == kind,
            )
            .returning(
                models.SamlPendingRequest.request_id,
                models.SamlPendingRequest.next_url,
                models.SamlPendingRequest.expires_at,
            )
        ).first()
    if row is None or row.expires_at <= _now():
        raise SamlError("SAML login state is invalid, expired or already used")
    return _PendingRequest(row.request_id, row.next_url, row.expires_at)


def begin_login(settings: Settings, *, next_url: str = "") -> SamlLogin:
    relay_state = secrets.token_urlsafe(32)
    auth = _auth(settings, request_data(settings))
    try:
        url = auth.login(return_to=relay_state)
    except Exception as exc:  # noqa: BLE001
        raise SamlError("SAML login request could not be created") from exc
    _store_request(settings, auth.get_last_request_id(), relay_state, kind="login", next_url=next_url)
    return SamlLogin(url, relay_state, max(30, settings.saml_state_ttl_seconds))


def complete_login(
    settings: Settings, *, saml_response: str, relay_state: str
) -> CompletedSamlLogin:
    pending = _consume_request(settings, relay_state, kind="login")
    auth = _auth(
        settings,
        request_data(settings, post_data={"SAMLResponse": saml_response, "RelayState": relay_state}),
    )
    try:
        auth.process_response(request_id=pending.request_id)
    except Exception as exc:  # noqa: BLE001
        raise SamlError("SAML response validation failed") from exc
    if auth.get_errors() or not auth.is_authenticated():
        logger.warning("SAML response refused: %s", ",".join(auth.get_errors()))
        raise SamlError("SAML response validation failed")
    subject = auth.get_nameid()
    if not subject:
        raise SamlError("SAML response has no NameID")
    attributes = auth.get_attributes()
    groups = listed_groups(
        attribute_values(attributes, settings.saml_groups_attribute),
        required=settings.idp_groups_claim_required,
    )
    username = first_attribute(attributes, settings.saml_username_attribute) or subject[:128]
    email = first_attribute(attributes, settings.saml_email_attribute) or None
    tenant_id = first_attribute(attributes, settings.saml_tenant_attribute) or settings.saml_default_tenant
    issuer = f"saml:{sp_settings(settings)['idp']['entityId']}"
    identity = FederatedIdentity(
        issuer=issuer,
        subject=subject,
        username=username,
        email=email,
        email_verified=bool(email and settings.saml_email_verified),
        role=role_for_groups(settings.oidc_role_map, groups, settings.saml_default_role),
        tenant_id=tenant_id,
        jit_enabled=settings.saml_jit_provisioning,
        groups=groups,
    )
    return CompletedSamlLogin(identity, pending.next_url)


def begin_logout(settings: Settings, *, next_url: str = "") -> SamlLogin:
    relay_state = secrets.token_urlsafe(32)
    data = request_data(settings, logout=True)
    auth = _auth(settings, data)
    try:
        url = auth.logout(return_to=relay_state)
    except Exception as exc:  # noqa: BLE001
        raise SamlError("SAML logout request could not be created") from exc
    _store_request(settings, auth.get_last_request_id(), relay_state, kind="logout", next_url=next_url)
    return SamlLogin(url, relay_state, max(30, settings.saml_state_ttl_seconds))


def complete_logout(settings: Settings, *, get_data: dict[str, Any]) -> str | None:
    relay_state = str(get_data.get("RelayState") or "")
    pending = _consume_request(settings, relay_state, kind="logout") if relay_state else None
    auth = _auth(settings, request_data(settings, get_data=get_data, logout=True))
    try:
        destination = auth.process_slo(request_id=pending.request_id if pending else None)
    except Exception as exc:  # noqa: BLE001
        raise SamlError("SAML logout validation failed") from exc
    if auth.get_errors():
        logger.warning("SAML logout refused: %s", ",".join(auth.get_errors()))
        raise SamlError("SAML logout validation failed")
    return destination or (pending.next_url if pending else None) or None


def reset_for_tests(settings: Settings | None = None) -> None:
    with _cache_lock:
        _metadata_cache.clear()
    if settings is not None:
        with get_session(settings.postgres_url) as session:
            session.execute(delete(models.SamlPendingRequest))
