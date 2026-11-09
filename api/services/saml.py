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
from lxml import etree
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

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
class SamlSubject:
    """The principal a LogoutRequest has to name. Stored on the console family."""

    name_id: str
    name_id_format: str = ""
    session_index: str = ""


@dataclass(frozen=True)
class CompletedSamlLogin:
    identity: FederatedIdentity
    next_url: str
    subject: SamlSubject


@dataclass(frozen=True)
class CompletedSamlLogout:
    """What a validated SLO message is allowed to end locally.

    ``message="response"`` is the IdP's reply to a logout this SP started:
    ``family_id`` is the only console family that logout may end.
    ``message="request"`` is an IdP-initiated LogoutRequest: end families with
    ``name_id`` and, when the request carries any, those ``session_indexes``.
    """

    next_url: str | None = None
    family_id: str | None = None
    name_id: str | None = None
    session_indexes: tuple[str, ...] = ()
    message: str = "response"


@dataclass(frozen=True)
class _PendingRequest:
    request_id: str
    next_url: str
    expires_at: datetime
    family_id: str = ""


_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol"


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
            # Sign-then-encrypt (Azure AD, Okta, ADFS) puts the signature on the
            # Assertion and then encrypts it. wantMessagesSigned still demands an
            # outer Response signature, which that profile does not have, and the
            # two flags are independent: they cannot express "either". Requiring
            # the Assertion signature accepts that profile. A Response signature
            # alone is not enough.
            "wantMessagesSigned": False,
            "wantAssertionsSigned": True,
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
    settings: Settings,
    request_id: str,
    relay_state: str,
    *,
    kind: str,
    next_url: str = "",
    family_id: str = "",
    expires_at: datetime | None = None,
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
                expires_at=expires_at
                or now + timedelta(seconds=max(30, settings.saml_state_ttl_seconds)),
                family_id=family_id or None,
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
                models.SamlPendingRequest.family_id,
            )
        ).first()
    if row is None or row.expires_at <= _now():
        raise SamlError("SAML login state is invalid, expired or already used")
    return _PendingRequest(row.request_id, row.next_url, row.expires_at, row.family_id or "")


def _peek_request(settings: Settings, relay_state: str, *, kind: str) -> _PendingRequest | None:
    """Read one pending row without deleting it. None when it is missing or expired."""
    if not relay_state:
        return None
    with get_session(settings.postgres_url) as session:
        row = session.execute(
            select(
                models.SamlPendingRequest.request_id,
                models.SamlPendingRequest.next_url,
                models.SamlPendingRequest.expires_at,
                models.SamlPendingRequest.family_id,
            ).where(
                models.SamlPendingRequest.relay_state_hash == _relay_hash(relay_state),
                models.SamlPendingRequest.kind == kind,
            )
        ).first()
    if row is None or row.expires_at <= _now():
        return None
    return _PendingRequest(row.request_id, row.next_url, row.expires_at, row.family_id or "")


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
    # python3-saml compares InResponseTo only when the attribute is present, so
    # an IdP-initiated Response (the attribute omitted) is otherwise accepted
    # and bound to whatever fresh RelayState the caller still holds.
    in_response_to = auth.get_last_response_in_response_to()
    if not in_response_to or in_response_to != pending.request_id:
        raise SamlError("SAML response is not a reply to this login")
    audiences = _assertion_audiences(auth.get_last_response_xml())
    if not settings.saml_sp_entity_id or settings.saml_sp_entity_id not in audiences:
        raise SamlError("SAML response audience is not this service provider")
    _remember_assertion(
        settings,
        auth.get_last_assertion_id(),
        auth.get_last_assertion_not_on_or_after(),
    )
    subject = auth.get_nameid()
    if not subject:
        raise SamlError("SAML response has no NameID")
    session_index = auth.get_session_index() or ""
    if isinstance(session_index, list):
        session_index = session_index[0] if session_index else ""
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
    return CompletedSamlLogin(
        identity,
        pending.next_url,
        SamlSubject(
            name_id=subject,
            name_id_format=str(auth.get_nameid_format() or ""),
            session_index=str(session_index or ""),
        ),
    )


def begin_logout(
    settings: Settings,
    *,
    name_id: str,
    next_url: str = "",
    name_id_format: str = "",
    session_index: str = "",
    family_id: str = "",
) -> SamlLogin:
    """Start SP-initiated SLO addressed to the NameID this session logged in with.

    A fresh ``OneLogin_Saml2_Auth`` has no NameID. Calling ``logout`` without
    one makes the toolkit send the SP entity NameID, which does not end the
    user's IdP session and can be aimed at the wrong principal.
    """
    if not name_id:
        raise SamlError("SAML logout has no NameID for this session")
    relay_state = secrets.token_urlsafe(32)
    data = request_data(settings, logout=True)
    auth = _auth(settings, data)
    try:
        url = auth.logout(
            return_to=relay_state,
            name_id=name_id,
            session_index=session_index or None,
            name_id_format=name_id_format or None,
        )
    except Exception as exc:  # noqa: BLE001
        raise SamlError("SAML logout request could not be created") from exc
    _store_request(
        settings,
        auth.get_last_request_id(),
        relay_state,
        kind="logout",
        next_url=next_url,
        family_id=family_id,
    )
    return SamlLogin(url, relay_state, max(30, settings.saml_state_ttl_seconds))


def complete_logout(settings: Settings, *, get_data: dict[str, Any]) -> CompletedSamlLogout:
    """Validate an SLO message, then forget pending state only if it validated.

    A RelayState on its own used to delete the pending logout before
    ``process_slo`` ran, so a forged callback burned the real one. An
    IdP-initiated LogoutRequest does not consume RelayState at all: the
    pending row belongs to the SP-initiated logout that is still in flight.
    """
    relay_state = str(get_data.get("RelayState") or "")
    if "SAMLResponse" in get_data:
        if not relay_state:
            raise SamlError("SAML logout response has no RelayState")
        pending = _peek_request(settings, relay_state, kind="logout")
        if pending is None:
            raise SamlError("SAML logout state is invalid, expired or already used")
        auth = _auth(settings, request_data(settings, get_data=get_data, logout=True))
        destination = _run_slo(auth, request_id=pending.request_id)
        _consume_request(settings, relay_state, kind="logout")
        return CompletedSamlLogout(
            next_url=destination or pending.next_url or None,
            family_id=pending.family_id or None,
            message="response",
        )
    if "SAMLRequest" in get_data:
        auth = _auth(settings, request_data(settings, get_data=get_data, logout=True))
        destination = _run_slo(auth, request_id=None)
        name_id, session_indexes = _logout_request_subject(auth.get_last_request_xml())
        if not name_id:
            raise SamlError("SAML logout request has no NameID")
        return CompletedSamlLogout(
            next_url=destination or None,
            name_id=name_id,
            session_indexes=session_indexes,
            message="request",
        )
    raise SamlError("SAML logout validation failed")


def _run_slo(auth: OneLogin_Saml2_Auth, *, request_id: str | None) -> str | None:
    try:
        destination = auth.process_slo(request_id=request_id)
    except Exception as exc:  # noqa: BLE001
        raise SamlError("SAML logout validation failed") from exc
    if auth.get_errors():
        logger.warning("SAML logout refused: %s", ",".join(auth.get_errors()))
        raise SamlError("SAML logout validation failed")
    return destination or None


def _assertion_audiences(xml: str | None) -> set[str]:
    """Audience values in a Response. The library does not store them on Auth.

    An assertion with no AudienceRestriction is not accepted: python3-saml
    skips the audience check when the element is absent.
    """
    if not xml:
        return set()
    try:
        root = etree.fromstring(xml.encode("utf-8") if isinstance(xml, str) else xml)
    except etree.XMLSyntaxError:
        return set()
    found: set[str] = set()
    for node in root.findall(f".//{{{_ASSERTION_NS}}}Audience"):
        if node.text and node.text.strip():
            found.add(node.text.strip())
    return found


def _remember_assertion(settings: Settings, assertion_id: str | None, not_on_or_after: Any) -> None:
    """Record an accepted assertion id until it expires. A second insert is a replay."""
    if not assertion_id:
        raise SamlError("SAML response has no assertion id")
    expires_at = _assertion_expiry(settings, not_on_or_after)
    key = f"assertion:{assertion_id}"
    try:
        _store_request(
            settings,
            key,
            key,
            kind="assertion",
            expires_at=expires_at,
        )
    except IntegrityError as exc:
        raise SamlError("SAML assertion was already used") from exc


def _assertion_expiry(settings: Settings, raw: Any) -> datetime:
    now = _now()
    expiry: datetime | None = None
    if isinstance(raw, datetime):
        expiry = raw.astimezone(UTC).replace(tzinfo=None) if raw.tzinfo else raw
    elif isinstance(raw, (int, float)) and raw > 0:
        expiry = datetime.fromtimestamp(raw, UTC).replace(tzinfo=None)
    elif isinstance(raw, str) and raw.strip():
        text = raw.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            parsed = None
        if parsed is not None:
            expiry = parsed.astimezone(UTC).replace(tzinfo=None) if parsed.tzinfo else parsed
    if expiry is None:
        expiry = now + timedelta(seconds=max(30, settings.saml_state_ttl_seconds))
    if expiry <= now:
        raise SamlError("SAML assertion has expired")
    return expiry


def _logout_request_subject(xml: str | None) -> tuple[str, tuple[str, ...]]:
    """NameID and SessionIndex values from a LogoutRequest. ``process_slo`` does not return them."""
    if not xml:
        return "", ()
    try:
        root = etree.fromstring(xml.encode("utf-8") if isinstance(xml, str) else xml)
    except etree.XMLSyntaxError:
        return "", ()
    name = root.find(f".//{{{_ASSERTION_NS}}}NameID")
    name_id = name.text.strip() if name is not None and name.text else ""
    indexes = tuple(
        node.text.strip()
        for node in root.findall(f".//{{{_PROTOCOL_NS}}}SessionIndex")
        if node.text and node.text.strip()
    )
    return name_id, indexes


def reset_for_tests(settings: Settings | None = None) -> None:
    with _cache_lock:
        _metadata_cache.clear()
    if settings is not None:
        with get_session(settings.postgres_url) as session:
            session.execute(delete(models.SamlPendingRequest))
