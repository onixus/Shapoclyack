"""OIDC single sign-on: discovery, JWKS, ID-token validation, state and nonce.

ROADMAP Track E listed "No SSO" as a gap that blocks a pilot outright. This
module is the provider-facing half of closing it; the routes that use it are in
``api/routes/auth.py`` and the account linking is in ``api/services/users.py``.

The flow is authorization code with PKCE (S256) against a generic provider
described by its ``.well-known/openid-configuration``. Choices worth stating:

* **Nothing about the provider is configured twice.** Endpoints and signing
  algorithms come from the discovery document, cached for
  ``oidc_cache_ttl_seconds``. Only the issuer, the client credentials and the
  redirect URI are operator-supplied, because those are the parts the provider
  cannot tell us.
* **The ID token is verified, never read.** Signature against the published
  JWKS, then ``iss``, ``aud``, ``exp``/``iat`` and ``nonce``. The signing
  algorithm is intersected with an asymmetric allowlist: a token is refused
  before ``alg`` is honoured, so neither ``none`` nor an HMAC algorithm keyed
  on a value the client publishes can ever be selected.
* **Key rotation is handled by refetching, once.** An unknown ``kid`` refreshes
  the JWKS past its cache and retries exactly one time. Retrying without a
  bound would make an unsigned-key token a way to hammer the provider.
* **State is signed *and* single-use.** The signed part (an HS256 JWT over the
  platform's own secret) proves the callback is answering a request this
  installation issued and bounds its lifetime; the server-side record proves it
  has not been answered already. The nonce and the PKCE verifier live only in
  that server-side record, so the browser never carries either.

The one-time record is process-local. That is deliberate rather than a
shortcut: the record lives for ``oidc_state_ttl_seconds`` (10 minutes by
default) between one browser redirect and its callback, and making it a table
would put a write on the unauthenticated login path. With more than one API
replica an authorization request must therefore come back to the replica that
issued it — see docs/configuration.md; installations behind a load balancer
enable session affinity for ``/api/auth/oidc/*``, exactly as they already do
for nothing else.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from api.settings import Settings

logger = logging.getLogger(__name__)

# Asymmetric only. The client secret is a *bearer* credential shared with the
# provider, so accepting an HMAC ``alg`` would let anyone holding it mint an
# ID token; "none" needs no comment.
ALLOWED_ID_TOKEN_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
)
DEFAULT_ID_TOKEN_ALGORITHMS = ("RS256",)
# Clock skew tolerated on exp/iat, matching api/core/security.py's decode leeway.
LEEWAY_SECONDS = 10
STATE_TOKEN_TYP = "oidc_state"
# A discovery document is JSON metadata; a JWKS is a handful of public keys.
# Neither is large, and an unbounded read from an operator-supplied URL is a
# memory-exhaustion primitive.
MAX_METADATA_BYTES = 512 * 1024


class OidcError(Exception):
    """Any refusal in the SSO flow. Carries no provider response body.

    The routes turn this into a 401 with this message, so nothing that reaches
    it may quote the client secret, the code, or a token — hence the deliberate
    absence of provider payloads in every message raised below.
    """


class OidcDisabledError(OidcError):
    """SSO was attempted on an installation that has not configured a provider."""


@dataclass(frozen=True)
class AuthorizationRequest:
    """What ``GET /api/auth/oidc/login`` hands the browser."""

    authorization_url: str
    state: str
    expires_in: int


@dataclass
class _StateRecord:
    """The server's half of one in-flight authorization request."""

    nonce: str
    code_verifier: str
    redirect_uri: str
    expires_at: float
    next_url: str = ""


@dataclass
class _CacheEntry:
    value: dict[str, Any]
    fetched_at: float = field(default_factory=time.monotonic)


_lock = threading.Lock()
_metadata_cache: dict[str, _CacheEntry] = {}
_jwks_cache: dict[str, _CacheEntry] = {}
_states: dict[str, _StateRecord] = {}

# Hard ceiling on pending (issued but unanswered) authorization requests. The
# login route is unauthenticated, so this is what stops it being a memory
# exhaustion primitive; see :func:`_prune_states`.
MAX_PENDING_STATES = 10_000


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def is_enabled(settings: Settings) -> bool:
    """True only when issuer, client id *and* client secret are all configured.

    A half-configured provider is a misconfiguration, not a partially enabled
    feature: reporting SSO as available and then failing at the redirect is
    strictly worse than reporting it as off.
    """
    return bool(
        settings.oidc_issuer.strip()
        and settings.oidc_client_id.strip()
        and settings.oidc_client_secret.strip()
    )


def redirect_uri(settings: Settings) -> str:
    """Where the provider sends the browser back.

    Derived from ``public_base_url`` when not set explicitly — never from the
    request's ``Host`` header, which the client writes. Whoever controls that
    header would otherwise choose where an authorization code is delivered.
    """
    configured = settings.oidc_redirect_uri.strip()
    if configured:
        return configured
    base = settings.public_base_url.strip().rstrip("/")
    if not base:
        raise OidcError(
            "OIDC redirect URI is not configured: set OCTO_OIDC_REDIRECT_URI or "
            "OCTO_PUBLIC_BASE_URL."
        )
    return f"{base}/api/auth/oidc/callback"


def public_config(settings: Settings) -> dict[str, Any]:
    """The unauthenticated feature flag the login page reads. No secrets.

    Reports only that SSO exists and what to call the button; deliberately not
    the issuer, which names the customer's identity provider to anyone who can
    reach the login form.
    """
    return {"enabled": is_enabled(settings), "login_url": "/api/auth/oidc/login"}


# --------------------------------------------------------------------------- #
# Provider metadata
# --------------------------------------------------------------------------- #


def _http_get_json(url: str, *, timeout: int) -> dict[str, Any]:
    """GET one JSON document. Seam the tests replace; no redirects are followed.

    ``urllib`` follows redirects by default, which on an operator-supplied URL
    is an SSRF pivot: the first hop passes review and the second one goes
    wherever the provider says. The opener below has no redirect handler, so a
    3xx surfaces as an error instead.
    """
    request = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:  # nosec B310 - https scheme checked below
            raw = response.read(MAX_METADATA_BYTES + 1)
    except urllib.error.URLError as exc:
        raise OidcError(f"OIDC provider request failed: {exc.reason}") from exc
    except OSError as exc:
        raise OidcError("OIDC provider request failed") from exc
    return _decode_json(raw)


def _http_post_form(url: str, form: dict[str, str], *, timeout: int) -> dict[str, Any]:
    """POST an ``application/x-www-form-urlencoded`` body and read back JSON.

    Used for the token endpoint only. Errors never quote the response body: it
    is the one place a provider echoes the client secret back on a bad request.
    """
    body = urllib.parse.urlencode(form).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:  # nosec B310 - https scheme checked below
            raw = response.read(MAX_METADATA_BYTES + 1)
    except urllib.error.HTTPError as exc:
        # Read and discard: the status is the whole of what may be reported.
        exc.close()
        raise OidcError(f"OIDC token exchange failed (HTTP {exc.code})") from None
    except urllib.error.URLError as exc:
        raise OidcError(f"OIDC token exchange failed: {exc.reason}") from exc
    except OSError as exc:
        raise OidcError("OIDC token exchange failed") from exc
    return _decode_json(raw)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102, ANN001
        raise OidcError("OIDC provider returned a redirect; refusing to follow it")


def _decode_json(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_METADATA_BYTES:
        raise OidcError("OIDC provider response is too large")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OidcError("OIDC provider returned a malformed response") from exc
    if not isinstance(parsed, dict):
        raise OidcError("OIDC provider returned a malformed response")
    return parsed


def _require_https(url: str, *, what: str) -> str:
    """Refuse a non-TLS provider URL outside a plain-HTTP loopback dev provider."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme == "https":
        return url
    if parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        return url
    raise OidcError(f"OIDC {what} must be an https URL")


def discovery_document(settings: Settings, *, force_refresh: bool = False) -> dict[str, Any]:
    """The provider's ``openid-configuration``, cached for the configured TTL.

    ``issuer`` inside the document must equal the configured issuer: without
    that check a provider (or anyone who can answer for its discovery URL)
    could point the flow at endpoints belonging to a different issuer while
    tokens continued to validate against the name we expected.
    """
    if not is_enabled(settings):
        raise OidcDisabledError("OIDC single sign-on is not configured")
    issuer = settings.oidc_issuer.strip().rstrip("/")
    ttl = max(60, settings.oidc_cache_ttl_seconds)

    with _lock:
        cached = _metadata_cache.get(issuer)
        if cached is not None and not force_refresh and time.monotonic() - cached.fetched_at < ttl:
            return cached.value

    url = _require_https(f"{issuer}/.well-known/openid-configuration", what="issuer")
    document = _http_get_json(url, timeout=settings.oidc_http_timeout_seconds)
    if str(document.get("issuer", "")).rstrip("/") != issuer:
        raise OidcError("OIDC discovery document names a different issuer")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        value = document.get(key)
        if not isinstance(value, str) or not value:
            raise OidcError(f"OIDC discovery document is missing {key}")
        _require_https(value, what=key)

    with _lock:
        _metadata_cache[issuer] = _CacheEntry(document)
    return document


def jwks(settings: Settings, *, force_refresh: bool = False) -> dict[str, Any]:
    """The provider's signing keys, cached beside the discovery document."""
    document = discovery_document(settings)
    uri = str(document["jwks_uri"])
    ttl = max(60, settings.oidc_cache_ttl_seconds)

    with _lock:
        cached = _jwks_cache.get(uri)
        if cached is not None and not force_refresh and time.monotonic() - cached.fetched_at < ttl:
            return cached.value

    keys = _http_get_json(uri, timeout=settings.oidc_http_timeout_seconds)
    if not isinstance(keys.get("keys"), list):
        raise OidcError("OIDC JWKS document has no keys")
    with _lock:
        _jwks_cache[uri] = _CacheEntry(keys)
    return keys


def _signing_algorithms(document: dict[str, Any]) -> list[str]:
    advertised = document.get("id_token_signing_alg_values_supported")
    if not isinstance(advertised, list) or not advertised:
        return list(DEFAULT_ID_TOKEN_ALGORITHMS)
    allowed = [str(alg) for alg in advertised if str(alg) in ALLOWED_ID_TOKEN_ALGORITHMS]
    if not allowed:
        raise OidcError("OIDC provider advertises no acceptable ID-token signing algorithm")
    return allowed


def _candidate_keys(settings: Settings, id_token: str) -> list[Any]:
    """Every public key the token could have been signed by, best first.

    A ``kid`` names exactly one key, and a rotated key is the ordinary reason it
    is unknown, so one forced refresh is the fix. It is bounded to one because
    an attacker can otherwise turn "sign with a key you invented" into a request
    amplifier against the provider's JWKS endpoint.

    Without a ``kid`` there is nothing to match on, and a provider is entitled
    to publish several signing keys — so every one of them is a candidate and
    the signature decides. Returning only the first would reject a perfectly
    valid token for as long as the provider signs with any other published key,
    and no refresh would ever fix it.
    """
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as exc:
        raise OidcError("ID token is malformed") from exc
    kid = header.get("kid")

    candidates: list[Any] = []
    for force in (False, True):
        key_set = jwks(settings, force_refresh=force)
        for raw_key in key_set.get("keys", []):
            if not isinstance(raw_key, dict):
                continue
            if kid is not None and raw_key.get("kid") != kid:
                continue
            if raw_key.get("use") not in (None, "sig"):
                continue
            try:
                candidates.append(jwt.PyJWK(raw_key).key)
            except Exception as exc:  # noqa: BLE001 - malformed key in a public document
                logger.warning("Skipping an unusable OIDC signing key: %s", exc)
                continue
        if candidates:
            return candidates
    raise OidcError("ID token was signed by an unknown key")


def validate_id_token(settings: Settings, id_token: str, *, nonce: str) -> dict[str, Any]:
    """Verify an ID token and return its claims.

    Every failure is the same class with a short message: the caller turns them
    into one 401, because "which check failed" is information the presenter of
    a forged token does not need.
    """
    document = discovery_document(settings)
    candidates = _candidate_keys(settings, id_token)
    claims: dict[str, Any] | None = None
    signature_error: jwt.PyJWTError | None = None
    for key in candidates:
        try:
            claims = jwt.decode(
                id_token,
                key,
                algorithms=_signing_algorithms(document),
                audience=settings.oidc_client_id,
                issuer=settings.oidc_issuer.strip().rstrip("/"),
                leeway=LEEWAY_SECONDS,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
            break
        except jwt.InvalidSignatureError as exc:
            # Only a signature mismatch is worth trying the next key on: every
            # other failure is a property of the token itself and would repeat.
            signature_error = exc
            continue
        except jwt.ExpiredSignatureError as exc:
            raise OidcError("ID token has expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise OidcError("ID token was issued for a different audience") from exc
        except jwt.InvalidIssuerError as exc:
            raise OidcError("ID token was issued by a different issuer") from exc
        except jwt.PyJWTError as exc:
            raise OidcError("ID token failed validation") from exc
    if claims is None:
        raise OidcError("ID token failed validation") from signature_error

    # ``azp`` is only meaningful when several audiences are present, but when it
    # is present it must be us: a token minted for another client of the same
    # provider would otherwise pass the audience check by listing us alongside.
    azp = claims.get("azp")
    if azp is not None and str(azp) != settings.oidc_client_id:
        raise OidcError("ID token was issued for a different client")

    presented = claims.get("nonce")
    if not isinstance(presented, str) or not secrets.compare_digest(presented, nonce):
        raise OidcError("ID token nonce does not match the authorization request")
    return claims


# --------------------------------------------------------------------------- #
# State, nonce and PKCE
# --------------------------------------------------------------------------- #


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _prune_states(now: float) -> None:
    """Drop expired records, then cap what is left. Called under ``_lock``.

    Expiry alone is not a bound: ``/api/auth/oidc/login`` is unauthenticated, so
    anyone able to reach it can mint records faster than they age out and grow
    this dict until the replica dies. The cap makes the store cost a fixed
    amount of memory; the price of hitting it is that the oldest pending logins
    are forgotten, and a login whose record is gone fails closed at
    :func:`consume_state` and can simply be retried.
    """
    for jti in [jti for jti, record in _states.items() if record.expires_at <= now]:
        _states.pop(jti, None)
    overflow = len(_states) - MAX_PENDING_STATES
    if overflow > 0:
        oldest = sorted(_states.items(), key=lambda item: item[1].expires_at)[:overflow]
        for jti, _record in oldest:
            _states.pop(jti, None)
        logger.warning(
            "OIDC pending-login store hit its %d-record cap; dropped %d of the oldest.",
            MAX_PENDING_STATES,
            overflow,
        )


def build_authorization_request(
    settings: Settings, *, next_url: str = ""
) -> AuthorizationRequest:
    """Start one SSO login: mint state, nonce and a PKCE verifier.

    The nonce and the verifier stay here; the browser receives only the signed
    state, which is an opaque JWT carrying an id and an expiry. That is what
    makes a stolen state useless on its own — it cannot be replayed (the record
    is consumed) and it discloses nothing about the exchange it belongs to.
    """
    document = discovery_document(settings)
    uri = redirect_uri(settings)
    ttl = max(30, settings.oidc_state_ttl_seconds)

    jti = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(24)
    code_verifier = secrets.token_urlsafe(48)
    challenge = _b64url(hashlib.sha256(code_verifier.encode("ascii")).digest())

    now = time.monotonic()
    with _lock:
        _states[jti] = _StateRecord(
            nonce=nonce,
            code_verifier=code_verifier,
            redirect_uri=uri,
            expires_at=now + ttl,
            next_url=next_url,
        )
        # After the insert, so the cap bounds what the store actually holds
        # rather than what it held one request ago.
        _prune_states(now)

    state = jwt.encode(
        {
            "typ": STATE_TOKEN_TYP,
            "jti": jti,
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(seconds=ttl),
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )

    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": settings.oidc_client_id,
            "redirect_uri": uri,
            "scope": settings.oidc_scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    authorize = str(document["authorization_endpoint"])
    separator = "&" if urllib.parse.urlsplit(authorize).query else "?"
    return AuthorizationRequest(
        authorization_url=f"{authorize}{separator}{query}", state=state, expires_in=ttl
    )


def consume_state(settings: Settings, state: str) -> _StateRecord:
    """Verify a returned state and spend it. A second use is refused.

    Both halves matter and neither substitutes for the other: the signature
    proves this installation issued the request, and removing the record proves
    nobody has answered it yet. A replayed callback — the same code and state
    delivered twice — therefore stops here rather than at the provider.
    """
    try:
        payload = jwt.decode(
            state,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            leeway=LEEWAY_SECONDS,
            options={"require": ["exp", "jti"]},
        )
    except jwt.PyJWTError as exc:
        raise OidcError("Invalid or expired login state") from exc
    if payload.get("typ") != STATE_TOKEN_TYP:
        raise OidcError("Invalid or expired login state")

    jti = str(payload.get("jti") or "")
    now = time.monotonic()
    with _lock:
        _prune_states(now)
        record = _states.pop(jti, None)
    if record is None or record.expires_at <= now:
        raise OidcError("Invalid or expired login state")
    return record


def exchange_code(settings: Settings, *, code: str, record: _StateRecord) -> dict[str, Any]:
    """Trade the authorization code for the provider's token response."""
    document = discovery_document(settings)
    response = _http_post_form(
        str(document["token_endpoint"]),
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": record.redirect_uri,
            "client_id": settings.oidc_client_id,
            "client_secret": settings.oidc_client_secret,
            "code_verifier": record.code_verifier,
        },
        timeout=settings.oidc_http_timeout_seconds,
    )
    id_token = response.get("id_token")
    if not isinstance(id_token, str) or not id_token:
        raise OidcError("OIDC token response carried no ID token")
    return response


def complete_callback(settings: Settings, *, code: str, state: str) -> dict[str, Any]:
    """The whole callback: spend the state, exchange the code, verify the token.

    Returns the validated ID-token claims. Account linking is a separate step
    (``api.services.users.resolve_oidc_identity``) so that "who does the
    provider say this is" and "which console account is that" stay two
    questions with two answers.
    """
    record = consume_state(settings, state)
    tokens = exchange_code(settings, code=code, record=record)
    claims = validate_id_token(settings, str(tokens["id_token"]), nonce=record.nonce)
    return {"claims": claims, "next_url": record.next_url}


# --------------------------------------------------------------------------- #
# Claim mapping
# --------------------------------------------------------------------------- #

_ROLE_RANK = {"viewer": 1, "operator": 2, "admin": 3}


def username_from_claims(settings: Settings, claims: dict[str, Any]) -> str:
    """Console username for these claims, in the operator's configured order.

    Falls back ``configured claim -> email -> sub`` so a provider that does not
    issue ``preferred_username`` still yields a stable, non-empty name.
    """
    for key in (settings.oidc_username_claim, "email", "sub"):
        if not key:
            continue
        value = claims.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:128]
    raise OidcError("ID token carries no usable username claim")


def email_verified_from_claims(claims: dict[str, Any]) -> bool:
    """Whether the provider vouches for the address, read strictly.

    ``bool()`` is the wrong test: OpenID Connect defines ``email_verified`` as a
    boolean, but providers do emit it as the *string* ``"false"``, and every
    non-empty string is truthy. Reading one as verified is exactly the
    account-takeover this claim is supposed to prevent, so only a real ``True``
    and the two unambiguous spellings of it count; anything else — including a
    value shaped in some way this does not recognise — is unverified.
    """
    value = claims.get("email_verified")
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1")
    return False


def role_from_claims(settings: Settings, claims: dict[str, Any]) -> str:
    """Console role for these claims: the highest mapped value, else the default.

    An unmapped group contributes nothing rather than falling to a role, so
    adding a group at the identity provider cannot quietly grant console
    access on its own.
    """
    claim = settings.oidc_role_claim.strip()
    if not claim or not settings.oidc_role_map:
        return settings.oidc_default_role
    raw = claims.get(claim)
    values: list[str]
    if isinstance(raw, str):
        values = [raw]
    elif isinstance(raw, (list, tuple)):
        values = [str(item) for item in raw]
    else:
        values = []
    mapped = [settings.oidc_role_map[value] for value in values if value in settings.oidc_role_map]
    if not mapped:
        return settings.oidc_default_role
    return max(mapped, key=lambda role: _ROLE_RANK.get(role, 0))


def tenant_from_claims(settings: Settings, claims: dict[str, Any]) -> str:
    """Tenant a provisioned account is granted membership in."""
    claim = settings.oidc_tenant_claim.strip()
    if claim:
        value = claims.get(claim)
        if isinstance(value, str) and value.strip():
            return value.strip()[:64]
    return settings.oidc_default_tenant


def reset_for_tests() -> None:
    """Drop the discovery/JWKS caches and every in-flight authorization request."""
    with _lock:
        _metadata_cache.clear()
        _jwks_cache.clear()
        _states.clear()
