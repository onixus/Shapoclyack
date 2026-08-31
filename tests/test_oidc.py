"""OIDC discovery, ID-token validation, state/nonce and claim mapping (Track E).

No Postgres and no HTTP: the provider is a dictionary and the signing key is
generated in-process, so every property this module is responsible for — which
tokens it accepts and which it refuses — is asserted directly rather than
through a route.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from api.services import oidc
from api.settings import Settings

ISSUER = "https://idp.example.com"
CLIENT_ID = "shapoclyack-console"
KID = "key-1"
ROTATED_KID = "key-2"


def _keypair(kid: str):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(private.public_key()))
    jwk["kid"] = kid
    jwk["alg"] = "RS256"
    jwk["use"] = "sig"
    return private, jwk


PRIVATE_KEY, PUBLIC_JWK = _keypair(KID)
OTHER_PRIVATE_KEY, OTHER_PUBLIC_JWK = _keypair(KID)  # same kid, different key
ROTATED_PRIVATE_KEY, ROTATED_PUBLIC_JWK = _keypair(ROTATED_KID)

DISCOVERY = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/authorize",
    "token_endpoint": f"{ISSUER}/token",
    "jwks_uri": f"{ISSUER}/jwks",
    "id_token_signing_alg_values_supported": ["RS256"],
}


def make_settings(**overrides) -> Settings:
    base = Settings(
        env="dev",
        jwt_secret="test-secret",
        oidc_issuer=ISSUER,
        oidc_client_id=CLIENT_ID,
        oidc_client_secret="client-secret",
        oidc_redirect_uri=f"{ISSUER}/callback",
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


class FakeProvider:
    """Stands in for the provider's two GET endpoints and its token endpoint."""

    def __init__(self, *, discovery=None, keys=None):
        self.discovery = dict(discovery or DISCOVERY)
        self.keys = list(keys if keys is not None else [PUBLIC_JWK])
        self.get_calls: list[str] = []
        self.token_response: dict = {}
        self.form_calls: list[dict] = []

    def get_json(self, url, *, timeout):
        self.get_calls.append(url)
        if url.endswith("/.well-known/openid-configuration"):
            return self.discovery
        if url == self.discovery["jwks_uri"]:
            return {"keys": self.keys}
        raise AssertionError(f"unexpected GET {url}")

    def post_form(self, url, form, *, timeout):
        self.form_calls.append(form)
        return self.token_response


@pytest.fixture(autouse=True)
def _clean_caches():
    oidc.reset_for_tests()
    yield
    oidc.reset_for_tests()


@pytest.fixture
def provider(monkeypatch):
    fake = FakeProvider()
    monkeypatch.setattr(oidc, "_http_get_json", fake.get_json)
    monkeypatch.setattr(oidc, "_http_post_form", fake.post_form)
    return fake


def make_id_token(
    *,
    nonce: str,
    key=PRIVATE_KEY,
    kid: str = KID,
    audience: str = CLIENT_ID,
    issuer: str = ISSUER,
    expires_in: int = 300,
    **claims,
) -> str:
    now = datetime.now(UTC)
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": "idp-subject-1",
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
        "nonce": nonce,
    }
    payload.update(claims)
    headers = {"kid": kid} if kid is not None else {}
    return jwt.encode(payload, key, algorithm="RS256", headers=headers)


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def test_sso_is_off_until_every_credential_is_configured():
    assert oidc.is_enabled(make_settings()) is True
    assert oidc.is_enabled(make_settings(oidc_client_secret="")) is False
    assert oidc.is_enabled(make_settings(oidc_issuer="")) is False
    assert oidc.is_enabled(Settings()) is False


def test_public_config_names_no_provider():
    config = oidc.public_config(make_settings())
    assert config["enabled"] is True
    assert ISSUER not in json.dumps(config)


def test_redirect_uri_derives_from_the_configured_public_base_url():
    settings = make_settings(oidc_redirect_uri="", public_base_url="https://console.example/")
    assert oidc.redirect_uri(settings) == "https://console.example/api/auth/oidc/callback"


def test_redirect_uri_refuses_to_guess():
    settings = make_settings(oidc_redirect_uri="", public_base_url="")
    with pytest.raises(oidc.OidcError):
        oidc.redirect_uri(settings)


# --------------------------------------------------------------------------- #
# Discovery and JWKS
# --------------------------------------------------------------------------- #


def test_discovery_is_cached(provider):
    settings = make_settings()
    oidc.discovery_document(settings)
    oidc.discovery_document(settings)
    assert provider.get_calls.count(f"{ISSUER}/.well-known/openid-configuration") == 1


def test_discovery_refuses_a_document_naming_another_issuer(provider):
    provider.discovery = dict(DISCOVERY, issuer="https://evil.example")
    with pytest.raises(oidc.OidcError):
        oidc.discovery_document(make_settings())


def test_discovery_refuses_a_plain_http_issuer(provider):
    with pytest.raises(oidc.OidcError):
        oidc.discovery_document(make_settings(oidc_issuer="http://idp.example.com"))


def test_disabled_installation_raises_the_disabled_error(provider):
    with pytest.raises(oidc.OidcDisabledError):
        oidc.discovery_document(make_settings(oidc_client_secret=""))


def test_unknown_kid_refetches_the_key_set_once(provider):
    settings = make_settings()
    request = oidc.build_authorization_request(settings)
    record = oidc.consume_state(settings, request.state)

    # The provider rotated: the cached set still holds the old key only.
    oidc.jwks(settings)
    provider.keys = [ROTATED_PUBLIC_JWK]
    token = make_id_token(nonce=record.nonce, key=ROTATED_PRIVATE_KEY, kid=ROTATED_KID)

    claims = oidc.validate_id_token(settings, token, nonce=record.nonce)
    assert claims["sub"] == "idp-subject-1"
    assert provider.get_calls.count(DISCOVERY["jwks_uri"]) == 2


def test_a_key_that_never_appears_is_refused_after_one_refetch(provider):
    settings = make_settings()
    request = oidc.build_authorization_request(settings)
    record = oidc.consume_state(settings, request.state)
    token = make_id_token(nonce=record.nonce, key=ROTATED_PRIVATE_KEY, kid="never-published")

    with pytest.raises(oidc.OidcError):
        oidc.validate_id_token(settings, token, nonce=record.nonce)
    # One cached read plus exactly one forced refresh — not a retry loop.
    assert provider.get_calls.count(DISCOVERY["jwks_uri"]) == 2


# --------------------------------------------------------------------------- #
# ID token validation
# --------------------------------------------------------------------------- #


def _fresh_nonce(settings) -> str:
    request = oidc.build_authorization_request(settings)
    return oidc.consume_state(settings, request.state).nonce


def test_valid_id_token_is_accepted(provider):
    settings = make_settings()
    nonce = _fresh_nonce(settings)
    claims = oidc.validate_id_token(
        settings, make_id_token(nonce=nonce, email="a@example.com"), nonce=nonce
    )
    assert claims["email"] == "a@example.com"


def test_token_signed_by_another_key_is_refused(provider):
    settings = make_settings()
    nonce = _fresh_nonce(settings)
    token = make_id_token(nonce=nonce, key=OTHER_PRIVATE_KEY)
    with pytest.raises(oidc.OidcError):
        oidc.validate_id_token(settings, token, nonce=nonce)


def test_tampered_payload_is_refused(provider):
    settings = make_settings()
    nonce = _fresh_nonce(settings)
    header, payload, signature = make_id_token(nonce=nonce).split(".")
    # Any edit to the payload invalidates the signature, which is the point.
    tampered = f"{header}.{payload[:-2]}AA.{signature}"
    with pytest.raises(oidc.OidcError):
        oidc.validate_id_token(settings, tampered, nonce=nonce)


def test_expired_token_is_refused(provider):
    settings = make_settings()
    nonce = _fresh_nonce(settings)
    token = make_id_token(nonce=nonce, expires_in=-3600)
    with pytest.raises(oidc.OidcError, match="expired"):
        oidc.validate_id_token(settings, token, nonce=nonce)


def test_wrong_audience_is_refused(provider):
    settings = make_settings()
    nonce = _fresh_nonce(settings)
    token = make_id_token(nonce=nonce, audience="some-other-client")
    with pytest.raises(oidc.OidcError, match="audience"):
        oidc.validate_id_token(settings, token, nonce=nonce)


def test_wrong_issuer_is_refused(provider):
    settings = make_settings()
    nonce = _fresh_nonce(settings)
    token = make_id_token(nonce=nonce, issuer="https://evil.example")
    with pytest.raises(oidc.OidcError, match="issuer"):
        oidc.validate_id_token(settings, token, nonce=nonce)


def test_token_for_another_client_of_the_same_provider_is_refused(provider):
    """``aud`` may list several clients; ``azp`` says which one it is for."""
    settings = make_settings()
    nonce = _fresh_nonce(settings)
    token = make_id_token(nonce=nonce, azp="another-client")
    with pytest.raises(oidc.OidcError, match="client"):
        oidc.validate_id_token(settings, token, nonce=nonce)


def test_mismatched_nonce_is_refused(provider):
    settings = make_settings()
    nonce = _fresh_nonce(settings)
    token = make_id_token(nonce="a-nonce-from-another-request")
    with pytest.raises(oidc.OidcError, match="nonce"):
        oidc.validate_id_token(settings, token, nonce=nonce)


def test_missing_nonce_is_refused(provider):
    settings = make_settings()
    nonce = _fresh_nonce(settings)
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "s",
            "iat": now,
            "exp": now + timedelta(seconds=300),
        },
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": KID},
    )
    with pytest.raises(oidc.OidcError, match="nonce"):
        oidc.validate_id_token(settings, token, nonce=nonce)


def test_hmac_signed_token_is_never_accepted(provider):
    """The client secret is shared with the provider; an HMAC ``alg`` would
    make everyone holding it able to mint an ID token."""
    settings = make_settings()
    nonce = _fresh_nonce(settings)
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "s",
            "iat": now,
            "exp": now + timedelta(seconds=300),
            "nonce": nonce,
        },
        settings.oidc_client_secret,
        algorithm="HS256",
        headers={"kid": KID},
    )
    with pytest.raises(oidc.OidcError):
        oidc.validate_id_token(settings, token, nonce=nonce)


def test_provider_advertising_only_unacceptable_algorithms_is_refused(provider):
    provider.discovery = dict(DISCOVERY, id_token_signing_alg_values_supported=["HS256", "none"])
    settings = make_settings()
    nonce = _fresh_nonce(settings)
    with pytest.raises(oidc.OidcError):
        oidc.validate_id_token(settings, make_id_token(nonce=nonce), nonce=nonce)


# --------------------------------------------------------------------------- #
# State, nonce and PKCE
# --------------------------------------------------------------------------- #


def test_authorization_url_carries_pkce_and_state(provider):
    request = oidc.build_authorization_request(make_settings())
    assert request.authorization_url.startswith(f"{ISSUER}/authorize?")
    for expected in ("code_challenge=", "code_challenge_method=S256", "response_type=code"):
        assert expected in request.authorization_url
    assert f"state={request.state}" in request.authorization_url.replace("%2E", ".") or "state=" in request.authorization_url


def test_state_is_single_use(provider):
    settings = make_settings()
    request = oidc.build_authorization_request(settings)
    assert oidc.consume_state(settings, request.state).nonce
    with pytest.raises(oidc.OidcError):
        oidc.consume_state(settings, request.state)


def test_state_signed_by_another_installation_is_refused(provider):
    settings = make_settings()
    request = oidc.build_authorization_request(settings)
    with pytest.raises(oidc.OidcError):
        oidc.consume_state(make_settings(jwt_secret="a-different-secret"), request.state)


def test_expired_state_is_refused(provider, monkeypatch):
    settings = make_settings()
    request = oidc.build_authorization_request(settings)
    # Past the record's TTL: the signed half may still verify within its
    # leeway, but the server-side record is gone.
    later = time.monotonic() + settings.oidc_state_ttl_seconds + 60
    monkeypatch.setattr(oidc.time, "monotonic", lambda: later)
    with pytest.raises(oidc.OidcError):
        oidc.consume_state(settings, request.state)


def test_a_state_this_installation_never_issued_is_refused(provider):
    settings = make_settings()
    forged = jwt.encode(
        {
            "typ": oidc.STATE_TOKEN_TYP,
            "jti": "never-issued",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    with pytest.raises(oidc.OidcError):
        oidc.consume_state(settings, forged)


def test_nonce_and_verifier_never_reach_the_browser(provider):
    settings = make_settings()
    request = oidc.build_authorization_request(settings)
    record = oidc.consume_state(settings, request.state)
    # The nonce is in the authorize URL by protocol; the PKCE *verifier* is the
    # secret half and must not be.
    assert record.code_verifier not in request.authorization_url
    assert record.code_verifier not in request.state


def test_replayed_callback_is_refused_before_the_provider_is_called(provider):
    settings = make_settings()
    request = oidc.build_authorization_request(settings)
    record = oidc.consume_state(settings, request.state)
    provider.token_response = {"id_token": make_id_token(nonce=record.nonce)}
    provider.form_calls.clear()

    with pytest.raises(oidc.OidcError):
        oidc.complete_callback(settings, code="code-1", state=request.state)
    assert provider.form_calls == []


def test_complete_callback_exchanges_the_code_with_the_pkce_verifier(provider):
    settings = make_settings()
    request = oidc.build_authorization_request(settings)
    # Peek without spending it: read the record the service stored.
    stored = next(iter(oidc._states.values()))  # noqa: SLF001 - asserting the seam
    provider.token_response = {"id_token": make_id_token(nonce=stored.nonce, email="x@y.z")}

    completed = oidc.complete_callback(settings, code="code-1", state=request.state)
    assert completed["claims"]["email"] == "x@y.z"
    form = provider.form_calls[0]
    assert form["grant_type"] == "authorization_code"
    assert form["code_verifier"] == stored.code_verifier
    assert form["redirect_uri"] == settings.oidc_redirect_uri


def test_token_response_without_an_id_token_is_refused(provider):
    settings = make_settings()
    request = oidc.build_authorization_request(settings)
    provider.token_response = {"access_token": "opaque"}
    with pytest.raises(oidc.OidcError):
        oidc.complete_callback(settings, code="code-1", state=request.state)


# --------------------------------------------------------------------------- #
# Claim mapping
# --------------------------------------------------------------------------- #


def test_username_falls_back_through_the_configured_order():
    settings = make_settings()
    assert oidc.username_from_claims(settings, {"preferred_username": "kim"}) == "kim"
    assert oidc.username_from_claims(settings, {"email": "kim@x.z", "sub": "s"}) == "kim@x.z"
    assert oidc.username_from_claims(settings, {"sub": "s"}) == "s"
    with pytest.raises(oidc.OidcError):
        oidc.username_from_claims(settings, {})


def test_role_defaults_to_the_lowest_privileged_role():
    settings = make_settings()
    assert oidc.role_from_claims(settings, {"groups": ["anything"]}) == "viewer"


def test_role_map_takes_the_highest_matching_group():
    settings = make_settings(
        oidc_role_claim="groups",
        oidc_role_map={"vm-ops": "operator", "vm-admins": "admin"},
    )
    assert oidc.role_from_claims(settings, {"groups": ["vm-ops", "vm-admins"]}) == "admin"
    assert oidc.role_from_claims(settings, {"groups": ["vm-ops"]}) == "operator"
    # An unmapped group grants nothing of its own.
    assert oidc.role_from_claims(settings, {"groups": ["unrelated"]}) == "viewer"
    assert oidc.role_from_claims(settings, {"groups": "vm-admins"}) == "admin"


def test_tenant_comes_from_the_claim_when_one_is_configured():
    settings = make_settings(oidc_tenant_claim="tenant", oidc_default_tenant="default")
    assert oidc.tenant_from_claims(settings, {"tenant": "acme"}) == "acme"
    assert oidc.tenant_from_claims(settings, {}) == "default"


# --------------------------------------------------------------------------- #
# Key selection without a ``kid``
# --------------------------------------------------------------------------- #


def test_a_token_without_a_kid_is_accepted_whichever_published_key_signed_it(provider):
    """A provider may omit ``kid`` and still publish several signing keys.

    Taking only the first candidate rejected a perfectly valid token for as long
    as the provider signed with any other published key, and no refetch could
    fix it — the key was in the set all along.
    """
    provider.keys = [PUBLIC_JWK, ROTATED_PUBLIC_JWK]
    settings = make_settings()
    for signer in (PRIVATE_KEY, ROTATED_PRIVATE_KEY):
        nonce = _fresh_nonce(settings)
        token = make_id_token(nonce=nonce, key=signer, kid=None)
        claims = oidc.validate_id_token(settings, token, nonce=nonce)
        assert claims["sub"] == "idp-subject-1"


def test_a_token_without_a_kid_signed_by_no_published_key_is_still_refused(provider):
    provider.keys = [PUBLIC_JWK, ROTATED_PUBLIC_JWK]
    settings = make_settings()
    nonce = _fresh_nonce(settings)
    token = make_id_token(nonce=nonce, key=OTHER_PRIVATE_KEY, kid=None)
    with pytest.raises(oidc.OidcError):
        oidc.validate_id_token(settings, token, nonce=nonce)


def test_an_expired_token_is_not_retried_against_every_key(provider):
    """Only a signature mismatch is worth another key; the rest would repeat."""
    provider.keys = [PUBLIC_JWK, ROTATED_PUBLIC_JWK]
    settings = make_settings()
    nonce = _fresh_nonce(settings)
    token = make_id_token(nonce=nonce, kid=None, expires_in=-10)
    with pytest.raises(oidc.OidcError, match="expired"):
        oidc.validate_id_token(settings, token, nonce=nonce)


# --------------------------------------------------------------------------- #
# ``email_verified``
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("raw", [True, "true", "True", "1"])
def test_email_verified_accepts_a_real_affirmative(raw):
    assert oidc.email_verified_from_claims({"email_verified": raw}) is True


@pytest.mark.parametrize("raw", [False, "false", "False", "0", "", "no", None, 0, [], {}])
def test_email_verified_reads_anything_else_as_unverified(raw):
    """``bool("false")`` is ``True``, and providers do emit the claim as a string.

    Reading one as verified hands an existing console account to whoever can
    register that address at the identity provider — the exact takeover the
    linking rule exists to prevent.
    """
    assert oidc.email_verified_from_claims({"email_verified": raw}) is False


def test_email_verified_is_false_when_the_claim_is_absent():
    assert oidc.email_verified_from_claims({}) is False


# --------------------------------------------------------------------------- #
# Pending-state store
# --------------------------------------------------------------------------- #


def test_the_pending_state_store_is_capped(provider, monkeypatch):
    """``/auth/oidc/login`` is unauthenticated, so the store needs a ceiling."""
    monkeypatch.setattr(oidc, "MAX_PENDING_STATES", 5)
    settings = make_settings()
    states = [oidc.build_authorization_request(settings).state for _ in range(20)]
    assert len(oidc._states) <= 5
    # The most recent requests survive and still work; the evicted ones fail
    # closed rather than being honoured from a stale record.
    oidc.consume_state(settings, states[-1])
    with pytest.raises(oidc.OidcError):
        oidc.consume_state(settings, states[0])
