"""Security keys and passkeys as a second factor, end to end (#315).

The defect: the only second factor was a six-digit code, and a code is exactly
what a convincing copy of the login page relays in real time. Every test below
fails against the pre-WebAuthn API — most because the ceremony endpoints did
not exist, the policy ones because nothing could tell a key from a code.

The assertions are real. ``tests/soft_authenticator.py`` holds an ES256 key
and signs what a hardware key would sign; the API verifies it with the same
library it runs in production. The attacks are the knobs on that
authenticator: another origin (the phishing page), another RP ID, a counter
that does not move (a clone), and a challenge presented twice.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from tests.conftest import (
    auth_headers,
    bearer,
    configured_client,
    make_settings,
    requires_postgres,
)
from tests.soft_authenticator import SoftAuthenticator
from tests.test_api_mfa import Clock, enrol, password_login

pytestmark = requires_postgres

RP_ID = "console.example"
ORIGIN = "https://console.example"
PHISHING_ORIGIN = "https://console-example.login-help.net"


@pytest.fixture
def clock(monkeypatch) -> Clock:
    instance = Clock()
    monkeypatch.setattr("api.services.mfa._now", instance)
    return instance


def _settings(tmp_path, **overrides):
    return make_settings(
        tmp_path, webauthn_rp_id=RP_ID, webauthn_origins=[ORIGIN], **overrides
    )


def _client(tmp_path, monkeypatch, **overrides):
    return configured_client(tmp_path, monkeypatch, settings=_settings(tmp_path, **overrides))


def _step_up(client, headers, clock: Clock, secret: str) -> dict[str, str]:
    """A session with a fresh code-proved step-up, as the console gets it."""
    response = client.post(
        "/api/auth/mfa/verify", headers=headers, json={"code": clock.next_code(secret)}
    )
    assert response.status_code == 200, response.text
    return bearer(response.json()["access_token"])


def _register(client, headers, key: SoftAuthenticator, name: str = "YubiKey") -> dict:
    options = client.post("/api/auth/mfa/webauthn/register/options", headers=headers)
    assert options.status_code == 200, options.text
    body = options.json()
    created = client.post(
        "/api/auth/mfa/webauthn/register/verify",
        headers=headers,
        json={
            "challenge_id": body["challenge_id"],
            "credential": key.create(body["public_key"]),
            "name": name,
        },
    )
    assert created.status_code == 201, created.text
    return created.json()


def _enrolled_with_key(client, clock: Clock, username: str = "admin"):
    """TOTP enrolled, a key registered. Returns (secret, key, stepped-up headers)."""
    headers = auth_headers(client, username)
    secret, _ = enrol(client, headers, clock, username)
    fresh = _step_up(client, headers, clock, secret)
    key = SoftAuthenticator(ORIGIN)
    _register(client, fresh, key)
    return secret, key, fresh


def _login_options(client, mfa_token: str) -> dict:
    response = client.post(
        "/api/auth/mfa/webauthn/authenticate/options", json={"mfa_token": mfa_token}
    )
    assert response.status_code == 200, response.text
    return response.json()


def _verify(client, mfa_token: str | None, challenge_id: str, credential: dict, headers=None):
    payload: dict = {"webauthn": {"challenge_id": challenge_id, "credential": credential}}
    if mfa_token:
        payload["mfa_token"] = mfa_token
    return client.post("/api/auth/mfa/verify", json=payload, headers=headers or {})


# --------------------------------------------------------------------------- #
# The login leg
# --------------------------------------------------------------------------- #


def test_a_registered_key_completes_a_login(tmp_path, monkeypatch, clock):
    client = _client(tmp_path, monkeypatch)
    _, key, _ = _enrolled_with_key(client, clock)

    challenge = password_login(client)["mfa_token"]
    options = _login_options(client, challenge)
    # The browser is told which key to use, and for which relying party.
    assert options["public_key"]["rpId"] == RP_ID
    assert [item["id"] for item in options["public_key"]["allowCredentials"]] == [
        key.credential_id_b64
    ]

    verified = _verify(client, challenge, options["challenge_id"], key.get(options["public_key"]))
    assert verified.status_code == 200, verified.text
    session = bearer(verified.json()["access_token"])
    assert client.get("/api/users", headers=session).status_code == 200
    # The session records *which* factor proved it: the policy below reads it.
    assert client.get("/api/auth/me", headers=session).json()["mfa_method"] == "webauthn"


def test_the_signature_is_checked_not_just_the_shape(tmp_path, monkeypatch, clock):
    client = _client(tmp_path, monkeypatch)
    _, key, _ = _enrolled_with_key(client, clock)

    challenge = password_login(client)["mfa_token"]
    options = _login_options(client, challenge)
    impostor = ec.generate_private_key(ec.SECP256R1())
    forged = key.get(options["public_key"], signing_key=impostor)
    assert _verify(client, challenge, options["challenge_id"], forged).status_code == 401


def test_a_malformed_response_is_a_refusal_not_a_server_error(tmp_path, monkeypatch, clock):
    # Garbage is what an attacker sends first. A 500 would say something about
    # the parser, and would skip the limiter's failure count besides.
    client = _client(tmp_path, monkeypatch)
    _, key, fresh = _enrolled_with_key(client, clock)

    challenge = password_login(client)["mfa_token"]
    options = _login_options(client, challenge)
    garbled = key.get(options["public_key"])
    garbled["response"]["userHandle"] = "!!not base64!!"
    assert _verify(client, challenge, options["challenge_id"], garbled).status_code == 401

    registration = client.post("/api/auth/mfa/webauthn/register/options", headers=fresh).json()
    broken = SoftAuthenticator(ORIGIN).create(registration["public_key"])
    broken["response"]["attestationObject"] = "AAAA"
    refused = client.post(
        "/api/auth/mfa/webauthn/register/verify",
        headers=fresh,
        json={"challenge_id": registration["challenge_id"], "credential": broken},
    )
    assert refused.status_code == 400


def test_an_assertion_made_for_another_origin_is_refused(tmp_path, monkeypatch, clock):
    # The phishing case itself: the victim's own key, signing on a page that is
    # not this console. The browser reports the page's real origin, and that
    # is what the signature covers.
    client = _client(tmp_path, monkeypatch)
    _, key, _ = _enrolled_with_key(client, clock)

    challenge = password_login(client)["mfa_token"]
    options = _login_options(client, challenge)
    relayed = key.get(options["public_key"], origin=PHISHING_ORIGIN)
    assert _verify(client, challenge, options["challenge_id"], relayed).status_code == 401


def test_an_assertion_for_another_relying_party_is_refused(tmp_path, monkeypatch, clock):
    client = _client(tmp_path, monkeypatch)
    _, key, _ = _enrolled_with_key(client, clock)

    challenge = password_login(client)["mfa_token"]
    options = _login_options(client, challenge)
    other_rp = key.get(options["public_key"], rp_id="login-help.net")
    assert _verify(client, challenge, options["challenge_id"], other_rp).status_code == 401


def test_a_challenge_can_be_answered_once(tmp_path, monkeypatch, clock):
    client = _client(tmp_path, monkeypatch)
    _, key, _ = _enrolled_with_key(client, clock)

    challenge = password_login(client)["mfa_token"]
    options = _login_options(client, challenge)
    first = _verify(client, challenge, options["challenge_id"], key.get(options["public_key"]))
    assert first.status_code == 200, first.text

    # A second, perfectly valid assertion over the same challenge — a fresh
    # signature with a higher counter, so only the challenge being spent can
    # be what refuses it.
    again = _verify(client, challenge, options["challenge_id"], key.get(options["public_key"]))
    assert again.status_code == 401


def test_a_failed_attempt_spends_the_challenge_too(tmp_path, monkeypatch, clock):
    # Otherwise one challenge would be a free retry loop: try the relayed
    # assertion, and when it fails, try the next thing against the same one.
    client = _client(tmp_path, monkeypatch)
    _, key, _ = _enrolled_with_key(client, clock)

    challenge = password_login(client)["mfa_token"]
    options = _login_options(client, challenge)
    bad = key.get(options["public_key"], origin=PHISHING_ORIGIN)
    assert _verify(client, challenge, options["challenge_id"], bad).status_code == 401
    good = key.get(options["public_key"])
    assert _verify(client, challenge, options["challenge_id"], good).status_code == 401


def test_a_challenge_is_bound_to_the_login_that_asked_for_it(tmp_path, monkeypatch, clock):
    client = _client(tmp_path, monkeypatch)
    _, key, _ = _enrolled_with_key(client, clock)

    first_login = password_login(client)["mfa_token"]
    options = _login_options(client, first_login)
    second_login = password_login(client)["mfa_token"]
    carried = _verify(
        client, second_login, options["challenge_id"], key.get(options["public_key"])
    )
    assert carried.status_code == 401


def test_an_expired_challenge_is_refused(tmp_path, monkeypatch, clock):
    client = _client(tmp_path, monkeypatch)
    _, key, _ = _enrolled_with_key(client, clock)

    challenge = password_login(client)["mfa_token"]
    options = _login_options(client, challenge)

    from api.services import passkeys as passkeys_service

    later = datetime.now(UTC).replace(tzinfo=None) + timedelta(
        seconds=passkeys_service.CHALLENGE_TTL_SECONDS + 1
    )
    monkeypatch.setattr(passkeys_service, "_now", lambda: later)
    late = _verify(client, challenge, options["challenge_id"], key.get(options["public_key"]))
    assert late.status_code == 401


def test_a_counter_that_does_not_advance_is_refused(tmp_path, monkeypatch, clock):
    # What a cloned key looks like: its copy of the counter is behind the
    # original's. The stored counter is advanced by each accepted assertion,
    # so replaying the value the server already saw must fail.
    client = _client(tmp_path, monkeypatch)
    _, key, _ = _enrolled_with_key(client, clock)

    challenge = password_login(client)["mfa_token"]
    options = _login_options(client, challenge)
    assert (
        _verify(client, challenge, options["challenge_id"], key.get(options["public_key"])).status_code
        == 200
    )
    seen = key.sign_count

    challenge = password_login(client)["mfa_token"]
    options = _login_options(client, challenge)
    clone = key.get(options["public_key"], sign_count=seen)
    assert _verify(client, challenge, options["challenge_id"], clone).status_code == 401

    # And the original, one step ahead, still works — the refusal was about the
    # counter, not about the key having been locked by the attempt.
    challenge = password_login(client)["mfa_token"]
    options = _login_options(client, challenge)
    assert (
        _verify(client, challenge, options["challenge_id"], key.get(options["public_key"])).status_code
        == 200
    )


def test_another_accounts_key_does_not_sign_this_one_in(tmp_path, monkeypatch, clock):
    client = _client(tmp_path, monkeypatch)
    _, admin_key, _ = _enrolled_with_key(client, clock, "admin")
    _enrolled_with_key(client, clock, "operator")

    challenge = password_login(client, "operator")["mfa_token"]
    options = _login_options(client, challenge)
    # Signed by admin's key over operator's challenge: a valid signature by a
    # key that is registered — to somebody else.
    borrowed = admin_key.get(options["public_key"])
    assert _verify(client, challenge, options["challenge_id"], borrowed).status_code == 401


def test_the_key_also_steps_up_a_signed_in_session(tmp_path, monkeypatch, clock):
    client = _client(tmp_path, monkeypatch, mfa_stepup_minutes=15)
    headers = auth_headers(client, "admin")
    secret, _ = enrol(client, headers, clock)
    key = SoftAuthenticator(ORIGIN)
    _register(client, _step_up(client, headers, clock, secret), key)

    clock.advance(16 * 60)
    stale = client.post(
        "/api/tenants/default/provisioning-keys", headers=headers, json={"label": "x"}
    )
    assert stale.status_code == 403

    options = client.post("/api/auth/mfa/webauthn/authenticate/options", headers=headers, json={})
    assert options.status_code == 200, options.text
    stepped = _verify(
        client, None, options.json()["challenge_id"], key.get(options.json()["public_key"]), headers
    )
    assert stepped.status_code == 200, stepped.text
    fresh = bearer(stepped.json()["access_token"])
    assert (
        client.post(
            "/api/tenants/default/provisioning-keys", headers=fresh, json={"label": "x"}
        ).status_code
        == 201
    )


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #


def test_registration_needs_a_recent_verification(tmp_path, monkeypatch, clock):
    # A stolen session must not be able to plant a key of its own.
    client = _client(tmp_path, monkeypatch)
    headers = auth_headers(client, "admin")
    enrol(client, headers, clock)

    refused = client.post("/api/auth/mfa/webauthn/register/options", headers=headers)
    assert refused.status_code == 403
    # The console's re-verify prompt keys on this sentence.
    assert "needs a recent multi-factor verification" in refused.json()["detail"]


def test_a_key_is_added_on_top_of_an_authenticator_app(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    refused = client.post(
        "/api/auth/mfa/webauthn/register/options", headers=auth_headers(client, "admin")
    )
    assert refused.status_code == 409
    assert "authenticator app" in refused.json()["detail"]


def test_without_a_relying_party_webauthn_is_unavailable(tmp_path, monkeypatch, clock):
    client = configured_client(tmp_path, monkeypatch)
    headers = auth_headers(client, "admin")
    secret, _ = enrol(client, headers, clock)
    fresh = _step_up(client, headers, clock, secret)
    assert client.get("/api/auth/mfa", headers=fresh).json()["webauthn_available"] is False
    response = client.post("/api/auth/mfa/webauthn/register/options", headers=fresh)
    assert response.status_code == 409
    assert "not configured" in response.json()["detail"]


def test_a_registration_made_for_another_origin_stores_nothing(tmp_path, monkeypatch, clock):
    client = _client(tmp_path, monkeypatch)
    headers = auth_headers(client, "admin")
    secret, _ = enrol(client, headers, clock)
    fresh = _step_up(client, headers, clock, secret)

    options = client.post("/api/auth/mfa/webauthn/register/options", headers=fresh).json()
    key = SoftAuthenticator(ORIGIN)
    refused = client.post(
        "/api/auth/mfa/webauthn/register/verify",
        headers=fresh,
        json={
            "challenge_id": options["challenge_id"],
            "credential": key.create(options["public_key"], origin=PHISHING_ORIGIN),
        },
    )
    # 400, not 401: the session is fine, and the console signs out on a 401.
    assert refused.status_code == 400
    assert client.get("/api/auth/mfa/webauthn/credentials", headers=fresh).json() == []


def test_the_inventory_lists_own_keys_and_revocation_is_audited(tmp_path, monkeypatch, clock):
    client = _client(tmp_path, monkeypatch)
    _, key, fresh = _enrolled_with_key(client, clock)

    listed = client.get("/api/auth/mfa/webauthn/credentials", headers=fresh)
    assert listed.status_code == 200
    [item] = listed.json()
    assert item["name"] == "YubiKey"
    assert item["credential_id"] == key.credential_id_b64
    assert "public_key" not in item
    assert client.get("/api/auth/mfa", headers=fresh).json()["webauthn_credentials"] == 1

    # Nobody else's inventory reaches it, and nobody else can remove it.
    operator = auth_headers(client, "operator")
    assert client.get("/api/auth/mfa/webauthn/credentials", headers=operator).json() == []
    assert (
        client.delete(
            f"/api/auth/mfa/webauthn/credentials/{item['id']}", headers=operator
        ).status_code
        == 404
    )

    removed = client.delete(f"/api/auth/mfa/webauthn/credentials/{item['id']}", headers=fresh)
    assert removed.status_code == 204
    assert client.get("/api/auth/mfa/webauthn/credentials", headers=fresh).json() == []

    events = client.get("/api/audit", headers=fresh, params={"action": "user.webauthn_revoke"})
    assert [event["resource_id"] for event in events.json()["items"]] == ["admin"]
    added = client.get("/api/audit", headers=fresh, params={"action": "user.webauthn_register"})
    assert [event["resource_id"] for event in added.json()["items"]] == ["admin"]

    # And the removed key no longer signs anything in.
    challenge = password_login(client)["mfa_token"]
    options = client.post(
        "/api/auth/mfa/webauthn/authenticate/options", json={"mfa_token": challenge}
    )
    assert options.status_code == 409


def test_removing_a_key_needs_a_recent_verification(tmp_path, monkeypatch, clock):
    client = _client(tmp_path, monkeypatch)
    _, _, fresh = _enrolled_with_key(client, clock)
    [item] = client.get("/api/auth/mfa/webauthn/credentials", headers=fresh).json()

    clock.advance(16 * 60)
    stale = client.delete(f"/api/auth/mfa/webauthn/credentials/{item['id']}", headers=fresh)
    assert stale.status_code == 403


def test_admin_reset_removes_the_keys_with_the_rest_of_the_factor(tmp_path, monkeypatch, clock):
    # The lost-key path. A key surviving the reset would be exactly the lost
    # key still working.
    client = _client(tmp_path, monkeypatch)
    _, key, _ = _enrolled_with_key(client, clock, "operator")
    admin = auth_headers(client, "admin")

    reset = client.post("/api/users/operator/mfa/reset", headers=admin)
    assert reset.status_code == 200, reset.text
    assert reset.json()["webauthn_credentials"] == 0

    events = client.get("/api/audit", headers=admin, params={"action": "user.mfa_reset"})
    [event] = events.json()["items"]
    assert event["before"]["webauthn_credentials"] == 1

    # One-leg login again; the old key has nothing to answer.
    assert password_login(client, "operator")["access_token"]


def test_turning_mfa_off_removes_the_keys(tmp_path, monkeypatch, clock):
    client = _client(tmp_path, monkeypatch)
    secret, _, fresh = _enrolled_with_key(client, clock)
    from tests.conftest import TEST_USERS

    done = client.post(
        "/api/auth/mfa/disable",
        headers=fresh,
        json={"password": TEST_USERS["admin"], "code": clock.next_code(secret)},
    )
    assert done.status_code == 200, done.text
    assert done.json()["webauthn_credentials"] == 0


# --------------------------------------------------------------------------- #
# Policy: a phishing-resistant factor for selected roles and for step-up
# --------------------------------------------------------------------------- #


def test_a_code_does_not_fully_sign_in_a_role_that_requires_a_key(tmp_path, monkeypatch, clock):
    client = _client(tmp_path, monkeypatch, mfa_phishing_resistant_roles=["admin"])
    headers = auth_headers(client, "admin")
    # The role is implicitly MFA-required: the first session is confined to
    # enrolment exactly as under OCTO_MFA_REQUIRED_ROLES — told to set up the
    # app first, not to register a key it cannot register yet.
    assert client.get("/api/users", headers=headers).status_code == 403
    first = client.get("/api/auth/me", headers=headers).json()
    assert first["mfa_pending"] is True
    assert first["phishing_resistant_pending"] is False
    secret, _ = enrol(client, headers, clock)

    challenge = password_login(client)["mfa_token"]
    by_code = client.post(
        "/api/auth/mfa/verify",
        json={"mfa_token": challenge, "code": clock.next_code(secret)},
    )
    assert by_code.status_code == 200
    coded = bearer(by_code.json()["access_token"])
    # Signed in by a code: confined, and told why.
    refused = client.get("/api/users", headers=coded)
    assert refused.status_code == 403
    assert "security key" in refused.json()["detail"]
    me = client.get("/api/auth/me", headers=coded).json()
    assert me["phishing_resistant_pending"] is True
    assert me["phishing_resistant_required"] is True

    # The way out is open on that very session: register a key...
    key = SoftAuthenticator(ORIGIN)
    _register(client, coded, key)
    # ...and sign in with it.
    challenge = password_login(client)["mfa_token"]
    options = _login_options(client, challenge)
    by_key = _verify(client, challenge, options["challenge_id"], key.get(options["public_key"]))
    assert by_key.status_code == 200, by_key.text
    assert client.get("/api/users", headers=bearer(by_key.json()["access_token"])).status_code == 200


def test_a_role_not_named_by_the_key_policy_signs_in_with_a_code(tmp_path, monkeypatch, clock):
    client = _client(tmp_path, monkeypatch, mfa_phishing_resistant_roles=["admin"])
    headers = auth_headers(client, "operator")
    secret, _ = enrol(client, headers, clock, "operator")
    challenge = password_login(client, "operator")["mfa_token"]
    verified = client.post(
        "/api/auth/mfa/verify", json={"mfa_token": challenge, "code": clock.next_code(secret)}
    )
    assert client.get("/api/runs", headers=bearer(verified.json()["access_token"])).status_code == 200


def test_a_step_up_by_code_does_not_satisfy_a_key_only_step_up(tmp_path, monkeypatch, clock):
    client = _client(tmp_path, monkeypatch, mfa_stepup_phishing_resistant=True)
    headers = auth_headers(client, "admin")
    secret, _ = enrol(client, headers, clock)
    by_code = _step_up(client, headers, clock, secret)

    refused = client.post(
        "/api/tenants/default/provisioning-keys", headers=by_code, json={"label": "x"}
    )
    assert refused.status_code == 403
    assert "needs a recent multi-factor verification" in refused.json()["detail"]
    assert "security key" in refused.json()["detail"]

    # The first key is bootstrapped by the code — there is nothing else to
    # prove — and then the key is what steps up.
    key = SoftAuthenticator(ORIGIN)
    _register(client, by_code, key)
    options = client.post(
        "/api/auth/mfa/webauthn/authenticate/options", headers=by_code, json={}
    ).json()
    stepped = _verify(client, None, options["challenge_id"], key.get(options["public_key"]), by_code)
    assert stepped.status_code == 200, stepped.text
    assert (
        client.post(
            "/api/tenants/default/provisioning-keys",
            headers=bearer(stepped.json()["access_token"]),
            json={"label": "x"},
        ).status_code
        == 201
    )


def test_a_second_key_under_the_policy_costs_the_first_one(tmp_path, monkeypatch, clock):
    # Otherwise a phished code would enrol the phisher's key next to the
    # owner's, and the policy would have bought nothing.
    client = _client(tmp_path, monkeypatch, mfa_stepup_phishing_resistant=True)
    headers = auth_headers(client, "admin")
    secret, _ = enrol(client, headers, clock)
    _register(client, _step_up(client, headers, clock, secret), SoftAuthenticator(ORIGIN))

    by_code = _step_up(client, headers, clock, secret)
    refused = client.post("/api/auth/mfa/webauthn/register/options", headers=by_code)
    assert refused.status_code == 403
    assert "one you already hold" in refused.json()["detail"]


@pytest.mark.parametrize(
    "policy",
    [{"mfa_phishing_resistant_roles": ["admin"]}, {"mfa_stepup_phishing_resistant": True}],
    ids=["role", "stepup"],
)
def test_a_relayed_code_cannot_turn_mfa_off_and_take_the_keys_with_it(
    tmp_path, monkeypatch, clock, policy
):
    # The side door around the key policy: a phishing kit relays the password
    # and a TOTP code, the resulting code-proved session calls disable — which
    # removes the owner's keys — and then enrols its own app and key from an
    # account that "has no key yet". Where policy wants a key and the account
    # holds one, turning the factor off must cost that key.
    from tests.conftest import TEST_USERS

    client = _client(tmp_path, monkeypatch, **policy)
    headers = auth_headers(client, "admin")
    secret, _ = enrol(client, headers, clock)
    key = SoftAuthenticator(ORIGIN)
    _register(client, _step_up(client, headers, clock, secret), key)

    challenge = password_login(client)["mfa_token"]
    relayed = client.post(
        "/api/auth/mfa/verify", json={"mfa_token": challenge, "code": clock.next_code(secret)}
    )
    phished = bearer(relayed.json()["access_token"])
    refused = client.post(
        "/api/auth/mfa/disable",
        headers=phished,
        json={"password": TEST_USERS["admin"], "code": clock.next_code(secret)},
    )
    assert refused.status_code == 403
    assert "needs a recent multi-factor verification" in refused.json()["detail"]
    # Nothing was removed by the attempt.
    assert client.get("/api/auth/mfa", headers=phished).json()["webauthn_credentials"] == 1

    # The owner, stepping up with the key, can still turn it off.
    options = client.post(
        "/api/auth/mfa/webauthn/authenticate/options", headers=phished, json={}
    ).json()
    by_key = _verify(client, None, options["challenge_id"], key.get(options["public_key"]), phished)
    done = client.post(
        "/api/auth/mfa/disable",
        headers=bearer(by_key.json()["access_token"]),
        json={"password": TEST_USERS["admin"], "code": clock.next_code(secret)},
    )
    assert done.status_code == 200, done.text
    assert done.json()["webauthn_credentials"] == 0


def test_the_phishing_resistant_policy_needs_a_relying_party_in_prod(tmp_path, monkeypatch):
    # A key-only policy with nothing to register a key against confines every
    # listed role to a page whose one action answers 409: an admin lockout.
    from api.settings import ENV_PROD, InsecureConfigurationError, _validate_production

    settings = make_settings(
        tmp_path, env=ENV_PROD, mfa_phishing_resistant_roles=["admin"], public_base_url=""
    )
    with pytest.raises(InsecureConfigurationError) as raised:
        _validate_production(settings, postgres_url_env="OCTO_POSTGRES_URL")
    assert "OCTO_MFA_PHISHING_RESISTANT_ROLES" in str(raised.value)

    settings.webauthn_rp_id = RP_ID
    settings.webauthn_origins = [ORIGIN]
    with pytest.raises(InsecureConfigurationError) as again:
        _validate_production(settings, postgres_url_env="OCTO_POSTGRES_URL")
    # Other prod defaults are still flagged; this one no longer is.
    assert "OCTO_MFA_PHISHING_RESISTANT_ROLES" not in str(again.value)


def test_a_code_still_signs_in_an_account_that_holds_a_key(tmp_path, monkeypatch, clock):
    # TOTP stays a supported factor after keys land; with no policy asking for
    # a key, the code is a complete login — recorded as what it was.
    client = _client(tmp_path, monkeypatch)
    secret, _, _ = _enrolled_with_key(client, clock)
    challenge = password_login(client)["mfa_token"]
    verified = client.post(
        "/api/auth/mfa/verify", json={"mfa_token": challenge, "code": clock.next_code(secret)}
    )
    assert verified.status_code == 200
    session = bearer(verified.json()["access_token"])
    assert client.get("/api/users", headers=session).status_code == 200
    assert client.get("/api/auth/me", headers=session).json()["mfa_method"] == "totp"
