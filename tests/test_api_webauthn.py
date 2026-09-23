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


#: The two ways policy asks for a key, each of which must hold on its own: a
#: check that reads only one of the two settings passes half of these.
POLICIES = pytest.mark.parametrize(
    "policy",
    [{"mfa_phishing_resistant_roles": ["admin"]}, {"mfa_stepup_phishing_resistant": True}],
    ids=["role", "stepup"],
)


def _code_session(client, clock: Clock, secret: str) -> dict[str, str]:
    """A fresh session signed in with password + code: what a phishing kit holds."""
    challenge = password_login(client)["mfa_token"]
    relayed = client.post(
        "/api/auth/mfa/verify", json={"mfa_token": challenge, "code": clock.next_code(secret)}
    )
    assert relayed.status_code == 200, relayed.text
    return bearer(relayed.json()["access_token"])


@POLICIES
def test_a_second_key_under_the_policy_costs_the_first_one(tmp_path, monkeypatch, clock, policy):
    # Otherwise a phished code would enrol the phisher's key next to the
    # owner's, and the policy would have bought nothing.
    client = _client(tmp_path, monkeypatch, **policy)
    headers = auth_headers(client, "admin")
    secret, _ = enrol(client, headers, clock)
    _register(client, _step_up(client, headers, clock, secret), SoftAuthenticator(ORIGIN))

    by_code = _code_session(client, clock, secret)
    refused = client.post("/api/auth/mfa/webauthn/register/options", headers=by_code)
    assert refused.status_code == 403
    assert "one you already hold" in refused.json()["detail"]


@POLICIES
def test_a_relayed_code_cannot_remove_the_owners_key(tmp_path, monkeypatch, clock, policy):
    # The other half of replacing the owner's key: remove it, then the next key
    # is a "first" one. Removal is a step-up operation, and under either
    # policy that step-up must be the key.
    client = _client(tmp_path, monkeypatch, **policy)
    headers = auth_headers(client, "admin")
    secret, _ = enrol(client, headers, clock)
    _register(client, _step_up(client, headers, clock, secret), SoftAuthenticator(ORIGIN))

    by_code = _code_session(client, clock, secret)
    [item] = client.get("/api/auth/mfa/webauthn/credentials", headers=by_code).json()
    refused = client.delete(f"/api/auth/mfa/webauthn/credentials/{item['id']}", headers=by_code)
    assert refused.status_code == 403
    assert "security key" in refused.json()["detail"]
    assert len(client.get("/api/auth/mfa/webauthn/credentials", headers=by_code).json()) == 1


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


def test_disabling_under_the_policy_needs_a_recent_key_not_an_old_one(
    tmp_path, monkeypatch, clock
):
    # "Proved with the key" is not enough on its own: a key-proved session left
    # open on a desk for an hour is not the owner at the keyboard.
    from tests.conftest import TEST_USERS

    client = _client(tmp_path, monkeypatch, mfa_stepup_phishing_resistant=True, mfa_stepup_minutes=15)
    secret, key, _ = _enrolled_with_key(client, clock)
    challenge = password_login(client)["mfa_token"]
    options = _login_options(client, challenge)
    by_key = bearer(
        _verify(client, challenge, options["challenge_id"], key.get(options["public_key"])).json()[
            "access_token"
        ]
    )

    clock.advance(16 * 60)
    stale = client.post(
        "/api/auth/mfa/disable",
        headers=by_key,
        json={"password": TEST_USERS["admin"], "code": clock.next_code(secret)},
    )
    assert stale.status_code == 403
    assert client.get("/api/auth/mfa", headers=by_key).json()["webauthn_credentials"] == 1


# --------------------------------------------------------------------------- #
# Challenges under pressure (review of #437)
# --------------------------------------------------------------------------- #


def test_somebody_with_the_password_cannot_evict_the_owners_challenge(
    tmp_path, monkeypatch, clock
):
    # The owner asks for a challenge; somebody else who has the password signs
    # in on their own and asks for challenges until any per-account cap would
    # have pushed the owner's out. The owner's key must still sign in.
    client = _client(tmp_path, monkeypatch)
    _, key, _ = _enrolled_with_key(client, clock)

    owners = password_login(client)["mfa_token"]
    options = _login_options(client, owners)

    intruders = password_login(client)["mfa_token"]
    for _ in range(12):
        client.post("/api/auth/mfa/webauthn/authenticate/options", json={"mfa_token": intruders})

    signed = _verify(client, owners, options["challenge_id"], key.get(options["public_key"]))
    assert signed.status_code == 200, signed.text


def test_asking_for_challenges_is_rate_limited(tmp_path, monkeypatch, clock):
    # Every options call writes a row. A caller holding one challenge token
    # must not be able to write them without bound — nor to make the owner's
    # challenges pay for it, which the test above pins.
    from api.services import passkeys as passkeys_service

    client = _client(tmp_path, monkeypatch)
    _enrolled_with_key(client, clock)
    token = password_login(client)["mfa_token"]
    statuses = [
        client.post(
            "/api/auth/mfa/webauthn/authenticate/options", json={"mfa_token": token}
        ).status_code
        for _ in range(passkeys_service.MAX_OPEN_CHALLENGES + 1)
    ]
    assert statuses[:-1] == [200] * passkeys_service.MAX_OPEN_CHALLENGES
    assert statuses[-1] == 429


def test_many_sign_ins_from_one_address_are_limited_too(tmp_path, monkeypatch, clock):
    # A fresh sign-in is a fresh binding; the per-address limit is what stops a
    # loop of them from writing rows without bound.
    from api.services import passkeys as passkeys_service

    monkeypatch.setattr(passkeys_service, "MAX_CHALLENGES_PER_WINDOW", 4)
    client = _client(tmp_path, monkeypatch)
    _enrolled_with_key(client, clock)
    statuses = [
        client.post(
            "/api/auth/mfa/webauthn/authenticate/options",
            json={"mfa_token": password_login(client)["mfa_token"]},
        ).status_code
        for _ in range(5)
    ]
    assert statuses == [200, 200, 200, 200, 429]


def test_a_failed_key_step_up_does_not_sign_the_console_out(tmp_path, monkeypatch, clock):
    # The console answers every 401 by dropping the session. A step-up that
    # fails — a stale challenge, a key from another tab — is a refusal of the
    # proof, not of the session, so it must not be a 401.
    client = _client(tmp_path, monkeypatch)
    _, key, fresh = _enrolled_with_key(client, clock)

    options = client.post(
        "/api/auth/mfa/webauthn/authenticate/options", headers=fresh, json={}
    ).json()
    wrong = key.get(options["public_key"], origin=PHISHING_ORIGIN)
    refused = _verify(client, None, options["challenge_id"], wrong, fresh)
    assert refused.status_code == 403
    # And it says what was refused: a key response, not a code.
    assert refused.json()["detail"] == "that security key response is not valid"
    assert "needs a recent multi-factor verification" not in refused.json()["detail"]
    # The session itself is untouched.
    assert client.get("/api/auth/me", headers=fresh).status_code == 200


def test_a_failed_login_leg_by_key_is_still_a_401_naming_the_key(tmp_path, monkeypatch, clock):
    client = _client(tmp_path, monkeypatch)
    _, key, _ = _enrolled_with_key(client, clock)
    challenge = password_login(client)["mfa_token"]
    options = _login_options(client, challenge)
    bad = key.get(options["public_key"], origin=PHISHING_ORIGIN)
    refused = _verify(client, challenge, options["challenge_id"], bad)
    assert refused.status_code == 401
    assert refused.json()["detail"] == "that security key response is not valid"


# --------------------------------------------------------------------------- #
# With refresh tokens (#314): the method lives in the session family
# --------------------------------------------------------------------------- #


def _refresh(client, response) -> dict[str, str]:
    from tests.test_refresh_tokens import cookie_value, refresh

    refreshed = refresh(client, cookie_value(response))
    assert refreshed.status_code == 200, refreshed.text
    return bearer(refreshed.json()["access_token"])


def test_a_key_proved_session_stays_key_proved_across_a_refresh(tmp_path, monkeypatch, clock):
    client = _client(tmp_path, monkeypatch, mfa_phishing_resistant_roles=["admin"])
    headers = auth_headers(client, "admin")
    secret, _ = enrol(client, headers, clock)
    coded = _code_session(client, clock, secret)
    key = SoftAuthenticator(ORIGIN)
    _register(client, coded, key)

    challenge = password_login(client)["mfa_token"]
    options = _login_options(client, challenge)
    signed = _verify(client, challenge, options["challenge_id"], key.get(options["public_key"]))
    assert signed.status_code == 200, signed.text

    # Fifteen minutes later the console refreshes; the new access token must
    # still say what the session was proved with, or the policy confines a
    # session that did everything right.
    refreshed = _refresh(client, signed)
    assert client.get("/api/auth/me", headers=refreshed).json()["mfa_method"] == "webauthn"
    assert client.get("/api/users", headers=refreshed).status_code == 200


def test_a_code_step_up_after_a_key_sign_in_does_not_keep_the_key_label(
    tmp_path, monkeypatch, clock
):
    # The method and the time are one fact. A step-up by code stamps a new
    # time; if it left "webauthn" standing, the next refresh would present a
    # fresh code-proved step-up as a key-proved one.
    client = _client(tmp_path, monkeypatch, mfa_stepup_phishing_resistant=True)
    secret, key, _ = _enrolled_with_key(client, clock)
    challenge = password_login(client)["mfa_token"]
    options = _login_options(client, challenge)
    signed = _verify(client, challenge, options["challenge_id"], key.get(options["public_key"]))
    by_key = bearer(signed.json()["access_token"])

    stepped = client.post(
        "/api/auth/mfa/verify", headers=by_key, json={"code": clock.next_code(secret)}
    )
    assert stepped.status_code == 200, stepped.text
    refreshed = _refresh(client, signed)
    assert client.get("/api/auth/me", headers=refreshed).json()["mfa_method"] == "totp"
    refused = client.post(
        "/api/tenants/default/provisioning-keys", headers=refreshed, json={"label": "x"}
    )
    assert refused.status_code == 403


def test_a_refresh_between_options_and_answer_does_not_break_the_ceremony(
    tmp_path, monkeypatch, clock
):
    # The challenge is bound to the session, not to one access token: the
    # console may well refresh while the user is finding the key.
    client = _client(tmp_path, monkeypatch)
    secret, key, _ = _enrolled_with_key(client, clock)
    challenge = password_login(client)["mfa_token"]
    login = client.post(
        "/api/auth/mfa/verify", json={"mfa_token": challenge, "code": clock.next_code(secret)}
    )
    session = bearer(login.json()["access_token"])

    options = client.post(
        "/api/auth/mfa/webauthn/authenticate/options", headers=session, json={}
    ).json()
    rotated = _refresh(client, login)
    stepped = _verify(
        client, None, options["challenge_id"], key.get(options["public_key"]), rotated
    )
    assert stepped.status_code == 200, stepped.text


# --------------------------------------------------------------------------- #
# Relying-party configuration in prod
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("rp_id", "origins", "complaint"),
    [
        ("10.0.0.5", ["https://10.0.0.5"], "IP address"),
        ("console.example", ["http://console.example"], "https"),
        ("console.example", ["https://other.example"], "suffix"),
    ],
    ids=["ip-rp-id", "plain-http", "not-a-suffix"],
)
def test_prod_refuses_a_relying_party_browsers_would_refuse(tmp_path, rp_id, origins, complaint):
    from api.settings import ENV_PROD, InsecureConfigurationError, _validate_production

    settings = make_settings(
        tmp_path, env=ENV_PROD, webauthn_rp_id=rp_id, webauthn_origins=origins
    )
    with pytest.raises(InsecureConfigurationError) as raised:
        _validate_production(settings, postgres_url_env="OCTO_POSTGRES_URL")
    assert "OCTO_WEBAUTHN" in str(raised.value)
    assert complaint in str(raised.value)


@pytest.mark.parametrize(
    ("rp_id", "origins"),
    [
        ("example.com", ["https://console.example.com", "https://example.com"]),
        # Browsers treat localhost as a secure context; so does the check.
        ("localhost", ["http://localhost:3000"]),
    ],
    ids=["parent-domain", "localhost"],
)
def test_prod_accepts_a_sound_relying_party(tmp_path, rp_id, origins):
    from api.settings import ENV_PROD, InsecureConfigurationError, _validate_production

    settings = make_settings(
        tmp_path, env=ENV_PROD, webauthn_rp_id=rp_id, webauthn_origins=origins
    )
    with pytest.raises(InsecureConfigurationError) as raised:
        _validate_production(settings, postgres_url_env="OCTO_POSTGRES_URL")
    assert "OCTO_WEBAUTHN" not in str(raised.value)


def test_configured_origins_are_compared_case_insensitively(monkeypatch):
    # Browsers serialise an origin in lower case; an operator who typed
    # https://Console.Example would otherwise refuse every assertion.
    from api.settings import load_settings

    monkeypatch.setenv("OCTO_WEBAUTHN_ORIGINS", "https://Console.Example/")
    assert load_settings().webauthn_origins == ["https://console.example"]
