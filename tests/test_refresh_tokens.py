"""Short access tokens, rotated refresh tokens and the idle timeout (#314).

What #314 left open after revocation was fixed: a console session was one
eight-hour bearer token in local storage, with nothing to renew it and nothing
to notice it had been copied. Every test below fails against the code before
this change — ``POST /api/auth/refresh`` did not exist, login set no cookie,
and an access token had no ``sid`` for an ended session to be refused by.

The cookie is ``Secure``, and the test client talks plain ``http://testserver``,
so its cookie jar never sends it back on its own. The tests pass it explicitly,
which is also the more honest statement of what each request carries.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from sqlalchemy import update

from api.db import models
from api.db.engine import get_session
from api.routes._session_cookie import REFRESH_COOKIE
from api.services import auth_audit
from api.services import sessions as sessions_service
from tests.conftest import (
    TEST_JWT_SECRET,
    TEST_USERS,
    auth_headers,
    bearer,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = make_settings(tmp_path, access_token_expire_minutes=15, session_idle_minutes=30)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    return client, settings


def set_cookie_header(response) -> str | None:
    """The raw ``Set-Cookie`` for the refresh token, or ``None``."""
    for header in response.headers.get_list("set-cookie"):
        if header.startswith(f"{REFRESH_COOKIE}="):
            return header
    return None


def cookie_value(response) -> str:
    header = set_cookie_header(response)
    assert header is not None, f"no refresh cookie in {response.headers.get_list('set-cookie')}"
    return header.split(";", 1)[0].split("=", 1)[1].strip('"')


def sign_in(client, username: str = "operator") -> tuple[str, str]:
    """Password login; returns (access token, refresh token)."""
    response = client.post(
        "/api/auth/login", json={"username": username, "password": TEST_USERS[username]}
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"], cookie_value(response)


def refresh(client, refresh_token: str | None):
    headers = {"Cookie": f"{REFRESH_COOKIE}={refresh_token}"} if refresh_token else {}
    return client.post("/api/auth/refresh", headers=headers)


def claims(token: str) -> dict:
    return jwt.decode(token, TEST_JWT_SECRET, algorithms=["HS256"])


def backdate(settings, family_id: str, **columns) -> None:
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.SessionFamily)
            .where(models.SessionFamily.family_id == family_id)
            .values(**columns)
        )


def naive_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


# --------------------------------------------------------------------------- #
# The pair
# --------------------------------------------------------------------------- #


def test_login_sets_a_refresh_cookie_scripts_cannot_read(env):
    client, _settings = env
    response = client.post(
        "/api/auth/login", json={"username": "operator", "password": TEST_USERS["operator"]}
    )
    assert response.status_code == 200
    header = set_cookie_header(response)
    assert header is not None
    attributes = {part.strip().lower() for part in header.split(";")[1:]}
    assert "httponly" in attributes
    assert "secure" in attributes
    assert "samesite=strict" in attributes
    assert "path=/api/auth" in attributes
    # Only the cookie carries it: a body field would be readable by script,
    # which is exactly what the cookie exists to prevent.
    assert cookie_value(response) not in response.text


def test_the_refresh_token_is_stored_only_as_a_digest(env):
    client, settings = env
    _access, refresh_token = sign_in(client)
    with get_session(settings.postgres_url) as session:
        stored = [row.token_hash for row in session.query(models.RefreshToken).all()]
    assert stored and refresh_token not in stored
    assert all(len(value) == 64 for value in stored)


def test_the_access_token_is_short_lived_and_names_its_session(env):
    client, settings = env
    access, _refresh = sign_in(client)
    payload = claims(access)
    lifetime = payload["exp"] - payload["iat"]
    assert lifetime == settings.access_token_expire_minutes * 60
    assert payload["sid"]
    assert sessions_service.get_family(settings, payload["sid"]) is not None


def test_refresh_rotates_the_cookie_and_mints_a_working_access_token(env):
    client, _settings = env
    first_access, first_refresh = sign_in(client)

    answer = refresh(client, first_refresh)
    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert body["username"] == "operator"
    assert body["role"] == "operator"
    second_refresh = cookie_value(answer)
    assert second_refresh != first_refresh
    assert body["access_token"] != first_access
    assert claims(body["access_token"])["sid"] == claims(first_access)["sid"]
    assert client.get("/api/auth/me", headers=bearer(body["access_token"])).status_code == 200

    # And the successor is good for the next one.
    assert refresh(client, second_refresh).status_code == 200


def test_refresh_without_a_cookie_is_a_401(env):
    client, _settings = env
    assert refresh(client, None).status_code == 401
    assert refresh(client, "not-a-token-this-server-issued").status_code == 401


def test_refresh_carries_the_role_from_the_table_not_from_the_session(env):
    """A role change bumps the generation, so it ends the session outright."""
    client, _settings = env
    admin = auth_headers(client, "admin")
    _access, refresh_token = sign_in(client)
    assert client.put(
        "/api/users/operator/role", headers=admin, json={"role": "viewer"}
    ).status_code == 200
    assert refresh(client, refresh_token).status_code == 401


# --------------------------------------------------------------------------- #
# Reuse detection
# --------------------------------------------------------------------------- #


def test_a_refresh_token_presented_twice_ends_the_whole_session(env):
    client, settings = env
    access, stolen = sign_in(client)
    sid = claims(access)["sid"]

    # The browser refreshes; the thief replays the copy it took before that.
    legitimate = refresh(client, stolen)
    assert legitimate.status_code == 200
    successor = cookie_value(legitimate)
    newest_access = legitimate.json()["access_token"]

    replay = refresh(client, stolen)
    assert replay.status_code == 401
    # The refusal also takes the dead cookie out of the browser.
    assert "max-age=0" in (set_cookie_header(replay) or "").lower()

    # Everything the family issued is now dead: the successor refresh token,
    # which the thief might equally hold, and the access token minted with it.
    assert refresh(client, successor).status_code == 401
    assert client.get("/api/auth/me", headers=bearer(newest_access)).status_code == 401
    assert client.get("/api/auth/me", headers=bearer(access)).status_code == 401
    assert sessions_service.get_family(settings, sid).revoked_reason == sessions_service.END_REUSE


def test_reuse_is_written_to_the_auth_trail(env):
    client, _settings = env
    _access, stolen = sign_in(client)
    assert refresh(client, stolen).status_code == 200
    assert refresh(client, stolen).status_code == 401

    events, _total = auth_audit.list_events(
        offset=0, limit=50, q="operator", outcome=auth_audit.OUTCOME_DENIED
    )
    assert any(event["reason"] == auth_audit.REASON_REFRESH_REUSE for event in events)


def test_reuse_ends_only_that_session(env):
    client, _settings = env
    _laptop_access, laptop = sign_in(client)
    phone_access, phone = sign_in(client)

    assert refresh(client, laptop).status_code == 200
    assert refresh(client, laptop).status_code == 401

    assert client.get("/api/auth/me", headers=bearer(phone_access)).status_code == 200
    assert refresh(client, phone).status_code == 200


def test_two_replicas_racing_one_token_exchange_it_once(env):
    """Two concurrent presentations serialize on the row lock: one wins, one is reuse.

    Without the lock both would read ``used_at IS NULL`` and both would mint a
    successor — two live branches of one session, which is the thing rotation
    exists to make impossible.
    """
    client, settings = env
    _access, token = sign_in(client)
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def present() -> None:
        barrier.wait()
        try:
            sessions_service.rotate(settings, token)
            outcomes.append("rotated")
        except sessions_service.RefreshTokenReused:
            outcomes.append("reuse")
        except PermissionError as exc:
            outcomes.append(f"refused: {exc}")

    threads = [threading.Thread(target=present) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert sorted(outcomes) == ["reuse", "rotated"]


# --------------------------------------------------------------------------- #
# Idle and absolute lifetime
# --------------------------------------------------------------------------- #


def test_a_session_idle_past_the_timeout_cannot_be_refreshed(env):
    client, settings = env
    access, refresh_token = sign_in(client)
    sid = claims(access)["sid"]
    backdate(settings, sid, last_used_at=naive_now() - timedelta(minutes=31))

    assert refresh(client, refresh_token).status_code == 401
    assert sessions_service.get_family(settings, sid).revoked_reason == sessions_service.END_IDLE
    # Ended means ended: the access token still inside its own fifteen minutes
    # is refused on its next request too.
    assert client.get("/api/auth/me", headers=bearer(access)).status_code == 401


def test_a_session_used_within_the_timeout_is_refreshed(env):
    """The other side of the boundary, so the idle test cannot pass by refusing everything."""
    client, settings = env
    access, refresh_token = sign_in(client)
    backdate(settings, claims(access)["sid"], last_used_at=naive_now() - timedelta(minutes=29))
    assert refresh(client, refresh_token).status_code == 200


def test_each_refresh_restarts_the_idle_clock(env):
    client, settings = env
    access, refresh_token = sign_in(client)
    sid = claims(access)["sid"]
    backdate(settings, sid, last_used_at=naive_now() - timedelta(minutes=29))
    answer = refresh(client, refresh_token)
    assert answer.status_code == 200
    last_used = sessions_service.get_family(settings, sid).last_used_at
    assert naive_now() - last_used < timedelta(minutes=1)


def test_an_idle_timeout_of_zero_is_off(tmp_path, monkeypatch):
    settings = make_settings(tmp_path, session_idle_minutes=0)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    access, refresh_token = sign_in(client)
    backdate(settings, claims(access)["sid"], last_used_at=naive_now() - timedelta(hours=7))
    assert refresh(client, refresh_token).status_code == 200


def test_refreshing_never_moves_the_absolute_end(env):
    client, settings = env
    access, refresh_token = sign_in(client)
    sid = claims(access)["sid"]
    backdate(settings, sid, expires_at=naive_now() - timedelta(seconds=1))
    assert refresh(client, refresh_token).status_code == 401
    assert sessions_service.get_family(settings, sid).revoked_reason == sessions_service.END_EXPIRED


def test_an_access_token_never_outlives_its_session(env):
    client, settings = env
    access, refresh_token = sign_in(client)
    end = naive_now() + timedelta(minutes=5)
    backdate(settings, claims(access)["sid"], expires_at=end)
    refreshed = refresh(client, refresh_token)
    assert refreshed.status_code == 200
    exp = claims(refreshed.json()["access_token"])["exp"]
    assert exp <= int(end.replace(tzinfo=UTC).timestamp())


# --------------------------------------------------------------------------- #
# Revocation reaches the refresh token
# --------------------------------------------------------------------------- #


def test_logout_ends_the_refresh_token_and_clears_the_cookie(env):
    client, settings = env
    access, refresh_token = sign_in(client)
    out = client.post(
        "/api/auth/logout",
        headers={**bearer(access), "Cookie": f"{REFRESH_COOKIE}={refresh_token}"},
    )
    assert out.status_code == 204
    assert "max-age=0" in (set_cookie_header(out) or "").lower()
    assert refresh(client, refresh_token).status_code == 401
    family = sessions_service.get_family(settings, claims(access)["sid"])
    assert family.revoked_reason == sessions_service.END_LOGOUT


def test_logout_without_the_cookie_still_ends_the_session_the_token_names(env):
    """A client that kept the access token but not the cookie jar."""
    client, _settings = env
    access, refresh_token = sign_in(client)
    assert client.post("/api/auth/logout", headers=bearer(access)).status_code == 204
    assert refresh(client, refresh_token).status_code == 401


def test_revoke_all_ends_every_refresh_token_of_the_account(env):
    client, _settings = env
    first_access, first = sign_in(client)
    _second_access, second = sign_in(client)
    assert client.post(
        "/api/auth/sessions/revoke-all", headers=bearer(first_access)
    ).status_code == 204
    assert refresh(client, first).status_code == 401
    assert refresh(client, second).status_code == 401


def test_disabling_the_account_ends_its_refresh_tokens(env):
    client, _settings = env
    admin = auth_headers(client, "admin")
    _access, refresh_token = sign_in(client)
    assert client.put(
        "/api/users/operator/disabled", headers=admin, json={"disabled": True}
    ).status_code == 200
    assert refresh(client, refresh_token).status_code == 401


def test_an_unreachable_session_store_is_a_503_not_a_sign_out(env, monkeypatch):
    client, _settings = env
    _access, refresh_token = sign_in(client)

    def unavailable(*_args, **_kwargs):
        raise sessions_service.SessionStoreUnavailable("session store is unavailable")

    monkeypatch.setattr(sessions_service, "rotate", unavailable)
    answer = refresh(client, refresh_token)
    assert answer.status_code == 503
    assert answer.headers["retry-after"] == "5"
    # The cookie is left alone: the session was not refused.
    assert set_cookie_header(answer) is None


def test_a_token_minted_before_refresh_tokens_existed_still_works(env):
    """No ``sid``: checked exactly as before migration 0060, and simply not refreshable."""
    client, _settings = env
    legacy = jwt.encode(
        {
            "sub": "operator",
            "role": "operator",
            "typ": "user",
            "ver": 0,
            "jti": "legacy-jti",
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(hours=8),
        },
        TEST_JWT_SECRET,
        algorithm="HS256",
    )
    assert client.get("/api/auth/me", headers=bearer(legacy)).status_code == 200
