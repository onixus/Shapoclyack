"""The refresh-token cookie, and opening a console session behind it (#314).

Three routes finish a sign-in — password login, the second leg of an MFA
login, the SSO callback — and each has to do the same three things in the same
order: open a session family, mint the access token that names it, and hand the
browser the family's refresh token. Doing them in one place is what keeps the
three from drifting into three slightly different cookies.

The cookie is the only place the refresh token ever leaves the server, and its
attributes are the whole of its protection:

* ``HttpOnly`` — no script on the console's origin can read it, so an XSS that
  lifts the access token out of local storage gets fifteen minutes, not eight
  hours;
* ``Secure`` — ``OCTO_REFRESH_COOKIE_SECURE``, on in prod (and refused off
  there), off by default in dev for a lab stand on plain http;
* ``SameSite=Strict`` — a cross-site page cannot make the browser send it, so
  it cannot trigger a rotation behind the user's back (which the reuse
  detection would then read as theft and answer by signing the user out);
* ``Path=/api/auth`` — it is sent to the refresh and logout routes and their
  neighbours, not with every scan upload and list request.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import Response

from api.auth import TokenUser, create_access_token
from api.services import sessions as sessions_service
from api.settings import Settings

REFRESH_COOKIE = "shapoclyack_refresh"
REFRESH_COOKIE_PATH = "/api/auth"


def set_refresh_cookie(
    response: Response, settings: Settings, opened: sessions_service.OpenedSession
) -> None:
    """Hand the browser a refresh token that lives exactly as long as its family."""
    max_age = max(0, int((opened.expires_at - datetime.now(UTC)).total_seconds()))
    response.set_cookie(
        REFRESH_COOKIE,
        opened.refresh_token,
        max_age=max_age,
        path=REFRESH_COOKIE_PATH,
        secure=settings.refresh_cookie_secure,
        httponly=True,
        samesite="strict",
    )


def clear_refresh_cookie(response: Response, settings: Settings) -> None:
    # The same attributes as when it was set: a browser matches a deletion to
    # the cookie by name, path and domain, and some refuse to overwrite a
    # Secure cookie from a Set-Cookie that is not.
    response.delete_cookie(
        REFRESH_COOKIE,
        path=REFRESH_COOKIE_PATH,
        secure=settings.refresh_cookie_secure,
        httponly=True,
        samesite="strict",
    )


def issue_session(
    settings: Settings, user: TokenUser, *, mfa_verified_at: datetime | None = None
) -> tuple[str, sessions_service.OpenedSession]:
    """Open a session family for ``user`` and mint its first access token.

    Returns the access token and the opened family; the caller sets the cookie
    with :func:`set_refresh_cookie` on whichever response it is about to send
    (the SSO callback answers with a redirect, not the injected ``Response``).

    Raises :class:`LookupError` when the account vanished between the
    credential check and here, which every caller already answers like a
    wrong password.
    """
    opened = sessions_service.open_session(
        settings, username=user.username, mfa_verified_at=mfa_verified_at
    )
    token = create_access_token(
        settings,
        user,
        session_id=opened.family_id,
        session_expires_at=opened.expires_at,
        mfa_verified_at=mfa_verified_at,
        # The generation the family was opened at, so the access token and
        # the refresh token it travels with can never disagree about it.
        token_version=opened.token_version,
    )
    return token, opened
