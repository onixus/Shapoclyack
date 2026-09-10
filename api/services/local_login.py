"""What password login is for once SSO is the way in (#315).

Before this, an installation that had wired up an identity provider still
accepted every local password, for every account, silently. That is a
break-glass door standing permanently open: the controls the customer's IdP
enforces — conditional access, device posture, its own MFA, its own
offboarding — were all optional, and nothing in the trail distinguished
"deliberately bypassed SSO" from "signed in".

``OCTO_LOCAL_LOGIN`` names which of three things the door is:

``enabled`` (default)
    Exactly the pre-#315 behaviour. Nothing about an upgrade changes.
``break-glass``
    Only the accounts named in ``OCTO_BREAK_GLASS_USERS`` may present a
    password, and each such login is its own audit action, its own reason in
    the login trail, its own metric and a WARNING log line — four places,
    because the value of a break-glass account is entirely in it being noticed.
``disabled``
    No password login at all.

None of it applies when no identity provider is configured. An installation
with no SSO that turned password login off would be an installation nobody can
reach, and this module refusing to be that is more useful than it being
literal.
"""

from __future__ import annotations

import logging

from api.db.engine import get_session
from api.services import audit as audit_service
from api.services import auth_audit
from api.services import metrics as metrics_service
from api.services import oidc as oidc_service
from api.settings import LOCAL_LOGIN_BREAK_GLASS, LOCAL_LOGIN_DISABLED, Settings

logger = logging.getLogger(__name__)


class LocalLoginRefused(PermissionError):
    """Password login refused by policy rather than by the credential.

    ``reason`` is the ``auth_events`` reason the route records; the message is
    what the caller is told, and it deliberately does not say whether the
    account exists or whether it is one of the break-glass names.
    """

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


def policy_applies(settings: Settings) -> bool:
    """Whether ``OCTO_LOCAL_LOGIN`` has anything to say on this installation."""
    return oidc_service.is_enabled(settings) and settings.local_login != "enabled"


def is_break_glass_account(settings: Settings, username: str) -> bool:
    return username in settings.break_glass_users


def check_allowed(settings: Settings, username: str) -> bool:
    """Decide whether ``username`` may present a password. Returns break-glass-ness.

    ``True`` means this login is a break-glass one and the caller must record
    it as such once it succeeds — see :func:`record_break_glass`. Raises
    :class:`LocalLoginRefused` when policy says no, which the login route
    answers with the same 401 a wrong password gets: telling an unauthenticated
    caller *which* accounts are the emergency ones would be handing over the
    list worth attacking.
    """
    if not policy_applies(settings):
        return False
    if settings.local_login == LOCAL_LOGIN_DISABLED:
        raise LocalLoginRefused(
            "password login is disabled on this installation; sign in with SSO",
            reason=auth_audit.REASON_LOCAL_LOGIN_DISABLED,
        )
    if settings.local_login == LOCAL_LOGIN_BREAK_GLASS:
        if not is_break_glass_account(settings, username):
            raise LocalLoginRefused(
                "password login is reserved for break-glass accounts on this "
                "installation; sign in with SSO",
                reason=auth_audit.REASON_NOT_BREAK_GLASS,
            )
        return True
    return False


def record_break_glass(settings: Settings, *, username: str, client_ip: str) -> None:
    """Announce one emergency login everywhere an operator might be watching.

    Four sinks and not one, because they are read by different people at
    different times: the administrative trail is what a review reads months
    later, the login trail is where it sits next to the other access decisions,
    ``octo_break_glass_logins_total`` is what Alertmanager pages on, and the log
    line is what somebody tailing the API sees within the second.

    Written in its own transaction, after the session has been issued: a
    failure to record must not be a failure to log in — an operator reaching
    for the emergency door usually cannot fix the recording either. It is
    logged loudly instead of swallowed.
    """
    metrics_service.BREAK_GLASS_LOGINS_TOTAL.inc()
    logger.warning(
        "Break-glass password login by %r from %s while SSO is configured. "
        "This bypasses the identity provider's controls; confirm it was expected.",
        username,
        client_ip or "unknown address",
    )
    try:
        auth_audit.record_break_glass_login(username=username, client_ip=client_ip)
        with get_session(settings.postgres_url) as session:
            audit_service.record(
                session,
                audit_service.system_context(actor=username),
                action=audit_service.ACTION_BREAK_GLASS_LOGIN,
                resource_type="user",
                resource_id=username,
                after={"client_ip": client_ip, "local_login": settings.local_login},
            )
    except Exception:  # noqa: BLE001 - see the docstring: fail-soft, but loudly
        # A break-glass login is what an operator does when the platform is
        # already unhealthy, and the database being the unhealthy part is a
        # realistic case. Refusing the login because the row could not be
        # written would turn a degraded installation into an unreachable one;
        # the WARNING above has already left the fact in the logs.
        logger.exception(
            "Failed to record the break-glass login of %r; the sign-in was allowed "
            "and this line is the trail.",
            username,
        )
