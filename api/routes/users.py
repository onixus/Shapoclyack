"""Console account administration (#156).

Everything here is ``admin``-only except ``POST /auth/password``, which is how
any authenticated user rotates their own password — the operation that was
impossible before this change, when accounts lived in an environment variable
and a rotation meant editing a Secret and restarting every pod.

No response model carries a password or a hash: :class:`UserInfo` has no field
for one, so a leak would take a deliberate schema change rather than an
oversight at one call site.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import Role, StepUpDep, TokenUser, get_current_user, get_settings, require_role
from api.routes._audit import AuditDep
from api.schemas import (
    ChangeOwnPasswordRequest,
    CreateUserRequest,
    SetUserDisabledRequest,
    SetUserEmailRequest,
    SetUserPasswordRequest,
    SetUserRoleRequest,
    UserInfo,
)
from api.services import sessions as sessions_service
from api.services import users as users_service
from api.settings import Settings

router = APIRouter(tags=["users"])


def _not_found(username: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail=f"user '{username}' not found"
    )


@router.get("/users", response_model=list[UserInfo])
def list_users(_: Annotated[TokenUser, Depends(require_role(Role.admin))]) -> list[UserInfo]:
    return [UserInfo.model_validate(u) for u in users_service.list_users()]


@router.post("/users", response_model=UserInfo, status_code=status.HTTP_201_CREATED)
def create_user(
    body: CreateUserRequest,
    admin: Annotated[TokenUser, Depends(require_role(Role.admin))],
    # Creating an account with a password and a role *is* issuing a credential,
    # so it sits behind the same recent second factor as minting a token
    # (#315). Without it, a stolen admin session that cannot mint a service
    # token can simply create an admin account with no MFA and mint one as
    # that. Inert for an admin who has not enabled MFA.
    _: StepUpDep,
    audit: AuditDep,
) -> UserInfo:
    try:
        created = users_service.create_user(
            username=body.username,
            password=body.password,
            role=body.role,
            email=body.email,
            created_by=admin.username,
            audit=audit,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return UserInfo.model_validate(created)


@router.put("/users/{username}/password", response_model=UserInfo)
def set_user_password(
    username: str,
    body: SetUserPasswordRequest,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
    # Setting somebody else's password is taking over their account, which is
    # the same bootstrap as creating one (#315).
    __: StepUpDep,
    audit: AuditDep,
) -> UserInfo:
    """Admin reset. Deliberately does not require the old password.

    An admin resetting an account does not know it; requiring it would make the
    reset useless in the case it exists for — a user who cannot log in. Which
    is also why it is recorded: taking over an account is one request, and the
    trail is the only thing that says it happened.
    """
    try:
        updated = users_service.set_password(username, body.password, audit=audit)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    if updated is None:
        raise _not_found(username)
    return UserInfo.model_validate(updated)


@router.put("/users/{username}/role", response_model=UserInfo)
def set_user_role(
    username: str,
    body: SetUserRoleRequest,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
    # Promotion to admin is the third way to end up holding an admin account
    # without a second factor (#315).
    __: StepUpDep,
    audit: AuditDep,
) -> UserInfo:
    if body.role != "admin" and users_service.count_active_admins(exclude=username) == 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="cannot demote the last active admin — create another admin first",
        )
    try:
        updated = users_service.set_role(username, body.role, audit=audit)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    if updated is None:
        raise _not_found(username)
    return UserInfo.model_validate(updated)


@router.put("/users/{username}/email", response_model=UserInfo)
def set_user_email(
    username: str,
    body: SetUserEmailRequest,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
    # A *verified* address is what an SSO identity is linked to an existing
    # account by, so setting one decides whose identity-provider account ends
    # up owning this one — the same class of act as setting a password, and
    # behind the same recent second factor (#315). Without it, an admin session
    # with a stale step-up could point an account it controls at a colleague's
    # login and walk in through the door step-up had just closed.
    __: StepUpDep,
) -> UserInfo:
    """Set an account's address, and whether this platform treats it as verified.

    ``verified`` is the only thing that makes an existing local account
    eligible to be linked to an SSO identity by email (Track E), which is why
    it is an admin decision rather than something the identity provider can
    assert on its own: whoever can register an address at the IdP would
    otherwise be able to take over the console account that claims it.
    """
    try:
        updated = users_service.set_email(username, body.email, verified=body.verified)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    if updated is None:
        raise _not_found(username)
    return UserInfo.model_validate(updated)


@router.put("/users/{username}/disabled", response_model=UserInfo)
def set_user_disabled(
    username: str,
    body: SetUserDisabledRequest,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
    audit: AuditDep,
) -> UserInfo:
    """Disable rather than delete: memberships and history survive the revocation."""
    if body.disabled and users_service.count_active_admins(exclude=username) == 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="cannot disable the last active admin — create another admin first",
        )
    updated = users_service.set_disabled(username, body.disabled, audit=audit)
    if updated is None:
        raise _not_found(username)
    return UserInfo.model_validate(updated)


@router.post("/users/{username}/sessions/revoke-all", status_code=status.HTTP_204_NO_CONTENT)
def revoke_user_sessions(
    username: str,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    """Sign one account out of everywhere, without changing anything else (#314).

    Disabling, demoting and resetting a password already end that account's
    sessions on their own. This exists for the case where none of those is the
    right answer — a laptop left in a taxi, a shared browser, a token pasted
    into a chat — and the account should simply start over.

    Platform admin, and deliberately not restricted to *other* accounts: an
    admin who wants to end their own sessions from here rather than from
    ``POST /api/auth/sessions/revoke-all`` gets the same effect, including on
    the token they are holding.
    """
    try:
        sessions_service.revoke_all(settings, username)
    except LookupError as exc:
        raise _not_found(username) from exc


@router.delete("/users/{username}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    username: str,
    admin: Annotated[TokenUser, Depends(require_role(Role.admin))],
    audit: AuditDep,
) -> None:
    if username == admin.username:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="cannot delete the account you are signed in as",
        )
    if users_service.count_active_admins(exclude=username) == 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="cannot delete the last active admin — create another admin first",
        )
    if not users_service.delete_user(username, audit=audit):
        raise _not_found(username)


@router.post("/auth/password", status_code=status.HTTP_204_NO_CONTENT)
def change_own_password(
    body: ChangeOwnPasswordRequest,
    user: Annotated[TokenUser, Depends(get_current_user)],
    audit: AuditDep,
) -> None:
    """Rotate your own password. Any role — this is not an admin operation.

    The current password is re-verified even though the caller already holds a
    valid token: a token can be a stolen one, and "can act as this user right
    now" is a weaker claim than "knows this user's password".
    """
    try:
        changed = users_service.change_own_password(
            user.username, current=body.current_password, new=body.new_password, audit=audit
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    if changed is None:
        # One status for both "wrong current password" and "account is gone",
        # matching the login endpoint's refusal to distinguish the two.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="current password is incorrect"
        )
