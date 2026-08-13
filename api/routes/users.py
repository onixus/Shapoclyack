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

from api.auth import Role, TokenUser, get_current_user, require_role
from api.schemas import (
    ChangeOwnPasswordRequest,
    CreateUserRequest,
    SetUserDisabledRequest,
    SetUserPasswordRequest,
    SetUserRoleRequest,
    UserInfo,
)
from api.services import users as users_service

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
) -> UserInfo:
    try:
        created = users_service.create_user(
            username=body.username,
            password=body.password,
            role=body.role,
            created_by=admin.username,
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
) -> UserInfo:
    """Admin reset. Deliberately does not require the old password.

    An admin resetting an account does not know it; requiring it would make the
    reset useless in the case it exists for — a user who cannot log in.
    """
    try:
        updated = users_service.set_password(username, body.password)
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
) -> UserInfo:
    if body.role != "admin" and users_service.count_active_admins(exclude=username) == 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="cannot demote the last active admin — create another admin first",
        )
    try:
        updated = users_service.set_role(username, body.role)
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
) -> UserInfo:
    """Disable rather than delete: memberships and history survive the revocation."""
    if body.disabled and users_service.count_active_admins(exclude=username) == 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="cannot disable the last active admin — create another admin first",
        )
    updated = users_service.set_disabled(username, body.disabled)
    if updated is None:
        raise _not_found(username)
    return UserInfo.model_validate(updated)


@router.delete("/users/{username}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    username: str,
    admin: Annotated[TokenUser, Depends(require_role(Role.admin))],
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
    if not users_service.delete_user(username):
        raise _not_found(username)


@router.post("/auth/password", status_code=status.HTTP_204_NO_CONTENT)
def change_own_password(
    body: ChangeOwnPasswordRequest,
    user: Annotated[TokenUser, Depends(get_current_user)],
) -> None:
    """Rotate your own password. Any role — this is not an admin operation.

    The current password is re-verified even though the caller already holds a
    valid token: a token can be a stolen one, and "can act as this user right
    now" is a weaker claim than "knows this user's password".
    """
    try:
        changed = users_service.change_own_password(
            user.username, current=body.current_password, new=body.new_password
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
