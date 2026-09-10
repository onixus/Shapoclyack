"""The role and permission catalogue, read side (#318).

An administrator about to grant a membership has to know which roles exist and
what each one can do, and the console has to render that without keeping a
second copy of the role table. Two lists, both reference data: they are seeded
by migration 0049 and change only when the platform's own vocabulary does.

Write side — a tenant defining a role of its own — is **not implemented**; see
:mod:`api.services.rbac` for exactly what is missing and what already holds it.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from api.auth import Role, TenantPrincipal, TokenUser, require_permission, require_role
from api.core import permissions as permission_catalog
from api.schemas import PermissionInfo, RoleInfo
from api.services import rbac as rbac_service

router = APIRouter(prefix="/rbac", tags=["rbac"])


@router.get("/permissions", response_model=list[PermissionInfo])
def list_permissions(
    _: Annotated[TokenUser, Depends(require_role(Role.viewer))],
) -> list[PermissionInfo]:
    """Every named authority this platform knows about.

    Open to any authenticated caller on purpose: it is the vocabulary, not an
    answer about anybody. Knowing that ``scan_scope.approve`` exists tells you
    nothing about who holds it — which is ``GET /rbac/roles`` plus the
    memberships, both of which are gated.
    """
    return [PermissionInfo.model_validate(item) for item in rbac_service.list_permissions()]


@router.get("/roles", response_model=list[RoleInfo])
def list_roles(
    principal: Annotated[
        TenantPrincipal,
        Depends(require_permission(permission_catalog.TENANT_MEMBER_READ)),
    ],
) -> list[RoleInfo]:
    """The built-in roles, plus any this tenant defined, with their permissions.

    Gated on ``tenant.member.read`` because this is the list somebody reads in
    order to grant a membership; a caller who cannot see who is in the tenant
    has no use for the menu of what they could be made.
    """
    return [
        RoleInfo.model_validate(item)
        for item in rbac_service.list_roles(principal.tenant_id)
    ]
