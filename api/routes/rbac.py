"""The role and permission catalogue, and the roles a tenant defines (#318).

An administrator about to grant a membership has to know which roles exist and
what each one can do, and the console has to render that without keeping a
second copy of the role table. Two lists, both reference data for the
built-ins: they are seeded by migration 0049 and change only when the
platform's own vocabulary does.

The write side is a tenant's own: ``/tenants/{tenant_id}/roles`` defines,
edits and deletes a role of that tenant, gated on ``tenant.member.manage`` —
the people who grant memberships decide what there is to grant. What a role
may contain, and why nobody can define one above themselves, is
:mod:`api.services.rbac`.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.auth import (
    Role,
    StepUpDep,
    TenantPrincipal,
    TokenUser,
    require_path_tenant_permission,
    require_permission,
    require_role,
)
from api.core import permissions as permission_catalog
from api.routes._audit import AuditDep
from api.schemas import (
    CreateRoleRequest,
    DeleteRoleResult,
    PermissionInfo,
    RoleInfo,
    UpdateRoleRequest,
)
from api.services import rbac as rbac_service

router = APIRouter(prefix="/rbac", tags=["rbac"])
#: The tenant-scoped write side, under ``/tenants/{tenant_id}`` like the
#: memberships it feeds — which also puts it out of every service token's reach
#: (``tenants`` is a forbidden scope resource).
tenant_router = APIRouter(tags=["rbac"])


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
    has no use for the menu of what they could be made. Another tenant's roles
    are never in it.
    """
    return [
        RoleInfo.model_validate(item)
        for item in rbac_service.list_roles(principal.tenant_id)
    ]


def _refusal(exc: Exception) -> HTTPException:
    """The status each service refusal answers with.

    Order matters: :class:`rbac_service.RoleExists` and
    :class:`rbac_service.RoleInUse` are ValueErrors too.
    """
    if isinstance(exc, LookupError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    if isinstance(exc, PermissionError):
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    if isinstance(exc, (rbac_service.RoleExists, rbac_service.RoleInUse)):
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))


@tenant_router.post(
    "/tenants/{tenant_id}/roles",
    response_model=RoleInfo,
    status_code=status.HTTP_201_CREATED,
)
def create_role(
    tenant_id: str,
    body: CreateRoleRequest,
    principal: Annotated[
        TenantPrincipal,
        Depends(require_path_tenant_permission(permission_catalog.TENANT_MEMBER_MANAGE)),
    ],
    # Defining a role is defining what a grant can hand out: a recent second
    # factor, as on the membership routes (#504). No effect without MFA.
    __: StepUpDep,
    audit: AuditDep,
) -> RoleInfo:
    """Define a role of this tenant: a name, a rank and an explicit permission set.

    ``422`` for an unknown permission, a platform-only one, or a combination
    the separation of duties forbids; ``403`` when the role would carry more
    than the caller holds here; ``409`` for a name that is taken or built in.
    """
    try:
        created = rbac_service.create_role(
            tenant_id=tenant_id,
            role_id=body.role_id,
            description=body.description,
            rank=body.rank,
            permissions=body.permissions,
            actor=principal.authority,
            created_by=principal.username,
            audit=audit,
        )
    except (LookupError, PermissionError, ValueError) as exc:
        raise _refusal(exc) from exc
    return RoleInfo.model_validate(created)


@tenant_router.patch("/tenants/{tenant_id}/roles/{role_id}", response_model=RoleInfo)
def update_role(
    tenant_id: str,
    role_id: str,
    body: UpdateRoleRequest,
    principal: Annotated[
        TenantPrincipal,
        Depends(require_path_tenant_permission(permission_catalog.TENANT_MEMBER_MANAGE)),
    ],
    # Editing a role changes every holder's authority at once (#504).
    __: StepUpDep,
    audit: AuditDep,
) -> RoleInfo:
    """Rename a role of this tenant or change what it may do.

    A new ``role_id`` carries every member holding the role along with it. A
    changed definition is what every holder may do from their next request,
    so the role before *and* after must be within the caller's authority.
    Built-in roles are not this tenant's to edit: ``404``.
    """
    try:
        updated = rbac_service.update_role(
            tenant_id=tenant_id,
            role_id=role_id,
            new_role_id=body.role_id,
            description=body.description,
            rank=body.rank,
            permissions=body.permissions,
            actor=principal.authority,
            updated_by=principal.username,
            audit=audit,
        )
    except (LookupError, PermissionError, ValueError) as exc:
        raise _refusal(exc) from exc
    return RoleInfo.model_validate(updated)


@tenant_router.delete("/tenants/{tenant_id}/roles/{role_id}", response_model=DeleteRoleResult)
def delete_role(
    tenant_id: str,
    role_id: str,
    principal: Annotated[
        TenantPrincipal,
        Depends(require_path_tenant_permission(permission_catalog.TENANT_MEMBER_MANAGE)),
    ],
    # Deleting with ``reassign_to`` regrants every holder (#504).
    __: StepUpDep,
    audit: AuditDep,
    reassign_to: Annotated[
        str | None,
        Query(description="Role the members holding this one are regranted", max_length=64),
    ] = None,
) -> DeleteRoleResult:
    """Delete a role of this tenant.

    ``409`` while any member holds it — nobody's access disappears with a role
    as a side effect. ``reassign_to`` names where they go instead, a role the
    caller may grant; each move is recorded as a ``membership.grant``.
    """
    try:
        deleted = rbac_service.delete_role(
            tenant_id=tenant_id,
            role_id=role_id,
            reassign_to=reassign_to,
            actor=principal.authority,
            audit=audit,
        )
    except (LookupError, PermissionError, ValueError) as exc:
        raise _refusal(exc) from exc
    return DeleteRoleResult.model_validate(deleted)
