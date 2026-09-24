"""Per-tenant retention windows and legal hold (#332).

Under ``/api/tenants/{tenant_id}/…`` like the rest of tenant administration, so
the tenant comes from the path and a service token cannot reach any of it —
``tenants`` is in ``service_tokens.FORBIDDEN_RESOURCES``. Three authorities,
and they are deliberately held by different people:

* ``tenant.retention.read`` — the tenant's admin and auditor. A customer's DPO
  asking how long their scan evidence is kept should get an answer from the
  console, not from a support ticket.
* ``tenant.retention.manage`` — the tenant's admin, within the platform bounds.
  Behind a step-up: shortening a window is a delete scheduled for the next
  sweep.
* ``platform.legal_hold.manage`` — platform admins only, behind a step-up. A
  tenant that could release its own hold could let evidence age out
  mid-litigation.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status

from api.auth import (
    StepUpDep,
    TenantPrincipal,
    TokenUser,
    get_settings,
    require_path_tenant_permission,
    require_platform_permission,
)
from api.core import permissions as permission_catalog
from api.routes._audit import AuditDep
from api.schemas import (
    LegalHoldInfo,
    LegalHoldRequest,
    RetentionPolicyInfo,
    RetentionPolicyRequest,
)
from api.services import legal_hold
from api.services import retention_policy
from api.services import tenants as tenants_service
from api.settings import Settings

router = APIRouter(tags=["retention"])


def _require_tenant(tenant_id: str) -> None:
    if tenants_service.get_tenant(tenant_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")


@router.get("/tenants/{tenant_id}/retention", response_model=RetentionPolicyInfo)
def get_retention(
    tenant_id: str,
    principal: Annotated[
        TenantPrincipal,
        Depends(require_path_tenant_permission(permission_catalog.TENANT_RETENTION_READ)),
    ],
    settings: Annotated[Settings, Depends(get_settings)],
) -> RetentionPolicyInfo:
    """How long each kind of this tenant's data is kept, and whether it is on hold.

    Every category is listed, inherited or not: "how long do you keep X" has
    an answer for every X, and a category missing from the page would read as
    "not kept". The tenant's own readers learn that a hold is in force and
    since when; who placed it and why is for platform admins
    (``legal_hold.public_view``).
    """
    _require_tenant(tenant_id)
    described = retention_policy.describe(settings, tenant_id)
    if not principal.is_platform_admin:
        described["legal_hold"] = legal_hold.public_view(described["legal_hold"])
    return RetentionPolicyInfo.model_validate(described)


@router.put("/tenants/{tenant_id}/retention", response_model=RetentionPolicyInfo)
def replace_retention(
    tenant_id: str,
    body: RetentionPolicyRequest,
    principal: Annotated[
        TenantPrincipal,
        Depends(require_path_tenant_permission(permission_catalog.TENANT_RETENTION_MANAGE)),
    ],
    _: StepUpDep,
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> RetentionPolicyInfo:
    """Set this tenant's retention windows, replacing whatever it had.

    Within the platform bounds or not at all: a value below a category's floor
    — a year of audit trail by default — is a 422 naming the bounds. The whole
    document, before and after, is in the audit trail, because the change that
    matters is the one that shortened a window: its effect is a delete on the
    next sweep.
    """
    try:
        described = retention_policy.replace_policy(
            settings,
            tenant_id,
            overrides=body.overrides,
            note=body.note,
            updated_by=principal.username,
            audit=audit,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if not principal.is_platform_admin:
        described["legal_hold"] = legal_hold.public_view(described["legal_hold"])
    return RetentionPolicyInfo.model_validate(described)


@router.delete("/tenants/{tenant_id}/retention", status_code=status.HTTP_204_NO_CONTENT)
def clear_retention(
    tenant_id: str,
    _: Annotated[
        TenantPrincipal,
        Depends(require_path_tenant_permission(permission_catalog.TENANT_RETENTION_MANAGE)),
    ],
    __: StepUpDep,
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> Response:
    """Put every category back on the platform default. 204 whether or not there was a policy."""
    _require_tenant(tenant_id)
    retention_policy.clear_policy(settings, tenant_id, audit=audit)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.put("/tenants/{tenant_id}/legal-hold", response_model=LegalHoldInfo)
def place_legal_hold(
    tenant_id: str,
    body: LegalHoldRequest,
    user: Annotated[
        TokenUser,
        Depends(require_platform_permission(permission_catalog.PLATFORM_LEGAL_HOLD_MANAGE)),
    ],
    _: StepUpDep,
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> LegalHoldInfo:
    """Stop every reaper from deleting this tenant's data, and the tenant from being deleted.

    Placing a hold that is already in force amends its reason and keeps when
    and by whom it was first placed.
    """
    try:
        hold = legal_hold.place_hold(
            settings, tenant_id, reason=body.reason, set_by=user.username, audit=audit
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return LegalHoldInfo.model_validate(hold)


@router.delete("/tenants/{tenant_id}/legal-hold", status_code=status.HTTP_204_NO_CONTENT)
def release_legal_hold(
    tenant_id: str,
    _: Annotated[
        TokenUser,
        Depends(require_platform_permission(permission_catalog.PLATFORM_LEGAL_HOLD_MANAGE)),
    ],
    __: StepUpDep,
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> Response:
    """Release the hold. The reapers resume on their next tick.

    Everything the hold kept past its window goes then, which is why this is a
    step-up and why the released hold is kept in the audit row's ``before``.
    204 whether or not there was a hold: the caller asked for none, and there
    is none.
    """
    _require_tenant(tenant_id)
    legal_hold.release_hold(settings, tenant_id, audit=audit)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
