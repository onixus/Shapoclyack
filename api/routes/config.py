from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import (
    TenantPrincipal,
    TokenUser,
    get_settings,
    require_permission,
    require_platform_permission,
)
from api.core import permissions as permission_catalog
from api.routes._audit import AuditDep
from api.schemas import ConfigResponse, ConfigUpdateRequest
from api.services import config_override as config_service
from api.settings import Settings

router = APIRouter(prefix="/config", tags=["config"])


@router.get("", response_model=ConfigResponse)
def get_config(
    _: Annotated[
        TenantPrincipal, Depends(require_permission(permission_catalog.CONFIG_READ))
    ],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ConfigResponse:
    """Editable scanner-config settings: whitelisted paths with their default
    (base file), effective (base + overrides), and the raw stored overrides.

    ``config.read`` since #318, which a viewer does not hold. This answer is
    the installation's scanning posture — which stages run, which profiles
    exist, which enrichment keys are configured (masked, but their presence is
    itself information) — and it was readable by the lowest role on the
    platform. Operators, tenant admins and auditors hold the permission; a
    viewer reads findings.
    """
    return ConfigResponse.model_validate(config_service.editable_snapshot(settings))


@router.put("", response_model=ConfigResponse)
def update_config(
    body: ConfigUpdateRequest,
    user: Annotated[
        TokenUser,
        Depends(require_platform_permission(permission_catalog.CONFIG_WRITE)),
    ],
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> ConfigResponse:
    """Replace the installation-wide config overrides (platform admin only).
    Overrides are validated against the editable whitelist AND the full merged
    schema; an invalid payload is rejected (422) and nothing is persisted.

    Platform, not tenant: this document is shared by every tenant on the
    installation, so a tenant admin editing it would be editing everybody's
    scanner — which is why the write is a ``platform.*`` permission and the
    read above is not.
    """
    try:
        nested = config_service.unflatten(body.overrides)
        config_service.set_overrides(settings, nested, username=user.username, audit=audit)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return ConfigResponse.model_validate(config_service.editable_snapshot(settings))
