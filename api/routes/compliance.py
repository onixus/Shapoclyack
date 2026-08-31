"""Compliance posture over the tenant's own evidence (Sprint 4).

Read-only and ``viewer``-gated throughout: nothing here changes state, and a
compliance page an analyst cannot open is a page that gets replaced by a
spreadsheet.

Unlike the vulnerability lists, an unscoped platform admin is **not** given a
cross-tenant view. A control status is a statement about one organisation's
estate; merging three customers' findings into one PCI score would produce a
number that is true of nobody.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import Role, TenantPrincipal, get_settings, require_tenant
from api.schemas import (
    ComplianceControlStatus,
    ComplianceFrameworkInfo,
    CompliancePosture,
)
from api.services import compliance as compliance_service
from api.settings import Settings

router = APIRouter(prefix="/compliance", tags=["compliance"])

SettingsDep = Annotated[Settings, Depends(get_settings)]


@router.get("/frameworks", response_model=list[ComplianceFrameworkInfo])
def list_frameworks(
    _principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
) -> list[dict]:
    return compliance_service.list_frameworks()


@router.get("/{framework_id}", response_model=CompliancePosture)
def get_posture(
    framework_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
) -> dict:
    posture = compliance_service.assess(
        settings, framework_id=framework_id, tenant_id=principal.tenant_id
    )
    if posture is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Unknown compliance framework"
        )
    return posture


@router.get(
    "/{framework_id}/controls/{control_id}", response_model=ComplianceControlStatus
)
def get_control(
    framework_id: str,
    control_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
) -> dict:
    """Every piece of evidence behind one control, not the summary's sample."""

    control = compliance_service.control_evidence(
        settings,
        framework_id=framework_id,
        control_id=control_id,
        tenant_id=principal.tenant_id,
    )
    if control is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown control")
    return control
