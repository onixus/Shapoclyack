"""Tenant-scoped compliance posture and admin-only custom catalogue import.

A control status describes one organisation; an unscoped platform admin is not
allowed a merged cross-tenant view. Importing a catalogue never imports code.
"""
from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from api.auth import Role, TenantPrincipal, get_settings, require_tenant
from api.routes._audit import AuditDep
from api.schemas import ComplianceControlStatus, ComplianceFrameworkInfo, CompliancePosture
from api.services import compliance as compliance_service
from api.services.compliance import definitions, registry
from api.settings import Settings

router = APIRouter(prefix="/compliance", tags=["compliance"])
SettingsDep = Annotated[Settings, Depends(get_settings)]


class FrameworkImport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: Literal["json", "csv"]
    content: str = Field(min_length=1, max_length=definitions.MAX_BYTES)


@router.get("/frameworks", response_model=list[ComplianceFrameworkInfo])
def list_frameworks(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
) -> list[dict]:
    return registry.list_frameworks(settings, tenant_id=principal.tenant_id)


@router.post("/frameworks/import", status_code=status.HTTP_201_CREATED)
def import_framework(
    payload: FrameworkImport,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: SettingsDep,
    audit: AuditDep,
    response: Response,
) -> dict[str, Any]:
    try:
        result, created = registry.import_definition(
            settings, tenant_id=principal.tenant_id,
            content=payload.content, format=payload.format, audit=audit,
        )
    except definitions.DefinitionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except registry.CatalogueConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if not created:
        response.status_code = status.HTTP_200_OK
    return result


@router.get("/frameworks/{framework_id}/definition")
def get_definition(
    framework_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
) -> dict[str, Any]:
    result = registry.get_definition(settings, tenant_id=principal.tenant_id, framework_id=framework_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Unknown custom compliance framework")
    return result


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
        raise HTTPException(status_code=404, detail="Unknown compliance framework")
    return posture


@router.get("/{framework_id}/controls/{control_id}", response_model=ComplianceControlStatus)
def get_control(
    framework_id: str,
    control_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
) -> dict:
    """Every piece of evidence behind one control, not the summary's sample."""
    control = compliance_service.control_evidence(
        settings, framework_id=framework_id, control_id=control_id, tenant_id=principal.tenant_id,
    )
    if control is None:
        raise HTTPException(status_code=404, detail="Unknown control")
    return control
