"""Report factory: branding, templates, schedules and generated reports (Sprint 4).

Roles follow what the action commits the tenant to, the same reasoning webhooks
and SLA policy already use:

* reading templates, schedules and reports is ``viewer``;
* rendering a report on demand is ``operator`` — it is work, not a commitment;
* **branding and schedules are ``admin``**, because a schedule sends this
  tenant's findings to an address outside the installation on a recurring basis
  and branding is what the customer sees the platform as. Both are decisions
  about the organisation rather than steps in somebody's remediation.

Every route is pinned to ``principal.tenant_id``. There is deliberately no
cross-tenant view for a platform admin here: a report is a document about one
organisation, and one that mixed two customers' findings would be a data leak
with a cover page.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse

from api.auth import Role, TenantPrincipal, get_settings, require_tenant
from api.schemas import (
    GeneratedReportInfo,
    GenerateReportRequest,
    ReportScheduleInfo,
    ReportScheduleRequest,
    ReportScheduleUpdate,
    ReportTemplateInfo,
    ReportTemplateRequest,
    ReportTemplateUpdate,
    TenantBrandingInfo,
    TenantBrandingRequest,
)
from api.services.reports import branding as branding_service
from api.services.reports import store
from api.settings import Settings

router = APIRouter(prefix="/reports", tags=["reports"])

SettingsDep = Annotated[Settings, Depends(get_settings)]


def _bad_request(exc: Exception) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


# ------------------------------------------------------------------ branding


@router.get("/branding", response_model=TenantBrandingInfo)
def get_branding(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
) -> dict[str, Any]:
    return branding_service.get_branding(settings, tenant_id=principal.tenant_id)


@router.put("/branding", response_model=TenantBrandingInfo)
def put_branding(
    payload: TenantBrandingRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: SettingsDep,
) -> dict[str, Any]:
    """Only the fields present in the body are written, so clearing the logo is
    an explicit ``"logo_png": null`` rather than a side effect of a rename."""

    try:
        return branding_service.set_branding(
            settings,
            tenant_id=principal.tenant_id,
            actor=principal.username,
            **payload.model_dump(exclude_unset=True),
        )
    except branding_service.BrandingError as exc:
        raise _bad_request(exc) from exc


# ----------------------------------------------------------------- templates


@router.get("/templates", response_model=list[ReportTemplateInfo])
def list_templates(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
) -> list[dict[str, Any]]:
    return store.list_templates(settings, tenant_id=principal.tenant_id)


@router.post(
    "/templates", response_model=ReportTemplateInfo, status_code=status.HTTP_201_CREATED
)
def create_template(
    payload: ReportTemplateRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
) -> dict[str, Any]:
    try:
        return store.create_template(
            settings,
            tenant_id=principal.tenant_id,
            name=payload.name,
            kind=payload.kind,
            framework_id=payload.framework_id,
            sections=payload.sections,
            actor=principal.username,
        )
    except store.ReportError as exc:
        raise _bad_request(exc) from exc


@router.patch("/templates/{template_id}", response_model=ReportTemplateInfo)
def update_template(
    template_id: str,
    payload: ReportTemplateUpdate,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
) -> dict[str, Any]:
    try:
        row = store.update_template(
            settings,
            template_id,
            tenant_id=principal.tenant_id,
            **payload.model_dump(exclude_unset=True),
        )
    except store.ReportError as exc:
        raise _bad_request(exc) from exc
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")
    return row


@router.delete("/templates/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_template(
    template_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
) -> None:
    """409 while a schedule still uses the template: deleting it would cascade
    onto an admin-created recurring delivery, and an operator does not get to
    undo that by side effect."""

    try:
        deleted = store.delete_template(settings, template_id, tenant_id=principal.tenant_id)
    except store.ReportError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")


# ----------------------------------------------------------------- schedules


@router.get("/schedules", response_model=list[ReportScheduleInfo])
def list_schedules(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
) -> list[dict[str, Any]]:
    return store.list_schedules(settings, tenant_id=principal.tenant_id)


@router.post(
    "/schedules", response_model=ReportScheduleInfo, status_code=status.HTTP_201_CREATED
)
def create_schedule(
    payload: ReportScheduleRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: SettingsDep,
) -> dict[str, Any]:
    try:
        return store.create_schedule(
            settings,
            tenant_id=principal.tenant_id,
            template_id=payload.template_id,
            name=payload.name,
            cron=payload.cron,
            fmt=payload.format,
            recipients=[entry.model_dump() for entry in payload.recipients],
            enabled=payload.enabled,
            actor=principal.username,
        )
    except store.ReportError as exc:
        raise _bad_request(exc) from exc


@router.patch("/schedules/{schedule_id}", response_model=ReportScheduleInfo)
def update_schedule(
    schedule_id: str,
    payload: ReportScheduleUpdate,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: SettingsDep,
) -> dict[str, Any]:
    fields = payload.model_dump(exclude_unset=True)
    if "recipients" in fields and fields["recipients"] is not None:
        fields["recipients"] = [dict(entry) for entry in fields["recipients"]]
    try:
        row = store.update_schedule(
            settings, schedule_id, tenant_id=principal.tenant_id, **fields
        )
    except store.ReportError as exc:
        raise _bad_request(exc) from exc
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found")
    return row


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(
    schedule_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: SettingsDep,
) -> None:
    if not store.delete_schedule(settings, schedule_id, tenant_id=principal.tenant_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found")


# ---------------------------------------------------------- generated reports


@router.post("/generate", response_model=GeneratedReportInfo)
def generate_report(
    payload: GenerateReportRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
) -> dict[str, Any]:
    """Render one report now. Returns the row whether it succeeded or failed —
    a failed render is a record with an error on it, not a 500."""

    try:
        return store.generate(
            settings,
            tenant_id=principal.tenant_id,
            template_id=payload.template_id,
            kind=payload.kind,
            framework_id=payload.framework_id,
            sections=payload.sections,
            fmt=payload.format,
            title=payload.title,
            actor=principal.username,
        )
    except store.ReportError as exc:
        raise _bad_request(exc) from exc


@router.get("", response_model=list[GeneratedReportInfo])
def list_reports(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[dict[str, Any]]:
    return store.list_reports(settings, tenant_id=principal.tenant_id, limit=limit)


@router.get("/{report_id}", response_model=GeneratedReportInfo)
def get_report(
    report_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
) -> dict[str, Any]:
    row = store.get_report(settings, report_id, tenant_id=principal.tenant_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return row


@router.get("/{report_id}/download")
def download_report(
    report_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
) -> FileResponse:
    resolved = store.resolve_report_file(settings, report_id, tenant_id=principal.tenant_id)
    if resolved is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    path, media_type, filename = resolved
    return FileResponse(path, media_type=media_type, filename=filename)


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_report(
    report_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
) -> None:
    if not store.delete_report(settings, report_id, tenant_id=principal.tenant_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
