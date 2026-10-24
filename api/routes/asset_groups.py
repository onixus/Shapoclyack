"""Tenant-authorized dynamic classification rules (#578)."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from api.auth import Role, TenantPrincipal, get_settings, require_tenant
from api.routes._pagination import PageParams, build_page
from api.services import asset_groups as service
from api.settings import Settings

router = APIRouter(prefix="/asset-groups", tags=["asset-groups"])
Reader = Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))]
Writer = Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))]
Config = Annotated[Settings, Depends(get_settings)]


class GroupDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=2000)
    enabled: bool = True
    priority: int = Field(default=0, ge=0, le=10000)
    rules: dict[str, Any]
    context: dict[str, Any] = Field(default_factory=dict)


class GroupPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    enabled: bool | None = None
    priority: int | None = Field(default=None, ge=0, le=10000)
    rules: dict[str, Any] | None = None
    context: dict[str, Any] | None = None


class PreviewDraft(GroupDraft):
    name: str = "Preview"
    group_id: str | None = Field(default=None, max_length=64)
    after_asset_id: str | None = Field(default=None, max_length=256)
    limit: int = Field(default=100, ge=1, le=500)


class RecalculateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    after_asset_id: str | None = Field(default=None, max_length=256)
    limit: int = Field(default=200, ge=1, le=500)


def _call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("")
def list_groups(principal: Reader, settings: Config, page: PageParams):
    items, total = _call(
        service.list_groups,
        settings,
        principal.tenant_id,
        offset=page.offset,
        limit=page.limit,
        q=page.q,
    )
    return build_page(items, total, page)


@router.post("", status_code=status.HTTP_201_CREATED)
def create_group(body: GroupDraft, principal: Writer, settings: Config):
    return _call(
        service.save_group,
        settings,
        principal.tenant_id,
        body.model_dump(),
        actor=principal.username,
    )


@router.post("/preview")
def preview(body: PreviewDraft, principal: Writer, settings: Config):
    return _call(
        service.preview,
        settings,
        principal.tenant_id,
        body.model_dump(exclude={"group_id", "limit", "after_asset_id"}),
        group_id=body.group_id,
        limit=body.limit,
        after_asset_id=body.after_asset_id,
    )


@router.get("/{group_id}")
def get_group(group_id: str, principal: Reader, settings: Config):
    return _call(service.get_group, settings, principal.tenant_id, group_id)


@router.patch("/{group_id}")
def update_group(group_id: str, body: GroupPatch, principal: Writer, settings: Config):
    return _call(
        service.save_group,
        settings,
        principal.tenant_id,
        body.model_dump(exclude_unset=True),
        group_id=group_id,
        actor=principal.username,
    )


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_group(group_id: str, principal: Writer, settings: Config):
    _call(
        service.delete_group,
        settings,
        principal.tenant_id,
        group_id,
        actor=principal.username,
    )


@router.post("/{group_id}/recalculate")
def recalculate(
    group_id: str, body: RecalculateBody, principal: Writer, settings: Config
):
    return _call(
        service.recalculate,
        settings,
        principal.tenant_id,
        group_id=group_id,
        actor=principal.username,
        **body.model_dump(),
    )


@router.get("/{group_id}/members")
def members(group_id: str, principal: Reader, settings: Config, page: PageParams):
    items, total = _call(
        service.list_members,
        settings,
        principal.tenant_id,
        group_id,
        offset=page.offset,
        limit=page.limit,
    )
    return build_page(items, total, page)


@router.get("/{group_id}/evaluations")
def evaluations(group_id: str, principal: Reader, settings: Config, page: PageParams):
    items, total = _call(
        service.list_evaluations,
        settings,
        principal.tenant_id,
        group_id,
        offset=page.offset,
        limit=page.limit,
    )
    return build_page(items, total, page)
