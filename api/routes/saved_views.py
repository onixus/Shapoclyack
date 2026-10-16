"""Personal preferences require viewer membership, including mutations."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response

from api.auth import Role, TenantPrincipal, get_settings, require_tenant
from api.services import saved_views as store
from api.settings import Settings

router = APIRouter(prefix="/saved-views", tags=["saved-views"])
Principal = Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))]
SettingsDep = Annotated[Settings, Depends(get_settings)]


def _duplicate(exc: Exception) -> HTTPException:
    # Both 409 refusals carry a code: the console maps by code, never by status.
    return HTTPException(409, {"code": "saved_view_duplicate_name", "message": str(exc)})


@router.get("")
def list_views(page: store.Page, principal: Principal, settings: SettingsDep):
    return store.list_views(settings, principal.tenant_id, principal.username, page)


@router.post("", status_code=201)
def create_view(payload: store.ViewInput, principal: Principal, settings: SettingsDep):
    try:
        return store.create_view(
            settings, principal.tenant_id, principal.username, payload
        )
    except store.DuplicateViewName as exc:
        raise _duplicate(exc) from exc
    except store.ViewLimitReached as exc:
        raise HTTPException(
            409, {"code": "saved_view_limit", "message": str(exc)}
        ) from exc


@router.patch("/{view_id}")
def rename_view(
    view_id: str, payload: store.ViewUpdate, principal: Principal, settings: SettingsDep
):
    try:
        result = store.change_view(
            settings, principal.tenant_id, principal.username, view_id, payload
        )
    except store.DuplicateViewName as exc:
        raise _duplicate(exc) from exc
    if result is None:
        raise HTTPException(404, "Saved view not found")
    return result


@router.delete("/{view_id}", status_code=204)
def delete_view(view_id: str, principal: Principal, settings: SettingsDep):
    if (
        store.change_view(
            settings, principal.tenant_id, principal.username, view_id, None
        )
        is None
    ):
        raise HTTPException(404, "Saved view not found")
    return Response(status_code=204)
