from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import Role, TokenUser, get_settings, require_role
from api.schemas import ConfigResponse, ConfigUpdateRequest
from api.services import config_override as config_service
from api.settings import Settings

router = APIRouter(prefix="/config", tags=["config"])


@router.get("", response_model=ConfigResponse)
def get_config(
    _: Annotated[TokenUser, Depends(require_role(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ConfigResponse:
    """Editable scanner-config settings: whitelisted paths with their default
    (base file), effective (base + overrides), and the raw stored overrides."""
    return ConfigResponse.model_validate(config_service.editable_snapshot(settings))


@router.put("", response_model=ConfigResponse)
def update_config(
    body: ConfigUpdateRequest,
    user: Annotated[TokenUser, Depends(require_role(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ConfigResponse:
    """Replace the installation-wide config overrides (admin only). Overrides
    are validated against the editable whitelist AND the full merged schema;
    an invalid payload is rejected (422) and nothing is persisted."""
    try:
        nested = config_service.unflatten(body.overrides)
        config_service.set_overrides(settings, nested, username=user.username)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return ConfigResponse.model_validate(config_service.editable_snapshot(settings))
