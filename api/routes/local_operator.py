"""Discover operator configuration without contacting an inference service."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import Role, TenantPrincipal, get_settings, require_tenant
from api.settings import Settings

router = APIRouter(prefix="/operator", tags=["operator"])
operator_principal = require_tenant(Role.viewer)


class OperatorStatus(BaseModel):
    enabled: bool
    provider: str
    model: str
    external_inference: bool
    runtime_status: Literal["not_checked"] = "not_checked"
    analysis_available: bool = False
    durable_sessions_available: bool = False


@router.get("/status", response_model=OperatorStatus)
def operator_status(
    principal: Annotated[TenantPrincipal, Depends(operator_principal)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> OperatorStatus:
    if not settings.operator_enabled:
        raise HTTPException(status_code=404, detail="Operator is disabled")
    # Validation is repeated for injected/test settings as well as the loader.
    from api.services.local_operator.config import OperatorConfig

    try:
        config = OperatorConfig.from_settings(settings)
    except ValueError:
        raise HTTPException(status_code=503, detail="Operator configuration is invalid") from None
    return OperatorStatus(
        enabled=True,
        provider=config.provider,
        model=config.model,
        external_inference=config.provider != "local",
    )
