"""Installation product license: status and signed-document upload (ADR 0007)."""

from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from api.auth import Role, TokenUser, get_settings, require_platform_permission, require_role
from api.core import permissions as permission_catalog
from api.routes._audit import AuditDep
from api.schemas import LicenseStatusResponse
from api.services import audit as audit_service
from api.services import licensing
from api.services.licensing import LicenseInvalid
from api.settings import Settings

router = APIRouter(prefix="/license", tags=["license"])

# Cap the upload so a huge body cannot exhaust memory before verify runs.
_MAX_LICENSE_BYTES = 256 * 1024


@router.get("", response_model=LicenseStatusResponse)
def get_license_status(
    _: Annotated[TokenUser, Depends(require_role(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Current product-license posture for the installation.

    Any authenticated viewer may read it: the console uses ``new_scans_allowed``
    and the feature flags to disable Start Scan / Lariska / Brand Watch without
    needing a platform permission.
    """
    return licensing.license_status(settings).as_dict()


@router.post("", response_model=LicenseStatusResponse)
async def upload_license(
    request: Request,
    user: Annotated[
        TokenUser,
        Depends(require_platform_permission(permission_catalog.PLATFORM_LICENSE_MANAGE)),
    ],
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> dict[str, Any]:
    """Verify and activate a signed license document.

    Accepts either a multipart file field named ``file`` / ``license``, or a
    raw JSON body (``application/json``). Platform-only: the document gates
    every tenant on the installation.
    """
    document = await _read_license_document(request)
    try:
        result = licensing.install_license(
            document,
            settings=settings,
            uploaded_by=user.username,
        )
    except LicenseInvalid as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    audit_service.record_standalone(
        audit,
        action="license.install",
        resource_type="product_license",
        resource_id=result.license_id or "",
        after={
            "license_id": result.license_id,
            "customer_name": result.customer_name,
            "expires_at": result.expires_at,
            "features": {
                "lariska": result.lariska,
                "brand_watch": result.brand_watch,
            },
        },
    )
    return result.as_dict()


async def _read_license_document(request: Request) -> bytes | dict[str, Any]:
    content_type = (request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    if content_type.startswith("multipart/form-data"):
        form = await request.form()
        upload = form.get("file") or form.get("license")
        if upload is None or not hasattr(upload, "read"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="multipart upload must include a file or license field",
            )
        # Bound ingestion like wordlists: refuse before the whole body is buffered.
        raw = await upload.read(_MAX_LICENSE_BYTES + 1)  # type: ignore[union-attr]
        if len(raw) > _MAX_LICENSE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"License body exceeds {_MAX_LICENSE_BYTES} bytes",
            )
        if not raw:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="License file is empty",
            )
        return raw

    # Starlette buffers request.body(); still refuse oversized Content-Length up front.
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > _MAX_LICENSE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"License body exceeds {_MAX_LICENSE_BYTES} bytes",
                )
        except ValueError:
            pass
    raw = await request.body()
    if len(raw) > _MAX_LICENSE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"License body exceeds {_MAX_LICENSE_BYTES} bytes",
        )
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="License body is empty",
        )
    if content_type in ("", "application/json", "text/json", "text/plain"):
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="License body is not valid UTF-8 JSON",
            ) from exc
        if not isinstance(parsed, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="License document must be a JSON object",
            )
        return parsed
    return raw
