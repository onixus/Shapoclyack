"""SCIM 2.0 provisioning endpoints under ``/scim/v2`` (#316).

Thin by design: authenticate the SCIM token, hand the request to
``api/services/scim.py``, translate its domain errors into SCIM error bodies
(RFC 7644 §3.12). Everything a token may or may not do — its tenant binding,
the accounts it may change — is decided in the service, on every call.

Only an ``octo_scim_`` token is accepted here. A console JWT or a service token
gets the same 401 as no credential at all: provisioning is not something a
person's session or a tenant's integration can do by presenting what they
already hold.

Every route is installation-wide (accounts and memberships span tenants), so
the dependency declares the system scope for the request — the route guard
test lists each endpoint with that reason.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials

from api.auth import bearer_scheme, get_settings
from api.db import tenant_scope
from api.services import audit as audit_service
from api.services import rate_limit
from api.services import scim as scim_service
from api.services import scim_tokens as scim_tokens_service
from api.services.users import AccountErased
from api.settings import Settings

router = APIRouter(tags=["scim"])

SCIM_MEDIA_TYPE = "application/scim+json"
SCIM_TOKEN_STATE_ATTR = "scim_token"
_SCOPE_REASON = (
    "SCIM provisioning: accounts and memberships are installation-wide; the "
    "token's tenant binding is enforced in api/services/scim.py"
)


def require_scim_token(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> scim_tokens_service.ScimPrincipal:
    """Authenticate an ``octo_scim_`` bearer token, and nothing else."""
    refused = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="A valid SCIM token is required",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise refused
    if not scim_tokens_service.looks_like_scim_token(credentials.credentials):
        raise refused
    # Across tenants: the token's hash is what says what it may manage.
    with tenant_scope.system("authentication: SCIM token"):
        principal = scim_tokens_service.verify_token(settings, credentials.credentials)
    if principal is None:
        raise refused
    try:
        rate_limit.charge(rate_limit.SCOPE_SERVICE_TOKEN, principal.token_id)
    except rate_limit.RateLimited as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc
    tenant_scope.declare_system(_SCOPE_REASON)
    setattr(request.state, SCIM_TOKEN_STATE_ATTR, principal)
    return principal


ScimTokenDep = Annotated[scim_tokens_service.ScimPrincipal, Depends(require_scim_token)]


def _audit(
    request: Request, settings: Settings, principal: scim_tokens_service.ScimPrincipal
) -> audit_service.AuditContext:
    # A non-interactive credential: the trail's service-token actor type, with
    # a name that says which kind.
    return audit_service.context_from_request(
        request,
        settings,
        actor=principal.actor,
        actor_type=audit_service.ACTOR_SERVICE_TOKEN,
    )


def _scim(body: Any, status_code: int = status.HTTP_200_OK) -> JSONResponse:
    return JSONResponse(body, status_code=status_code, media_type=SCIM_MEDIA_TYPE)


def _error(
    status_code: int,
    detail: str,
    scim_type: str | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {
        "schemas": [scim_service.SCHEMA_ERROR],
        "status": str(status_code),
        "detail": detail,
    }
    if scim_type:
        body["scimType"] = scim_type
    response = _scim(body, status_code)
    response.headers.update(headers or {})
    return response


def _answer(call, status_code: int = status.HTTP_200_OK) -> Response:
    """Run a service call and translate its domain errors into SCIM errors."""
    try:
        result = call()
    except LookupError as exc:
        return _error(status.HTTP_404_NOT_FOUND, str(exc).strip("'\""))
    except AccountErased as exc:
        return _error(status.HTTP_409_CONFLICT, str(exc))
    except scim_service.ScimConflict as exc:
        return _error(status.HTTP_409_CONFLICT, str(exc), "uniqueness")
    except scim_service.ScimBusy as exc:
        # Nothing was applied; Okta and Entra ID retry a 503 on their own.
        return _error(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), headers={"Retry-After": "1"})
    except scim_service.ScimError as exc:
        return _error(status.HTTP_400_BAD_REQUEST, str(exc), exc.scim_type)
    except PermissionError as exc:
        return _error(status.HTTP_403_FORBIDDEN, str(exc))
    except ValueError as exc:
        return _error(status.HTTP_400_BAD_REQUEST, str(exc), "invalidValue")
    if result is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    return _scim(result, status_code)


_Filter = Annotated[str | None, Query(alias="filter", max_length=512)]
_StartIndex = Annotated[int | None, Query(alias="startIndex", ge=1)]
_Count = Annotated[int | None, Query(alias="count", ge=0)]
_Payload = Annotated[dict[str, Any], Body()]


# --- discovery -----------------------------------------------------------------


@router.get("/ServiceProviderConfig")
def scim_service_provider_config(_: ScimTokenDep) -> Response:
    return _scim(scim_service.service_provider_config())


@router.get("/ResourceTypes")
def scim_resource_types(_: ScimTokenDep) -> Response:
    return _scim(scim_service.resource_types())


@router.get("/Schemas")
def scim_schemas(_: ScimTokenDep) -> Response:
    return _scim(scim_service.schemas())


# --- users ---------------------------------------------------------------------


@router.get("/Users")
def scim_list_users(
    principal: ScimTokenDep,
    filter_: _Filter = None,
    start_index: _StartIndex = None,
    count: _Count = None,
) -> Response:
    return _answer(
        lambda: scim_service.list_users(
            principal, filter=filter_, start_index=start_index, count=count
        )
    )


@router.post("/Users")
def scim_create_user(
    request: Request,
    principal: ScimTokenDep,
    payload: _Payload,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    audit = _audit(request, settings, principal)
    return _answer(
        lambda: scim_service.create_user(principal, payload, audit=audit),
        status.HTTP_201_CREATED,
    )


@router.get("/Users/{user_id}")
def scim_get_user(user_id: str, principal: ScimTokenDep) -> Response:
    return _answer(lambda: scim_service.get_user(principal, user_id))


@router.put("/Users/{user_id}")
def scim_replace_user(
    user_id: str,
    request: Request,
    principal: ScimTokenDep,
    payload: _Payload,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    audit = _audit(request, settings, principal)
    return _answer(lambda: scim_service.replace_user(principal, user_id, payload, audit=audit))


@router.patch("/Users/{user_id}")
def scim_patch_user(
    user_id: str,
    request: Request,
    principal: ScimTokenDep,
    payload: _Payload,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    audit = _audit(request, settings, principal)
    return _answer(lambda: scim_service.patch_user(principal, user_id, payload, audit=audit))


@router.delete("/Users/{user_id}")
def scim_delete_user(
    user_id: str,
    request: Request,
    principal: ScimTokenDep,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    """Deactivates; the account and its history stay (see the service)."""
    audit = _audit(request, settings, principal)
    return _answer(lambda: scim_service.deactivate_user(principal, user_id, audit=audit))


# --- groups --------------------------------------------------------------------


@router.get("/Groups")
def scim_list_groups(
    principal: ScimTokenDep,
    filter_: _Filter = None,
    start_index: _StartIndex = None,
    count: _Count = None,
) -> Response:
    return _answer(
        lambda: scim_service.list_groups(
            principal, filter=filter_, start_index=start_index, count=count
        )
    )


@router.post("/Groups")
def scim_create_group(
    request: Request,
    principal: ScimTokenDep,
    payload: _Payload,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    audit = _audit(request, settings, principal)
    return _answer(
        lambda: scim_service.create_group(principal, payload, audit=audit),
        status.HTTP_201_CREATED,
    )


@router.get("/Groups/{group_id}")
def scim_get_group(group_id: str, principal: ScimTokenDep) -> Response:
    return _answer(lambda: scim_service.get_group(principal, group_id))


@router.put("/Groups/{group_id}")
def scim_replace_group(
    group_id: str,
    request: Request,
    principal: ScimTokenDep,
    payload: _Payload,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    audit = _audit(request, settings, principal)
    return _answer(lambda: scim_service.replace_group(principal, group_id, payload, audit=audit))


@router.patch("/Groups/{group_id}")
def scim_patch_group(
    group_id: str,
    request: Request,
    principal: ScimTokenDep,
    payload: _Payload,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    audit = _audit(request, settings, principal)
    return _answer(lambda: scim_service.patch_group(principal, group_id, payload, audit=audit))


@router.delete("/Groups/{group_id}")
def scim_delete_group(
    group_id: str,
    request: Request,
    principal: ScimTokenDep,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    audit = _audit(request, settings, principal)
    return _answer(lambda: scim_service.delete_group(principal, group_id, audit=audit))
