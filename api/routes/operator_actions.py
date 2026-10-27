"""Explicit UI confirmation boundary for the optional operator."""
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from api.routes._audit import AuditDep
from api.routes.local_operator import Admin, OperatorSettings, PathId, Writer
from api.routes.operator_evidence import _query
from api.services.local_operator import actions, store
from api.services import maintenance, quotas

router = APIRouter(prefix="/operator", tags=["operator"])


class Confirmation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    arguments_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class CloseUnknown(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    resolution: Literal["no_effect", "effect_confirmed"]


def _call(action, *args):
    try:
        return action(*args)
    except store.OperatorStoreError as exc:
        code = {"not_found": 404, "access_revoked": 403, "stale_proposal": 409,
                "idempotency_conflict": 409, "queue_full": 429}.get(exc.code, 409)
        raise HTTPException(code, detail=exc.code) from None
    except quotas.QuotaExceeded as exc:
        headers = {"Retry-After": str(exc.retry_after_seconds)} if exc.retry_after_seconds is not None else None
        raise HTTPException(429, detail="action_quota_exceeded", headers=headers) from None
    except maintenance.MaintenanceBlocked as exc:
        headers = {"Retry-After": str(exc.retry_after_seconds)} if exc.retry_after_seconds is not None else None
        raise HTTPException(409, detail="action_maintenance_blocked", headers=headers) from None
    except PermissionError:
        raise HTTPException(403, detail="action_not_permitted") from None
    except ValueError:
        raise HTTPException(422, detail="action_preconditions_failed") from None
    except RuntimeError:
        raise HTTPException(409, detail="action_unavailable") from None


@router.post("/sessions/{session_id}/proposals", status_code=201)
def prepare_action(request: Request, session_id: PathId, body: actions.PrepareAction,
                   context: Writer, settings: OperatorSettings, audit: AuditDep):
    _query(request, {"tenant_id"})
    return _call(actions.prepare, settings, context, session_id, body, audit)


@router.get("/proposals/{proposal_id}")
def get_proposal(request: Request, proposal_id: PathId, context: Writer, settings: OperatorSettings):
    _query(request, {"tenant_id"})
    return _call(actions.get, settings, context, proposal_id)


@router.post("/proposals/{proposal_id}/confirm")
def confirm_action(request: Request, proposal_id: PathId, body: Confirmation, context: Writer,
                   settings: OperatorSettings, audit: AuditDep):
    _query(request, {"tenant_id"})
    return _call(actions.confirm, settings, context, proposal_id, body.arguments_sha256, audit)


@router.post("/proposals/{proposal_id}/close")
def close_unknown_action(request: Request, proposal_id: PathId, body: CloseUnknown, context: Admin,
                         settings: OperatorSettings, audit: AuditDep):
    """Tenant admin closes an action stuck in ``unknown`` (or a stale ``executing``)."""
    _query(request, {"tenant_id"})
    return _call(actions.close, settings, context, proposal_id, body.resolution, audit)
