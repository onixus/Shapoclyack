"""Tenant-scoped read-only comparison of two accepted published runs."""
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request

from api.routes._audit import AuditDep
from api.routes.local_operator import OperatorSettings, Reader
from api.routes.operator_evidence import _query
from api.services import artifact_store
from api.services.local_operator import comparison, gateway, store

router = APIRouter(prefix="/operator", tags=["operator"])
RunId = Annotated[str, Query(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")]


@router.get("/compare")
def compare_runs(request: Request, context: Reader, settings: OperatorSettings, audit: AuditDep,
                 previous_run_id: RunId, current_run_id: RunId,
                 language: Literal["ru", "en"] = "ru"):
    _query(request, {"tenant_id", "previous_run_id", "current_run_id", "language"})
    try:
        return comparison.compare(settings, context, previous_run_id, current_run_id, language, audit)
    except store.OperatorStoreError as exc:
        raise HTTPException(403 if exc.code == "access_revoked" else 422, detail=exc.code) from None
    except gateway.GatewayError as exc:
        code = 404 if exc.code in {"operator_source_unavailable", "operator_invalid_run"} else 409
        raise HTTPException(code, detail=exc.code) from None
    except (artifact_store.ArtifactStoreError, OSError):
        raise HTTPException(503, detail="operator_storage_unavailable") from None
