"""Durable, side-effect-free model intent selection."""
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException

from api.routes.local_operator import OperatorSettings, PathId, Writer, _call
from api.services.local_operator.planner import PlanRequest

router = APIRouter(prefix="/operator", tags=["operator"])


@router.post("/sessions/{session_id}/plan", status_code=202)
def plan_request(session_id: PathId, body: PlanRequest, context: Writer,
                 settings: OperatorSettings,
                 idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=128)]):
    if not settings.operator_worker_enabled:
        raise HTTPException(503, detail="Operator worker is disabled")
    return _call(settings, context, "submit_task", session_id=session_id,
        run_id=body.context.run_id or "planner-context", language=body.language,
        idempotency_key=idempotency_key, kind="plan_request",
        payload={"request": body.model_dump(), "auth_session_id": context.auth_session_id})
