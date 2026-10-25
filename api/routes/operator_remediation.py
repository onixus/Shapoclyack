"""Authenticated read-only remediation cards over current local evidence."""
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Path, Query, Request

from api.db import tenant_scope
from api.db.engine import get_session
from api.routes._audit import AuditDep
from api.routes.local_operator import OperatorSettings, Reader
from api.routes.operator_evidence import _authorize, _query
from api.services import audit as audit_service
from api.services.local_operator import remediation
from api.services.local_operator.gateway import GatewayError
from api.services.local_operator import store

router = APIRouter(prefix="/operator/remediation", tags=["operator"])
DeviceId = Annotated[str, Path(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")]


def _read(settings, context, action, audit, **kwargs):
    principal = _authorize(settings, context)
    try:
        result = getattr(remediation, action)(settings, principal, **kwargs)
        _authorize(settings, context)
        if result is None:
            raise HTTPException(status_code=404, detail="operator_source_unavailable")
        current = getattr(remediation, action)(settings, principal, **kwargs)
        _authorize(settings, context)
        if current != result:
            raise HTTPException(status_code=409, detail="operator_source_changed")
        if action in {"get_source", "get_finding_source"}:
            sources = [result]
        else:
            sources = [source for card in result["items"] for source in card["sources"]]
        with tenant_scope.tenant(principal.tenant_id), get_session(settings.postgres_url) as db:
            audit_service.record(db, audit, action="operator.remediation.read", resource_type="operator",
                resource_id=kwargs.get("device_id") or kwargs["vuln_id"], tenant_id=principal.tenant_id,
                after={"tool_version": "vendor-remediation-v1", "source_references": [
                    {"source_id": source["source_id"], "source_sha256": source["source_hash"],
                     "snapshot_id": source["snapshot_id"]} for source in sources]})
        _authorize(settings, context)
        return result
    except GatewayError as exc:
        code = {"operator_source_changed": 409, "operator_invalid_query": 422}.get(exc.code, 409)
        raise HTTPException(status_code=code, detail=exc.code) from None


@router.get("/devices/{device_id}")
def device_remediation(device_id: DeviceId, request: Request, principal: Reader,
                       settings: OperatorSettings, audit: AuditDep, language: Literal["ru", "en"] = "ru",
                       limit: Annotated[int, Query(ge=1, le=100)] = 50):
    _query(request, {"tenant_id", "language", "limit"})
    return _read(settings, principal, "for_device", audit, device_id=device_id, language=language, limit=limit)


@router.get("/devices/{device_id}/sources/{source_id}")
def remediation_source(device_id: DeviceId, source_id: Annotated[str, Path(pattern=r"^[0-9]{1,20}$")],
                       request: Request, principal: Reader, settings: OperatorSettings,
                       audit: AuditDep,
                       snapshot_id: Annotated[str, Query(min_length=1, max_length=256)],
                       source_hash: Annotated[str, Query(pattern=r"^[a-f0-9]{64}$")]):
    _query(request, {"tenant_id", "snapshot_id", "source_hash"})
    return _read(settings, principal, "get_source", audit, device_id=device_id, source_id=source_id,
                 snapshot_id=snapshot_id, source_hash=source_hash)


@router.get("/findings/{vuln_id}")
def finding_remediation(vuln_id: DeviceId, request: Request, principal: Reader,
                        settings: OperatorSettings, audit: AuditDep, language: Literal["ru", "en"] = "ru"):
    _query(request, {"tenant_id", "language"})
    return _read(settings, principal, "for_finding", audit, vuln_id=vuln_id, language=language)


@router.get("/findings/{vuln_id}/sources/{source_id}")
def finding_remediation_source(vuln_id: DeviceId, source_id: DeviceId,
                              request: Request, principal: Reader, settings: OperatorSettings, audit: AuditDep,
                              snapshot_id: Annotated[str, Query(min_length=1, max_length=256)],
                              source_hash: Annotated[str, Query(pattern=r"^[a-f0-9]{64}$")],
                              language: Literal["ru", "en"] = "ru"):
    _query(request, {"tenant_id", "snapshot_id", "source_hash", "language"})
    return _read(settings, principal, "get_finding_source", audit, vuln_id=vuln_id,
        source_id=source_id, snapshot_id=snapshot_id, source_hash=source_hash, language=language)


@router.post("/findings/{vuln_id}/applicability-review", status_code=201)
def review_finding_applicability(vuln_id: DeviceId, body: remediation.ApplicabilityReview,
                                request: Request, context: Reader, settings: OperatorSettings, audit: AuditDep):
    _query(request, {"tenant_id"})
    try:
        result = remediation.review_finding(settings, context, vuln_id=vuln_id, body=body, audit=audit)
        if result is None:
            raise HTTPException(404, detail="operator_source_unavailable")
        return result
    except store.OperatorStoreError:
        raise HTTPException(403, detail="operator_access_revoked") from None
    except GatewayError as exc:
        raise HTTPException(422 if exc.code == "operator_invalid_query" else 409, detail=exc.code) from None
