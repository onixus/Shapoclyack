"""Bounded, current-source evidence retrieval for authenticated console users."""
from __future__ import annotations

import ipaddress
import re
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Query, Request
from pydantic import BaseModel, ConfigDict

from api.auth import TenantPrincipal
from api.db import tenant_scope
from api.routes.local_operator import OperatorContext, OperatorSettings, Reader, Writer
from api.services.local_operator import store
from api.services.local_operator.gateway import COUNT_FIELDS, GatewayError

router = APIRouter(prefix="/operator/evidence", tags=["operator"])
Identifier = Annotated[str, Query(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")]
SourceId = Annotated[str, Path(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")]
RunId = Annotated[str, Path(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")]
Digest = Annotated[str, Query(pattern=r"^[a-f0-9]{64}$")]


class RefreshEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def _query(request: Request, allowed: set[str]):
    keys = list(request.query_params.keys())
    if any(key not in allowed or len(request.query_params.getlist(key)) != 1 for key in keys):
        raise HTTPException(status_code=422, detail="Unsupported or repeated evidence argument")


def _authorize(settings, context: OperatorContext, *, writer=False) -> TenantPrincipal:
    """Fence both ends of retrieval against stale SID and current grants."""
    principal = context.principal
    try:
        # Membership fallback depends on whether grants exist in ANY tenant.
        # A tenant-scoped transaction would hide other grants and incorrectly
        # restore the legacy default-tenant fallback after revocation.
        with tenant_scope.system("operator evidence current console authority"), store.get_session_db(settings.postgres_url) as db:
            user = store._lock_actor(db, settings, principal.username, context.auth_session_id,  # noqa: SLF001
                                     writer=writer)
            store._lock_tenant(db, principal.tenant_id)  # noqa: SLF001
            current = store.resolve_role(db, user, principal.tenant_id)
            if current is None or current[1] < (2 if writer else 1):
                raise store.OperatorStoreError("access_revoked")
            role, rank = current
            return TenantPrincipal(username=principal.username, tenant_id=principal.tenant_id,
                                   role=role, rank=rank, tenant_requested=True,
                                   is_platform_admin=user.role == "admin")
    except store.OperatorStoreError:
        raise HTTPException(status_code=403, detail="operator_access_revoked") from None


def _safe_scalar(key, value):
    if key in COUNT_FIELDS:
        return type(value) is int and 0 <= value <= 2**63 - 1
    if key == "port":
        return type(value) is int and 0 <= value <= 65535
    if not isinstance(value, str) or not 1 <= len(value) <= 192:
        return False
    if key == "host":
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,190}[A-Za-z0-9])?", value) is not None
    # Fields are identifiers, never arbitrary source locations. In particular,
    # a URL hidden in an otherwise allowed metadata key must not survive.
    patterns = {
        "cve": r"CVE-[0-9]{4}-[0-9]{4,19}", "cwe": r"CWE-[0-9]{1,8}",
        "service": r"[A-Za-z0-9][A-Za-z0-9_+-]{0,63}",
        "severity": r"(?:critical|high|medium|low|info|unknown)",
        "asset_id": r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}",
        "package": r"@?[A-Za-z0-9][A-Za-z0-9_.+@/~-]{0,190}",
        "version": r"[A-Za-z0-9][A-Za-z0-9_.+~:-]{0,191}",
    }
    return key in patterns and re.fullmatch(patterns[key], value) is not None


def _item(value):
    # Retrieval constructs these fields from structured scan facts. Never expose
    # a source's arbitrary URLs, titles, banner text, or nested raw metadata.
    fields = {"source_id", "source_hash", "snapshot_id", "document_hash", "source_type",
              "observed_at", "indexed_at", "status"}
    result = {key: value[key] for key in fields if key in value}
    context = value.get("context", {})
    allowed = {*COUNT_FIELDS, "cve", "cwe", "host", "port", "service", "severity", "asset_id", "package", "version"}
    result["context"] = {key: val for key, val in context.items()
                         if key in allowed and _safe_scalar(key, val)}
    if isinstance(context.get("counts"), dict):
        result["context"]["counts"] = {key: val for key, val in context["counts"].items()
                                      if key in COUNT_FIELDS and type(val) is int and val >= 0}
    citation = value.get("citation")
    if isinstance(citation, dict):
        result["citation"] = {key: citation[key] for key in (
            "schema_version", "source_id", "source_type", "source_hash", "snapshot_id", "observed_at", "status"
        ) if key in citation}
    return result


def _call(settings, context, action, *, writer=False, **kwargs):
    from api.services.local_operator import retrieval

    principal = _authorize(settings, context, writer=writer)
    try:
        result = getattr(retrieval, action)(settings, principal, **kwargs)
        _authorize(settings, context, writer=writer)
        if result is None:
            raise HTTPException(status_code=404, detail="operator_source_unavailable")
        if action == "get_citation":
            return _item(result)
        response = {key: result[key] for key in (
            "snapshot_id", "state", "mode", "semantic_status", "run_id", "indexed_at", "document_count",
            "embedding_model", "model_fingerprint", "embedding_dimensions", "semantic_indexed_at", "scope_kind", "scope_id"
        ) if key in result}
        if "items" in result:
            response["items"] = [_item(item) for item in result["items"][:kwargs.get("limit", 10)]]
        return response
    except GatewayError as exc:
        status = {"operator_access_revoked": 403, "operator_invalid_query": 422,
                  "operator_invalid_limit": 422, "operator_source_changed": 409,
                  "operator_source_unavailable": 404, "operator_storage_unavailable": 503,
                  "operator_embeddings_unavailable": 503, "operator_embeddings_not_ready": 503,
                  "operator_embedding_configuration_invalid": 503}.get(exc.code, 409)
        raise HTTPException(status_code=status, detail=exc.code) from None


@router.get("/search")
def search_evidence(
    request: Request, principal: Reader, settings: OperatorSettings,
    run_id: Annotated[str, Query(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")],
    query: Annotated[str, Query(max_length=256)] = "",
    cve: Annotated[str | None, Query(max_length=32, pattern=r"^CVE-[0-9]{4}-[0-9]{4,19}$")] = None,
    package: Annotated[str | None, Query(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.+:-]*$")] = None,
    limit: Annotated[int, Query(ge=1, le=10)] = 10,
):
    _query(request, {"tenant_id", "run_id", "query", "cve", "package", "limit"})
    return _call(settings, principal, "search", run_id=run_id, query=query, cve=cve,
                 package=package, limit=limit, max_context_chars=12000)


@router.post("/runs/{run_id}/refresh")
def refresh_evidence(run_id: RunId, body: RefreshEvidence, request: Request,
                     principal: Writer, settings: OperatorSettings):
    _query(request, {"tenant_id"})
    return _call(settings, principal, "refresh_run", writer=True, run_id=run_id)


def _semantic_call(settings, context, action, *, writer=False, **kwargs):
    from api.services.local_operator import semantic
    principal = _authorize(settings, context, writer=writer)
    try:
        result = getattr(semantic, action)(settings, principal, **kwargs)
        if result is None:
            raise HTTPException(404, detail="operator_source_unavailable")
        _authorize(settings, context, writer=writer)
        corpus = semantic.device_corpus(settings, principal, kwargs["device_id"])
        if result["snapshot_id"] != corpus["source_snapshot"]:
            raise HTTPException(409, detail="operator_source_changed")
        return result
    except GatewayError as exc:
        code = {"operator_source_unavailable": 404, "operator_invalid_query": 422,
                "operator_embeddings_unavailable": 503, "operator_embeddings_not_ready": 503,
                "operator_embedding_configuration_invalid": 503}.get(exc.code, 409)
        raise HTTPException(code, detail=exc.code) from None


@router.post("/devices/{device_id}/refresh")
def refresh_device_evidence(device_id: SourceId, body: RefreshEvidence, request: Request,
                            principal: Writer, settings: OperatorSettings):
    _query(request, {"tenant_id"})
    return _semantic_call(settings, principal, "refresh_device", writer=True, device_id=device_id)


@router.get("/devices/{device_id}/search")
def search_device_evidence(device_id: SourceId, request: Request, principal: Reader, settings: OperatorSettings,
                           query: Annotated[str, Query(max_length=256)] = "",
                           cve: Annotated[str | None, Query(max_length=32, pattern=r"^CVE-[0-9]{4}-[0-9]{4,19}$")] = None,
                           package: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
                           source_kind: Annotated[str | None, Query(pattern=r"^(?:inventory|advisory)$")] = None,
                           limit: Annotated[int, Query(ge=1, le=10)] = 10):
    _query(request, {"tenant_id", "query", "cve", "package", "source_kind", "limit"})
    return _semantic_call(settings, principal, "search_device", device_id=device_id, query=query,
                          cve=cve, package=package, source_kind=source_kind, limit=limit)


@router.get("/devices/{device_id}/sources/{source_id}")
def get_device_evidence(device_id: SourceId, source_id: SourceId, request: Request,
                        principal: Reader, settings: OperatorSettings, snapshot_id: Identifier, source_hash: Digest):
    _query(request, {"tenant_id", "snapshot_id", "source_hash"})
    return _semantic_call(settings, principal, "device_source", device_id=device_id,
                          source_id=source_id, snapshot_id=snapshot_id, source_hash=source_hash)


@router.get("/runs/{run_id}/summary")
def get_summary_evidence(run_id: RunId, request: Request, principal: Reader,
                         settings: OperatorSettings, snapshot_id: Identifier,
                         source_hash: Digest):
    from api.services.local_operator.gateway import read_evidence

    _query(request, {"tenant_id", "snapshot_id", "source_hash"})
    current = _authorize(settings, principal)
    try:
        counts, citation = read_evidence(settings, current, run_id)
        if citation.snapshot_id != snapshot_id or citation.source_hash != source_hash:
            raise HTTPException(409, detail="operator_source_changed")
        _authorize(settings, principal)
        # Bind the displayed observations to the current publication, even if
        # it was replaced during the authority lookup.
        if read_evidence(settings, current, run_id)[1] != citation:
            raise HTTPException(409, detail="operator_source_changed")
        return {"context": {"counts": counts}, "citation": citation.model_dump(mode="json")}
    except GatewayError as exc:
        code = 503 if exc.code == "operator_storage_unavailable" else 404
        raise HTTPException(code, detail=exc.code) from None


@router.get("/{source_id}")
def get_evidence(source_id: SourceId, request: Request, principal: Reader,
                 settings: OperatorSettings, snapshot_id: Identifier, source_hash: Digest):
    _query(request, {"tenant_id", "snapshot_id", "source_hash"})
    return _call(settings, principal, "get_citation", source_id=source_id,
                 snapshot_id=snapshot_id, source_hash=source_hash)
