"""Bounded published evidence: exact identifiers + PostgreSQL simple full text.

This is not semantic search. Authorization belongs to every gateway/API call;
this module additionally checks tenant/run publication eligibility on every read.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import case, delete, func, literal_column, or_, select

from api.db import models, tenant_scope
from api.db.engine import get_session
from api.services import artifact_store, legal_hold
from api.services.artifact_store import keys

MAX_FINDINGS_BYTES = 2 * 1024 * 1024
MAX_DOCUMENTS = 1000
PACKAGE = re.compile(r"@?[A-Za-z0-9][A-Za-z0-9_.+@/~-]{0,190}")
_SCALARS = {
    "service": re.compile(r"[A-Za-z0-9][A-Za-z0-9_+-]{0,63}"),
    "asset_id": re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}"),
    "version": re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+~:-]{0,191}"),
    "package": PACKAGE,
    "severity": re.compile(r"(?:critical|high|medium|low|info|unknown)"),
    "host": re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,190}[A-Za-z0-9])?"),
}
CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")
CWE = re.compile(r"^CWE-[0-9]{1,8}$")
HASH = re.compile(r"^[0-9a-f]{64}$")


def _error(code):
    from .gateway import GatewayError
    return GatewayError(code)


def _capture(settings, principal, run_id):
    from .gateway import read_evidence, _json, _read, GatewayError
    counts, citation = read_evidence(settings, principal, run_id)
    store = artifact_store.get_store(settings)
    ref = keys.run_ref(run_id, principal.tenant_id)
    if not store.exists(keys.run_artifact(ref, "summary.json")):
        ref = keys.run_ref(run_id)
    key = keys.run_artifact(ref, "vulnerabilities.json")
    state, digest, findings, observed = "missing", "missing", [], citation.observed_at
    info = store.stat(key)
    if info is not None:
        observed = datetime.fromtimestamp(info.modified, UTC)
        if info.size > MAX_FINDINGS_BYTES:
            state, digest = "truncated", "oversized"
        else:
            raw = _read(store, key, MAX_FINDINGS_BYTES)
            digest = hashlib.sha256(raw).hexdigest()
            try:
                source = _json(raw)
                if not isinstance(source, list):
                    raise ValueError("findings must be a list")
                findings = source[:MAX_DOCUMENTS]
                state = "truncated" if len(source) > MAX_DOCUMENTS else "partial"
            except (ValueError, TypeError, RecursionError):
                state = "partial"
    # Avoid accepting a summary/publication changed during findings extraction.
    _, after = read_evidence(settings, principal, run_id)
    if after != citation:
        raise GatewayError("operator_source_changed")
    return counts, citation, findings, digest, observed, state


def _extract(row):
    if not isinstance(row, dict):
        return {}
    result = {}
    for key in ("cve", "cwe", "host", "service", "severity", "asset_id", "package", "version"):
        value = row.get(key)
        if not isinstance(value, str) or not 1 <= len(value) <= 192:
            continue
        if key in {"cve", "cwe"}:
            value = value.upper()
            pattern = CVE if key == "cve" else CWE
        else:
            if key == "severity":
                value = value.lower()
            pattern = _SCALARS[key]
        if key == "host":
            try:
                ipaddress.ip_address(value)
            except ValueError:
                pass
            else:
                result[key] = value
                continue
        if pattern.fullmatch(value):
            result[key] = value
    port = row.get("port")
    if isinstance(port, str) and port.isascii() and port.isdigit() and len(port) <= 5:
        port = int(port)
    if type(port) is int and 0 <= port <= 65535:
        result["port"] = port
    return result


def _metadata(row):
    return {"snapshot_id": row.snapshot_id, "state": row.state,
            "mode": "exact_fulltext", "semantic_status": "unsupported",
            "indexed_at": row.indexed_at.isoformat() + "Z"}


def refresh_run(settings, principal, run_id):
    counts, citation, findings, findings_hash, observed, state = _capture(settings, principal, run_id)
    now = datetime.now(UTC).replace(tzinfo=None)
    snapshot_id = uuid4().hex
    with tenant_scope.tenant(principal.tenant_id), get_session(settings.postgres_url) as db:
        # Serializes concurrent builders; readers observe either complete snapshot.
        db.scalar(select(models.Tenant).where(models.Tenant.tenant_id == principal.tenant_id).with_for_update())
        current = db.scalar(select(models.OperatorEvidenceSnapshot).where(
            models.OperatorEvidenceSnapshot.tenant_id == principal.tenant_id,
            models.OperatorEvidenceSnapshot.run_id == run_id))
        if (current is not None and current.summary_hash == citation.source_hash
                and current.publication_snapshot == citation.snapshot_id
                and current.findings_hash == findings_hash and current.state == state):
            return _metadata(current)
        try:
            legal_hold.assert_not_on_hold(db, principal.tenant_id, action="operator.evidence.refresh")
        except legal_hold.LegalHoldActive:
            raise _error("operator_legal_hold") from None
        db.execute(delete(models.OperatorEvidenceSnapshot).where(
            models.OperatorEvidenceSnapshot.tenant_id == principal.tenant_id,
            models.OperatorEvidenceSnapshot.run_id == run_id))
        snapshot = models.OperatorEvidenceSnapshot(snapshot_id=snapshot_id,
            tenant_id=principal.tenant_id, run_id=run_id, publication_snapshot=citation.snapshot_id,
            summary_hash=citation.source_hash, findings_hash=findings_hash, state=state, indexed_at=now, last_checked_at=now)
        db.add(snapshot)
        db.flush()
        documents = [("summary.json", counts, citation.source_hash, citation.observed_at)]
        documents.extend(("vulnerabilities.json", value, findings_hash, observed)
                         for row in findings if (value := _extract(row)))
        for artifact, context, source_hash, source_time in documents:
            content = json.dumps(context, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
            db.add(models.OperatorEvidenceDocument(source_id=uuid4().hex,
                tenant_id=principal.tenant_id, snapshot_id=snapshot_id, artifact=artifact,
                source_hash=source_hash, document_hash=hashlib.sha256(content.encode()).hexdigest(),
                content=content, cve=context.get("cve", ""), package=context.get("package", ""),
                observed_at=source_time.replace(tzinfo=None)))
        return _metadata(snapshot)


def _current(settings, principal, row):
    _, citation, _, findings_hash, _, _ = _capture(settings, principal, row.run_id)
    if (citation.source_hash != row.summary_hash or citation.snapshot_id != row.publication_snapshot
            or findings_hash != row.findings_hash):
        raise _error("operator_source_changed")


def _item(doc, snapshot):
    citation = {"source_id": doc.source_id, "source_hash": doc.source_hash,
                "snapshot_id": snapshot.snapshot_id, "source_type": "run",
                "observed_at": doc.observed_at.isoformat() + "Z", "status": "partial"}
    return {**citation, "citation": citation, "document_hash": doc.document_hash,
            "source_artifact": doc.artifact,
            "indexed_at": snapshot.indexed_at.isoformat() + "Z", "context": json.loads(doc.content)}


def search(settings, principal, run_id, query="", cve=None, package=None, limit=10, max_context_chars=12000,
           source_artifact=None):
    if source_artifact not in {None, "summary.json", "vulnerabilities.json"}:
        raise _error("operator_invalid_query")
    if isinstance(cve, str):
        cve = cve.upper()
    if isinstance(query, str) and CVE.fullmatch(query.strip().upper()):
        query = query.strip().upper()
    if (not isinstance(query, str) or len(query) > 512 or any(ord(c) < 32 for c in query)
            or (cve is not None and (not isinstance(cve, str) or not CVE.fullmatch(cve)))
            or (package is not None and (not isinstance(package, str) or not PACKAGE.fullmatch(package)))):
        raise _error("operator_invalid_query")
    if type(limit) is not int or not 1 <= limit <= 50 or type(max_context_chars) is not int or not 128 <= max_context_chars <= 24000:
        raise _error("operator_invalid_limit")
    from .gateway import read_evidence
    read_evidence(settings, principal, run_id)
    with tenant_scope.tenant(principal.tenant_id), get_session(settings.postgres_url) as db:
        snapshot = db.scalar(select(models.OperatorEvidenceSnapshot).where(
            models.OperatorEvidenceSnapshot.tenant_id == principal.tenant_id,
            models.OperatorEvidenceSnapshot.run_id == run_id))
        if snapshot is None:
            return {"snapshot_id": None, "state": "missing", "mode": "exact_fulltext",
                    "semantic_status": "unsupported", "items": []}
        _current(settings, principal, snapshot)
        statement = select(models.OperatorEvidenceDocument).where(
            models.OperatorEvidenceDocument.tenant_id == principal.tenant_id,
            models.OperatorEvidenceDocument.snapshot_id == snapshot.snapshot_id)
        if source_artifact is not None:
            statement = statement.where(models.OperatorEvidenceDocument.artifact == source_artifact)
        if cve is not None:
            statement = statement.where(models.OperatorEvidenceDocument.cve == cve)
        if package is not None:
            statement = statement.where(models.OperatorEvidenceDocument.package == package)
        if query.strip():
            exact = or_(models.OperatorEvidenceDocument.cve == query.strip(),
                        models.OperatorEvidenceDocument.package == query.strip())
            if db.bind.dialect.name == "postgresql":
                language = literal_column("'simple'::regconfig")
                matches = func.to_tsvector(language, models.OperatorEvidenceDocument.content).op("@@")(
                    func.plainto_tsquery(language, query))
            else:
                # SQLite portability is exact-only; no semantic/fulltext claim.
                matches = models.OperatorEvidenceDocument.content.contains(query, autoescape=True)
            statement = statement.where(or_(exact, matches)).order_by(case((exact, 0), else_=1))
        documents = db.scalars(statement.order_by(models.OperatorEvidenceDocument.source_id).limit(limit + 1)).all()
        items, total = [], 0
        result = _metadata(snapshot)
        if len(documents) > limit:
            result["state"] = "truncated"
        for doc in documents[:limit]:
            item = _item(doc, snapshot)
            size = len(json.dumps(item, ensure_ascii=False))
            if total + size > max_context_chars:
                result["state"] = "truncated"
                break
            items.append(item)
            total += size
        return {**result, "items": items}


def get_citation(settings, principal, source_id, snapshot_id, source_hash):
    if (not isinstance(source_id, str) or not re.fullmatch(r"[0-9a-f]{32}", source_id)
            or not isinstance(snapshot_id, str) or not re.fullmatch(r"[0-9a-f]{32}", snapshot_id)
            or not isinstance(source_hash, str) or not HASH.fullmatch(source_hash)):
        return None
    with tenant_scope.tenant(principal.tenant_id), get_session(settings.postgres_url) as db:
        doc = db.scalar(select(models.OperatorEvidenceDocument).where(
            models.OperatorEvidenceDocument.tenant_id == principal.tenant_id,
            models.OperatorEvidenceDocument.source_id == source_id,
            models.OperatorEvidenceDocument.snapshot_id == snapshot_id,
            models.OperatorEvidenceDocument.source_hash == source_hash))
        snapshot = db.scalar(select(models.OperatorEvidenceSnapshot).where(
            models.OperatorEvidenceSnapshot.snapshot_id == snapshot_id,
            models.OperatorEvidenceSnapshot.tenant_id == principal.tenant_id))
        if doc is None or snapshot is None:
            return None
        _current(settings, principal, snapshot)
        return _item(doc, snapshot)


def prune_invalid(settings, limit=20):
    """Remove stale derived chunks; held evidence remains inaccessible but retained."""
    from types import SimpleNamespace
    from .gateway import GatewayError
    if type(limit) is not int or not 1 <= limit <= 100:
        raise _error("operator_invalid_limit")
    removed = 0
    with tenant_scope.system("operator evidence expiry cleanup"), get_session(settings.postgres_url) as db:
        candidates = db.scalars(select(models.OperatorEvidenceSnapshot).order_by(
            models.OperatorEvidenceSnapshot.last_checked_at,
            models.OperatorEvidenceSnapshot.snapshot_id).limit(limit)).all()
        for snapshot in candidates:
            snapshot.last_checked_at = datetime.now(UTC).replace(tzinfo=None)
            db.scalar(select(models.Tenant).where(models.Tenant.tenant_id == snapshot.tenant_id).with_for_update())
            if db.get(models.TenantLegalHold, snapshot.tenant_id) is not None:
                continue
            try:
                _current(settings, SimpleNamespace(tenant_id=snapshot.tenant_id), snapshot)
            except GatewayError:
                db.delete(snapshot)
                removed += 1
    return removed
