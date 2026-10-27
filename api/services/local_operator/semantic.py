"""Tenant/source/model-bound hybrid retrieval over minimized local evidence.

Vectors are a derived index, never authority. Every refresh, search and source
open reconstructs its current authorized source corpus. Runtime calls happen
outside transactions; one completed corpus replaces its predecessor atomically.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import delete, func, literal_column, select, update

from api.db import models, tenant_scope
from api.db.engine import get_session
from api.services import audit, legal_hold
from .embeddings import EmbeddingClient, EmbeddingConfig, EmbeddingError, MAX_TEXT_CHARS, normalized_vector

MAX_DOCUMENTS = 1001
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+~-]{0,191}")


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _error(code):
    from .gateway import GatewayError
    return GatewayError(code)


def _config(settings):
    try:
        return EmbeddingConfig.from_settings(settings)
    except ValueError:
        raise _error("operator_embedding_configuration_invalid") from None


def minimized_text(context):
    """Only deterministic scalar observations; no host, owner, banner or prose."""
    from . import retrieval
    safe = retrieval._extract(context)
    allowed = {key: value for key, value in safe.items() if key not in {"host", "asset_id"}}
    for key in ("distro", "distro_release", "architecture", "advisory_id", "provider"):
        value = context.get(key)
        if isinstance(value, str) and _IDENTIFIER.fullmatch(value):
            allowed[key] = value
    cves = context.get("cve_ids")
    if isinstance(cves, list):
        allowed["cve_ids"] = sorted({cve for cve in cves[:100] if isinstance(cve, str) and retrieval.CVE.fullmatch(cve)})
    for key in ("alive_hosts", "open_host_port_pairs", "potential_vulnerabilities", "unconfirmed_findings", "vulnerable_hosts"):
        value = context.get(key)
        if type(value) is int and 0 <= value <= 2**63 - 1:
            allowed[key] = value
    text = "; ".join(f"{key}: {', '.join(value) if isinstance(value, list) else value}"
                     for key, value in sorted(allowed.items()) if value != [])
    if len(text) > 2048:
        raise _error("operator_embedding_source_too_large")
    return text or "Published observation; no supported semantic fields"


def _finalize(corpus):
    if len(corpus["items"]) > MAX_DOCUMENTS:
        raise _error("operator_embedding_source_too_large")
    for item in corpus["items"]:
        kind = item.get("source_kind")
        prefix = f"source_kind: {kind}; " if kind in {"finding", "summary", "inventory", "advisory"} else ""
        item["text"] = prefix + minimized_text(item["context"])
        if len(item["text"]) > MAX_TEXT_CHARS:
            raise _error("operator_embedding_source_too_large")
        item["text_hash"] = hashlib.sha256(item["text"].encode()).hexdigest()
    corpus["corpus_hash"] = _digest(sorted((item["source_id"], item["document_hash"], item["text_hash"])
                                          for item in corpus["items"]))
    return corpus


def run_corpus(settings, principal, run_id):
    from . import retrieval
    with tenant_scope.tenant(principal.tenant_id), get_session(settings.postgres_url) as db:
        snapshot = db.scalar(select(models.OperatorEvidenceSnapshot).where(
            models.OperatorEvidenceSnapshot.tenant_id == principal.tenant_id,
            models.OperatorEvidenceSnapshot.run_id == run_id))
        if snapshot is None:
            raise _error("operator_embeddings_not_ready")
        retrieval._current(settings, principal, snapshot)
        docs = db.scalars(select(models.OperatorEvidenceDocument).where(
            models.OperatorEvidenceDocument.tenant_id == principal.tenant_id,
            models.OperatorEvidenceDocument.snapshot_id == snapshot.snapshot_id)
            .order_by(models.OperatorEvidenceDocument.source_id).limit(MAX_DOCUMENTS + 1)).all()
        items = [{**retrieval._item(doc, snapshot), "evidence_source_id": doc.source_id,
                  "source_kind": "finding" if doc.artifact == "vulnerabilities.json" else "summary"}
                 for doc in docs]
        return _finalize({"scope_kind": "run", "scope_id": run_id,
            "source_snapshot": snapshot.snapshot_id, "evidence_snapshot_id": snapshot.snapshot_id, "inventory_snapshot_id": None,
            "state": snapshot.state, "items": items})


def device_corpus(settings, principal, device_id):
    from . import remediation
    result = remediation.for_device(settings, principal, device_id=device_id, limit=100)
    if result is None:
        raise _error("operator_source_unavailable")
    # Every match source hash covers inventory digest + current feed records,
    # applicability and freshness. A feed replacement changes this snapshot.
    snapshot = _digest({"inventory_snapshot": result["snapshot_id"], "state": result["state"],
        "sources": sorted((source["source_id"], source["source_hash"]) for card in result["items"] for source in card["sources"])})
    items = []
    safe_cards = result["items"] if result["state"] not in {"stale", "unknown"} else []
    for card in safe_cards:
        if card["status"] not in {"fix_available", "fixed", "not_applicable", "no_fix"}:
            continue
        sources = card["sources"]
        if not sources:
            continue
        common = {"package": card["package"], "distro": card["distro"],
                  "distro_release": card["distro_release"], "architecture": card["architecture"],
                  "cve_ids": card["cve_ids"]}
        derived = [("inventory", {**common, "version": card["installed_version"]}, sources)]
        derived += [("advisory", {**common, "version": card["target_version"],
                     "advisory_id": source["advisory_id"], "provider": source["provider"]}, [source]) for source in sources]
        for kind, context, references in derived:
            # Retain only the same strict scalar projection used for embedding.
            from . import retrieval
            projected = {key: value for key, value in retrieval._extract(context).items() if key not in {"host", "asset_id"}}
            for key in ("distro", "distro_release", "architecture", "advisory_id", "provider"):
                value = context.get(key)
                if isinstance(value, str) and _IDENTIFIER.fullmatch(value):
                    projected[key] = value
            projected["cve_ids"] = [cve for cve in card["cve_ids"] if retrieval.CVE.fullmatch(cve)]
            source_id = _digest({"device": device_id, "kind": kind, "references": [s["source_id"] for s in references],
                                 "package": projected.get("package")})[:32]
            source_hash = _digest({"context": projected, "references": references, "kind": kind})
            citation = {"source_id": source_id, "source_type": "document", "source_hash": source_hash,
                        "snapshot_id": snapshot, "observed_at": references[0]["observed_at"], "status": "partial"}
            items.append({**citation, "source_kind": kind, "context": projected, "citation": citation,
                          "document_hash": source_hash, "evidence_source_id": None, "references": references})
    return _finalize({"scope_kind": "device_remediation", "scope_id": device_id, "source_snapshot": snapshot,
        "evidence_snapshot_id": None, "inventory_snapshot_id": result["snapshot_id"],
        "state": "partial" if items else "stale" if result["state"] == "stale" else "unknown",
        "items": items, "truncated": result["truncated"]})


def _current_corpus(settings, principal, corpus):
    current = (run_corpus(settings, principal, corpus["scope_id"]) if corpus["scope_kind"] == "run"
               else device_corpus(settings, principal, corpus["scope_id"]))
    if current["source_snapshot"] != corpus["source_snapshot"] or current["corpus_hash"] != corpus["corpus_hash"]:
        raise _error("operator_source_changed")
    return current


def _index_query(principal, corpus, config):
    return select(models.OperatorEmbeddingIndex).where(
        models.OperatorEmbeddingIndex.tenant_id == principal.tenant_id,
        models.OperatorEmbeddingIndex.scope_kind == corpus["scope_kind"],
        models.OperatorEmbeddingIndex.scope_id == corpus["scope_id"],
        models.OperatorEmbeddingIndex.source_snapshot == corpus["source_snapshot"],
        models.OperatorEmbeddingIndex.model_fingerprint == config.fingerprint,
        models.OperatorEmbeddingIndex.corpus_hash == corpus["corpus_hash"])


def _metadata(index, config):
    return {"semantic_status": "ready", "mode": "exact_fulltext_vector", "embedding_model": config.model,
            "model_fingerprint": config.fingerprint, "embedding_dimensions": config.dimensions,
            "semantic_indexed_at": index.indexed_at.isoformat() + "Z"}


def _audit_inference(settings, principal, corpus, config, *, query=None):
    # Commit the minimized disclosure receipt before contacting the runtime.
    # Hashes identify the fixed source corpus and query without recording text.
    with tenant_scope.tenant(principal.tenant_id), get_session(settings.postgres_url) as db:
        audit.record(db, audit.AuditContext(actor=getattr(principal, "username", "operator-retrieval")),
            action="operator.embedding.query" if query is not None else "operator.embedding.build",
            resource_type="operator", resource_id=corpus["scope_id"], tenant_id=principal.tenant_id,
            after={"scope_kind": corpus["scope_kind"], "snapshot_id": corpus["source_snapshot"],
                   "corpus_sha256": corpus["corpus_hash"], "model_fingerprint": config.fingerprint,
                   "model_revision": config.revision, "document_count": len(corpus["items"]),
                   **({"query_sha256": hashlib.sha256(query.encode()).hexdigest()} if query is not None else {})})


def metadata(settings, principal, corpus):
    config = _config(settings)
    if not config.enabled:
        return {"semantic_status": "unsupported", "mode": "exact_fulltext"}
    if not corpus["items"] or corpus["state"] in {"missing", "stale", "unknown"}:
        return {"semantic_status": "no_eligible_sources", "mode": "exact_fulltext"}
    with tenant_scope.tenant(principal.tenant_id), get_session(settings.postgres_url) as db:
        index = db.scalar(_index_query(principal, corpus, config))
        if index is None:
            return {"semantic_status": "not_indexed", "mode": "exact_fulltext"}
        count = db.scalar(select(func.count()).select_from(models.OperatorEvidenceEmbedding).where(
            models.OperatorEvidenceEmbedding.tenant_id == principal.tenant_id,
            models.OperatorEvidenceEmbedding.index_id == index.index_id))
        if count != index.document_count or count != len(corpus["items"]):
            return {"semantic_status": "not_indexed", "mode": "exact_fulltext"}
        return _metadata(index, config)


def refresh(settings, principal, corpus):
    config = _config(settings)
    if not config.enabled:
        return {"semantic_status": "unsupported", "mode": "exact_fulltext"}
    if not corpus["items"] or corpus["state"] in {"missing", "stale", "unknown"}:
        return {"semantic_status": "no_eligible_sources", "mode": "exact_fulltext"}
    existing = metadata(settings, principal, corpus)
    if existing["semantic_status"] == "ready":
        _current_corpus(settings, principal, corpus)
        return existing
    with tenant_scope.tenant(principal.tenant_id), get_session(settings.postgres_url) as db:
        try:
            legal_hold.assert_not_on_hold(db, principal.tenant_id, action="operator.embedding.refresh")
        except legal_hold.LegalHoldActive:
            raise _error("operator_legal_hold") from None
    _audit_inference(settings, principal, corpus, config)
    try:
        vectors = EmbeddingClient(config).encode([item["text"] for item in corpus["items"]])
    except EmbeddingError:
        raise _error("operator_embeddings_unavailable") from None
    _current_corpus(settings, principal, corpus)
    with tenant_scope.tenant(principal.tenant_id), get_session(settings.postgres_url) as db:
        db.scalar(select(models.Tenant).where(models.Tenant.tenant_id == principal.tenant_id).with_for_update())
        try:
            legal_hold.assert_not_on_hold(db, principal.tenant_id, action="operator.embedding.refresh")
        except legal_hold.LegalHoldActive:
            raise _error("operator_legal_hold") from None
        # This lock is also held by exact-snapshot replacement and tenant purge.
        if corpus["evidence_snapshot_id"] is not None:
            current = db.scalar(select(models.OperatorEvidenceSnapshot).where(
                models.OperatorEvidenceSnapshot.tenant_id == principal.tenant_id,
                models.OperatorEvidenceSnapshot.snapshot_id == corpus["evidence_snapshot_id"]))
            if current is None:
                raise _error("operator_source_changed")
        existing = db.scalar(_index_query(principal, corpus, config))
        if existing is not None:
            return _metadata(existing, config)
        db.execute(delete(models.OperatorEmbeddingIndex).where(
            models.OperatorEmbeddingIndex.tenant_id == principal.tenant_id,
            models.OperatorEmbeddingIndex.scope_kind == corpus["scope_kind"],
            models.OperatorEmbeddingIndex.scope_id == corpus["scope_id"]))
        index = models.OperatorEmbeddingIndex(index_id=uuid4().hex, tenant_id=principal.tenant_id,
            evidence_snapshot_id=corpus["evidence_snapshot_id"], inventory_snapshot_id=corpus["inventory_snapshot_id"], scope_kind=corpus["scope_kind"], scope_id=corpus["scope_id"],
            source_snapshot=corpus["source_snapshot"], model_fingerprint=config.fingerprint,
            model_revision=config.revision, model_sha256=config.model_sha256, dimensions=config.dimensions,
            corpus_hash=corpus["corpus_hash"], document_count=len(corpus["items"]), indexed_at=datetime.now(UTC).replace(tzinfo=None), last_checked_at=datetime.now(UTC).replace(tzinfo=None))
        db.add(index)
        db.flush()
        for item, vector in zip(corpus["items"], vectors, strict=True):
            db.add(models.OperatorEvidenceEmbedding(index_id=index.index_id, source_id=item["source_id"],
                tenant_id=principal.tenant_id, evidence_source_id=item["evidence_source_id"],
                document_hash=item["document_hash"], text_hash=item["text_hash"], content=item["text"], vector=vector))
        return _metadata(index, config)


def _rank(settings, principal, corpus, query, eligible, exact_ids):
    config = _config(settings)
    if not config.enabled:
        raise _error("operator_embeddings_disabled")
    by_id = {item["source_id"]: item for item in corpus["items"] if item["source_id"] in eligible}
    with tenant_scope.tenant(principal.tenant_id), get_session(settings.postgres_url) as db:
        index = db.scalar(_index_query(principal, corpus, config))
        if index is None or index.document_count != len(corpus["items"]):
            raise _error("operator_embeddings_not_ready")
        count = db.scalar(select(func.count()).select_from(models.OperatorEvidenceEmbedding).where(
            models.OperatorEvidenceEmbedding.tenant_id == principal.tenant_id,
            models.OperatorEvidenceEmbedding.index_id == index.index_id))
        if count != index.document_count:
            raise _error("operator_embeddings_not_ready")
        rows = db.scalars(select(models.OperatorEvidenceEmbedding).where(
            models.OperatorEvidenceEmbedding.tenant_id == principal.tenant_id,
            models.OperatorEvidenceEmbedding.index_id == index.index_id,
            models.OperatorEvidenceEmbedding.source_id.in_(list(by_id))).limit(MAX_DOCUMENTS)).all()
        language = literal_column("'simple'::regconfig")
        if db.bind.dialect.name == "postgresql":
            text_vector = func.to_tsvector(language, models.OperatorEvidenceEmbedding.content)
            text_query = func.plainto_tsquery(language, query)
            lexical = db.scalars(select(models.OperatorEvidenceEmbedding.source_id).where(
                models.OperatorEvidenceEmbedding.tenant_id == principal.tenant_id,
                models.OperatorEvidenceEmbedding.index_id == index.index_id,
                models.OperatorEvidenceEmbedding.source_id.in_(list(by_id)), text_vector.op("@@")(text_query))
                .order_by(func.ts_rank_cd(text_vector, text_query).desc(), models.OperatorEvidenceEmbedding.source_id)).all()
        else:
            lexical = [row.source_id for row in rows if query.casefold() in row.content.casefold()]
        meta = _metadata(index, config)
    if not by_id:
        return [], meta
    if len(rows) != len(by_id) or any(row.document_hash != by_id[row.source_id]["document_hash"]
                                     or row.text_hash != by_id[row.source_id]["text_hash"] for row in rows):
        raise _error("operator_source_changed")
    _audit_inference(settings, principal, corpus, config, query=query)
    try:
        query_vector = EmbeddingClient(config).encode([query], query=True)[0]
        scores = {row.source_id: sum(a * b for a, b in zip(query_vector, normalized_vector(row.vector, config.dimensions), strict=True))
                  for row in rows}
    except EmbeddingError:
        raise _error("operator_embeddings_unavailable") from None
    vector_rank = {source: rank for rank, source in enumerate(sorted(scores, key=lambda source: (-scores[source], source)), 1)}
    lexical_rank = {source: rank for rank, source in enumerate(lexical, 1)}
    ordered = sorted(by_id, key=lambda source: (0 if source in exact_ids else 1,
        -(1 / (60 + vector_rank[source]) + (1 / (60 + lexical_rank[source]) if source in lexical_rank else 0)), source))
    _current_corpus(settings, principal, corpus)
    return [by_id[source] for source in ordered], meta


def _bounded(corpus, items, meta, limit, max_context_chars):
    result, size = [], 0
    state = corpus["state"]
    if len(items) > limit or corpus.get("truncated"):
        state = "truncated"
    for item in items[:limit]:
        exposed = {key: value for key, value in item.items() if key not in {"text", "text_hash", "evidence_source_id", "references"}}
        length = len(json.dumps(exposed, ensure_ascii=False))
        if size + length > max_context_chars:
            state = "truncated"
            break
        result.append(exposed)
        size += length
    return {"snapshot_id": corpus["source_snapshot"], "scope_kind": corpus["scope_kind"],
            "scope_id": corpus["scope_id"], "state": state, **meta, "items": result}


def search_run(settings, principal, run_id, *, query, cve=None, package=None, limit=10, max_context_chars=12000, source_artifact=None):
    corpus = run_corpus(settings, principal, run_id)
    eligible = [item for item in corpus["items"] if (source_artifact is None or item["source_artifact"] == source_artifact)
                and (cve is None or item["context"].get("cve") == cve)
                and (package is None or item["context"].get("package") == package)]
    exact = {item["source_id"] for item in eligible if query.strip() in {item["context"].get("cve"), item["context"].get("package")}}
    items, meta = _rank(settings, principal, corpus, query, {item["source_id"] for item in eligible}, exact)
    return _bounded(corpus, items, meta, limit, max_context_chars)


def refresh_device(settings, principal, *, device_id):
    corpus = device_corpus(settings, principal, device_id)
    return {"snapshot_id": corpus["source_snapshot"], "state": corpus["state"], "scope_kind": "device_remediation",
            "scope_id": device_id, "document_count": len(corpus["items"]), **refresh(settings, principal, corpus)}


def search_device(settings, principal, *, device_id, query="", cve=None, package=None, source_kind=None, limit=10):
    from . import retrieval
    if (not isinstance(query, str) or len(query) > 512 or any(ord(char) < 32 for char in query)
            or type(limit) is not int or not 1 <= limit <= 10 or source_kind not in {None, "inventory", "advisory"}
            or (cve is not None and (not isinstance(cve, str) or not retrieval.CVE.fullmatch(cve)))
            or (package is not None and (not isinstance(package, str) or not retrieval.PACKAGE.fullmatch(package)))):
        raise _error("operator_invalid_query")
    corpus = device_corpus(settings, principal, device_id)
    items = [item for item in corpus["items"] if (source_kind is None or item["source_kind"] == source_kind)
             and (cve is None or cve in item["context"].get("cve_ids", []))
             and (package is None or item["context"].get("package") == package)]
    if query.strip() and corpus["items"]:
        exact = {item["source_id"] for item in items if query.strip() == item["context"].get("package")
                 or query.strip().upper() in item["context"].get("cve_ids", [])}
        if retrieval.CVE.fullmatch(query.strip().upper()):
            items = [item for item in items if item["source_id"] in exact]
            meta = {**metadata(settings, principal, corpus), "mode": "exact_fulltext"}
        else:
            items, meta = _rank(settings, principal, corpus, query, {item["source_id"] for item in items}, exact)
    else:
        meta = metadata(settings, principal, corpus)
    return _bounded(corpus, items, meta, limit, 12000)


def device_source(settings, principal, *, device_id, source_id, snapshot_id, source_hash):
    from . import remediation
    corpus = device_corpus(settings, principal, device_id)
    if corpus["source_snapshot"] != snapshot_id:
        raise _error("operator_source_changed")
    item = next((item for item in corpus["items"] if item["source_id"] == source_id and item["source_hash"] == source_hash), None)
    if item is None:
        return None
    for ref in item["references"]:
        if remediation.get_source(settings, principal, device_id=device_id, source_id=ref["source_id"],
                                  snapshot_id=ref["snapshot_id"], source_hash=ref["source_hash"]) is None:
            raise _error("operator_source_changed")
    _current_corpus(settings, principal, corpus)
    return {key: value for key, value in item.items() if key not in {"text", "text_hash", "evidence_source_id", "references"}}


def prune_invalid(settings, *, limit=20):
    """Bounded rotating cleanup; legal hold retains inaccessible old vectors."""
    from types import SimpleNamespace
    from .gateway import GatewayError
    if type(limit) is not int or not 1 <= limit <= 100:
        raise _error("operator_invalid_limit")
    reason = "operator minimized embedding retention"
    with tenant_scope.system(reason), get_session(settings.postgres_url) as db:
        rows = db.scalars(select(models.OperatorEmbeddingIndex).order_by(
            models.OperatorEmbeddingIndex.last_checked_at, models.OperatorEmbeddingIndex.index_id).limit(limit)).all()
        candidates = [{key: getattr(row, key) for key in (
            "index_id", "tenant_id", "scope_kind", "scope_id", "source_snapshot", "corpus_hash")} for row in rows]
        if candidates:
            db.execute(update(models.OperatorEmbeddingIndex).where(
                models.OperatorEmbeddingIndex.index_id.in_([row["index_id"] for row in candidates]))
                .values(last_checked_at=datetime.now(UTC).replace(tzinfo=None)))
    removed = 0
    for candidate in candidates:
        try:
            _current_corpus(settings, SimpleNamespace(tenant_id=candidate["tenant_id"]), candidate)
            continue
        except GatewayError as exc:
            if exc.code not in {"operator_source_changed", "operator_source_unavailable", "operator_embeddings_not_ready"}:
                continue
        with tenant_scope.system(reason), get_session(settings.postgres_url) as db:
            db.scalar(select(models.Tenant).where(models.Tenant.tenant_id == candidate["tenant_id"]).with_for_update())
            if db.get(models.TenantLegalHold, candidate["tenant_id"]) is not None:
                continue
            removed += db.execute(delete(models.OperatorEmbeddingIndex).where(
                models.OperatorEmbeddingIndex.tenant_id == candidate["tenant_id"],
                models.OperatorEmbeddingIndex.index_id == candidate["index_id"])).rowcount
    return removed
