"""Storage/authority/ranking checks with fixed vectors, not model acceptance."""
import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.attributes import flag_modified

from api.db import models, tenant_scope
from api.db.engine import get_session
from api.services.artifact_store import keys
from api.services.local_operator import gateway, retrieval, semantic
from api.services.local_operator.embeddings import EmbeddingError
from tests.conftest import requires_postgres
from tests.test_operator_gateway import env as gateway_env  # noqa: F401

pytestmark = requires_postgres

FINDINGS = [
    {"cve": "CVE-2026-10001", "package": "openssl", "version": "3.0.1", "service": "https", "port": 443,
     "host": "192.0.2.10", "owner": "sensitive-owner", "evidence": {"password": "secret"}},
    {"cve": "CVE-2026-10002", "package": "openssh", "version": "9.1", "service": "ssh", "port": 22},
    {"cve": "CVE-2026-10003", "package": "postfix", "version": "3.0", "service": "smtp", "port": 25},
]


def enable(settings):
    settings.operator_embeddings_enabled = True
    settings.operator_embeddings_revision = "a" * 40
    settings.operator_embeddings_model_sha256 = "b" * 64
    settings.operator_embeddings_dimensions = 3


def fake_vector(value):
    lowered = value.lower()
    if any(word in lowered for word in ("https", "encrypted", "web", "openssl")):
        return [1.0, 0.0, 0.0]
    if any(word in lowered for word in ("ssh", "shell", "terminal")):
        return [0.0, 1.0, 0.0]
    return [0.0, 0.0, 1.0]


@pytest.fixture
def env(gateway_env, monkeypatch):  # noqa: F811
    settings, task, store, ref = gateway_env
    enable(settings)
    principal = gateway.authorize_actor(settings, task)
    store.put_bytes(keys.run_artifact(ref, "vulnerabilities.json"), json.dumps(FINDINGS).encode())
    calls = []
    def encode(self, texts, *, query=False):
        calls.append((list(texts), query))
        return [fake_vector(value) for value in texts]
    monkeypatch.setattr(semantic.EmbeddingClient, "encode", encode)
    return settings, task, store, ref, principal, calls


def test_refresh_persists_minimized_model_bound_vectors_and_semantic_recall(env):
    settings, task, _, _, principal, calls = env
    first = retrieval.refresh_run(settings, principal, task["run_id"])
    assert first["semantic_status"] == "ready" and first["embedding_dimensions"] == 3
    assert len(calls) == 1 and not calls[0][1]
    assert "192.0.2.10" not in str(calls) and "sensitive-owner" not in str(calls)
    assert retrieval.refresh_run(settings, principal, task["run_id"]) == first
    assert len(calls) == 1
    result = retrieval.search(settings, principal, task["run_id"], query="encrypted web endpoint", limit=1)
    assert result["mode"] == "exact_fulltext_vector" and result["semantic_status"] == "ready"
    assert result["items"][0]["context"]["package"] == "openssl"
    assert result["state"] == "truncated"
    assert result["items"][0]["citation"]["source_type"] == "finding"
    with get_session(settings.postgres_url) as db:
        index = db.scalar(select(models.OperatorEmbeddingIndex))
        assert index.model_revision == "a" * 40 and index.model_sha256 == "b" * 64
        assert index.document_count == 4
        rows = list(db.scalars(select(models.OperatorEvidenceEmbedding)))
        assert len(rows) == 4 and all(row.tenant_id == principal.tenant_id for row in rows)
        assert "192.0.2.10" not in str([row.content for row in rows])
        assert all(len(row.vector) == 3 for row in rows)


def test_exact_filters_win_and_cve_never_uses_near_neighbors(env, monkeypatch):
    settings, task, _, _, principal, calls = env
    retrieval.refresh_run(settings, principal, task["run_id"])
    count = len(calls)
    exact = retrieval.search(settings, principal, task["run_id"], query="cve-2026-10002", limit=1)
    assert exact["items"][0]["context"]["package"] == "openssh"
    assert exact["mode"] == "exact_fulltext" and len(calls) == count
    assert not retrieval.search(settings, principal, task["run_id"], query="CVE-2026-99999")["items"]
    monkeypatch.setattr(semantic.EmbeddingClient, "encode", lambda *args, **kwargs: [[0.0, 1.0, 0.0]])
    exact_package = retrieval.search(settings, principal, task["run_id"], query="openssl", limit=1)
    assert exact_package["items"][0]["context"]["package"] == "openssl"
    assert not retrieval.search(settings, principal, task["run_id"], query="shell", package="nonexistent")["items"]


def test_model_change_cannot_reuse_previous_vectors_and_refresh_is_atomic(env):
    settings, task, _, _, principal, calls = env
    first = retrieval.refresh_run(settings, principal, task["run_id"])
    settings.operator_embeddings_model_sha256 = "c" * 64
    with pytest.raises(gateway.GatewayError, match="not_ready"):
        retrieval.search(settings, principal, task["run_id"], query="encrypted web")
    assert len(calls) == 1
    second = retrieval.refresh_run(settings, principal, task["run_id"])
    assert second["snapshot_id"] == first["snapshot_id"]
    assert second["model_fingerprint"] != first["model_fingerprint"]
    with get_session(settings.postgres_url) as db:
        assert db.scalar(select(func.count()).select_from(models.OperatorEmbeddingIndex)) == 1
        assert db.scalar(select(func.count()).select_from(models.OperatorEvidenceEmbedding)) == 4


def test_unavailable_embeddings_do_not_silently_downgrade_hybrid_search(env, monkeypatch):
    settings, task, _, _, principal, _ = env
    def unavailable(*args, **kwargs):
        raise EmbeddingError("secret-upstream-data")
    monkeypatch.setattr(semantic.EmbeddingClient, "encode", unavailable)
    with pytest.raises(gateway.GatewayError, match="^operator_embeddings_unavailable$"):
        retrieval.refresh_run(settings, principal, task["run_id"])
    with pytest.raises(gateway.GatewayError, match="not_ready"):
        retrieval.search(settings, principal, task["run_id"], query="encrypted web")
    exact = retrieval.search(settings, principal, task["run_id"], cve=FINDINGS[0]["cve"])
    assert exact["semantic_status"] == "not_indexed" and exact["mode"] == "exact_fulltext"
    assert exact["items"][0]["context"]["package"] == "openssl"
    with get_session(settings.postgres_url) as db:
        assert db.scalar(select(func.count()).select_from(models.OperatorEmbeddingIndex)) == 0


@pytest.mark.parametrize("phase", ["build", "query"])
def test_midflight_changed_source_is_discarded_without_mixed_snapshot(env, monkeypatch, phase):
    settings, task, store, ref, principal, _ = env
    if phase == "query":
        retrieval.refresh_run(settings, principal, task["run_id"])
    def change_source(self, texts, *, query=False):
        store.put_bytes(keys.run_artifact(ref, "vulnerabilities.json"), b"[]")
        return [fake_vector(value) for value in texts]
    monkeypatch.setattr(semantic.EmbeddingClient, "encode", change_source)
    with pytest.raises(gateway.GatewayError, match="source_changed"):
        if phase == "build":
            retrieval.refresh_run(settings, principal, task["run_id"])
        else:
            retrieval.search(settings, principal, task["run_id"], query="encrypted web")
    if phase == "build":
        with get_session(settings.postgres_url) as db:
            assert db.scalar(select(func.count()).select_from(models.OperatorEmbeddingIndex)) == 0


def test_rls_and_composite_foreign_keys_separate_tenant_vectors(env):
    settings, task, _, _, principal, calls = env
    retrieval.refresh_run(settings, principal, task["run_id"])
    corpus = semantic.run_corpus(settings, principal, task["run_id"])
    foreign = SimpleNamespace(tenant_id="foreign-semantic")
    with tenant_scope.system("embedding foreign tenant fixture"), get_session(settings.postgres_url) as db:
        db.add(models.Tenant(tenant_id=foreign.tenant_id, name="Foreign", created_at=datetime.now(UTC)))
    count = len(calls)
    with pytest.raises(gateway.GatewayError):
        semantic._rank(settings, foreign, corpus, "encrypted", {item["source_id"] for item in corpus["items"]}, set())
    assert len(calls) == count
    with tenant_scope.system("raw vector RLS fixture"), get_session(settings.postgres_url) as db:
        db.execute(text("SET LOCAL ROLE shapoclyack_tenant"))
        db.execute(text("SELECT set_config('shapoclyack.tenant_id', :tenant, true)"), {"tenant": foreign.tenant_id})
        assert db.scalar(select(func.count()).select_from(models.OperatorEmbeddingIndex)) == 0
        assert db.scalar(select(func.count()).select_from(models.OperatorEvidenceEmbedding)) == 0
    with get_session(settings.postgres_url) as db:
        index_id = db.scalar(select(models.OperatorEmbeddingIndex.index_id))
    with pytest.raises(IntegrityError):
        with tenant_scope.system("composite FK rejection"), get_session(settings.postgres_url) as db:
            db.add(models.OperatorEvidenceEmbedding(index_id=index_id, source_id="forged", tenant_id=foreign.tenant_id,
                evidence_source_id=None, document_hash="a" * 64, text_hash="b" * 64, content="forged", vector=[1, 0, 0]))


def test_source_deletion_cascades_vectors_and_held_stale_vectors_are_inaccessible(env):
    settings, task, store, ref, principal, _ = env
    retrieval.refresh_run(settings, principal, task["run_id"])
    with get_session(settings.postgres_url) as db:
        db.add(models.TenantLegalHold(tenant_id=principal.tenant_id, reason="fixture", set_by="admin", set_at=datetime.now(UTC)))
    store.delete(keys.run_artifact(ref, "summary.json"))
    assert retrieval.prune_invalid(settings, limit=100) == 0
    with pytest.raises(gateway.GatewayError):
        retrieval.search(settings, principal, task["run_id"], query="encrypted web")
    with get_session(settings.postgres_url) as db:
        assert db.scalar(select(func.count()).select_from(models.OperatorEvidenceEmbedding)) == 4
        db.execute(delete(models.TenantLegalHold).where(models.TenantLegalHold.tenant_id == principal.tenant_id))
    assert retrieval.prune_invalid(settings, limit=100) >= 1
    with get_session(settings.postgres_url) as db:
        assert db.scalar(select(func.count()).select_from(models.OperatorEvidenceEmbedding)) == 0
        assert db.scalar(select(func.count()).select_from(models.OperatorEmbeddingIndex)) == 0


@pytest.mark.parametrize("corrupt", [[True, 0, 0], [1.0, 0.0]])
def test_corrupt_or_wrong_dimension_stored_vector_fails_closed(env, corrupt):
    settings, task, _, _, principal, _ = env
    current = retrieval.refresh_run(settings, principal, task["run_id"])
    with get_session(settings.postgres_url) as db:
        # Other scopes may legitimately retain vectors in a mixed suite. Corrupt
        # the exact corpus that the subsequent search will read, not an arbitrary
        # row selected by PostgreSQL's physical storage order.
        row = db.scalar(select(models.OperatorEvidenceEmbedding).join(
            models.OperatorEmbeddingIndex,
            models.OperatorEmbeddingIndex.index_id == models.OperatorEvidenceEmbedding.index_id,
        ).where(
            models.OperatorEvidenceEmbedding.tenant_id == principal.tenant_id,
            models.OperatorEmbeddingIndex.tenant_id == principal.tenant_id,
            models.OperatorEmbeddingIndex.scope_kind == "run",
            models.OperatorEmbeddingIndex.scope_id == task["run_id"],
            models.OperatorEmbeddingIndex.evidence_snapshot_id == current["snapshot_id"],
            models.OperatorEmbeddingIndex.model_fingerprint == current["model_fingerprint"],
        ))
        assert row is not None
        row.vector = corrupt
        # Python considers True == 1.0, so JSON equality can otherwise suppress
        # the intended corrupting UPDATE when the original vector starts at 1.
        flag_modified(row, "vector")
        identity = (row.index_id, row.source_id)
    with get_session(settings.postgres_url) as db:
        persisted = db.get(models.OperatorEvidenceEmbedding, identity).vector
        assert len(persisted) == len(corrupt)
        assert type(persisted[0]) is type(corrupt[0])
    with pytest.raises(gateway.GatewayError, match="^operator_embeddings_unavailable$"):
        retrieval.search(settings, principal, task["run_id"], query="encrypted web")


def test_missing_sources_do_not_invoke_embedding_model(gateway_env, monkeypatch):  # noqa: F811
    settings, task, _, _ = gateway_env
    enable(settings)
    monkeypatch.setattr(semantic.EmbeddingClient, "encode", lambda *a, **kw: pytest.fail("missing findings reached model"))
    principal = gateway.authorize_actor(settings, task)
    result = retrieval.refresh_run(settings, principal, task["run_id"])
    assert result["semantic_status"] == "no_eligible_sources" and result["state"] == "missing"
