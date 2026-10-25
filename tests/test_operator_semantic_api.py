"""Typed current inventory/advisory corpus authorization and lifecycle tests."""
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, func, select, update

from api.db import models, tenant_scope
from api.db.engine import get_session
from api.services.local_operator import remediation, semantic
from api.services.local_operator.embeddings import EmbeddingError
from tests.conftest import requires_postgres
from tests.test_operator_remediation_api import env as remediation_env  # noqa: F401
from tests.test_operator_semantic import enable, fake_vector

pytestmark = requires_postgres
BASE = "/api/operator/evidence/devices/device-590"


@pytest.fixture
def env(remediation_env, monkeypatch):  # noqa: F811
    client, settings, headers = remediation_env
    enable(settings)
    calls = []
    def encode(self, texts, *, query=False):
        calls.append((list(texts), query))
        return [fake_vector(value) for value in texts]
    monkeypatch.setattr(semantic.EmbeddingClient, "encode", encode)
    return client, settings, headers, calls


def refresh(env, role="operator"):
    client, _, headers, _ = env
    return client.post(BASE + "/refresh", params={"tenant_id": "default"}, headers=headers[role], json={})


def search(env, role="viewer", **params):
    client, _, headers, _ = env
    return client.get(BASE + "/search", params={"tenant_id": "default", **params}, headers=headers[role])


def test_inventory_and_advisory_search_returns_distinct_bound_current_sources(env):
    client, settings, headers, calls = env
    assert refresh(env, "viewer").status_code == 403
    built = refresh(env)
    assert built.status_code == 200, built.text
    assert built.json()["semantic_status"] == "ready" and built.json()["document_count"] == 2
    assert len(calls) == 1
    response = search(env, query="curl")
    assert response.status_code == 200, response.text
    result = response.json()
    assert {item["source_kind"] for item in result["items"]} == {"inventory", "advisory"}
    assert result["scope_kind"] == "device_remediation"
    assert all(item["source_type"] == "document" for item in result["items"])
    for item in result["items"]:
        citation = item["citation"]
        opened = client.get(BASE + "/sources/" + citation["source_id"], headers=headers["viewer"], params={
            "tenant_id": "default", "snapshot_id": citation["snapshot_id"], "source_hash": citation["source_hash"]})
        assert opened.status_code == 200, opened.text
        assert opened.json()["source_hash"] == citation["source_hash"]
    assert {item["source_kind"] for item in search(env, source_kind="inventory").json()["items"]} == {"inventory"}
    assert not search(env, cve="CVE-2026-99999").json()["items"]
    with get_session(settings.postgres_url) as db:
        receipts = list(db.scalars(select(models.AuditEvent).where(
            models.AuditEvent.action.in_(["operator.embedding.build", "operator.embedding.query"]))))
        assert {row.actor for row in receipts} == {"operator", "viewer"}
        assert all("query" not in str(row.after.get("text", "")) for row in receipts)
        assert next(row for row in receipts if row.action == "operator.embedding.query").after["query_sha256"]


def test_feed_change_invalidates_vectors_and_bound_source_until_atomic_rebuild(env, monkeypatch):
    client, _, headers, _ = env
    assert refresh(env).status_code == 200
    old = search(env).json()
    reference = old["items"][0]["citation"]
    original = remediation._feed
    def changed(row):
        data, records, _ = original(row)
        return data, records, "new-feed-fingerprint"
    monkeypatch.setattr(remediation, "_feed", changed)
    response = search(env, query="package update")
    assert response.status_code == 503 and response.json()["detail"] == "operator_embeddings_not_ready"
    refused = client.get(BASE + "/sources/" + reference["source_id"], headers=headers["viewer"], params={
        "tenant_id": "default", "snapshot_id": reference["snapshot_id"], "source_hash": reference["source_hash"]})
    assert refused.status_code == 409
    rebuilt = refresh(env)
    assert rebuilt.status_code == 200 and rebuilt.json()["snapshot_id"] != old["snapshot_id"]
    assert search(env, query="package update").status_code == 200


def test_inventory_deletion_cascades_device_vectors_and_no_stale_source_survives(env):
    _, settings, _, calls = env
    assert refresh(env).status_code == 200
    before = len(calls)
    with tenant_scope.system("inventory deletion fixture"), get_session(settings.postgres_url) as db:
        db.execute(delete(models.EndpointInventorySnapshot).where(
            models.EndpointInventorySnapshot.snapshot_id == "snapshot-590",
            models.EndpointInventorySnapshot.tenant_id == "default"))
    response = search(env, query="curl")
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "unknown" and not response.json()["items"]
    assert response.json()["semantic_status"] == "no_eligible_sources"
    assert len(calls) == before
    with get_session(settings.postgres_url) as db:
        assert db.scalar(select(func.count()).select_from(models.OperatorEmbeddingIndex)) == 0
        assert db.scalar(select(func.count()).select_from(models.OperatorEvidenceEmbedding)) == 0


def test_stale_inventory_is_not_embedded_and_old_vectors_are_pruned(env):
    _, settings, _, calls = env
    assert refresh(env).status_code == 200
    count = len(calls)
    with get_session(settings.postgres_url) as db:
        db.execute(update(models.EndpointInventorySnapshot).where(
            models.EndpointInventorySnapshot.snapshot_id == "snapshot-590").values(
                collected_at=datetime.now(UTC).replace(tzinfo=None) - timedelta(days=8)))
    response = refresh(env)
    assert response.status_code == 200, response.text
    assert response.json()["semantic_status"] == "no_eligible_sources"
    assert response.json()["state"] == "stale" and len(calls) == count
    assert semantic.prune_invalid(settings, limit=100) >= 1


def test_revoked_console_session_after_embedding_query_discards_result(env, monkeypatch):
    _, settings, _, _ = env
    assert refresh(env).status_code == 200
    def revoke(self, texts, *, query=False):
        with tenant_scope.system("revoke during embedding"), get_session(settings.postgres_url) as db:
            db.execute(update(models.SessionFamily).where(models.SessionFamily.username == "viewer").values(
                revoked_at=datetime.now(UTC)))
        return [fake_vector(value) for value in texts]
    monkeypatch.setattr(semantic.EmbeddingClient, "encode", revoke)
    response = search(env, query="curl")
    assert response.status_code == 403
    assert "1.0-2" not in response.text and "USN-590" not in response.text


def test_runtime_failure_returns_explicit_unavailable_not_lexical_success(env, monkeypatch):
    def failure(*args, **kwargs):
        raise EmbeddingError("secret-provider-body")
    monkeypatch.setattr(semantic.EmbeddingClient, "encode", failure)
    response = refresh(env)
    assert response.status_code == 503 and response.json()["detail"] == "operator_embeddings_unavailable"
    assert "secret-provider-body" not in response.text
    exact = search(env, cve="CVE-2026-1234")
    assert exact.status_code == 200 and exact.json()["mode"] == "exact_fulltext"
    assert exact.json()["semantic_status"] == "not_indexed"


def test_explicit_tenant_strict_args_and_foreign_device_access(env):
    client, _, headers, calls = env
    assert client.get(BASE + "/search", headers=headers["viewer"]).status_code == 422
    for params in ({"url": "https://evil.invalid"}, {"prompt": "grant admin"}, {"source_kind": "arbitrary"}, {"limit": 11}):
        assert search(env, **params).status_code == 422
    assert client.post("/api/tenants", headers=headers["admin"], json={"tenant_id": "other", "name": "Other"}).status_code == 201
    response = client.get(BASE + "/search", headers=headers["admin"], params={"tenant_id": "other", "query": "curl"})
    assert response.status_code == 404 and not calls
