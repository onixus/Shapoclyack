"""Real PostgreSQL console authorization and current-source evidence routes."""

import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, update

from api.db import models, tenant_scope
from api.db.engine import get_session
from api.services import artifact_store, users
from api.services.artifact_store import keys
from tests.conftest import (
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres
BASE = "/api/operator/evidence"


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = make_settings(tmp_path, operator_enabled=True)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    headers = {
        role: auth_headers(client, role) for role in ("admin", "operator", "viewer")
    }
    with tenant_scope.system("evidence API fixture"):
        with get_session(settings.postgres_url) as db:
            moment = datetime.now(UTC).replace(tzinfo=None)
            db.add(
                models.Job(
                    job_id="evidence-job",
                    tenant_id="default",
                    run_id="evidence-run",
                    status="succeeded",
                    queued_at=moment,
                    finished_at=moment,
                )
            )
    artifacts = artifact_store.get_store(settings)
    ref = keys.run_ref("evidence-run", "default")
    artifacts.put_bytes(
        keys.run_artifact(ref, "tenant.json"),
        json.dumps(
            {
                "tenant_id": "default",
                "job_id": "evidence-job",
                "publication_id": "pub-1",
            }
        ).encode(),
    )
    artifacts.put_bytes(
        keys.run_artifact(ref, "summary.json"),
        json.dumps(
            {
                "alive_hosts": 3,
                "potential_vulnerabilities": 7,
                "url": "https://private.invalid/secret",
                "banner": "secret-banner",
            }
        ).encode(),
    )
    return client, settings, headers, artifacts, ref


def _refresh(env):
    client, _, headers, _, _ = env
    response = client.post(
        BASE + "/runs/evidence-run/refresh?tenant_id=default",
        headers=headers["operator"],
        json={},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _search(env, role="viewer", **params):
    client, _, headers, _, _ = env
    return client.get(
        BASE + "/search",
        headers=headers[role],
        params={"tenant_id": "default", "run_id": "evidence-run", **params},
    )


def test_summary_citation_opens_exact_current_publication(env):
    from api.auth import TenantPrincipal
    from api.services.local_operator.gateway import read_evidence

    client, settings, headers, artifacts, ref = env
    principal = TenantPrincipal(
        username="viewer",
        tenant_id="default",
        role="viewer",
        rank=1,
        tenant_requested=True,
        is_platform_admin=False,
    )
    _, citation = read_evidence(settings, principal, "evidence-run")
    params = {
        "tenant_id": "default",
        "snapshot_id": citation.snapshot_id,
        "source_hash": citation.source_hash,
    }
    url = BASE + "/runs/evidence-run/summary"
    response = client.get(url, headers=headers["viewer"], params=params)
    assert response.status_code == 200, response.text
    assert response.json()["context"]["counts"]["alive_hosts"] == 3
    assert (
        "secret-banner" not in response.text and "private.invalid" not in response.text
    )
    assert (
        client.get(
            url, headers=headers["viewer"], params={**params, "source_hash": "0" * 64}
        ).status_code
        == 409
    )
    artifacts.put_bytes(keys.run_artifact(ref, "summary.json"), b'{"alive_hosts": 4}')
    assert client.get(url, headers=headers["viewer"], params=params).status_code == 409


def test_tenant_index_shared_by_console_roles_with_bound_citation(env):
    _refresh(env)
    client, _, headers, _, _ = env
    response = _search(env)
    assert response.status_code == 200, response.text
    assert (
        "secret-banner" not in response.text and "private.invalid" not in response.text
    )
    item = response.json()["items"][0]
    opened = client.get(
        BASE + "/" + item["source_id"],
        headers=headers["viewer"],
        params={
            "tenant_id": "default",
            "snapshot_id": item["snapshot_id"],
            "source_hash": item["source_hash"],
        },
    )
    assert opened.status_code == 200, opened.text
    assert opened.json()["source_hash"] == item["source_hash"]
    assert opened.json()["console_target"] == {"kind": "run", "run_id": "evidence-run"}
    assert (
        client.post(
            BASE + "/runs/evidence-run/refresh?tenant_id=default",
            headers=headers["viewer"],
            json={},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/tenants",
            headers=headers["admin"],
            json={"tenant_id": "other", "name": "other"},
        ).status_code
        == 201
    )
    assert _search(env, tenant_id="other").status_code == 403
    other = _search(env, "admin", tenant_id="other")
    assert other.status_code in {200, 404}, other.text
    if other.status_code == 200:
        assert other.json()["items"] == []


@pytest.mark.parametrize(
    "changes",
    [
        {"url": "https://unsafe.invalid"},
        {"prompt": "arbitrary"},
        {"query": "x" * 257},
        {"cve": "CVE-2026-1234 OR 1=1"},
        {"package": "../unsafe"},
        {"limit": 11},
        {"limit": 0},
        {"run_id": "../unsafe"},
    ],
)
def test_search_rejects_unsafe_and_unbounded_arguments(env, changes):
    assert _search(env, **changes).status_code == 422


def test_strict_body_and_snapshot_arguments(env):
    client, settings, headers, _, _ = env
    for body in ({"url": "https://unsafe.invalid"}, [], "", None):
        response = client.post(
            BASE + "/runs/evidence-run/refresh?tenant_id=default",
            headers=headers["operator"],
            json=body,
        )
        assert response.status_code == 422, response.text
    assert (
        client.get(
            BASE + "/search?tenant_id=default&run_id=evidence-run&limit=1&limit=2",
            headers=headers["viewer"],
        ).status_code
        == 422
    )
    assert (
        client.get(
            BASE + "/id?tenant_id=default&snapshot_id=snap&source_hash=" + "A" * 64,
            headers=headers["viewer"],
        ).status_code
        == 422
    )
    assert (
        client.get(
            BASE + "/search?run_id=evidence-run", headers=headers["viewer"]
        ).status_code
        == 422
    )
    settings.operator_enabled = False
    assert _search(env).status_code == 404


@pytest.mark.parametrize("change", ["mutated", "deleted", "foreign"])
def test_old_citation_cannot_open_after_source_changes(env, change):
    _refresh(env)
    client, _, headers, artifacts, ref = env
    item = _search(env).json()["items"][0]
    if change == "deleted":
        artifacts.delete(keys.run_artifact(ref, "summary.json"))
    elif change == "foreign":
        artifacts.put_bytes(
            keys.run_artifact(ref, "tenant.json"), b'{"tenant_id":"other"}'
        )
    else:
        artifacts.put_bytes(
            keys.run_artifact(ref, "summary.json"), b'{"alive_hosts":99}'
        )
    response = client.get(
        BASE + "/" + item["source_id"],
        headers=headers["viewer"],
        params={
            "tenant_id": "default",
            "snapshot_id": item["snapshot_id"],
            "source_hash": item["source_hash"],
        },
    )
    assert response.status_code in {404, 409}, response.text


@pytest.mark.parametrize("change", ["recreated", "revoked"])
def test_held_read_discards_data_after_console_identity_revoked(
    env, monkeypatch, change
):
    from api.services.local_operator import retrieval

    _refresh(env)
    _, settings, _, _, _ = env
    original = retrieval.search

    def interleave(*args, **kwargs):
        result = original(*args, **kwargs)
        with tenant_scope.system("evidence held read identity regression"):
            if change == "recreated":
                assert users.delete_user("viewer")
                users.create_user(
                    username="viewer",
                    password="replacement-password-1234",
                    role="viewer",
                )
            else:
                with get_session(settings.postgres_url) as db:
                    db.execute(
                        update(models.SessionFamily)
                        .where(models.SessionFamily.username == "viewer")
                        .values(revoked_at=datetime.now(UTC))
                    )
        return result

    monkeypatch.setattr(retrieval, "search", interleave)
    response = _search(env)
    assert response.status_code == 403, response.text
    assert "items" not in response.json()


def test_service_tokens_cannot_query_or_refresh_evidence(env):
    client, _, headers, _, _ = env
    issued = client.post(
        "/api/tenants/default/service-tokens",
        headers=headers["admin"],
        json={"name": "evidence-machine", "role": "admin", "scopes": ["*"]},
    )
    assert issued.status_code == 201, issued.text
    token = {"Authorization": "Bearer " + issued.json()["token"]}
    assert (
        client.get(
            BASE + "/search?tenant_id=default&run_id=evidence-run", headers=token
        ).status_code
        == 403
    )
    assert (
        client.post(
            BASE + "/runs/evidence-run/refresh?tenant_id=default",
            headers=token,
            json={},
        ).status_code
        == 403
    )


def test_held_read_cannot_restore_default_fallback_with_other_tenant_grants(
    env, monkeypatch
):
    from sqlalchemy import delete
    from api.services.local_operator import retrieval

    _refresh(env)
    client, settings, headers, _, _ = env
    assert settings.tenant_rls == "enforce"
    assert (
        client.post(
            "/api/tenants",
            headers=headers["admin"],
            json={"tenant_id": "other", "name": "other"},
        ).status_code
        == 201
    )
    for tenant in ("default", "other"):
        response = client.put(
            f"/api/tenants/{tenant}/members/viewer",
            headers=headers["admin"],
            json={"role": "viewer"},
        )
        assert response.status_code == 200, response.text
    original = retrieval.search

    def revoke_default(*args, **kwargs):
        result = original(*args, **kwargs)
        with tenant_scope.system("evidence held request membership revocation"):
            with get_session(settings.postgres_url) as db:
                db.execute(
                    delete(models.UserTenant).where(
                        models.UserTenant.username == "viewer",
                        models.UserTenant.tenant_id == "default",
                    )
                )
        return result

    monkeypatch.setattr(retrieval, "search", revoke_default)
    response = _search(env)
    assert response.status_code == 403, response.text
    assert "items" not in response.json()


def test_unique_finding_source_opens_its_card_and_ambiguity_stays_on_the_run(env):
    client, settings, headers, artifacts, ref = env
    now = datetime.now(UTC).replace(tzinfo=None)
    with (
        tenant_scope.system("evidence finding target"),
        get_session(settings.postgres_url) as db,
    ):
        db.add(
            models.Asset(
                asset_id="asset-evidence",
                tenant_id="default",
                status="active",
                first_seen=now,
                last_seen=now,
            )
        )
        db.add(
            models.AssetIdentifier(
                asset_id="asset-evidence",
                tenant_id="default",
                identifier_type="ip",
                identifier_value="192.0.2.8",
            )
        )
        db.add(
            models.Vulnerability(
                vuln_id="vln-evidence",
                tenant_id="default",
                asset_id="asset-evidence",
                finding_key="k-evidence",
                state="OPEN",
                state_changed_at=now,
                severity="high",
                title="SSH",
                cve="CVE-2025-0001",
                port="22",
                last_seen_run_id="evidence-run",
                first_seen_at=now,
                last_seen_at=now,
                sla_started_at=now,
                created_at=now,
                updated_at=now,
            )
        )
    artifacts.put_bytes(
        keys.run_artifact(ref, "vulnerabilities.json"),
        json.dumps(
            [
                {
                    "host": "192.0.2.8",
                    "port": 22,
                    "cve": "CVE-2025-0001",
                    "severity": "high",
                    "title": "do not disclose",
                    "url": "https://private.invalid/finding",
                }
            ]
        ).encode(),
    )
    try:
        _refresh(env)
        found = _search(env, cve="CVE-2025-0001")
        assert found.status_code == 200, found.text
        item = next(
            row
            for row in found.json()["items"]
            if row.get("context", {}).get("cve") == "CVE-2025-0001"
        )
        opened = client.get(
            BASE + "/" + item["source_id"],
            headers=headers["viewer"],
            params={
                "tenant_id": "default",
                "snapshot_id": item["snapshot_id"],
                "source_hash": item["source_hash"],
            },
        )
        assert opened.status_code == 200, opened.text
        assert opened.json()["console_target"] == {
            "kind": "finding",
            "vuln_id": "vln-evidence",
            "run_id": "evidence-run",
        }
        assert (
            "private.invalid" not in opened.text
            and "do not disclose" not in opened.text
        )
        with (
            tenant_scope.system("evidence ambiguous finding"),
            get_session(settings.postgres_url) as db,
        ):
            db.add(
                models.Vulnerability(
                    vuln_id="vln-evidence-2",
                    tenant_id="default",
                    asset_id="asset-evidence",
                    finding_key="k-evidence-2",
                    state="OPEN",
                    state_changed_at=now,
                    severity="low",
                    title="other",
                    cve="CVE-2025-0002",
                    port="22",
                    last_seen_run_id="evidence-run",
                    first_seen_at=now,
                    last_seen_at=now,
                    sla_started_at=now,
                    created_at=now,
                    updated_at=now,
                )
            )
        again = client.get(
            BASE + "/" + item["source_id"],
            headers=headers["viewer"],
            params={
                "tenant_id": "default",
                "snapshot_id": item["snapshot_id"],
                "source_hash": item["source_hash"],
            },
        )
        assert again.status_code == 200, again.text
        assert again.json()["console_target"]["kind"] == "run_finding"
        assert "vuln_id" not in again.json()["console_target"]
    finally:
        with (
            tenant_scope.system("evidence finding target cleanup"),
            get_session(settings.postgres_url) as db,
        ):
            db.execute(
                delete(models.Vulnerability).where(
                    models.Vulnerability.vuln_id.in_(("vln-evidence", "vln-evidence-2"))
                )
            )
            db.execute(
                delete(models.AssetIdentifier).where(
                    models.AssetIdentifier.asset_id == "asset-evidence"
                )
            )
            db.execute(
                delete(models.Asset).where(models.Asset.asset_id == "asset-evidence")
            )


def test_allowlisted_context_keys_cannot_smuggle_source_urls(env, monkeypatch):
    from api.services.local_operator import retrieval

    _refresh(env)
    original = retrieval.search

    def polluted(*args, **kwargs):
        result = original(*args, **kwargs)
        result["items"][0]["context"].update(
            {
                "host": "https://private.invalid/host",
                "package": "https://private.invalid/pkg",
                "service": "https://private.invalid/service",
                "url": "https://private.invalid/raw",
                "version": "file:/private/secret",
                "asset_id": "x" * 1000,
                "alive_hosts": True,
            }
        )
        return result

    monkeypatch.setattr(retrieval, "search", polluted)
    response = _search(env)
    assert response.status_code == 200, response.text
    assert (
        "private.invalid" not in response.text and "private/secret" not in response.text
    )
    context = response.json()["items"][0]["context"]
    assert not set(context) & {
        "host",
        "package",
        "service",
        "url",
        "version",
        "asset_id",
        "alive_hosts",
    }
