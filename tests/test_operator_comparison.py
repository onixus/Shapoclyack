"""Published comparison keeps provenance and refuses invented remediation."""
import json
from datetime import UTC, datetime

import pytest

from api.db import models
from api.db.engine import get_session
from api.services import artifact_store
from api.services.artifact_store import keys
from api.services.local_operator import comparison
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres

pytestmark = requires_postgres


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = make_settings(tmp_path, operator_enabled=True)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    headers = auth_headers(client, "viewer")
    artifacts = artifact_store.get_store(settings)
    for run_id in ("before-run", "after-run"):
        moment = datetime.now(UTC).replace(tzinfo=None)
        with get_session(settings.postgres_url) as db:
            db.add(models.Job(job_id=run_id + "-job", tenant_id="default", run_id=run_id,
                status="succeeded", queued_at=moment, finished_at=moment))
        ref = keys.run_ref(run_id, "default")
        artifacts.put_bytes(keys.run_artifact(ref, "tenant.json"), json.dumps({"tenant_id": "default",
            "job_id": run_id + "-job", "publication_id": run_id + "-publication"}).encode())
        artifacts.put_bytes(keys.run_artifact(ref, "summary.json"), b'{"alive_hosts":1}')
    diff = {"previous_run_dir": "/secret/before-run", "current_run_dir": "/private/after-run",
        "counts": {key: 1 for key in comparison.COUNT_KEYS},
        "events": [{"kind": "model instruction", "url": "https://beacon.invalid/token"}],
        "vulnerabilities": {"removed": [{"cve": "invented", "secret": "password"}]}}
    ref = keys.run_ref("after-run", "default")
    artifacts.put_bytes(keys.run_artifact(ref, "diff.json"), json.dumps(diff).encode())
    return client, settings, headers, artifacts, ref, diff


def _compare(env, **kwargs):
    client, settings, headers, artifacts, ref, diff = env
    return client.get("/api/operator/compare", headers=headers, params={"tenant_id": "default",
        "previous_run_id": "before-run", "current_run_id": "after-run", **kwargs})


@pytest.mark.parametrize("language", ["ru", "en"])
def test_published_comparison_is_bounded_and_never_claims_remediation(env, language):
    response = _compare(env, language=language)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["status"] == "incomplete"
    assert data["quality_status"] == "quality_unverified"
    assert data["language"] == language
    assert data["counts"]["vulns_removed"] == 1
    assert len(data["citations"]) == 2
    assert len(data["diff_source"]["source_hash"]) == 64
    for private in ("/secret/", "/private/", "beacon.invalid", "password", "invented", "model instruction"):
        assert private not in response.text


def test_missing_diff_is_unsupported_instead_of_synthesized_cve_difference(env):
    env[3].delete(keys.run_artifact(env[4], "diff.json"))
    response = _compare(env)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "unsupported"
    assert response.json()["counts"] == {}
    assert response.json()["diff_source"] is None


@pytest.mark.parametrize("bad", ["baseline", "bool_count", "negative", "overflow", "missing_count", "bad_path"])
def test_invalid_or_different_baseline_never_becomes_an_accepted_diff(env, bad):
    diff = env[5]
    if bad == "baseline":
        diff["previous_run_dir"] = "/foreign/run"
    elif bad == "bad_path":
        diff["previous_run_dir"] = {"path": "before-run"}
    else:
        diff["counts"]["vulns_removed"] = {"bool_count": True, "negative": -1,
            "overflow": 2**64, "missing_count": None}[bad]
    env[3].put_bytes(keys.run_artifact(env[4], "diff.json"), json.dumps(diff).encode())
    response = _compare(env)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "unsupported"
    assert response.json()["counts"] == {}


@pytest.mark.parametrize("status", ["failed", "cancelled", "running"])
def test_unaccepted_current_run_is_never_compared(env, status):
    with get_session(env[1].postgres_url) as db:
        db.get(models.Job, "after-run-job").status = status
    assert _compare(env).status_code == 404


def test_foreign_marker_and_unknown_tenant_cannot_disclose_counts(env):
    env[3].put_bytes(keys.run_artifact(env[4], "tenant.json"), b'{"tenant_id":"foreign"}')
    assert _compare(env).status_code == 404
    assert _compare(env, tenant_id="unknown").status_code in {403, 404}


def test_mutating_diff_during_retrieval_refuses_output(env, monkeypatch):
    original = comparison.gateway._read
    reads = []

    def changed(artifacts, key, limit):
        raw = original(artifacts, key, limit)
        if key.endswith("diff.json"):
            reads.append(key)
            if len(reads) == 2:
                return raw + b" "
        return raw

    monkeypatch.setattr(comparison.gateway, "_read", changed)
    assert _compare(env).status_code == 409


@pytest.mark.parametrize("parameters", [{"previous_run_id": "../before-run"},
    {"current_run_id": "before-run"}, {"language": "xx"}])
def test_invalid_request_is_refused(env, parameters):
    assert _compare(env, **parameters).status_code == 422
