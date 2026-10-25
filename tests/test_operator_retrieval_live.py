"""Explicit real-model recall measurement; mocks never satisfy this gate."""
import hashlib
import json
import os
from pathlib import Path
import resource
import sys
import time
from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text

from api.db import models, tenant_scope
from api.db.engine import get_session
from api.services.artifact_store import keys
from api.services.local_operator import gateway, remediation, retrieval, semantic
from api.services.local_operator.embeddings import EmbeddingConfig
from tests.conftest import requires_postgres
from tests.test_operator_gateway import env as gateway_env  # noqa: F401
from tests.test_operator_remediation import feed_for

FIXTURE = Path(__file__).parent / "fixtures/operator_retrieval_eval.json"
DATASET_SHA256 = "d18074d87edc89d9e646c8cfe9d46ab4dc4dc6076ba3cc5bb153b1c0b3790092"
ROOT = Path(__file__).parents[1]
pytestmark = [requires_postgres, pytest.mark.skipif(
    os.environ.get("OCTO_OPERATOR_EMBEDDING_ACCEPTANCE") != "1",
    reason="requires explicitly provisioned pinned local CPU embedding runtime; mocks are not acceptance")]


def percentile(values, fraction):
    return sorted(values)[max(0, __import__("math").ceil(len(values) * fraction) - 1)] if values else None


def test_real_pinned_cpu_embedding_recall_and_exact_identifier_acceptance(gateway_env, monkeypatch):  # noqa: F811
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == DATASET_SHA256
    dataset = json.loads(FIXTURE.read_text())
    settings, task, artifacts, ref = gateway_env
    settings.operator_embeddings_enabled = True
    settings.operator_embeddings_base_url = os.environ.get("OCTO_EMBEDDING_ACCEPTANCE_URL", "http://127.0.0.1:8084/v1")
    settings.operator_embeddings_revision = "370f27d7550e0def9b39c1f16d3fbaa13aa67728"
    settings.operator_embeddings_model_sha256 = "06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439"
    settings.operator_embeddings_dimensions = 1024
    config = EmbeddingConfig.from_settings(settings)
    principal = gateway.authorize_actor(settings, task)
    artifacts.put_bytes(keys.run_artifact(ref, "vulnerabilities.json"), json.dumps(dataset["documents"]).encode())
    now = datetime.now(UTC).replace(tzinfo=None)
    device_id, inventory_id = "retrieval-acceptance-device", "retrieval-acceptance-inventory"
    with tenant_scope.system("frozen retrieval acceptance corpus"), get_session(settings.postgres_url) as db:
        db.add(models.EndpointDevice(device_id=device_id, tenant_id=principal.tenant_id,
            agent_id="retrieval-acceptance-agent", hostname="synthetic-fixture", agent_version="fixture-v1",
            first_seen=now, last_seen=now, os_arch="amd64", latest_snapshot_id=inventory_id, software_snapshot_id=inventory_id))
        db.flush()
        db.add(models.EndpointInventorySnapshot(snapshot_id=inventory_id, tenant_id=principal.tenant_id,
            device_id=device_id, schema_version=1, collected_at=now, received_at=now,
            payload_digest=DATASET_SHA256, software_count=len(dataset["device_packages"])))
        db.flush()
        rows = []
        for index, package in enumerate(dataset["device_packages"]):
            row = models.SoftwareCveMatch(tenant_id=principal.tenant_id, device_id=device_id,
                snapshot_id=inventory_id, match_key=f"fixture-match-{index}", cve_id=f"CVE-2026-{30000 + index}",
                status="vulnerable", severity="high", source_package=package, installed_package=package,
                installed_version="1.0-1", fixed_version="1.0-2", advisory_id=f"FIXTURE-USN-{index}", provider="ubuntu",
                distro="ubuntu", distro_release="focal", purl=f"pkg:deb/ubuntu/{package}@1.0-1",
                feed_date=now.date().isoformat(), matched_at=now)
            rows.append(row)
            db.add(row)
        db.flush()
        fixture_feed = feed_for(rows, source="synthetic-frozen-retrieval-fixture", date=now.date().isoformat())
    monkeypatch.setattr(remediation, "_feed", lambda _: fixture_feed)
    report_path = Path(os.environ.get("OCTO_OPERATOR_RETRIEVAL_REPORT", "/private/tmp/shapo-ai-retrieval-acceptance.json"))
    code_files = ["api/services/local_operator/embeddings.py", "api/services/local_operator/semantic.py",
                  "api/services/local_operator/retrieval.py", "api/services/local_operator/remediation.py"]
    report = {"schema_version": "1", "dataset_sha256": DATASET_SHA256, "scope": dataset["scope"],
        "started_at": datetime.now(UTC).isoformat(), "model": config.model, "model_revision": config.revision,
        "model_sha256": config.model_sha256, "model_fingerprint": config.fingerprint,
        "dimensions": config.dimensions, "placement": "CPU deployment expected; externally verified by runtime report",
        "configured_runtime_image": "ghcr.io/ggml-org/llama.cpp:server@sha256:20c4196fc08b459a34ef78aaa05b101333b2fac687e30ec99f37b3c9dc071b44",
        "code_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in code_files},
        "thresholds": dataset["thresholds"], "planned_cases": len(dataset["queries"]),
        "semantic_cases": sum(case["scope"] != "exact" for case in dataset["queries"]),
        "exact_cases": sum(case["scope"] == "exact" for case in dataset["queries"]),
        "semantic_hits": 0, "exact_hits": 0, "semantic_recall_at_10": 0.0,
        "exact_identifier_hit_rate": 0.0, "executed_cases": 0, "records": []}
    try:
        moment = time.perf_counter()
        run_index = retrieval.refresh_run(settings, principal, task["run_id"])
        report["run_index_seconds"] = time.perf_counter() - moment
        assert run_index["semantic_status"] == "ready"
        moment = time.perf_counter()
        device_index = semantic.refresh_device(settings, principal, device_id=device_id)
        report["device_index_seconds"] = time.perf_counter() - moment
        assert device_index["semantic_status"] == "ready"
        with get_session(settings.postgres_url) as db:
            report["index_documents"] = sum(db.scalars(select(models.OperatorEmbeddingIndex.document_count)))
            report["postgres_index_bytes"] = db.execute(text(
                "SELECT pg_total_relation_size('operator_embedding_indexes') + pg_total_relation_size('operator_evidence_embeddings')")).scalar_one()
        for case in dataset["queries"]:
            started = time.perf_counter()
            record = {"case_id": case["id"], "scope": case["scope"], "language": case["language"],
                      "query_sha256": hashlib.sha256(case["query"].encode()).hexdigest(), "hit": False}
            try:
                if case["scope"] == "device":
                    result = semantic.search_device(settings, principal, device_id=device_id, query=case["query"], limit=10)
                elif case["scope"] == "exact":
                    result = retrieval.search(settings, principal, task["run_id"], limit=10,
                        **({"cve": case["query"]} if case["query"].startswith("CVE-") else {"package": case["query"]}))
                else:
                    result = retrieval.search(settings, principal, task["run_id"], query=case["query"], limit=10)
                record["state"] = result["state"]
                record["semantic_status"] = result["semantic_status"]
                record["returned_count"] = len(result["items"])
                record["sources"] = [{key: item.get(key) for key in ("source_id", "source_hash", "snapshot_id", "source_kind")}
                                     | {"package": item["context"].get("package")} for item in result["items"]]
                record["hit"] = any(item["context"].get("package") == case["gold_package"]
                    and (case["scope"] != "device" or item.get("source_kind") == case["source_kind"]) for item in result["items"])
            except gateway.GatewayError as exc:
                record["error"] = exc.code
            record["seconds"] = time.perf_counter() - started
            report["records"].append(record)
            report["executed_cases"] = len(report["records"])
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2))
        natural = [record for record in report["records"] if record["scope"] != "exact"]
        exact = [record for record in report["records"] if record["scope"] == "exact"]
        report["semantic_hits"] = sum(record["hit"] for record in natural)
        report["semantic_cases"] = len(natural)
        report["semantic_recall_at_10"] = report["semantic_hits"] / len(natural)
        report["exact_hits"] = sum(record["hit"] for record in exact)
        report["exact_cases"] = len(exact)
        report["exact_identifier_hit_rate"] = report["exact_hits"] / len(exact)
        report["latency_seconds"] = {scope: {"p50": percentile([r["seconds"] for r in report["records"] if r["scope"] == scope], 0.50),
            "p95": percentile([r["seconds"] for r in report["records"] if r["scope"] == scope], 0.95)} for scope in ("run", "device", "exact")}
        report["by_language"] = {language: {"hits": sum(r["hit"] for r in natural if r["language"] == language),
            "cases": sum(r["language"] == language for r in natural)} for language in ("ru", "en")}
        assert report["semantic_recall_at_10"] >= dataset["thresholds"]["semantic_recall_at_10"]
        assert report["exact_identifier_hit_rate"] >= dataset["thresholds"]["exact_identifier_hit_rate"]
        report["status"] = "passed"
    except BaseException as exc:
        report["status"] = "failed"
        report["failure_type"] = type(exc).__name__
        if isinstance(exc, gateway.GatewayError):
            report["failure_code"] = exc.code
        raise
    finally:
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        report["harness_peak_rss_bytes"] = peak if sys.platform == "darwin" else peak * 1024
        report["finished_at"] = datetime.now(UTC).isoformat()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2))
