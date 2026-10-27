"""Bounded projection of the scanner's published comparison, without inference.

The operator never derives differences from paginated findings or CVE-only
sets. Missing detector coverage never becomes evidence of remediation.
"""
from hashlib import sha256
from pathlib import PurePosixPath

from sqlalchemy import select

from api.db import models
from api.services import artifact_store, audit
from api.services.artifact_store import keys
from api.services.local_operator import gateway, store

MAX_DIFF_BYTES = 2 * 1024 * 1024
COUNT_KEYS = ("hosts_added", "hosts_removed", "ports_added", "ports_removed",
              "vulns_added", "vulns_removed", "events")
TEXT = {
    "ru": {
        "summary": "Сравнение опубликованных наблюдений. Отсутствие повторного наблюдения не доказывает исправление.",
        "missing": "Для выбранной пары нет опубликованного сравнения.",
        "coverage": "Полнота и совпадение detector coverage не подтверждены; исчезнувшие наблюдения не считаются исправленными.",
        "invalid": "Опубликованный diff не содержит корректных ограниченных счётчиков выбранной пары.",
    },
    "en": {
        "summary": "Comparison of published observations. An observation missing from a later scan does not prove remediation.",
        "missing": "No published comparison is available for the selected pair.",
        "coverage": "Complete and matching detector coverage is unverified; missing observations do not establish remediation.",
        "invalid": "The published diff does not contain valid bounded counts for this pair.",
    },
}


def _artifact(settings, principal, run_id):
    artifacts = artifact_store.get_store(settings)
    ref = keys.run_ref(run_id, principal.tenant_id)
    if not artifacts.exists(keys.run_artifact(ref, "summary.json")):
        ref = keys.run_ref(run_id)
    return artifacts, keys.run_artifact(ref, "diff.json")


def compare(settings, context, previous_run_id, current_run_id, language, audit_context):
    if previous_run_id == current_run_id or language not in TEXT:
        raise store.OperatorStoreError("invalid_input")
    p = context.principal
    # Live console identity/membership remain fenced through source retrieval.
    with store._personal_db(settings, p.tenant_id, p.username, context.auth_session_id) as db:
        tenant = db.scalar(select(models.Tenant).where(models.Tenant.tenant_id == p.tenant_id).with_for_update(read=True))
        if tenant is None or tenant.status != "active":
            raise store.OperatorStoreError("access_revoked")
        _, before = gateway.read_evidence(settings, p, previous_run_id)
        _, current = gateway.read_evidence(settings, p, current_run_id)
        texts = TEXT[language]
        result = {"status": "unsupported", "quality_status": "quality_unverified",
            "language": language, "previous_run_id": previous_run_id, "current_run_id": current_run_id,
            "summary": texts["summary"], "counts": {}, "reason": texts["missing"],
            "citations": [before.model_dump(mode="json"), current.model_dump(mode="json")],
            "diff_source": None}
        artifacts, key = _artifact(settings, p, current_run_id)
        if artifacts.stat(key) is not None:
            raw = gateway._read(artifacts, key, MAX_DIFF_BYTES)
            source_hash = sha256(raw).hexdigest()
            try:
                diff = gateway._json(raw)
                if not isinstance(diff, dict):
                    raise ValueError("invalid diff")
                # Paths are provenance labels only, never opened or returned.
                if (PurePosixPath(diff.get("previous_run_dir", "")).name != previous_run_id
                        or PurePosixPath(diff.get("current_run_dir", "")).name != current_run_id):
                    raise ValueError("different baseline")
                counts = diff.get("counts")
                if not isinstance(counts, dict) or any(type(counts.get(key)) is not int
                        or not 0 <= counts[key] <= 2**63 - 1 for key in COUNT_KEYS):
                    raise ValueError("invalid counts")
                result.update(status="incomplete", counts={key: counts[key] for key in COUNT_KEYS},
                    reason=texts["coverage"], diff_source={"run_id": current_run_id,
                        "artifact": "diff.json", "source_hash": source_hash,
                        "snapshot_id": current.snapshot_id})
            except (ValueError, TypeError, RecursionError):
                result["reason"] = texts["invalid"]
            # Revalidate diff bytes as well as both publication references.
            if sha256(gateway._read(artifacts, key, MAX_DIFF_BYTES)).hexdigest() != source_hash:
                raise gateway.GatewayError("operator_source_changed")
        if (gateway.read_evidence(settings, p, previous_run_id)[1] != before
                or gateway.read_evidence(settings, p, current_run_id)[1] != current):
            raise gateway.GatewayError("operator_source_changed")
        audit.record(db, audit_context, action="operator.compare", resource_type="operator",
            resource_id=current_run_id, tenant_id=p.tenant_id,
            after={"previous_run_id": previous_run_id, "current_run_id": current_run_id,
                "status": result["status"], "source_references": result["citations"],
                "diff_source": result["diff_source"]})
        return result
