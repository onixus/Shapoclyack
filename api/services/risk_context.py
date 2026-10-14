"""One tenant-scoped, operation-local risk context and immutable fold receipts.

No socket/DNS guesses: only registered IP/FQDN identifiers connect observations.
A missing database/asset is an explicitly incomplete host heuristic. Receipts are
captured by the tracker transaction; current API assessments never mutate them.
"""

from __future__ import annotations

import copy
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from api.services.risk_scoring import FOOTHOLD, LOCAL, index_cdn_waf, path_role

CONTEXT_VERSION = "asset-risk-context-1"


class RiskAssessmentPending(RuntimeError):
    """A managed publication has not captured its canonical risk receipt yet."""


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def observation_digest(entries: list[dict[str, Any]], fingerprint: Any) -> str:
    return digest({"findings": entries, "fingerprint": fingerprint})


def normalized_host(value: Any) -> str:
    return str(value or "").strip().lower()


@dataclass
class BatchContext:
    tenant_id: str
    assets: dict[str, Any]
    by_host: dict[str, Any]
    declared_surface: str | None
    available: bool

    def asset_for(self, item: dict[str, Any]) -> Any | None:
        # An explicit asset identity is valid only if loaded under this tenant.
        explicit = str(item.get("asset_id") or "")
        if explicit:
            return self.assets.get(explicit)
        return self.by_host.get(normalized_host(item.get("host")))

    def correlation(self, item: dict[str, Any]) -> tuple[str, str]:
        asset = self.asset_for(item)
        if asset is not None:
            return "asset", asset.asset_id
        # Tenant is part of the key even for incomplete/offline operations.
        return "host-fallback", f"{self.tenant_id}:{normalized_host(item.get('host'))}"


def load_batch(
    session: Any, *, tenant_id: str, run_id: str, entries: list[dict[str, Any]], job_id: str | None = None
) -> BatchContext:
    """At most three SELECTs, independent of finding count (no lazy relations)."""
    from sqlalchemy import select
    from api.db import models
    from api.services.scan_surface import declared_surface_for_job
    from scanner.pipeline.asset_identity import identity_candidates_for_host

    hosts = {normalized_host(item.get("host")) for item in entries} - {""}
    explicit = {str(item["asset_id"]) for item in entries if item.get("asset_id")}
    candidate_keys = { (c.identifier_type, c.identifier_value): c.key
        for host in hosts for c in identity_candidates_for_host(tenant_id, host_ip=host) }
    candidates = set(candidate_keys)
    values = {value for _, value in candidates}
    identifiers = (
        session.execute(
            select(
                models.AssetIdentifier.identifier_type,
                models.AssetIdentifier.identifier_value,
                models.AssetIdentifier.asset_id,
            ).where(
                models.AssetIdentifier.tenant_id == tenant_id,
                models.AssetIdentifier.identifier_type.in_(("ip", "fqdn")),
                models.AssetIdentifier.identifier_value.in_(values),
            )
        ).all()
        if values
        else []
    )
    ids = explicit | {row.asset_id for row in identifiers} | set(candidate_keys.values())
    assets = (
        {
            row.asset_id: row
            for row in session.scalars(
                select(models.Asset).where(
                    models.Asset.tenant_id == tenant_id, models.Asset.asset_id.in_(ids)
                )
            )
        }
        if ids
        else {}
    )
    mapped: dict[str, set[str]] = {}
    for row in identifiers:
        if (
            row.identifier_type,
            row.identifier_value,
        ) in candidates and row.asset_id in assets:
            mapped.setdefault(normalized_host(row.identifier_value), set()).add(
                row.asset_id
            )
    # Legacy asset rows can predate identifiers. Their tenant-qualified stable
    # identity key is still a registered asset, never an inferred DNS merge.
    for (_, value), key in candidate_keys.items():
        if normalized_host(value) not in mapped and key in assets:
            mapped[normalized_host(value)] = {key}
    # Ambiguous identities must not create a same-asset path or inherit operator values.
    by_host = {
        host: assets[next(iter(ids))] for host, ids in mapped.items() if len(ids) == 1
    }
    jobs = session.scalars(select(models.Job).where(
        models.Job.tenant_id == tenant_id, models.Job.run_id == run_id,
        models.Job.job_id == job_id if job_id else True,
    ).limit(2)).all() if run_id else []
    # An unbound legacy run may use one unambiguous owning job, never the
    # newest of several jobs sharing the tenant-chosen run ID.
    job = jobs[0] if len(jobs) == 1 else None
    return BatchContext(
        tenant_id, assets, by_host, declared_surface_for_job(job.scan_options if job else None), True,
    )


def score_batch(
    entries: list[dict[str, Any]],
    *,
    context: BatchContext,
    fingerprint: Any,
    scorer: Any,
    now: datetime,
    mode: str,
) -> list[dict[str, Any]]:
    """Shared formula, same evidence, same operation clock, no consumer re-scoring."""
    now = now.replace(tzinfo=UTC) if now.tzinfo is None else now.astimezone(UTC)
    cdn = index_cdn_waf(fingerprint)
    footholds = {
        context.correlation(item) for item in entries
        if path_role(item) == FOOTHOLD and (normalized_host(item.get("host")) or context.asset_for(item) is not None)
    }
    out = []
    data_version = scorer.data_version()
    input_digest = observation_digest(entries, fingerprint)
    for item in entries:
        asset = context.asset_for(item)
        correlation = context.correlation(item)
        result = scorer.score_vulnerability(
            item,
            asset_criticality_override=asset.asset_criticality if asset else None,
            operator_exposure=asset.exposure_level if asset else None,
            declared_surface=context.declared_surface,
            cdn_waf_index=cdn,
            same_asset_foothold=path_role(item) == LOCAL and correlation in footholds,
            now=now,
        )
        inputs = {
            "asset_id": asset.asset_id if asset else None,
            "criticality": asset.asset_criticality if asset else None,
            "exposure": asset.exposure_level if asset else None,
            "context_source": asset.context_source if asset else None,
            "declared_surface": context.declared_surface,
            "correlation": correlation[0],
            "cdn_waf": result.get("cdn_waf", []),
        }
        result["risk_assessment"] = {
            "mode": mode,
            "evaluated_at": now.isoformat(),
            "context_version": CONTEXT_VERSION,
            "observation_digest": input_digest,
            "context_digest": digest(inputs),
            "data_version": data_version,
            "model_version": result["scoring_model_version"],
            "inputs": inputs,
            "complete": mode != "pending-current" and bool(
                context.available
                and asset is not None
                and inputs["criticality"] is not None
                and (
                    inputs["exposure"] is not None
                    or context.declared_surface is not None
                )
            ),
            "criticality_source": "operator"
            if inputs["criticality"] is not None
            else "heuristic",
            "asset_source": "registered" if asset else "host-fallback",
            "context_status": "loaded" if context.available else "unavailable",
        }
        out.append(result)
    return out


#: What a workflow event keeps of an assessment: enough to find the immutable
#: receipt and tell which evaluation it was, not a copy of the scores and
#: explanation -- ``observed`` events are high-volume and never swept.
_REFERENCE_KEYS = (
    "assessment_id",
    "execution_id",
    "publication_id",
    "mode",
    "evaluated_at",
    "context_version",
    "model_version",
    "data_version",
    "observation_digest",
    "context_digest",
    "complete",
)


def receipt_reference(scored: dict[str, Any]) -> dict[str, Any]:
    assessment = scored.get("risk_assessment") or {}
    return {key: assessment[key] for key in _REFERENCE_KEYS if key in assessment}


def read_snapshot(session: Any, *, tenant_id: str, run_id: str,
                  input_digest: str | None = None, execution_id: str | None = None,
                  job_id: str | None = None) -> list[dict[str, Any]] | None:
    from sqlalchemy import select
    from api.db import models
    if not execution_id and not job_id:
        return None  # no trusted execution hint, no invented historical identity
    conditions = [models.RunRiskAssessment.tenant_id == tenant_id,
                  models.RunRiskAssessment.run_id == run_id]
    if input_digest is not None:
        conditions.append(models.RunRiskAssessment.observation_digest == input_digest)
    if execution_id:
        conditions.append(models.RunRiskAssessment.execution_id == execution_id)
    if job_id:
        conditions.append(models.RunRiskAssessment.job_id == job_id)
    rows = session.scalars(select(models.RunRiskAssessment).where(*conditions).limit(2)).all()
    if len(rows) > 1:
        raise RiskAssessmentPending("ambiguous accepted execution; explicit publication identity required")
    return copy.deepcopy(rows[0].scores) if rows else None


def capture_snapshot(session: Any, *, tenant_id: str, run_id: str,
                     entries: list[dict[str, Any]], fingerprint: Any,
                     scores: list[dict[str, Any]], now: datetime,
                     publication_id: str, job_id: str | None = None) -> list[dict[str, Any]]:
    from api.db import models
    from api.db.engine import insert_or_skip
    execution_id = "publication:" + publication_id
    assessment_id = f"rass_{uuid.uuid4().hex}"
    for score in scores:
        score["risk_assessment"].update({"assessment_id": assessment_id,
            "publication_id": publication_id, "execution_id": execution_id,
            "job_id": job_id, "tenant_id": tenant_id, "run_id": run_id})
    row = models.RunRiskAssessment(assessment_id=assessment_id, tenant_id=tenant_id,
        run_id=run_id, execution_id=execution_id, job_id=job_id,
        observation_digest=observation_digest(entries, fingerprint), captured_at=now,
        publication_id=publication_id, scores=copy.deepcopy(scores))
    if insert_or_skip(session, row, conflict=["tenant_id", "run_id", "execution_id", "observation_digest"]):
        return scores
    saved = read_snapshot(session, tenant_id=tenant_id, run_id=run_id,
                          execution_id=execution_id, input_digest=row.observation_digest)
    if saved is None:
        raise RuntimeError("risk assessment capture lost its canonical receipt")
    return saved


def receipt_required(session: Any, *, tenant_id: str, run_id: str,
                     job_id: str | None = None, execution_id: str | None = None) -> bool:
    from sqlalchemy import literal, select, union_all
    from api.db import models
    publication = select(models.RunPublication.risk_assessment_contract).where(
        models.RunPublication.tenant_id == tenant_id, models.RunPublication.run_id == run_id,
        models.RunPublication.job_status == "succeeded",
        models.RunPublication.risk_assessment_contract.is_not(None))
    job = select(models.Job.risk_assessment_contract).where(
        models.Job.tenant_id == tenant_id, models.Job.run_id == run_id,
        models.Job.risk_assessment_contract.is_not(None))
    receipt = select(literal(CONTEXT_VERSION)).where(
        models.RunRiskAssessment.tenant_id == tenant_id, models.RunRiskAssessment.run_id == run_id)
    if job_id:
        publication = publication.where(models.RunPublication.job_id == job_id)
        job = job.where(models.Job.job_id == job_id)
        receipt = receipt.where(models.RunRiskAssessment.job_id == job_id)
    if execution_id:
        # One accepted execution owes its own receipt; another publication of
        # the same run or job does not make this one pending.
        publication = publication.where(
            models.RunPublication.publication_id
            == execution_id.removeprefix("publication:")
        )
        job = job.where(models.Job.risk_assessment_execution_id == execution_id)
        receipt = receipt.where(models.RunRiskAssessment.execution_id == execution_id)
    return session.scalars(union_all(publication, job, receipt).limit(1)).first() is not None


def assess_operation(settings: Any, *, tenant_id: str, run_id: str,
                     entries: list[dict[str, Any]], fingerprint: Any, scorer: Any,
                     mode: str = "historical", now: datetime | None = None,
                     require_captured: bool = False, generation: Any = None,
                     job_id: str | None = None) -> list[dict[str, Any]]:
    if mode not in ("historical", "current"):
        raise ValueError("assessment mode must be historical or current")
    clock = now or datetime.now(UTC)
    marker = generation if isinstance(generation, dict) else {}
    job_id = job_id or str(marker.get("job_id") or "") or None
    pub_id = str(marker.get("publication_id") or "") or None
    execution_id = "publication:" + pub_id if pub_id else None
    if settings is not None and settings.postgres_url.strip():
        from api.db.engine import get_session
        with get_session(settings.postgres_url) as session:
            if mode == "historical":
                saved = read_snapshot(session, tenant_id=tenant_id, run_id=run_id,
                    job_id=job_id, execution_id=execution_id,
                    input_digest=observation_digest(entries, fingerprint))
                if saved is not None:
                    return saved
            pending = mode == "historical" and receipt_required(session,
                tenant_id=tenant_id, run_id=run_id, job_id=job_id, execution_id=execution_id)
            if pending and require_captured:
                raise RiskAssessmentPending("accepted execution risk receipt is not captured yet")
            context = load_batch(session, tenant_id=tenant_id, run_id=run_id,
                                 entries=entries, job_id=job_id)
            return score_batch(entries, context=context, fingerprint=fingerprint, scorer=scorer,
                now=clock, mode="pending-current" if pending else ("legacy-current" if mode == "historical" else "current"))
    return score_batch(entries, context=BatchContext(tenant_id, {}, {}, None, False),
        fingerprint=fingerprint, scorer=scorer, now=clock,
        mode="uncaptured-current" if mode == "historical" else "current")


def validate_generation(directory: Any, *, tenant_id: str, publication: Any) -> None:
    """Reject a mutable run folder replaced by another accepted execution."""
    from api.services import runs
    marker = runs._load_json(directory / runs.RUN_TENANT_FILE) if directory else None
    if not isinstance(marker, dict) or marker.get("tenant_id") != tenant_id or marker.get("job_id") != publication.job_id or marker.get("publication_id") != publication.publication_id:
        raise RiskAssessmentPending("run folder generation differs from the accepted publication")


def ensure_publication_receipt(settings: Any, publication: Any) -> None:
    from api.db import models
    from api.db.engine import get_session
    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication.publication_id)
        if row is None or row.risk_assessment_contract != CONTEXT_VERSION or row.job_status != "succeeded":
            return
        # A completed old execution stays complete even if another publication
        # replaced the shared run folder. Its canonical receipt is immutable.
        saved = read_snapshot(session, tenant_id=row.tenant_id, run_id=row.run_id,
                              execution_id="publication:" + row.publication_id)
        if saved is None:
            raise RiskAssessmentPending("accepted publication risk receipt capture has not completed")
