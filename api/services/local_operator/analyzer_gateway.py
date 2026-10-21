"""Read-only analysis with fresh authority and verified source bindings."""
from __future__ import annotations

import hashlib
import json

from starlette.concurrency import run_in_threadpool

from . import analysis, gateway, retrieval, store
from .config import OperatorConfig
from .providers import OperatorProviderError

TOOL_VERSION = "published-findings-v1"


async def execute(settings, task):
    principal = await run_in_threadpool(gateway.authorize_actor, settings, task)
    await run_in_threadpool(retrieval.refresh_run, settings, principal, task["run_id"])
    evidence = await run_in_threadpool(retrieval.search, settings, principal, task["run_id"],
                                      source_artifact="vulnerabilities.json")
    prompt = analysis.build_prompt(task["language"], evidence)
    attempt = None
    if not evidence["items"] or evidence["state"] in {"missing", "stale", "unknown"}:
        raw = json.dumps({"language": task["language"], "summary": "insufficient_evidence",
                          "recommendations": []})
    else:
        await run_in_threadpool(gateway.authorize_actor, settings, task)
        config = OperatorConfig.from_settings(settings)
        attempt = {"provider": config.provider, "model": config.model,
                   "prompt_version": analysis.PROMPT_VERSION, "tool_version": TOOL_VERSION,
                   "prompt_hash": hashlib.sha256(json.dumps(prompt, sort_keys=True).encode()).hexdigest(),
                   "source_references": [item["citation"] for item in evidence["items"]]}
        if not await run_in_threadpool(store.record_inference_attempt, settings, task, attempt):
            raise gateway.GatewayError("operator_interrupted")
        try:
            output = await gateway.InferenceProvider(config).complete(prompt)
            raw = output.content
        except OperatorProviderError as exc:
            raise gateway.GatewayError(exc.args[0]) from None
    try:
        result = analysis.validate_output(raw, task["language"], evidence)
    except analysis.AnalysisError:
        raise gateway.GatewayError("operator_invalid_model_output") from None
    principal = await run_in_threadpool(gateway.authorize_actor, settings, task)
    # Revalidate every disclosed observation, even when the model abstains.
    for item in evidence["items"]:
        current = await run_in_threadpool(retrieval.get_citation, settings, principal,
                                         item["source_id"], item["snapshot_id"], item["source_hash"])
        if current is None or current["document_hash"] != item["document_hash"]:
            raise gateway.GatewayError("operator_source_changed")
    # Missing evidence still requires a current eligible publication.
    await run_in_threadpool(gateway.read_evidence, settings, principal, task["run_id"])
    return {"schema_version": "1", "analysis": result, "quality_status": "quality_unverified",
            "retrieval_state": evidence["state"], "semantic_status": "unsupported",
            "audit": {**(attempt or {"prompt_version": analysis.PROMPT_VERSION,
                                     "tool_version": TOOL_VERSION, "source_references": []}),
                      "inference_performed": attempt is not None,
                      "output_hash": hashlib.sha256(raw.encode()).hexdigest()}}
