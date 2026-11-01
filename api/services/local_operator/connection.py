"""Connection test and model discovery for any configured inference endpoint.

Works for the pinned local runtime, an arbitrary OpenAI-compatible server on a
private address and a hosted provider alike: it asks ``/models`` (and, only
when asked, one tiny completion) through the same bounded, egress-checked
provider the worker uses. Nothing an upstream wrote is returned except
sanitized model identifiers.
"""

from __future__ import annotations

import dataclasses
from time import monotonic

from .config import OperatorConfig, OperatorConfigurationError
from .providers import InferenceProvider, OperatorProviderError

#: Codes that mean the request never reached a server that answered.
_UNREACHED = {"operator_transport_failed", "operator_endpoint_not_public", "invalid_operator_base_url"}
PING = [{"role": "user", "content": "Reply with the single word OK."}]


async def check(config: OperatorConfig, *, transport=None, resolver=None, completion: bool = False) -> dict:
    started = monotonic()
    provider = InferenceProvider(config, transport=transport, resolver=resolver)
    error = None
    models = []
    try:
        models = await provider.list_models()
    except OperatorProviderError as exc:
        error = exc.args[0]
    listed = None
    if error is None:
        listed = any(model.id == config.model for model in models)
        if not listed:
            error = "operator_model_not_listed"
    completion_state = "not_checked"
    if completion and error not in _UNREACHED and error != "operator_upstream_unauthorized":
        try:
            probe_config = dataclasses.replace(config, enabled=True, max_output_tokens=min(config.max_output_tokens, 64))
            await InferenceProvider(probe_config, transport=transport, resolver=resolver).complete(PING)
            completion_state = "ok"
        except (OperatorProviderError, OperatorConfigurationError) as exc:
            completion_state = exc.args[0]
    if error == "operator_models_unsupported" and completion_state == "ok":
        # Discovery is optional in the OpenAI-compatible surface; a completion is the proof.
        error = None
    # Completion failures also carry reachability/authentication evidence.
    failure = completion_state if completion_state not in ("not_checked", "ok") else error
    ok = error is None and completion_state in ("not_checked", "ok")
    return {
        "ok": ok,
        "error": error if error is not None else (None if ok else completion_state),
        "reachable": failure not in _UNREACHED,
        "authenticated": None if failure in _UNREACHED else failure != "operator_upstream_unauthorized",
        "provider": config.provider,
        "model": config.model,
        "model_listed": listed,
        "models": [dataclasses.asdict(model) for model in models],
        "completion": completion_state,
        "latency_ms": int((monotonic() - started) * 1000),
    }
