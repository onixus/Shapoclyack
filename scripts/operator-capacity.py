#!/usr/bin/env python3
"""Measure the real 8192-token local runtime capacity; separate from quality.

8064 tokenizer-generated input IDs plus 128 forced output tokens exercise the
full budget. Native SSE provides actual first-token latency and final counters.
No model call is retried and no profile or threshold is silently reduced.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import sys
from time import monotonic

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from api.services.local_operator.config import OperatorConfig  # noqa: E402

INPUT_TOKENS = 8064
OUTPUT_TOKENS = 128
MODEL_SHA256 = "03b74727a860a56338e042c4420bb3f04b2fec5734175f4cb9fa853daf52b7e8"
RUNTIME_IMAGE_SHA256 = "sha256:20c4196fc08b459a34ef78aaa05b101333b2fac687e30ec99f37b3c9dc071b44"
TOKENIZER_TEXT = "Synthetic tenant-local scan observation. No action, installation or external access is authorized. "
UPSTREAM_CONTRACT = "https://github.com/ggml-org/llama.cpp/blob/8e5a58df87ab59dfceb5b961ae26691e39f30c24/tools/server/README.md"


def sha(value):
    return hashlib.sha256(value).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def completion_payload(base_tokens):
    if not isinstance(base_tokens, list) or not base_tokens or any(type(token) is not int or token < 0 for token in base_tokens):
        raise ValueError("capacity_invalid_tokenizer_output")
    tokens = (base_tokens * ((INPUT_TOKENS + len(base_tokens) - 1) // len(base_tokens)))[:INPUT_TOKENS]
    return {"prompt": tokens, "n_predict": OUTPUT_TOKENS, "temperature": 0, "seed": 42,
            "cache_prompt": False, "n_keep": -1, "ignore_eos": True, "stream": True,
            "return_tokens": True, "return_progress": True, "timings_per_token": True}


def verified_profile(provenance):
    if provenance.get("model_sha256") != MODEL_SHA256:
        return False
    runtime = provenance.get("runtime")
    command = runtime.get("command", []) if isinstance(runtime, dict) else provenance.get("containers", {}).get("inference", {}).get("arguments", [])
    for flag, expected in (("--ctx-size", "8192"), ("--parallel", "1"), ("--temp", "0"), ("--seed", "42")):
        if flag not in command or command.index(flag) + 1 >= len(command) or command[command.index(flag) + 1] != expected:
            return False
    return True


def pinned_boundary_semantics(provenance):
    runtime = provenance.get("runtime")
    image = runtime.get("image_id") if isinstance(runtime, dict) else provenance.get("containers", {}).get("inference", {}).get("image_id")
    return image == RUNTIME_IMAGE_SHA256


def validate_completion(final, generated_tokens, *, profile_verified, boundary_semantics_verified=False):
    timings = final.get("timings") or {}
    processed_full = timings.get("prompt_n") == INPUT_TOKENS and timings.get("cache_n") == 0
    # The final sampled token need not be fed back for another prediction.
    # Thus intact cache after 128 outputs is 8064 + 127 = 8191. In the pinned
    # runtime, process_token's >=n_ctx guard marks this boundary truncated
    # BEFORE checking the already exhausted n_predict budget. That flag alone
    # does not establish token loss. Require independently counted full input,
    # all streamed output and the intact cache, rather than ignoring the flag.
    intact_cache = final.get("tokens_cached") == INPUT_TOKENS + OUTPUT_TOKENS - 1
    native_flag = final.get("truncated")
    no_loss = processed_full and intact_cache and (
        native_flag is False or native_flag is True and boundary_semantics_verified)
    checks = {"profile_verified": profile_verified, "input_tokens_exact": final.get("tokens_evaluated") == INPUT_TOKENS,
              "runtime_context_8192": profile_verified,
              "all_input_tokens_really_processed": processed_full,
              "intact_context_cache_8191": intact_cache,
              "output_tokens_exact": final.get("tokens_predicted") == OUTPUT_TOKENS,
              "observed_output_tokens_exact": len(generated_tokens) == OUTPUT_TOKENS,
              "no_context_loss_or_shift": no_loss,
              "prediction_budget_reached": final.get("stop_type") == "limit",
              "model_alias_matches": final.get("model") == "Qwen3.5-9B-Q4_K_M"}
    return checks


def generated_event_tokens(value):
    # The pinned server populates a dummy token in prompt-progress frames.
    # Only a positive native decode counter without prompt progress proves a
    # generated token; token ID zero itself remains a legitimate model token.
    if "prompt_progress" in value or not isinstance(value.get("tokens_predicted"), int) or value["tokens_predicted"] <= 0:
        return []
    return value.get("tokens", [])


def recompute(recorded, output):
    """Interpret an existing raw stream again, without another model request."""
    recorded, output = Path(recorded), Path(output)
    output.mkdir(parents=True, exist_ok=False)
    original = json.loads((recorded / "report.json").read_text())
    provenance = json.loads((recorded / "provenance.json").read_text())
    payload = json.loads((recorded / "request.json").read_text())
    final = json.loads((recorded / "completion.json").read_text())
    generated, first_token = [], None
    for line in (recorded / "events.jsonl").read_text().splitlines():
        event = json.loads(line)
        tokens = generated_event_tokens(event["event"])
        if tokens:
            if first_token is None:
                first_token = event["elapsed_seconds"]
            generated.extend(tokens)
    checks = validate_completion(final, generated, profile_verified=verified_profile(provenance),
                                 boundary_semantics_verified=pinned_boundary_semantics(provenance))
    checks["recorded_request_budget_exact"] = len(payload.get("prompt", [])) == INPUT_TOKENS and payload.get("n_predict") == OUTPUT_TOKENS
    report = {**original, "checks": checks, "capacity_gate_passed": all(checks.values()),
              "true_first_token_seconds": first_token, "stream_output_tokens": len(generated),
              "native_truncated": final.get("truncated"),
              "native_context_status": "capacity_boundary_stop" if final.get("truncated") is True and all(checks.values())
                  else "no_boundary_flag" if final.get("truncated") is False else "truncation_or_incomplete_result",
              "raw_event_interpretation_corrected": True, "additional_model_calls": 0,
              "correction_reason": "Ignore dummy progress tokens; interpret pinned native boundary flag using actual processed/streamed/cache counters",
              "boundary_semantics_source": "https://github.com/ggml-org/llama.cpp/blob/8e5a58df87ab59dfceb5b961ae26691e39f30c24/tools/server/server-context.cpp#L2142",
              "processed_counter_source": "https://github.com/ggml-org/llama.cpp/blob/8e5a58df87ab59dfceb5b961ae26691e39f30c24/tools/server/server-common.cpp#L139",
              "producer_source_sha256": original["source_sha256"],
              "analysis_source_sha256": sha(Path(__file__).read_bytes()),
              "original_report_sha256": sha((recorded / "report.json").read_bytes()),
              "original_events_sha256": sha((recorded / "events.jsonl").read_bytes()),
              "original_report_preserved": True}
    save(output / "report.json", report)
    return report


async def capacity(base_url, output, provenance, *, timeout_seconds=1200, transport=None):
    base_url = OperatorConfig(enabled=True, base_url=base_url).base_url.rstrip("/")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    save(output / "provenance.json", provenance)
    report = {"stage": "capacity", "started_at": datetime.now(UTC).isoformat(),
              "source_sha256": sha(Path(__file__).read_bytes()), "upstream_contract": UPSTREAM_CONTRACT,
              "input_budget_tokens": INPUT_TOKENS, "output_budget_tokens": OUTPUT_TOKENS,
              "total_budget_tokens": INPUT_TOKENS + OUTPUT_TOKENS, "capacity_gate_passed": False,
              "quality_or_typical_latency_acceptance_claimed": False, "oom_verified_by_this_script": False,
              "profile_verified": verified_profile(provenance), "model_calls": 0, "retries": 0}
    started = monotonic()
    final = None
    generated = []
    first_token_seconds = None
    try:
        async with asyncio.timeout(timeout_seconds), httpx.AsyncClient(
                timeout=timeout_seconds, trust_env=False, follow_redirects=False, transport=transport) as client:
            tokenizer_request = {"content": TOKENIZER_TEXT, "add_special": False, "parse_special": False}
            response = await client.post(base_url + "/tokenize", json=tokenizer_request)
            if response.status_code != 200:
                raise ValueError("capacity_tokenizer_failed")
            if len(response.content) > 65536:
                raise ValueError("capacity_tokenizer_response_too_large")
            tokenizer = response.json()
            save(output / "tokenizer.json", {"request": tokenizer_request, "response": tokenizer})
            payload = completion_payload(tokenizer.get("tokens"))
            save(output / "request.json", payload)
            report["prompt_tokens_sha256"] = sha(json.dumps(payload["prompt"], separators=(",", ":")).encode())
            report["model_calls"] = 1
            model_started = monotonic()
            last_progress = 0.0
            async with client.stream("POST", base_url + "/completion", json=payload) as response:
                report["http_status"] = response.status_code
                if response.status_code != 200:
                    raise ValueError("capacity_completion_failed")
                stream_bytes = 0
                with (output / "stream.sse").open("w") as raw, (output / "events.jsonl").open("w") as events:
                    async for line in response.aiter_lines():
                        stream_bytes += len(line.encode("utf-8")) + 1
                        if stream_bytes > 4 * 1024 * 1024:
                            raise ValueError("capacity_stream_too_large")
                        raw.write(line + "\n")
                        raw.flush()
                        if not line.startswith("data:") or line[5:].strip() == "[DONE]":
                            continue
                        value = json.loads(line[5:].strip())
                        if not isinstance(value, dict) or "error" in value:
                            raise ValueError("capacity_stream_invalid")
                        elapsed = monotonic() - model_started
                        events.write(json.dumps({"elapsed_seconds": elapsed, "event": value}, ensure_ascii=False) + "\n")
                        events.flush()
                        tokens = value.get("tokens", [])
                        if not isinstance(tokens, list) or any(type(token) is not int or token < 0 for token in tokens):
                            raise ValueError("capacity_stream_tokens_invalid")
                        tokens = generated_event_tokens(value)
                        if tokens:
                            if first_token_seconds is None:
                                first_token_seconds = elapsed
                                print(f"First generated token after {elapsed:.2f}s", flush=True)
                            generated.extend(tokens)
                        if value.get("prompt_progress") and elapsed - last_progress >= 10:
                            print(json.dumps({"capacity_progress": value["prompt_progress"], "elapsed_seconds": elapsed}), flush=True)
                            last_progress = elapsed
                        if value.get("stop") is True:
                            if final is not None:
                                raise ValueError("capacity_duplicate_final_frame")
                            final = value
            if final is None:
                raise ValueError("capacity_missing_final_frame")
            save(output / "completion.json", final)
            report["checks"] = validate_completion(final, generated, profile_verified=report["profile_verified"],
                                                    boundary_semantics_verified=pinned_boundary_semantics(provenance))
            report["capacity_gate_passed"] = all(report["checks"].values())
            report["native_truncated"] = final.get("truncated")
            report["native_context_status"] = ("capacity_boundary_stop" if final.get("truncated") is True and report["capacity_gate_passed"]
                                                else "no_boundary_flag" if final.get("truncated") is False else "truncation_or_incomplete_result")
            report["observed_input_tokens"] = final.get("tokens_evaluated")
            report["observed_output_tokens"] = final.get("tokens_predicted")
            report["stream_output_tokens"] = len(generated)
            report["native_timings"] = final.get("timings")
            report["generation_settings"] = final.get("generation_settings")
    except (ValueError, httpx.HTTPError, TimeoutError) as exc:
        message = str(exc)
        report["error_type"] = type(exc).__name__
        report["error_code"] = message if message.startswith("capacity_") else "capacity_transport_failed"
    finally:
        report["elapsed_seconds"] = monotonic() - started
        report["true_first_token_seconds"] = first_token_seconds
        for filename in ("tokenizer.json", "request.json", "stream.sse", "events.jsonl", "completion.json"):
            path = output / filename
            if path.exists():
                report[filename + "_sha256"] = sha(path.read_bytes())
        save(output / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://172.30.83.2:8082")
    parser.add_argument("--output", required=True)
    parser.add_argument("--provenance-json")
    parser.add_argument("--recompute-from")
    parser.add_argument("--timeout-seconds", type=int, default=1200)
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 1800:
        raise SystemExit("Capacity deadline must be bounded to at most1800seconds")
    if args.recompute_from:
        report = recompute(args.recompute_from, args.output)
    else:
        if not args.provenance_json:
            raise SystemExit("Runtime provenance is required for a capacity measurement")
        provenance = json.loads(Path(args.provenance_json).read_text())
        report = asyncio.run(capacity(args.base_url, args.output, provenance, timeout_seconds=args.timeout_seconds))
    print(json.dumps({key: report.get(key) for key in (
        "capacity_gate_passed", "observed_input_tokens", "observed_output_tokens", "true_first_token_seconds", "elapsed_seconds", "error_code")}))
    return 0 if report["capacity_gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
