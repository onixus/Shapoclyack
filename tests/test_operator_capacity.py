"""Capacity-probe protocol tests; these do not assert a real runtime result."""
import asyncio
import importlib.util
import json
from pathlib import Path

import httpx
import pytest

SPEC = importlib.util.spec_from_file_location("operator_capacity", Path(__file__).parents[1] / "scripts/operator-capacity.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def provenance():
    return {"model_sha256": probe.MODEL_SHA256, "runtime": {"image_id": probe.RUNTIME_IMAGE_SHA256, "command": [
        "--ctx-size", "8192", "--parallel", "1", "--temp", "0", "--seed", "42"]}}


def final(**changes):
    return {"stop": True, "tokens": [], "model": "Qwen3.5-9B-Q4_K_M", "tokens_evaluated": 8064,
            "tokens_predicted": 128, "tokens_cached": 8191,
            "timings": {"prompt_n": 8064, "cache_n": 0}, "truncated": False, "stop_type": "limit", **changes}


def test_token_ids_fill_exact_budget_without_padding_eos_or_hidden_bos():
    payload = probe.completion_payload([10, 11, 12])
    assert len(payload["prompt"]) == 8064
    assert payload["prompt"][:6] == [10, 11, 12, 10, 11, 12]
    assert len(payload["prompt"]) + payload["n_predict"] == 8192
    assert payload["cache_prompt"] is False and payload["ignore_eos"] is True


@pytest.mark.parametrize("tokens", [[], None, [True], [-1], ["BOS"]])
def test_invalid_tokenizer_output_cannot_become_fake_capacity(tokens):
    with pytest.raises(ValueError):
        probe.completion_payload(tokens)


@pytest.mark.parametrize("changes", [
    {"tokens_evaluated": 8063}, {"tokens_predicted": 127}, {"truncated": True},
    {"stop_type": "eos"}, {"model": "different-model"},
])
def test_reduced_budget_truncation_or_early_stop_fails(changes):
    assert not all(probe.validate_completion(final(**changes), [1] * 128, profile_verified=True).values())


def test_missing_observed_output_or_profile_cannot_pass():
    assert not all(probe.validate_completion(final(), [1] * 127, profile_verified=True).values())
    assert not all(probe.validate_completion(final(), [1] * 128, profile_verified=False).values())
    changed = provenance()
    changed["model_sha256"] = "f" * 64
    assert not probe.verified_profile(changed)


def test_pinned_boundary_flag_passes_only_with_every_independent_counter():
    checks = probe.validate_completion(final(truncated=True), [1] * 128,
        profile_verified=True, boundary_semantics_verified=True)
    assert all(checks.values())
    assert not all(probe.validate_completion(final(truncated=True), [1] * 128,
        profile_verified=True, boundary_semantics_verified=False).values())


@pytest.mark.parametrize("changes", [
    {"timings": {"prompt_n": 8063, "cache_n": 0}},
    {"timings": {"prompt_n": 8064, "cache_n": 1}},
    {"tokens_cached": 8128}, {"tokens_predicted": 127},
])
def test_real_input_loss_context_shift_or_short_output_still_fails(changes):
    assert not all(probe.validate_completion(final(truncated=True, **changes), [1] * 128,
        profile_verified=True, boundary_semantics_verified=True).values())


def test_actual_native_stream_protocol_and_final_counters(tmp_path):
    calls = []

    def handler(request):
        calls.append(request.url.path)
        if request.url.path == "/tokenize":
            assert json.loads(request.content)["add_special"] is False
            return httpx.Response(200, json={"tokens": [10, 11, 12]})
        payload = json.loads(request.content)
        assert len(payload["prompt"]) == 8064 and payload["n_predict"] == 128
        frames = [{"content": "", "tokens": [0], "tokens_predicted": 0, "stop": False, "prompt_progress": {"total": 8064, "processed": 4096}},
                  {"content": "synthetic", "tokens": [7] * 128, "tokens_predicted": 128, "stop": False}, final()]
        stream = "".join("data: " + json.dumps(frame) + "\n\n" for frame in frames)
        return httpx.Response(200, text=stream, headers={"content-type": "text/event-stream"})

    report = asyncio.run(probe.capacity("http://127.0.0.1:8082", tmp_path / "probe", provenance(),
                                       transport=httpx.MockTransport(handler)))
    assert report["capacity_gate_passed"]
    assert report["observed_input_tokens"] == 8064 and report["observed_output_tokens"] == 128
    assert report["true_first_token_seconds"] is not None
    assert calls == ["/tokenize", "/completion"] and report["retries"] == 0


def test_progress_placeholder_is_not_a_generated_token_or_ttft():
    assert probe.generated_event_tokens({"tokens": [0], "tokens_predicted": 0, "prompt_progress": {}}) == []
    assert probe.generated_event_tokens({"tokens": [0], "tokens_predicted": 1}) == [0]


def test_incomplete_stream_retains_failure_without_retry(tmp_path):
    calls = []

    def handler(request):
        calls.append(request.url.path)
        if request.url.path == "/tokenize":
            return httpx.Response(200, json={"tokens": [10]})
        return httpx.Response(200, text='data: {"tokens":[7],"stop":false}\n\n')

    report = asyncio.run(probe.capacity("http://127.0.0.1:8082", tmp_path / "incomplete", provenance(),
                                       transport=httpx.MockTransport(handler)))
    assert not report["capacity_gate_passed"]
    assert report["error_code"] == "capacity_missing_final_frame"
    assert calls == ["/tokenize", "/completion"]
    assert (tmp_path / "incomplete" / "stream.sse").exists()
