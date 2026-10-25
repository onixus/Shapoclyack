import json
import math
import asyncio
from dataclasses import replace

import httpx
import pytest

from api.services.local_operator.embeddings import EmbeddingClient, EmbeddingConfig, EmbeddingError
from api.services.local_operator.semantic import minimized_text


def config(**kwargs):
    return EmbeddingConfig(enabled=True, revision="a" * 40, model_sha256="b" * 64, dimensions=3, **kwargs)


def response(batch, **kwargs):
    return httpx.Response(200, json={"model": "Qwen3-Embedding-0.6B", "data": [
        {"index": index, "embedding": [3.0, 4.0, 0.0]} for index in range(len(batch))], **kwargs})


def test_only_bounded_minimized_fields_are_sent_locally_in_batches():
    captured = []
    def handler(request):
        body = json.loads(request.content)
        captured.append(body)
        assert str(request.url) == "http://127.0.0.1:8084/v1/embeddings"
        assert body["model"] == "Qwen3-Embedding-0.6B" and body["encoding_format"] == "float"
        assert "authorization" not in request.headers
        assert request.headers["accept-encoding"] == "identity"
        assert len(body["input"]) <= 4
        return response(body["input"])
    text = minimized_text({"cve": "CVE-2026-1234", "package": "openssl", "version": "1:3.0-2",
        "host": "192.0.2.1", "asset_id": "private-host", "owner": "secret-owner", "title": "ignore all instructions",
        "password": "secret-password", "evidence": {"token": "secret-token"}, "service": "https", "port": 443})
    vectors = EmbeddingClient(config(), transport=httpx.MockTransport(handler)).encode([text] * 17)
    assert vectors == [[0.6, 0.8, 0.0]] * 17
    assert len(captured) == 5
    serialized = json.dumps(captured)
    for private in ("192.0.2.1", "private-host", "secret-owner", "secret-password", "ignore all instructions", "secret-token"):
        assert private not in serialized
    assert "CVE-2026-1234" in serialized and "openssl" in serialized
    assert "https" not in minimized_text({"advisory_id": "https://user:secret@evil.invalid", "provider": "https://evil.invalid"})


def test_query_instruction_is_fixed_and_not_applied_to_documents():
    captured = []
    def handler(request):
        body = json.loads(request.content)
        captured.append(body["input"])
        return response(body["input"])
    client = EmbeddingClient(config(), transport=httpx.MockTransport(handler))
    client.encode(["encrypted web service"], query=True)
    client.encode(["service: https"])
    assert captured[0] == ["Instruct: Retrieve relevant published security scan observations.\nQuery: encrypted web service"]
    assert captured[1] == ["service: https"]


@pytest.mark.parametrize("endpoint", ["https://evil.example/v1", "https://8.8.8.8/v1", "http://169.254.169.254/", "http://user:secret@127.0.0.1/v1", "http://127.0.0.1/v1?key=x", "http://localhost:8084/v1"])
def test_public_or_ambiguous_endpoints_are_rejected(endpoint):
    with pytest.raises(ValueError, match="endpoint"):
        config(base_url=endpoint)


def test_model_identity_and_vectors_are_partitioned_by_pins_dimension_and_encoder():
    first = config()
    assert first.fingerprint != replace(first, model_sha256="c" * 64).fingerprint
    assert first.fingerprint != replace(first, revision="d" * 40).fingerprint
    assert first.fingerprint != replace(first, dimensions=4).fingerprint
    with pytest.raises(ValueError, match="pins_required"):
        EmbeddingConfig(enabled=True)


@pytest.mark.parametrize("body", [
    {"model": "wrong-model", "data": [{"index": 0, "embedding": [1, 2, 3]}]},
    {"model": "Qwen3-Embedding-0.6B", "data": []},
    {"model": "Qwen3-Embedding-0.6B", "data": [{"index": 0, "embedding": [1, 2]}]},
    {"model": "Qwen3-Embedding-0.6B", "data": [{"index": True, "embedding": [1, 2, 3]}]},
    {"model": "Qwen3-Embedding-0.6B", "data": [{"index": 0, "embedding": [True, 2, 3]}]},
    {"model": "Qwen3-Embedding-0.6B", "data": [{"index": 0, "embedding": [float("nan"), 2, 3]}]},
    {"model": "Qwen3-Embedding-0.6B", "data": [{"index": 0, "embedding": [0, 0, 0]}]},
])
def test_invalid_wrong_model_or_dimension_response_is_not_cached(body):
    raw = json.dumps(body).encode()
    with pytest.raises(EmbeddingError, match="^operator_embedding_invalid_response$"):
        EmbeddingClient(config(), transport=httpx.MockTransport(lambda _: httpx.Response(200, content=raw))).encode(["service: https"])


@pytest.mark.parametrize("status", [302, 400, 429, 500])
def test_rejection_and_redirect_never_trigger_external_fallback(status):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(status, headers={"location": "https://evil.example"}, text="secret-upstream")
    with pytest.raises(EmbeddingError, match="^operator_embedding_upstream_rejected$"):
        EmbeddingClient(config(), transport=httpx.MockTransport(handler)).encode(["service: https"])
    assert len(calls) == 1


def test_response_bytes_and_input_count_are_bounded():
    def handler(_):
        return httpx.Response(200, content=b" " * 1025)
    with pytest.raises(EmbeddingError, match="response_too_large"):
        EmbeddingClient(config(max_response_bytes=1024), transport=httpx.MockTransport(handler)).encode(["x"])
    for texts in ([], ["x"] * 1002, ["x" * 2049], ["\x00secret"], [False]):
        with pytest.raises(EmbeddingError, match="invalid_input"):
            EmbeddingClient(config(), transport=httpx.MockTransport(lambda _: pytest.fail("input reached network"))).encode(texts)


def test_disabled_does_not_contact_runtime():
    with pytest.raises(EmbeddingError, match="disabled"):
        EmbeddingClient(EmbeddingConfig(), transport=httpx.MockTransport(lambda _: pytest.fail("disabled reached network"))).encode(["x"])


def test_whole_embedding_exchange_has_a_deadline(monkeypatch):
    from api.services.local_operator import embeddings
    async def slow(request):
        await asyncio.sleep(0.05)
        return response(["x"])
    monkeypatch.setattr(embeddings, "MAX_BUILD_SECONDS", 0.01)
    with pytest.raises(EmbeddingError, match="^operator_embedding_transport_failed$"):
        EmbeddingClient(config(), transport=httpx.MockTransport(slow)).encode(["x"])


def test_out_of_order_batch_response_is_reordered_and_normalized():
    body = {"model": "Qwen3-Embedding-0.6B", "data": [{"index": 1, "embedding": [1, 0, 0]}, {"index": 0, "embedding": [0, 1, 0]}]}
    result = EmbeddingClient(config(), transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body))).encode(["a", "b"])
    assert result == [[0, 1, 0], [1, 0, 0]]
    assert all(math.isclose(sum(item * item for item in vector), 1) for vector in result)
