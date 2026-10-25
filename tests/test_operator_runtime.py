"""Readiness is live health plus a pinned startup record, never model self-attestation."""
import hashlib
import json
from datetime import UTC, datetime
from types import SimpleNamespace

import httpx
import pytest

from api.services.local_operator.runtime import probe


@pytest.fixture
def configured(tmp_path):
    manifest = {"schema_version": 1, "profile": "mac-arm64-cpu",
        "model": "Qwen3.5-9B-Q4_K_M", "model_sha256": "a" * 64,
        "runtime_revision": "b" * 40,
        "runtime_image": "ghcr.io/ggml-org/llama.cpp:server@sha256:" + "c" * 64,
        "context_tokens": 8192, "parallel": 1, "verified_at": datetime.now(UTC).isoformat()}
    raw = json.dumps(manifest).encode()
    path = tmp_path / "startup.json"
    path.write_bytes(raw)
    settings = SimpleNamespace(operator_enabled=True, operator_provider="local",
        operator_model=manifest["model"], operator_base_url="http://127.0.0.1:8082/v1",
        operator_runtime_manifest_path=path,
        operator_runtime_manifest_sha256=hashlib.sha256(raw).hexdigest(),
        operator_embeddings_enabled=False)
    return settings, manifest


def transport(handler=None):
    def default(request):
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(200, json={"data": [{"id": "Qwen3.5-9B-Q4_K_M", "meta": {"n_ctx": 8192}}]})
    return httpx.MockTransport(handler or default)


def test_no_manifest_does_not_probe_any_network():
    def forbidden(_request):
        pytest.fail("No configured trust record")
    assert probe(SimpleNamespace(), transport=transport(forbidden))["runtime_status"] == "not_checked"


def test_ready_binds_live_model_and_verified_startup(configured):
    settings, manifest = configured
    result = probe(settings, transport=transport())
    assert result["runtime_status"] == "ready"
    assert result["runtime_verified"]
    assert result["model_integrity"] == "verified_at_startup"
    assert result["model_sha256"] == manifest["model_sha256"]
    assert str(settings.operator_runtime_manifest_path) not in json.dumps(result)


@pytest.mark.parametrize("change", ["hash", "content", "symlink"])
def test_untrusted_manifest_never_reaches_provider(configured, tmp_path, change):
    settings, manifest = configured
    if change == "hash":
        settings.operator_runtime_manifest_sha256 = "0" * 64
    elif change == "content":
        settings.operator_runtime_manifest_path.write_text("{}")
    else:
        target = tmp_path / "link.json"
        target.symlink_to(settings.operator_runtime_manifest_path)
        settings.operator_runtime_manifest_path = target
    def forbidden(_request):
        pytest.fail("Untrusted startup record")
    result = probe(settings, transport=transport(forbidden))
    assert result["runtime_status"] == "unavailable"
    assert result["model_integrity"] == "not_checked"


@pytest.mark.parametrize("mode", ["redirect", "failure", "model", "context", "oversize"])
def test_live_health_or_model_mismatch_is_not_ready(configured, mode):
    settings, _ = configured
    def handler(request):
        if mode == "redirect":
            return httpx.Response(302, headers={"Location": "https://private.invalid/secret"})
        if mode == "failure":
            return httpx.Response(503, text="secret-upstream")
        if mode == "oversize":
            return httpx.Response(200, content=b"x" * 65537)
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(200, json={"data": [{"id": "foreign" if mode == "model" else settings.operator_model,
                                                   "meta": {"n_ctx": 4096 if mode == "context" else 8192}}]})
    result = probe(settings, transport=transport(handler))
    assert result["runtime_status"] == "unavailable"
    assert "secret" not in json.dumps(result)


@pytest.mark.parametrize("path,body", [("/health", []), ("/v1/models", []),
    ("/v1/models", {"data": None}), ("/v1/models", {"data": [None]}),
    ("/v1/models", {"data": [{"id": "Qwen3.5-9B-Q4_K_M", "meta": None}]})])
def test_malformed_live_document_is_sanitized_unavailable(configured, path, body):
    settings, _ = configured
    def handler(request):
        if request.url.path == path:
            return httpx.Response(200, json=body)
        return httpx.Response(200, json={"status": "ok"})
    assert probe(settings, transport=transport(handler))["runtime_status"] == "unavailable"
