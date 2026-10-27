"""Pinned local CPU-embedding transport; no downloads, proxies or fallback.

The runtime and its CPU-only placement are deployment-owned. This client binds
stored vectors to the configured model artifact, revision, dimension and text
encoder version. An HTTP response alone cannot attest the deployed weights.
"""
from __future__ import annotations

import hashlib
import asyncio
import ipaddress
import json
import math
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

ENCODER_VERSION = "minimized-security-observations-v1"
MAX_BATCH = 4
MAX_TEXT_CHARS = 2048
MAX_TEXTS = 1001
MAX_BUILD_SECONDS = 60.0


class EmbeddingError(RuntimeError):
    """Stable, data-free error at the local inference boundary."""


@dataclass(frozen=True)
class EmbeddingConfig:
    enabled: bool = False
    base_url: str = "http://127.0.0.1:8084/v1"
    model: str = "Qwen3-Embedding-0.6B"
    revision: str = ""
    model_sha256: str = ""
    dimensions: int = 1024
    timeout_seconds: float = 30.0
    max_response_bytes: int = 2097152

    def __post_init__(self):
        if type(self.enabled) is not bool:
            raise ValueError("invalid_operator_embedding_config")
        if not self.base_url:
            object.__setattr__(self, "base_url", "http://127.0.0.1:8084/v1")
        try:
            url = urlsplit(self.base_url)
            address = ipaddress.ip_address(url.hostname)
            private = any(address in ipaddress.ip_network(network) for network in (
                "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"))
            valid = (private and url.scheme in {"http", "https"} and url.port != 0
                     and not url.username and not url.password and not url.query and not url.fragment)
        except (ValueError, TypeError, AttributeError):
            valid = False
        if not valid:
            raise ValueError("invalid_operator_embedding_endpoint")
        if self.model != "Qwen3-Embedding-0.6B":
            raise ValueError("invalid_operator_embedding_model")
        if self.enabled and (not isinstance(self.revision, str) or not re.fullmatch(r"[a-f0-9]{40}", self.revision)
                             or not isinstance(self.model_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", self.model_sha256)):
            raise ValueError("operator_embedding_pins_required")
        if type(self.dimensions) is not int or not 1 <= self.dimensions <= 4096:
            raise ValueError("invalid_operator_embedding_dimensions")
        if (isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float))
                or not math.isfinite(self.timeout_seconds) or not 0 < self.timeout_seconds <= 60):
            raise ValueError("invalid_operator_embedding_timeout")
        if type(self.max_response_bytes) is not int or not 1024 <= self.max_response_bytes <= 8388608:
            raise ValueError("invalid_operator_embedding_response_limit")

    @classmethod
    def from_settings(cls, settings):
        defaults = cls()
        return cls(**{name: getattr(settings, "operator_embeddings_" + name, getattr(defaults, name))
                      for name in cls.__dataclass_fields__})

    @property
    def fingerprint(self):
        return hashlib.sha256(json.dumps({"model": self.model, "revision": self.revision,
            "model_sha256": self.model_sha256, "dimensions": self.dimensions,
            "encoder_version": ENCODER_VERSION}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def normalized_vector(value, dimensions):
    if (not isinstance(value, list) or len(value) != dimensions
            or any(isinstance(number, bool) or not isinstance(number, (int, float))
                   or not math.isfinite(number) or abs(number) > 1e10 for number in value)):
        raise EmbeddingError("operator_embedding_invalid_response")
    magnitude = math.sqrt(sum(float(number) ** 2 for number in value))
    if magnitude <= 1e-12:
        raise EmbeddingError("operator_embedding_invalid_response")
    return [float(number) / magnitude for number in value]


class EmbeddingClient:
    def __init__(self, config: EmbeddingConfig, *, transport=None):
        self.config, self.transport = config, transport

    def encode(self, texts, *, query=False):
        # Retrieval services are synchronous; gateways run them in a bounded
        # thread pool. The async transport provides a true whole-build deadline,
        # including a peer that drips response bytes under the read timeout.
        return asyncio.run(self._encode(texts, query=query))

    async def _encode(self, texts, *, query=False):
        config = self.config
        if not config.enabled:
            raise EmbeddingError("operator_embeddings_disabled")
        if (not isinstance(texts, (list, tuple)) or not 1 <= len(texts) <= MAX_TEXTS
                or any(not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT_CHARS
                       or any(ord(char) < 32 and char != "\n" for char in text) for text in texts)
                or (query and len(texts) != 1)):
            raise EmbeddingError("operator_embedding_invalid_input")
        vectors = []
        try:
            async with asyncio.timeout(MAX_BUILD_SECONDS), httpx.AsyncClient(trust_env=False, follow_redirects=False, transport=self.transport) as client:
                for offset in range(0, len(texts), MAX_BATCH):
                    batch = list(texts[offset:offset + MAX_BATCH])
                    if query:
                        batch = ["Instruct: Retrieve relevant published security scan observations.\nQuery: " + batch[0]]
                    payload = {"model": config.model, "input": batch, "encoding_format": "float"}
                    raw = bytearray()
                    async with client.stream("POST", config.base_url.rstrip("/") + "/embeddings", json=payload,
                                             timeout=config.timeout_seconds,
                                             headers={"Accept": "application/json", "Accept-Encoding": "identity"}) as response:
                        if response.status_code != 200:
                            raise EmbeddingError("operator_embedding_upstream_rejected")
                        if response.headers.get("content-encoding", "identity").lower() != "identity":
                            raise EmbeddingError("operator_embedding_invalid_response")
                        async for chunk in response.aiter_bytes():
                            if len(raw) + len(chunk) > config.max_response_bytes:
                                raise EmbeddingError("operator_embedding_response_too_large")
                            raw.extend(chunk)
                    body = json.loads(raw)
                    if body.get("model") != config.model or not isinstance(body.get("data"), list) or len(body["data"]) != len(batch):
                        raise EmbeddingError("operator_embedding_invalid_response")
                    ordered = {}
                    for item in body["data"]:
                        if (not isinstance(item, dict) or type(item.get("index")) is not int
                                or item["index"] in ordered or not 0 <= item["index"] < len(batch)):
                            raise EmbeddingError("operator_embedding_invalid_response")
                        ordered[item["index"]] = normalized_vector(item.get("embedding"), config.dimensions)
                    vectors.extend(ordered[index] for index in range(len(batch)))
        except EmbeddingError:
            raise
        except (httpx.HTTPError, TimeoutError):
            raise EmbeddingError("operator_embedding_transport_failed") from None
        except (ValueError, KeyError, IndexError, TypeError, AttributeError, RecursionError):
            raise EmbeddingError("operator_embedding_invalid_response") from None
        return vectors
