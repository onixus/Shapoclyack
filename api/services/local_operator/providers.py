"""Bounded OpenAI-compatible inference, without tools or provider fallback."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from dataclasses import dataclass
from typing import Awaitable, Callable, Iterable, Sequence
from urllib.parse import urlsplit

import httpcore
import httpx

from .config import OperatorConfig, is_public_address

Resolver = Callable[[str, int], Awaitable[Iterable[str]]]

MAX_SCHEMA_BYTES = 65536
MAX_SCHEMA_NODES = 16384


def _response_format(schema: dict) -> dict:
    """Copy a bounded service-owned schema before entering the transport.

    The schema constrains generation; the caller must still validate every
    response. In particular, this never turns model-selected references into
    authorized evidence. External schema references are not a network tool.
    """
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise OperatorProviderError("invalid_operator_response_schema")
    pending = [(schema, 0)]
    nodes = 0
    text_size = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if depth > 32 or nodes > MAX_SCHEMA_NODES:
            raise OperatorProviderError("operator_response_schema_too_large")
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise OperatorProviderError("invalid_operator_response_schema")
            text_size += sum(len(key) for key in value)
            if "$ref" in value and (not isinstance(value["$ref"], str) or not value["$ref"].startswith("#")):
                raise OperatorProviderError("invalid_operator_response_schema")
            if len(value) > MAX_SCHEMA_NODES - nodes:
                raise OperatorProviderError("operator_response_schema_too_large")
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, (list, tuple)):
            if len(value) > MAX_SCHEMA_NODES - nodes:
                raise OperatorProviderError("operator_response_schema_too_large")
            pending.extend((item, depth + 1) for item in value)
        elif isinstance(value, str):
            text_size += len(value)
        if text_size > MAX_SCHEMA_BYTES:
            raise OperatorProviderError("operator_response_schema_too_large")
    try:
        encoded = json.dumps(schema, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(encoded) > MAX_SCHEMA_BYTES:
            raise OperatorProviderError("operator_response_schema_too_large")
        copied = json.loads(encoded)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise OperatorProviderError("invalid_operator_response_schema") from None
    return {"type": "json_schema", "json_schema": {
        "name": "operator_response", "strict": True, "schema": copied,
    }}


class OperatorProviderError(RuntimeError):
    """Only stable error codes escape the transport boundary."""


@dataclass(frozen=True)
class Completion:
    content: str
    provider: str
    model: str


MAX_MODELS = 500
MAX_MODELS_BYTES = 1048576


@dataclass(frozen=True)
class ModelInfo:
    id: str
    context_tokens: int | None = None


async def _system_resolver(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


class _PinnedBackend(httpcore.AsyncNetworkBackend):
    """Dial the address that passed the public-endpoint check, not a fresh lookup.

    TLS still verifies the certificate and SNI against the URL's hostname:
    only the TCP destination is fixed, which closes DNS rebinding between the
    check and the connection.
    """

    def __init__(self, address: str, inner: httpcore.AsyncNetworkBackend):
        self._address = address
        self._inner = inner

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        return await self._inner.connect_tcp(
            self._address, port, timeout=timeout, local_address=local_address, socket_options=socket_options
        )

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise OperatorProviderError("operator_transport_failed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def _pinned_transport(address: str) -> httpx.AsyncHTTPTransport:
    transport = httpx.AsyncHTTPTransport()
    pool = getattr(transport, "_pool", None)
    inner = getattr(pool, "_network_backend", None)
    if inner is None:
        # A future httpx without this seam must fail closed, not dial unpinned.
        raise OperatorProviderError("operator_transport_failed")
    pool._network_backend = _PinnedBackend(address, inner)
    return transport


class InferenceProvider:
    def __init__(self, config: OperatorConfig, *, transport: httpx.AsyncBaseTransport | None = None,
                 resolver: Resolver | None = None):
        self.config = config
        self._transport = transport
        # An injected transport never reaches the network, so it is only
        # guarded when a resolver is injected alongside it.
        self._resolver = resolver if resolver is not None or transport is not None else _system_resolver

    async def _require_public_endpoint(self) -> str | None:
        """Refuse hosted names that resolve to private, loopback or metadata space.

        Returns the address the connection must be pinned to (``None`` when the
        endpoint is not checked), so the client cannot resolve the name again
        to something else.
        """
        if self.config.provider == "local" or self._resolver is None:
            return None
        url = urlsplit(self.config.base_url)
        addresses = list(await self._resolver(url.hostname, url.port or 443))
        if not addresses:
            raise OperatorProviderError("operator_transport_failed")
        for value in addresses:
            try:
                public = is_public_address(ipaddress.ip_address(value))
            except ValueError:
                public = False
            if not public:
                raise OperatorProviderError("operator_endpoint_not_public")
        return str(ipaddress.ip_address(addresses[0]))

    def _client(self, timeout: float, address: str | None) -> httpx.AsyncClient:
        transport = self._transport
        if transport is None and address is not None:
            transport = _pinned_transport(address)
        return httpx.AsyncClient(timeout=timeout, trust_env=False, follow_redirects=False, transport=transport)

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
        if self.config.api_key:
            headers["Authorization"] = "Bearer " + self.config.api_key
        return headers

    async def list_models(self) -> list[ModelInfo]:
        """Model discovery over ``GET {base}/models``; works before the operator is enabled.

        Only bounded, printable identifiers leave this method: never the
        upstream body, which an arbitrary endpoint controls.
        """
        config = self.config
        if not config.base_url:
            raise OperatorProviderError("invalid_operator_base_url")
        try:
            async with asyncio.timeout(min(config.timeout_seconds, 15.0)):
                address = await self._require_public_endpoint()
                async with self._client(min(config.timeout_seconds, 15.0), address) as client:
                    async with client.stream("GET", config.base_url.rstrip("/") + "/models", headers=self._headers()) as response:
                        if response.status_code in (401, 403):
                            raise OperatorProviderError("operator_upstream_unauthorized")
                        if response.status_code == 404:
                            raise OperatorProviderError("operator_models_unsupported")
                        if response.status_code != 200:
                            raise OperatorProviderError("operator_upstream_rejected")
                        if response.headers.get("content-encoding", "identity").lower() != "identity":
                            raise OperatorProviderError("operator_invalid_response")
                        data = bytearray()
                        async for chunk in response.aiter_bytes():
                            if len(data) + len(chunk) > MAX_MODELS_BYTES:
                                raise OperatorProviderError("operator_response_too_large")
                            data.extend(chunk)
            entries = json.loads(data)["data"]
            if not isinstance(entries, list):
                raise ValueError
            models: list[ModelInfo] = []
            for entry in entries[:MAX_MODELS]:
                model_id = entry.get("id") if isinstance(entry, dict) else None
                if not isinstance(model_id, str) or not 0 < len(model_id) <= 256 or any(ord(c) < 32 or ord(c) == 127 for c in model_id):
                    continue
                # OpenRouter reports context_length; llama.cpp reports meta.n_ctx.
                context = entry.get("context_length")
                if context is None and isinstance(entry.get("meta"), dict):
                    context = entry["meta"].get("n_ctx")
                models.append(ModelInfo(id=model_id, context_tokens=context if type(context) is int and 0 < context <= 10_000_000 else None))
            return models
        except OperatorProviderError:
            raise
        except (httpx.HTTPError, TimeoutError, OSError):
            raise OperatorProviderError("operator_transport_failed") from None
        except (ValueError, KeyError, IndexError, TypeError, AttributeError, RecursionError):
            raise OperatorProviderError("operator_invalid_response") from None

    async def complete(self, messages: Sequence[dict[str, str]], *, response_schema: dict | None = None) -> Completion:
        config = self.config
        if not config.enabled:
            raise OperatorProviderError("operator_disabled")
        if not isinstance(messages, (list, tuple)) or not 1 <= len(messages) <= 64:
            raise OperatorProviderError("invalid_operator_messages")
        size = 0
        cleaned = []
        for message in messages:
            if not isinstance(message, dict) or set(message) != {"role", "content"} or not isinstance(message["role"], str) or message["role"] not in {"system", "user", "assistant"} or not isinstance(message["content"], str):
                raise OperatorProviderError("invalid_operator_messages")
            size += len(message["content"])
            cleaned.append({"role": message["role"], "content": message["content"]})
        if size > config.max_input_chars:
            raise OperatorProviderError("operator_input_too_large")
        headers = self._headers()
        payload = {"model": config.model, "messages": cleaned, "max_tokens": config.max_output_tokens, "stream": False}
        if response_schema is not None:
            payload["response_format"] = _response_format(response_schema)
        try:
            # The outer deadline bounds the complete exchange, including slow-drip bodies.
            async with asyncio.timeout(config.timeout_seconds):
                address = await self._require_public_endpoint()
                async with self._client(config.timeout_seconds, address) as client:
                    async with client.stream("POST", config.base_url.rstrip("/") + "/chat/completions", headers=headers, json=payload) as response:
                        if response.status_code in (401, 403):
                            raise OperatorProviderError("operator_upstream_unauthorized")
                        if response.status_code != 200:
                            raise OperatorProviderError("operator_upstream_rejected")
                        if response.headers.get("content-encoding", "identity").lower() != "identity":
                            raise OperatorProviderError("operator_invalid_response")
                        data = bytearray()
                        async for chunk in response.aiter_bytes():
                            if len(data) + len(chunk) > config.max_response_bytes:
                                raise OperatorProviderError("operator_response_too_large")
                            data.extend(chunk)
            body = json.loads(data)
            choice = body["choices"][0]
            message = choice["message"]
            if choice.get("finish_reason") not in (None, "stop") or message.get("tool_calls") or message.get("function_call") or message.get("refusal"):
                raise OperatorProviderError("operator_incomplete_response")
            content = message["content"]
            if not isinstance(content, str) or not content.strip():
                raise ValueError
            return Completion(content=content, provider=config.provider, model=config.model)
        except OperatorProviderError:
            raise
        except (httpx.HTTPError, TimeoutError, OSError):
            raise OperatorProviderError("operator_transport_failed") from None
        except (ValueError, KeyError, IndexError, TypeError, AttributeError, RecursionError):
            raise OperatorProviderError("operator_invalid_response") from None
