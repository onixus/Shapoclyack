"""Bounded OpenAI-compatible inference, without tools or provider fallback."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Sequence

import httpx

from .config import OperatorConfig


class OperatorProviderError(RuntimeError):
    """Only stable error codes escape the transport boundary."""


@dataclass(frozen=True)
class Completion:
    content: str
    provider: str
    model: str


class InferenceProvider:
    def __init__(self, config: OperatorConfig, *, transport: httpx.AsyncBaseTransport | None = None):
        self.config = config
        self._transport = transport

    async def complete(self, messages: Sequence[dict[str, str]]) -> Completion:
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
        headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
        if config.api_key:
            headers["Authorization"] = "Bearer " + config.api_key
        payload = {"model": config.model, "messages": cleaned, "max_tokens": config.max_output_tokens, "stream": False}
        try:
            # The outer deadline bounds the complete exchange, including slow-drip bodies.
            async with asyncio.timeout(config.timeout_seconds):
                async with httpx.AsyncClient(timeout=config.timeout_seconds, trust_env=False, follow_redirects=False, transport=self._transport) as client:
                    async with client.stream("POST", config.base_url.rstrip("/") + "/chat/completions", headers=headers, json=payload) as response:
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
        except (httpx.HTTPError, TimeoutError):
            raise OperatorProviderError("operator_transport_failed") from None
        except (ValueError, KeyError, IndexError, TypeError, AttributeError, RecursionError):
            raise OperatorProviderError("operator_invalid_response") from None
