import asyncio
import json

import httpx
import pytest

from api.services.local_operator.config import OperatorConfig
from api.services.local_operator.providers import InferenceProvider, OperatorProviderError


def complete(config=None, handler=None, messages=None):
    provider = InferenceProvider(config or OperatorConfig(enabled=True), transport=httpx.MockTransport(handler or (lambda _: httpx.Response(200, json={"choices": [{"message": {"content": "bounded answer"}}]}))))
    return asyncio.run(provider.complete(messages if messages is not None else [{"role": "user", "content": "question"}]))


@pytest.mark.parametrize("provider,base", [("local", "http://127.0.0.1:8080/v1"), ("openrouter", "https://openrouter.ai/api/v1"), ("omnirouter", "https://router.example/v1")])
def test_posts_bounded_chat_completion(provider, base):
    seen = []
    def handler(request):
        seen.append(request)
        assert str(request.url) == base + "/chat/completions"
        body = json.loads(request.content)
        assert body == {"model": "test/model", "messages": [{"role": "user", "content": "question"}], "max_tokens": 32, "stream": False}
        assert request.headers["authorization"] == "Bearer private-key"
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(200, json={"choices": [{"message": {"content": "answer"}}]})
    config = OperatorConfig(enabled=True, provider=provider, base_url=base, model="test/model", api_key="private-key", allow_external=provider != "local", max_output_tokens=32)
    result = complete(config, handler)
    assert (result.content, result.provider, result.model) == ("answer", provider, "test/model")
    assert len(seen) == 1


def test_disabled_never_opens_transport():
    with pytest.raises(OperatorProviderError, match="^operator_disabled$"):
        complete(OperatorConfig(), lambda _: pytest.fail("disabled made request"))


@pytest.mark.parametrize("messages", [[], [{"role": "tool", "content": "x"}], [{"role": [], "content": "x"}], [{"role": "user", "content": "x", "tools": []}], [{"role": "user", "content": 123}], [{"role": "user", "content": "x"}] * 65])
def test_invalid_messages_never_open_transport(messages):
    with pytest.raises(OperatorProviderError, match="invalid_operator_messages"):
        complete(handler=lambda _: pytest.fail("invalid input made request"), messages=messages)


def test_input_limit_never_opens_transport():
    with pytest.raises(OperatorProviderError, match="operator_input_too_large"):
        complete(OperatorConfig(enabled=True, max_input_chars=2), handler=lambda _: pytest.fail("too large input made request"))


@pytest.mark.parametrize("status", [302, 401, 429, 500])
def test_upstream_errors_and_redirects_are_sanitized_without_fallback(status):
    seen = []
    def handler(request):
        seen.append(request)
        return httpx.Response(status, headers={"location": "https://attacker.example/key"}, text="private-key upstream exception")
    with pytest.raises(OperatorProviderError, match="^operator_upstream_rejected$"):
        complete(handler=handler)
    assert len(seen) == 1


@pytest.mark.parametrize("body", [b"not-json private-key", b"{}", b'{"choices":[]}', b'{"choices":[{"message":{"content":null}}]}', b'{"choices":[{"message":{"content":""}}]}'])
def test_malformed_response_is_sanitized(body):
    with pytest.raises(OperatorProviderError, match="^operator_invalid_response$"):
        complete(handler=lambda _: httpx.Response(200, content=body))


def test_response_limit():
    with pytest.raises(OperatorProviderError, match="^operator_response_too_large$"):
        complete(OperatorConfig(enabled=True, max_response_bytes=5))


def test_transport_errors_are_sanitized():
    def handler(request):
        raise httpx.ConnectError("private-key leaked in transport", request=request)
    with pytest.raises(OperatorProviderError, match="^operator_transport_failed$"):
        complete(handler=handler)


def test_complete_exchange_has_deadline():
    async def handler(request):
        await asyncio.sleep(.05)
        return httpx.Response(200, json={})
    with pytest.raises(OperatorProviderError, match="^operator_transport_failed$"):
        complete(OperatorConfig(enabled=True, timeout_seconds=.01), handler)


def test_refuses_compressed_response():
    with pytest.raises(OperatorProviderError, match="^operator_invalid_response$"):
        complete(handler=lambda _: httpx.Response(200, headers={"content-encoding": "gzip"}, content=b""))


@pytest.mark.parametrize("finish,message_extra", [("length", {}), ("tool_calls", {}), ("content_filter", {}), ("stop", {"tool_calls": [{"id": "x"}]}), ("stop", {"function_call": {"name": "x"}}), ("stop", {"refusal": "refused"})])
def test_incomplete_tool_and_refusal_responses_are_rejected(finish, message_extra):
    body = {"choices": [{"finish_reason": finish, "message": {"content": "partial", **message_extra}}]}
    with pytest.raises(OperatorProviderError, match="^operator_incomplete_response$"):
        complete(handler=lambda _: httpx.Response(200, json=body))


@pytest.mark.parametrize("choice", [None, [], {"message": None}, {"message": []}])
def test_invalid_choice_shape_is_sanitized(choice):
    with pytest.raises(OperatorProviderError, match="^operator_invalid_response$"):
        complete(handler=lambda _: httpx.Response(200, json={"choices": [choice]}))
