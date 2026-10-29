import asyncio
import json

import httpx
import pytest

from api.services.local_operator.config import OperatorConfig
from api.services.local_operator.providers import InferenceProvider, OperatorProviderError


def complete(config=None, handler=None, messages=None, *, response_schema=None):
    provider = InferenceProvider(config or OperatorConfig(enabled=True), transport=httpx.MockTransport(handler or (lambda _: httpx.Response(200, json={"choices": [{"message": {"content": "bounded answer"}}]}))))
    return asyncio.run(provider.complete(messages if messages is not None else [{"role": "user", "content": "question"}], response_schema=response_schema))


@pytest.mark.parametrize("provider,base", [("local", "http://127.0.0.1:8080/v1"), ("openrouter", "https://openrouter.ai/api/v1"), ("omnirouter", "https://router.example/v1")])
def test_explicit_schema_requests_strict_json_without_changing_contract(provider, base):
    schema = {"type": "object", "additionalProperties": False, "properties": {"result": {"type": "string"}}, "required": ["result"]}
    requests = []
    def handler(request):
        requests.append(request)
        payload = json.loads(request.content)
        assert payload["response_format"] == {"type": "json_schema", "json_schema": {
            "name": "operator_response", "strict": True, "schema": schema}}
        assert "tools" not in payload and payload["stream"] is False
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": '{"result":"bounded"}'}}]})
    config = OperatorConfig(enabled=True, provider=provider, base_url=base, model="test/model", api_key="private-key", allow_external=provider != "local")
    assert complete(config, handler, response_schema=schema).content == '{"result":"bounded"}'
    assert len(requests) == 1
    assert schema["properties"]["result"] == {"type": "string"}


@pytest.mark.parametrize("schema", [[], {}, {"type": "array"}, {"type": "object", "enum": {1, 2}}, {"type": "object", "minimum": float("nan")}, {"type": "object", "$ref": "https://untrusted.example/schema"}, {"type": "object", "$ref": 1}, {"type": "object", 1: "not-a-json-key"}])
def test_invalid_schema_never_opens_transport(schema):
    with pytest.raises(OperatorProviderError, match="^invalid_operator_response_schema$"):
        complete(handler=lambda _: pytest.fail("invalid schema reached transport"), response_schema=schema)


@pytest.mark.parametrize("schema", [
    {"type": "object", "title": "x" * 65537},
    {"type": "object", "title": "界" * 24000},
    {"type": "object", "enum": [True] * 17000},
])
def test_schema_byte_and_node_limits_precede_transport(schema):
    with pytest.raises(OperatorProviderError, match="^operator_response_schema_too_large$"):
        complete(handler=lambda _: pytest.fail("oversized schema reached transport"), response_schema=schema)


def test_schema_depth_is_bounded_before_transport():
    schema = {"type": "object"}
    nested = schema
    for _ in range(40):
        nested["properties"] = {"nested": {"type": "object"}}
        nested = nested["properties"]["nested"]
    with pytest.raises(OperatorProviderError, match="^operator_response_schema_too_large$"):
        complete(handler=lambda _: pytest.fail("deep schema reached transport"), response_schema=schema)


def test_schema_rejected_by_upstream_is_not_retried_as_unconstrained_output():
    requests = []
    def handler(request):
        requests.append(request)
        assert "response_format" in json.loads(request.content)
        return httpx.Response(400, text="private-key schema unsupported")
    with pytest.raises(OperatorProviderError, match="^operator_upstream_rejected$"):
        complete(handler=handler, response_schema={"type": "object"})
    assert len(requests) == 1


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


def _hosted(provider="openai_compatible", base="https://llm.example.com/v1"):
    return OperatorConfig(enabled=True, provider=provider, base_url=base, model="m", api_key="k", allow_external=True)


def _ok(_):
    return httpx.Response(200, json={"choices": [{"message": {"content": "bounded answer"}}]})


def _run(config, resolver, handler=_ok):
    provider = InferenceProvider(config, transport=httpx.MockTransport(handler), resolver=resolver)
    return asyncio.run(provider.complete([{"role": "user", "content": "q"}]))


@pytest.mark.parametrize("addresses", [["10.0.0.7"], ["93.184.216.34", "169.254.169.254"], ["::1"], ["::ffff:127.0.0.1"], ["not-an-ip"]])
def test_hosted_name_resolving_to_private_space_never_opens_transport(addresses):
    async def resolver(host, port):
        assert (host, port) == ("llm.example.com", 443)
        return addresses
    with pytest.raises(OperatorProviderError, match="^operator_endpoint_not_public$"):
        _run(_hosted(), resolver, lambda _: pytest.fail("private resolution reached transport"))


def test_hosted_public_resolution_proceeds_and_port_is_honoured():
    seen = []
    async def resolver(host, port):
        seen.append((host, port))
        return ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]
    assert _run(_hosted(base="https://llm.example.com:8443/v1"), resolver).content == "bounded answer"
    assert seen == [("llm.example.com", 8443)]


@pytest.mark.parametrize("failure", [[], OSError("no such host")])
def test_hosted_resolution_failure_is_sanitized_transport_failure(failure):
    async def resolver(host, port):
        if isinstance(failure, Exception):
            raise failure
        return failure
    with pytest.raises(OperatorProviderError, match="^operator_transport_failed$"):
        _run(_hosted(), resolver, lambda _: pytest.fail("unresolved name reached transport"))


def test_local_provider_skips_resolution():
    async def resolver(host, port):
        pytest.fail("local endpoint is an IP literal and is not resolved")
    assert _run(OperatorConfig(enabled=True), resolver).content == "bounded answer"


def test_default_provider_guards_hosted_endpoints_with_system_resolver():
    from api.services.local_operator import providers
    assert InferenceProvider(_hosted())._resolver is providers._system_resolver
