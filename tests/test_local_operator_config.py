from types import SimpleNamespace

import pytest

from api.services.local_operator.config import OperatorConfig, OperatorConfigurationError


def test_defaults_are_local_and_disabled():
    config = OperatorConfig.from_settings(SimpleNamespace())
    assert config.base_url == "http://127.0.0.1:8080/v1"
    assert config.status() == {"enabled": False, "provider": "local", "model": "Qwen3.5-9B-Q4_K_M", "external": False, "runtime_verified": False}


@pytest.mark.parametrize("url", ["https://example.com/v1", "http://169.254.169.254/v1", "http://localhost/v1", "http://0.0.0.0/v1", "http://127.0.0.1/v1?x=1", "http://secret@127.0.0.1/v1", "http://127.0.0.1:0/v1", "http://[invalid/v1"])
def test_local_rejects_public_dns_metadata_and_ambiguous_urls(url):
    with pytest.raises(OperatorConfigurationError):
        OperatorConfig(base_url=url)


@pytest.mark.parametrize("url", ["http://10.0.0.2:8080/v1", "https://192.168.1.2/v1", "http://[::1]:8080/v1", "http://[fd00::1]/v1"])
def test_local_accepts_private_ip_literals(url):
    assert OperatorConfig(base_url=url).base_url == url


@pytest.mark.parametrize("allow,key", [(False, ""), (True, ""), (False, "secret")])
def test_hosted_requires_both_opt_in_and_key(allow, key):
    with pytest.raises(OperatorConfigurationError, match="hosted_operator_requires_opt_in_and_key"):
        OperatorConfig(enabled=True, provider="openrouter", allow_external=allow, api_key=key)


def test_openrouter_default_and_no_secret_in_repr_or_status():
    config = OperatorConfig(enabled=True, provider="openrouter", allow_external=True, api_key="private-key", model="vendor/model")
    assert config.base_url == "https://openrouter.ai/api/v1"
    assert "private-key" not in repr(config)
    assert "private-key" not in str(config.status())


def test_omnirouter_requires_explicit_https_base():
    with pytest.raises(OperatorConfigurationError):
        OperatorConfig(enabled=True, provider="omnirouter", allow_external=True, api_key="key")
    with pytest.raises(OperatorConfigurationError, match="requires_https"):
        OperatorConfig(provider="omnirouter", base_url="http://router.example/v1")
    config = OperatorConfig(enabled=True, provider="omnirouter", base_url="https://router.example/v1", allow_external=True, api_key="key")
    assert config.provider == "omnirouter"


@pytest.mark.parametrize("kwargs", [{"timeout_seconds": float("nan")}, {"timeout_seconds": 121}, {"max_response_bytes": 0}, {"max_input_chars": True}, {"max_output_tokens": 8193}, {"api_key": "key\r\nleak"}, {"provider": "unknown"}, {"provider": "openrouter", "base_url": "https://attacker.example/v1"}])
def test_rejects_invalid_limits_and_configuration(kwargs):
    with pytest.raises(OperatorConfigurationError):
        OperatorConfig(**kwargs)


def test_settings_field_contract():
    config = OperatorConfig.from_settings(SimpleNamespace(operator_enabled=True, operator_model="local-test", operator_max_output_tokens=200))
    assert config.enabled and config.model == "local-test" and config.max_output_tokens == 200


def test_openai_compatible_accepts_any_public_https_endpoint_with_consent():
    config = OperatorConfig(enabled=True, provider="openai_compatible", base_url="https://llm.example.com:8443/openai/v1",
                            allow_external=True, api_key="key", model="qwen/qwen3.5-9b")
    assert config.status()["external"] is True and config.status()["provider"] == "openai_compatible"
    assert OperatorConfig(provider="openai_compatible", base_url="https://8.8.8.8/v1").base_url == "https://8.8.8.8/v1"


def test_openai_compatible_needs_explicit_base_https_and_consent():
    assert OperatorConfig(provider="openai_compatible").base_url == ""
    with pytest.raises(OperatorConfigurationError, match="invalid_operator_base_url"):
        OperatorConfig(enabled=True, provider="openai_compatible", allow_external=True, api_key="key")
    with pytest.raises(OperatorConfigurationError, match="requires_https"):
        OperatorConfig(provider="openai_compatible", base_url="http://llm.example.com/v1")
    with pytest.raises(OperatorConfigurationError, match="hosted_operator_requires_opt_in_and_key"):
        OperatorConfig(enabled=True, provider="openai_compatible", base_url="https://llm.example.com/v1", api_key="key")


@pytest.mark.parametrize("provider", ["omnirouter", "openai_compatible"])
@pytest.mark.parametrize("host", [
    "127.0.0.1", "10.0.0.5", "192.168.1.10", "172.16.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
    "[::1]", "[fd00::1]", "[fe80::1]", "[::ffff:10.0.0.1]", "[64:ff9b::a00:1]", "[2002:a00:1::1]",
    "localhost", "llm", "llm.local", "metadata.google.internal", "api.svc.cluster.local", "ollama.lan",
    "2130706433", "127.1", "0x7f.1",
])
def test_hosted_rejects_private_internal_and_ambiguous_hosts(provider, host):
    with pytest.raises(OperatorConfigurationError, match="hosted_operator_requires_public_host"):
        OperatorConfig(provider=provider, base_url=f"https://{host}/v1")


def test_private_endpoint_is_configured_as_local_not_hosted():
    config = OperatorConfig(enabled=True, provider="local", base_url="http://192.168.1.50:8080/v1", api_key="lan-key")
    assert config.status()["external"] is False
