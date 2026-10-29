"""Deployment-owned inference configuration; never accepts request-level URLs."""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass, field, fields
from urllib.parse import urlsplit


class OperatorConfigurationError(ValueError):
    """A sanitized configuration error, safe for status responses."""


PROVIDERS = frozenset({"local", "openrouter", "omnirouter", "openai_compatible"})
# Hosted providers whose base URL is deployment-supplied rather than fixed.
EXPLICIT_BASE_PROVIDERS = frozenset({"omnirouter", "openai_compatible"})
LOCAL_NETWORKS = tuple(ipaddress.ip_network(net) for net in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"))
# IPv6 forms that carry an IPv4 address the global check does not look through.
_EMBEDDED_IPV4_NETWORKS = tuple(ipaddress.ip_network(net) for net in (
    "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32", "::/96"))
_INTERNAL_SUFFIXES = (".localhost", ".local", ".internal", ".intranet", ".lan", ".home.arpa", ".corp", ".svc", ".cluster.local")


def is_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for globally routable unicast addresses without embedded IPv4."""
    if address.version == 6 and any(address in net for net in _EMBEDDED_IPV4_NETWORKS):
        return False
    return address.is_global and not address.is_multicast


def _hosted_host_allowed(host: str) -> bool:
    """A hosted endpoint is a public IP literal or a qualified public-looking name.

    Names are not resolved here; the provider re-checks resolved addresses
    before every exchange.
    """
    try:
        return is_public_address(ipaddress.ip_address(host))
    except ValueError:
        pass
    name = host.rstrip(".").lower()
    if "." not in name or name.endswith(_INTERNAL_SUFFIXES):
        return False
    labels = name.split(".")
    # Shorthand numeric forms such as 2130706433 or 127.1 are IPv4 to some resolvers.
    return not all(label.isdigit() or label.startswith("0x") for label in labels)


@dataclass(frozen=True)
class OperatorConfig:
    enabled: bool = False
    provider: str = "local"
    base_url: str = ""
    model: str = "Qwen3.5-9B-Q4_K_M"
    api_key: str = field(default="", repr=False)
    allow_external: bool = False
    timeout_seconds: float = 120.0
    max_response_bytes: int = 262144
    max_input_chars: int = 24000
    max_output_tokens: int = 1024

    def __post_init__(self) -> None:
        if self.provider not in PROVIDERS:
            raise OperatorConfigurationError("unsupported_operator_provider")
        if not self.base_url:
            defaults = {"local": "http://127.0.0.1:8080/v1", "openrouter": "https://openrouter.ai/api/v1"}
            object.__setattr__(self, "base_url", defaults.get(self.provider, ""))
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(self.timeout_seconds, bool) or not math.isfinite(self.timeout_seconds) or not 0 < self.timeout_seconds <= 120:
            raise OperatorConfigurationError("invalid_operator_timeout")
        for name, ceiling in (("max_response_bytes", 1048576), ("max_input_chars", 131072), ("max_output_tokens", 8192)):
            value = getattr(self, name)
            if type(value) is not int or not 0 < value <= ceiling:
                raise OperatorConfigurationError("invalid_operator_limit")
        if not isinstance(self.api_key, str) or any(ord(c) < 33 or ord(c) > 126 for c in self.api_key):
            raise OperatorConfigurationError("invalid_operator_api_key")
        if not isinstance(self.model, str) or len(self.model) > 256 or any(ord(c) < 32 for c in self.model):
            raise OperatorConfigurationError("invalid_operator_model")
        if self.enabled and not self.model.strip():
            raise OperatorConfigurationError("operator_model_required")
        if self.provider in EXPLICIT_BASE_PROVIDERS and not self.base_url and not self.enabled:
            return
        try:
            url = urlsplit(self.base_url)
            valid_url = bool(url.hostname) and url.port != 0 and not url.username and not url.password and not url.query and not url.fragment
        except (ValueError, TypeError):
            valid_url = False
        if not valid_url or url.scheme not in {"http", "https"}:
            raise OperatorConfigurationError("invalid_operator_base_url")
        if self.provider == "local":
            try:
                address = ipaddress.ip_address(url.hostname)
            except ValueError:
                raise OperatorConfigurationError("local_operator_requires_private_ip_literal") from None
            if not any(address in net for net in LOCAL_NETWORKS):
                raise OperatorConfigurationError("local_operator_requires_private_ip_literal")
        else:
            if url.scheme != "https":
                raise OperatorConfigurationError("hosted_operator_requires_https")
            if not _hosted_host_allowed(url.hostname):
                # Private endpoints belong to the local provider, which never needs egress consent.
                raise OperatorConfigurationError("hosted_operator_requires_public_host")
            if self.provider == "openrouter" and self.base_url.rstrip("/") != "https://openrouter.ai/api/v1":
                raise OperatorConfigurationError("invalid_openrouter_base_url")
            if self.enabled and (not self.allow_external or not self.api_key):
                raise OperatorConfigurationError("hosted_operator_requires_opt_in_and_key")

    @classmethod
    def from_settings(cls, settings: object) -> OperatorConfig:
        defaults = cls()
        return cls(**{f.name: getattr(settings, "operator_" + f.name, getattr(defaults, f.name)) for f in fields(cls)})

    def status(self) -> dict[str, object]:
        """Configuration only: this does not claim model/runtime readiness."""
        return {"enabled": self.enabled, "provider": self.provider, "model": self.model,
                "external": self.provider != "local", "runtime_verified": False}
