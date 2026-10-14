"""Compatibility entry point for shared stdlib HTTP proxy and CA policy.

API-specific outbound target restrictions stay with their existing callers.
The default urllib redirect behavior is preserved here.
"""

from __future__ import annotations

import urllib.request

from agent.runtime import egress as _shared
from agent.runtime.egress import (
    _HTTP_PROXY_VARS as _HTTP_PROXY_VARS,
    _HTTPS_PROXY_VARS as _HTTPS_PROXY_VARS,
    _NO_PROXY_VARS as _NO_PROXY_VARS,
    CA_BUNDLE_VAR as CA_BUNDLE_VAR,
    EgressConfigError as EgressConfigError,
    Proxy as Proxy,
    ca_bundle as ca_bundle,
    describe as describe,
    matches_no_proxy as matches_no_proxy,
    parse_proxy as parse_proxy,
    proxy_for as proxy_for,
    proxy_for_url as proxy_for_url,
    proxy_headers as proxy_headers,
    ssl_context as ssl_context,
)


def build_opener(
    url: str, *handlers: urllib.request.BaseHandler
) -> urllib.request.OpenerDirector:
    """Build an API opener with canonical proxy/CA policy."""
    return _shared.build_opener(url, *handlers)
