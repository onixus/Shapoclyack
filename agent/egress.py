"""Sensor adapter for the shared stdlib HTTP proxy and CA policy.

The canonical implementation lives in ``agent.runtime.egress`` and is shipped
with the standalone sensor. This adapter retains the sensor's no-redirect
policy and support for its client-certificate SSL context. NATS uses the CA
helpers, but HTTP proxies do not carry NATS.
"""

from __future__ import annotations

import ssl
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
from agent.runtime.egress import NoRedirects as NoRedirects


def build_opener(
    url: str,
    *handlers: urllib.request.BaseHandler,
    context: ssl.SSLContext | None = None,
) -> urllib.request.OpenerDirector:
    """Build a sensor opener; redirects never carry its bearer token."""
    return _shared.build_opener(
        url, *handlers, context=context, follow_redirects=False
    )
