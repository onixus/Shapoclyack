"""Where this API's outbound HTTP goes and what it trusts on the way (#359).

Two things every egress path in a corporate network needs and none of them
had: the proxy it must go through, and the CA that signs what comes back.

**The proxy.** ``OCTO_HTTP_PROXY``, ``OCTO_HTTPS_PROXY`` and ``OCTO_NO_PROXY``,
falling back to the conventional ``HTTP_PROXY``/``HTTPS_PROXY``/``NO_PROXY``
(and their lowercase spellings) when the ``OCTO_`` ones are unset. The prefixed
names exist because a pod inherits ``HTTPS_PROXY`` from a cluster-wide
injection meant for something else, and an operator needs a way to say "this
process, this proxy" without unsetting the ambient one.

**The CA.** ``OCTO_CA_BUNDLE`` is a PEM file *added to* the system trust store,
not a replacement for it: a TLS-inspecting proxy re-signs every connection with
an internal root, and the receivers reached without it still have public
certificates. Verification is never turned off — an inspected connection is
verified against the inspector's own CA, which is the point of naming it.

The plain-HTTP direction reads ``http_proxy`` in **lowercase** and ignores
``HTTP_PROXY``. That is the httpoxy mitigation, and it points the way curl
points it: a CGI-shaped environment derives ``HTTP_PROXY`` from an incoming
``Proxy:`` request header, so the uppercase name is one an untrusted caller can
write, while the lowercase one is not. ``OCTO_HTTP_PROXY`` is what an operator
should set and is out of reach either way — a header of that name would arrive
as ``HTTP_OCTO_HTTP_PROXY``. Only this direction is affected; no request header
spells ``HTTPS_PROXY``.

A proxy URL must itself be ``http://``. This client speaks to the proxy in the
clear (a ``CONNECT`` for HTTPS targets, an absolute-URI request for plain HTTP)
and does not wrap that hop in TLS, so accepting ``https://`` would promise an
encrypted hop that never happens — and send ``Proxy-Authorization: Basic`` over
it. :func:`parse_proxy` refuses it by name rather than downgrading silently.

**What this does not cover.** NATS is not HTTP and no HTTP proxy carries it;
see ``docs/network-requirements.md``. The SSRF boundary in
``api/services/outbound_targets.py`` still decides *whether* a webhook target
may be dialed — a proxy changes who opens the socket, not what is allowed.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import ssl
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

#: Read in order; the first non-empty one wins.
#: Uppercase ``HTTP_PROXY`` is absent on purpose: httpoxy. See the module
#: docstring — an operator sets ``OCTO_HTTP_PROXY``.
_HTTP_PROXY_VARS = ("OCTO_HTTP_PROXY", "http_proxy")
_HTTPS_PROXY_VARS = ("OCTO_HTTPS_PROXY", "HTTPS_PROXY", "https_proxy")
_NO_PROXY_VARS = ("OCTO_NO_PROXY", "NO_PROXY", "no_proxy")
CA_BUNDLE_VAR = "OCTO_CA_BUNDLE"


class EgressConfigError(ValueError):
    """A proxy or CA setting is not usable, and pretending otherwise is worse."""


@dataclass(frozen=True)
class Proxy:
    """One resolved proxy endpoint, with its credentials kept out of ``authority``."""

    scheme: str
    host: str
    port: int
    username: str = ""
    password: str = ""

    @property
    def authority(self) -> str:
        """``host:port`` — what may go in a log line. Never the credentials."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    def proxy_url(self) -> str:
        """The URL form ``urllib``'s ``ProxyHandler`` expects, credentials included."""
        userinfo = ""
        if self.username:
            userinfo = f"{self.username}:{self.password}@" if self.password else f"{self.username}@"
        return f"{self.scheme}://{userinfo}{self.authority}"


def _first_env(names: tuple[str, ...]) -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


def parse_proxy(raw: str) -> Proxy:
    """Parse ``[http://][user:pass@]host[:port]`` the way every client does.

    ``https://`` is refused rather than accepted-and-downgraded: see the module
    docstring. A bare ``host:port`` is read as ``http://``, which is what every
    other client does with it.
    """
    candidate = raw if "://" in raw else f"http://{raw}"
    parts = urlsplit(candidate)
    if parts.scheme == "https":
        raise EgressConfigError(
            "proxy URL must be http://; this client talks to the proxy in the clear "
            "and would send Proxy-Authorization over it, so https:// would promise "
            "an encrypted hop that does not exist"
        )
    if parts.scheme != "http":
        raise EgressConfigError(f"proxy URL must be http, got {parts.scheme!r}")
    if not parts.hostname:
        raise EgressConfigError("proxy URL must include a host")
    try:
        port = parts.port
    except ValueError as exc:
        raise EgressConfigError("proxy URL contains an invalid port") from exc
    return Proxy(
        scheme=parts.scheme,
        host=parts.hostname,
        port=port or 80,
        username=parts.username or "",
        password=parts.password or "",
    )


def _no_proxy_entries() -> tuple[str, ...]:
    raw = _first_env(_NO_PROXY_VARS)
    return tuple(item.strip().lower() for item in raw.split(",") if item.strip())


def matches_no_proxy(hostname: str, port: int, entry: str) -> bool:
    """One ``NO_PROXY`` entry against one target, in the conventional dialect.

    ``*`` bypasses everything; ``host:port`` pins the port; a CIDR matches an
    address literal inside it; anything else matches the name exactly or as a
    dotted suffix, so ``example.com`` and ``.example.com`` both cover
    ``api.example.com`` and neither covers ``notexample.com``.
    """
    if entry == "*":
        return True
    host = hostname.strip("[]").lower()
    if "/" in entry:
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return False
    if entry.count(":") == 1 and not entry.startswith("["):
        candidate, _, entry_port = entry.rpartition(":")
        if entry_port.isdigit():
            if int(entry_port) != port:
                return False
            entry = candidate
    entry = entry.strip("[]").lstrip(".")
    if not entry:
        return False
    return host == entry or host.endswith(f".{entry}")


def proxy_for(scheme: str, hostname: str, port: int) -> Proxy | None:
    """The proxy this target must go through, or ``None`` for a direct dial."""
    if not hostname:
        return None
    for entry in _no_proxy_entries():
        if matches_no_proxy(hostname, port, entry):
            return None
    raw = _first_env(_HTTPS_PROXY_VARS if scheme == "https" else _HTTP_PROXY_VARS)
    if not raw:
        return None
    return parse_proxy(raw)


def proxy_for_url(url: str) -> Proxy | None:
    """:func:`proxy_for` for a whole URL. A URL this cannot read goes direct."""
    parts = urlsplit((url or "").strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return None
    return proxy_for(parts.scheme, parts.hostname, port)


def ca_bundle() -> str | None:
    """Path in ``OCTO_CA_BUNDLE``, or ``None``. Raises if it is not readable.

    A missing file is an error rather than a shrug: silently falling back to
    the system store turns "verify against our internal root" into "every TLS
    handshake behind the inspecting proxy fails", diagnosed hours later.
    """
    path = os.environ.get(CA_BUNDLE_VAR, "").strip()
    if not path:
        return None
    if not os.path.isfile(path):
        raise EgressConfigError(f"{CA_BUNDLE_VAR}={path} is not a readable file")
    return path


def ssl_context() -> ssl.SSLContext:
    """A verifying context that also trusts ``OCTO_CA_BUNDLE``.

    ``load_verify_locations`` on a default context *adds* to the system store,
    so a fleet behind an inspecting proxy keeps reaching receivers that are not
    behind it.
    """
    context = ssl.create_default_context()
    bundle = ca_bundle()
    if bundle:
        try:
            context.load_verify_locations(cafile=bundle)
        except (OSError, ssl.SSLError) as exc:
            raise EgressConfigError(
                f"{CA_BUNDLE_VAR}={bundle} is not a usable PEM bundle: {exc}"
            ) from exc
    return context


def proxy_headers(proxy: Proxy) -> dict[str, str]:
    """``Proxy-Authorization`` for a proxy that carries credentials, else ``{}``."""
    if not proxy.username:
        return {}
    token = base64.b64encode(
        f"{proxy.username}:{proxy.password}".encode("utf-8")
    ).decode("ascii")
    return {"Proxy-Authorization": f"Basic {token}"}


def build_opener(
    url: str, *handlers: urllib.request.BaseHandler
) -> urllib.request.OpenerDirector:
    """A ``urllib`` opener for ``url``: this process's proxy and CA, nothing else.

    The proxy is resolved here and handed to ``ProxyHandler`` explicitly rather
    than left to its environment scan, so ``OCTO_NO_PROXY`` and the ``OCTO_``
    overrides decide — an empty mapping is how ``urllib`` is told *not* to pick
    the ambient variables up.
    """
    proxy = proxy_for_url(url)
    mapping = {"http": proxy.proxy_url(), "https": proxy.proxy_url()} if proxy else {}
    return urllib.request.build_opener(
        urllib.request.ProxyHandler(mapping),
        urllib.request.HTTPSHandler(context=ssl_context()),
        *handlers,
    )
