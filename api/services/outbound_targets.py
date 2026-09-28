"""Where this API is allowed to open an outbound connection (#151, #240).

Two callers, two policies, one implementation.

``api/services/integrations/delivery.py`` POSTs webhooks to a URL a tenant
admin typed. Its rule (#151) is that the address must be *public*: a receiver
that resolves into the cluster's own space is the SSRF shape where the
"integration" is really a probe of this platform's internals.
``webhook_allow_private_targets`` is the deliberate escape hatch for an
on-cluster receiver reached by service DNS.

``api/services/agent_deployer.py`` dials SSH on a host a tenant admin typed,
and there that same rule would be wrong: an agent exists precisely to live
inside a private network the platform cannot otherwise reach, so RFC1918 is
the normal answer, not the suspicious one. What is never normal is a
deployment target that is the API pod's own loopback, a link-local address
(``169.254.169.254`` is a cloud metadata service, not a Linux box to install
an agent on), a multicast group, or the unspecified address. Those are refused
whatever ``allow_private`` says, because no real deployment names them and the
only thing reaching them yields is an answer about the platform itself.

**The port is policy too.** A host-key probe against an arbitrary port is a
port scanner with a tidy response format — "there is SSH here" is the whole of
what a network map is built from — so a caller may pin the ports it is willing
to dial. Webhooks keep the full range (a receiver is published wherever its
operator published it); the deployer's list is short and configurable
(``OCTO_AGENT_DEPLOY_SSH_PORTS``).

What this module deliberately does **not** know is the tenant. Whether *this*
tenant may touch *that* host is the approved scan scope's question (#226),
asked by the deployer against ``api/services/scan_scopes.py`` once the
addresses have been resolved here.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class OutboundTargetError(ValueError):
    """The requested target is not one this service may connect to."""


@dataclass(frozen=True)
class TargetPolicy:
    """What one caller's outbound targets are allowed to be.

    ``subject`` is the word every refusal uses for the thing the operator
    submitted ("webhook", "deployment target"), so the message reads about
    their request rather than about this module.
    """

    subject: str
    #: False refuses every address that is not globally routable — loopback,
    #: RFC1918, link-local, CGNAT, multicast, and the IPv6 forms that deliver
    #: to one of those (see :func:`is_public_address`). True accepts them,
    #: which is the right default only for a caller whose targets
    #: legitimately live inside a private network.
    allow_private: bool = False
    #: Refused whatever ``allow_private`` says: loopback, link-local,
    #: multicast, unspecified and reserved space. Set by callers that accept
    #: private addresses but have no legitimate use for these.
    reject_special: bool = False
    #: Ports this caller may dial. ``None`` is the full range.
    allowed_ports: frozenset[int] | None = None
    #: Appended to a non-public refusal — the setting that would allow it.
    private_remedy: str = ""


@dataclass(frozen=True)
class Target:
    """A host and port that passed this policy, plus its approved addresses.

    The addresses are carried rather than re-derived because they *are* the
    validation result: a caller that resolves the hostname a second time at
    connect time has handed a DNS answer the chance to redirect an approved
    name inward after the check (the pinning that closed #151).
    """

    hostname: str
    port: int
    addresses: tuple[IpAddress, ...]


@dataclass(frozen=True)
class HttpTarget(Target):
    """A validated HTTP(S) URL, split into what one request needs.

    The hostname stays separate from the addresses because HTTPS must verify
    the receiver's certificate and send SNI for the original DNS name while the
    TCP socket is opened directly to one of the already-validated addresses.
    That separation is the SSRF boundary.
    """

    scheme: str
    request_target: str
    host_header: str


def webhook_policy(*, allow_private: bool) -> TargetPolicy:
    """The webhook boundary from #151: :func:`is_public_address` addresses or the flag."""
    return TargetPolicy(
        subject="webhook",
        allow_private=allow_private,
        private_remedy="set OCTO_WEBHOOK_ALLOW_PRIVATE_TARGETS=true to allow it",
    )


def ssh_deploy_policy(*, allowed_ports: frozenset[int] | None) -> TargetPolicy:
    """The SSH deployer's boundary (#240): private yes, the platform's own no.

    See the module docstring for why this is not the webhook policy with a
    different flag: refusing RFC1918 here would refuse the ordinary case.
    """
    return TargetPolicy(
        subject="deployment target",
        allow_private=True,
        reject_special=True,
        allowed_ports=allowed_ports,
    )


def parse_ports(value: str) -> frozenset[int] | None:
    """Parse a configured port allowlist. ``"*"`` (or empty) means any port.

    Raises ValueError on anything that is not a port, so a typo in the
    environment is a refusal to start rather than a silently narrower list.
    """
    text = (value or "").strip()
    if not text or text == "*":
        return None
    ports: set[int] = set()
    for item in text.replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        port = int(item)
        if not 1 <= port <= 65535:
            raise ValueError(f"not a TCP port: {item!r}")
        ports.add(port)
    return frozenset(ports) or None


def resolve(hostname: str) -> list[IpAddress]:
    """Every address ``hostname`` resolves to. Unresolvable → empty list.

    An IP literal resolves to itself without a lookup, so a caller naming an
    address is validated against that address rather than against whatever a
    resolver would have said about it.
    """
    try:
        literal = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        pass
    else:
        return [literal]
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    addresses: list[IpAddress] = []
    for info in infos:
        try:
            address = ipaddress.ip_address(info[4][0])
        except ValueError:  # pragma: no cover - getaddrinfo returned a non-address
            continue
        if address not in addresses:
            addresses.append(address)
    return addresses


#: RFC 6052 well-known NAT64 prefix. It is a /96, so the IPv4 destination is
#: exactly the low 32 bits: no operator-chosen length, no u-octet to skip.
_NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")

#: IPv6 ranges that deliver to an embedded IPv4 address this code cannot
#: judge, refused outright. See :func:`is_public_address` for each one.
_EMBEDDED_IPV4_REFUSED = (
    ipaddress.IPv6Network("64:ff9b:1::/48"),  # RFC 8215 local-use NAT64
    ipaddress.IPv6Network("::ffff:0:0:0/96"),  # RFC 2765 SIIT, replaced by RFC 6052
    ipaddress.IPv6Network("2002::/16"),  # RFC 3056 6to4
    ipaddress.IPv6Network("::/96"),  # RFC 4291 IPv4-compatible, deprecated
)


def _embedded_ipv4(address: IpAddress) -> IpAddress:
    """The IPv4 address a packet to ``address`` is delivered to, where the RFC fixes it.

    ``::ffff:127.0.0.1`` is 127.0.0.1 wearing a hat, and behind a NAT64
    translator ``64:ff9b::a00:5`` is 10.0.0.5; judge the address itself.
    Anything else comes back unchanged.
    """
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped
        if address in _NAT64_WELL_KNOWN:
            return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    return address


def is_public_address(address: IpAddress) -> bool:
    """Whether ``address`` is public in the webhook sense (``allow_private=False``).

    ``is_global`` alone is not the answer for an IPv6 address that is really an
    IPv4 destination in transit. ``ipaddress`` calls ``64:ff9b::a00:5`` global
    (IANA lists the NAT64 well-known prefix as globally reachable), but on an
    API pod whose IPv6-only egress goes through NAT64 that address *is*
    10.0.0.5, and ``64:ff9b::a9fe:a9fe`` is the cloud metadata service.

    - ``::ffff:0:0/96`` (IPv4-mapped) and ``64:ff9b::/96`` (NAT64 well-known)
      are judged by the IPv4 address in their low 32 bits. Unwrapped rather
      than refused because DNS64 answers every IPv4-only name with a
      synthesized ``64:ff9b::/96`` AAAA and :func:`check_addresses` refuses a
      name if *any* of its addresses fails: refusing the prefix would refuse
      every IPv4-only receiver on an IPv6-only pod. RFC 6052 section 3.1
      forbids the prefix for non-global IPv4, so nothing a conforming DNS64
      produces is lost.
    - ``64:ff9b:1::/48`` (local-use NAT64: where the IPv4 address sits depends
      on the operator's prefix length), ``::ffff:0:0:0/96`` (SIIT
      IPv4-translated), ``2002::/16`` (6to4) and ``::/96`` (IPv4-compatible)
      are refused outright, so the verdict does not move with the
      interpreter's special-purpose table (3.9 passes local-use and 6to4).

    This is the API's copy of ``scanner/pipeline/safe_http.is_public_address``,
    whose docstring has the full reasoning for each range; the scanner cannot
    import ``api/``, and ``tests/test_outbound_targets.py`` pins the two to the
    same verdicts. A network-specific NAT64 prefix carved from the operator's
    own global space is out of reach of any address-only rule.
    """
    if isinstance(address, ipaddress.IPv6Address) and any(
        address in network for network in _EMBEDDED_IPV4_REFUSED
    ):
        return False
    candidate = _embedded_ipv4(address)
    return bool(candidate.is_global) and not candidate.is_multicast


def _special_reason(address: IpAddress) -> str | None:
    """Why no legitimate target is ever at this address, or None.

    A NAT64 well-known address is named after the IPv4 address it reaches
    (``64:ff9b::a9fe:a9fe`` is the metadata service, not just "reserved"), and
    one that reaches an ordinary IPv4 address is still refused as reserved, as
    it was before the prefix was unwrapped: ``ipaddress`` files it under
    ``::/8``, and RFC 6052 forbids it for the private space agents live in.
    """
    candidate = _embedded_ipv4(address)
    if candidate.is_loopback:
        return "loopback address"
    if candidate.is_link_local:
        return "link-local address (cloud metadata lives here)"
    if candidate.is_multicast:
        return "multicast address"
    if candidate.is_unspecified:
        return "unspecified address"
    if candidate.is_reserved:
        return "reserved address"
    if isinstance(candidate, ipaddress.IPv4Address) and candidate == ipaddress.IPv4Address(
        "255.255.255.255"
    ):
        return "broadcast address"
    if address in _NAT64_WELL_KNOWN:
        return "reserved address"
    return None


def check_port(port: int, *, policy: TargetPolicy) -> None:
    """Raise unless ``port`` is one this caller may dial."""
    if policy.allowed_ports is not None and port not in policy.allowed_ports:
        allowed = ", ".join(str(item) for item in sorted(policy.allowed_ports))
        raise OutboundTargetError(
            f"{policy.subject} port {port} is not allowed; this installation permits "
            f"{allowed}"
        )


def check_addresses(
    hostname: str,
    addresses: tuple[IpAddress, ...],
    *,
    policy: TargetPolicy,
) -> None:
    """Raise on the first address ``policy`` refuses.

    An empty tuple passes: a name that does not resolve has not been shown to
    violate anything, and the caller decides whether that is a retryable
    failure (webhook delivery) or a refusal (a deployment target that is not
    there).
    """
    for address in addresses:
        if policy.reject_special:
            reason = _special_reason(address)
            if reason is not None:
                raise OutboundTargetError(
                    f"{policy.subject} host {hostname} resolves to {address}, "
                    f"a {reason} — nothing deployable is there, and reaching it "
                    "would only report on this platform's own internals"
                )
        if not policy.allow_private and not is_public_address(address):
            remedy = f"; {policy.private_remedy}" if policy.private_remedy else ""
            raise OutboundTargetError(
                f"{policy.subject} host {hostname} resolves to non-public address "
                f"{address}{remedy}"
            )


def resolve_target(host: str, port: int, *, policy: TargetPolicy) -> Target:
    """Validate a bare ``host``/``port`` pair and return its approved addresses.

    Unlike :func:`parse_url` this refuses a host that does not resolve: a
    caller naming a host it cannot reach has nothing to retry into, and letting
    the name through would push the failure into a socket call whose error is
    a worse description of the same problem.
    """
    hostname = (host or "").strip().strip("[]")
    if not hostname:
        raise OutboundTargetError(f"{policy.subject} host required")
    check_port(port, policy=policy)
    addresses = tuple(resolve(hostname))
    if not addresses:
        raise OutboundTargetError(
            f"{policy.subject} host {hostname} does not resolve to any address"
        )
    check_addresses(hostname, addresses, policy=policy)
    return Target(hostname=hostname, port=port, addresses=addresses)


def parse_url(url: str, *, policy: TargetPolicy) -> HttpTarget:
    """Validate an HTTP(S) URL and split it into what one request needs."""
    url = (url or "").strip()
    if not url:
        raise OutboundTargetError(f"{policy.subject} url required")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise OutboundTargetError(f"{policy.subject} url must be http or https")
    if not parts.hostname:
        raise OutboundTargetError(f"{policy.subject} url must include a host")
    if parts.username is not None or parts.password is not None:
        raise OutboundTargetError(f"{policy.subject} url must not contain userinfo")
    try:
        port = parts.port
    except ValueError as exc:
        raise OutboundTargetError(f"{policy.subject} url contains an invalid port") from exc
    port = port or (443 if parts.scheme == "https" else 80)
    check_port(port, policy=policy)

    addresses = tuple(resolve(parts.hostname))
    check_addresses(parts.hostname, addresses, policy=policy)

    path = parts.path or "/"
    request_target = f"{path}?{parts.query}" if parts.query else path
    host = parts.hostname
    host_for_header = f"[{host}]" if ":" in host else host
    default_port = 443 if parts.scheme == "https" else 80
    host_header = host_for_header if port == default_port else f"{host_for_header}:{port}"
    return HttpTarget(
        hostname=host,
        port=port,
        addresses=addresses,
        scheme=parts.scheme,
        request_target=request_target,
        host_header=host_header,
    )
