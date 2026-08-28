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
    #: RFC1918, link-local, CGNAT, multicast. True accepts them, which is the
    #: right default only for a caller whose targets legitimately live inside
    #: a private network.
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
    """The webhook boundary from #151, unchanged: public addresses or the flag."""
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


def _unmapped(address: IpAddress) -> IpAddress:
    """``::ffff:127.0.0.1`` is 127.0.0.1 wearing a hat; judge the address itself."""
    mapped = getattr(address, "ipv4_mapped", None)
    return mapped or address


def _special_reason(address: IpAddress) -> str | None:
    """Why no legitimate target is ever at this address, or None."""
    candidate = _unmapped(address)
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
        if not policy.allow_private and (not address.is_global or address.is_multicast):
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
