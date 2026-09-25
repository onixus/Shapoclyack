"""Which DNS servers the scanner tells its ProjectDiscovery tools to ask.

Left to its defaults, nuclei does not resolve the way the rest of the host
does. nuclei v3.11.1 dials through fastdialer v0.5.14, which takes the
``nameserver`` lines of ``/etc/resolv.conf`` and then *appends* its built-in
1.1.1.1, 1.0.0.1, 8.8.8.8 and 8.8.4.4; retryabledns then picks among them
round-robin. With one system nameserver, four lookups in five go to a public
resolver. nuclei's DNS-protocol templates are worse: that client asks the four
public servers and nothing else. ``-system-resolvers`` does not help, because
it only turns on a fallback and leaves the public four in the rotation.

Measured on the kind stand, with the image's own binary and the scanner's own
flags against an IP-only target:

- 256 of 320 lookups went to Cloudflare or Google. They included the name an
  HTTP redirect pointed to, the interactsh hosts, and query names built from
  the scanned address itself (``http://10.x.y.z``, from the JavaScript
  templates).
- An internal-only name did not resolve at all, so a template following a
  redirect to it matched nothing. Outbound port 53 is closed on the stand, so
  the public servers timed out. Where they are reachable, they would answer
  NXDOMAIN for a split-horizon name instead. Either way nuclei reports
  nothing, not an error.

Passing ``-resolvers <file>`` replaces the public four. fastdialer keeps
resolv.conf first and puts the given servers after it, and the DNS client uses
the given servers alone. Which servers go in the file is decided here:
``dns.resolvers`` from the scanner config, or the system's own when that is
empty. Rerun on the stand with the flag, every name derived from a target went
to the system resolver only.

One client ignores the flag: interactsh. nuclei builds it with
retryablehttp's default dialer (``internal/runner/runner.go``), which still
rotates the public four in. With the flag, 160 of 312 lookups still went
public. All of them were for the six interactsh server names
(``oast.pro``, ``oast.live``, ...), which are fixed public names and not
derived from any target. Stopping those is a matter of ``-no-interactsh`` or a
self-hosted ``-interactsh-server``, not of resolvers.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from pathlib import Path

#: Read at call time, not bound as a default argument, so a test can point it
#: at a fixture file.
RESOLV_CONF = Path("/etc/resolv.conf")

#: What the C library asks when resolv.conf names no server (glibc's
#: ``INADDR_LOOPBACK`` default; Go's resolver does the same).
_NO_NAMESERVER_FALLBACK = ("127.0.0.1",)

DNS_PORT = 53


def parse_resolver(value: str) -> tuple[str, int]:
    """Split ``ip``, ``ip:port``, ``ipv6`` or ``[ipv6]:port`` into address and port.

    Only address literals are accepted. A resolver given by name would have to
    be resolved first, by some other resolver, which is the question this
    setting exists to answer. Raises ``ValueError`` on anything else.
    """
    raw = value.strip()
    port_text: str | None = None
    if raw.startswith("["):
        host, closed, rest = raw[1:].partition("]")
        if not closed or (rest and not rest.startswith(":")):
            raise ValueError(f"not an address: {value!r}")
        port_text = rest[1:] if rest else None
    elif raw.count(":") == 1:
        host, _, port_text = raw.partition(":")
    else:
        host = raw
    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise ValueError(f"not an IP address: {value!r}") from None
    if port_text is None:
        return host, DNS_PORT
    if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        raise ValueError(f"bad port in {value!r}")
    return host, int(port_text)


def host_port(resolver: str) -> str:
    """``resolver`` as ``host:port``, bracketing IPv6, which is what nuclei's ``-resolvers`` file needs.

    nuclei adds ``:53`` only to a line with no colon in it. A bare IPv6
    address has colons, so nuclei would read it as ``host:port`` and mangle
    it. Writing every entry with an explicit port avoids that.
    """
    host, port = parse_resolver(resolver)
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def system_resolvers(path: Path | None = None) -> list[str]:
    """The ``nameserver`` addresses in resolv.conf, in file order, without duplicates.

    A missing file, or one without a usable ``nameserver`` line, yields the
    loopback resolver, which is what the C library itself would ask. It does
    not yield an empty list: with no list, the tool falls back to its built-in
    public servers, and that is the leak this module exists to close.
    """
    try:
        text = (path or RESOLV_CONF).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return list(_NO_NAMESERVER_FALLBACK)
    found: list[str] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[0] != "nameserver":
            continue
        try:
            host, _ = parse_resolver(fields[1])
        except ValueError:
            continue
        if host not in found:
            found.append(host)
    return found or list(_NO_NAMESERVER_FALLBACK)


def scan_resolvers(configured: Sequence[str]) -> list[str]:
    """``dns.resolvers`` when it is set, otherwise the system's resolvers."""
    return list(configured) if configured else system_resolvers()
