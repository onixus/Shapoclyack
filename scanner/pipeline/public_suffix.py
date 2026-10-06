"""Public Suffix List lookups: where a name stops being somebody's domain.

Every stage that derives its seed from the run's scope -- CT, ASN, ownership,
cloud buckets, domain monitoring, zone hygiene, mail posture, credential
leaks -- used to cut an FQDN down to its last two labels. For
``www.bbc.co.uk``, ``shop.example.com.ru`` and ``x.github.io`` that is the
public suffix itself (``co.uk``, ``com.ru``, ``github.io``): a zone run by a
registry, a registrar or a hosting platform, not by whoever is being scanned.
For the AXFR probe in ``dns_hygiene`` it meant a zone-transfer attempt against
Nominet's or GitHub's nameservers.

The list is a snapshot of https://publicsuffix.org/list/public_suffix_list.dat
committed next to this module byte-for-byte (MPL-2.0, header intact) and only
ever read from disk: the scanner runs in restricted networks and never fetches
it. Refresh it with ``scripts/fetch-public-suffix-list.sh``. It lives here and
not under ``scanner/data`` on purpose -- that directory is where the images
mount the shared enrichment volume, and a volume seeded before this file
existed would hide it.

Both sections of the list are used. The private section is the part that
matters most here: ``github.io``, ``com.ru`` and ``herokuapp.com`` are all
private-section entries, suffixes under which unrelated parties hold names.
``registries_only=True`` is for the one question where a hosting platform's
tenant name must not pass for a domain: "could anybody register this?". It
reads the ICANN section plus the private-section blocks of operators that run
public registries (:data:`PUBLIC_REGISTRY_OPERATORS`: CentralNic's ``uk.com``,
FAITID's ``com.ru``/``msk.ru``, ``eu.org``, ``pp.ua`` …). The ICANN section
alone is not "what a registry sells": those registries submit their suffixes
to the private section, next to GitHub's and Heroku's.

Staleness, honestly. A suffix added upstream after the snapshot is unknown
here, falls to the list's default rule ``*`` (the last label alone) and gets
the old last-two-labels answer until the snapshot is refreshed. A suffix
removed upstream stays a suffix here, which only makes a seed longer or drops
it -- fewer queries, never a different party's zone. A truncated file is
refused at load time instead of silently losing its private section.
"""

from __future__ import annotations

import functools
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

PSL_PATH = Path(__file__).with_name("public_suffix_list.dat")

#: One LDH label, plus ``_`` -- the same shape ``cert_names`` accepts.
_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")

#: Markers a complete download carries. Losing the tail of the file loses the
#: private section first, which is exactly where github.io and com.ru live.
_REQUIRED_MARKERS = ("===END ICANN DOMAINS===", "===END PRIVATE DOMAINS===")


#: Names under which nothing can be registered from a registry, although some
#: of them are on the list (``onion``, ``home.arpa``) or look like a TLD: the
#: special-use names of RFC 6761/6762/7686/8375/9476, ICANN's private-use
#: ``internal``, the documentation domains, and ``arpa`` as a whole, an
#: infrastructure zone. Undelegated private TLDs (``corp``, ``lan``) are not
#: listed here; they fail :func:`has_icann_tld` instead.
SPECIAL_USE_DOMAINS = frozenset({
    "local", "localhost", "invalid", "test", "example", "onion", "alt", "internal",
    "arpa", "example.com", "example.net", "example.org",
})


#: Private-section blocks whose suffixes are sold or given out to the public
#: by a registry, keyed by the operator name in the block's header line
#: (``// <operator> : <url>``) -- the list itself documents each one there,
#: with the URL quoted beside each entry below. Matching by block rather than
#: by suffix keeps every suffix the operator submitted (FAITID alone has dozens
#: of ``.ru``/``.su`` names); ``tests/test_public_suffix.py`` pins a fixed list
#: of suffixes that must come out registrable, so a renamed header shows.
#: Left out until somebody checks they sell to unrelated parties: KV GmbH
#: (co.de), UDR Limited (hk.com), Radix (in.net), Africa.com, Globe Hosting
#: (co.ro), priv.at, Smallregistry, NGO.US, Bielsko-Biala.
PUBLIC_REGISTRY_OPERATORS = frozenset({
    "CentralNic",  # br.com, uk.com, us.com, gb.net, ... (https://teaminternet.com/)
    "co.com Registry, LLC",  # co.com (https://registry.co.com)
    "co.ca",  # co.ca (http://registry.co.ca/)
    "FAITID",  # com.ru, msk.ru, spb.ru, ru.net, ... (https://faitid.org/)
    "MSK-IX",  # net.ru, org.ru, pp.ru (https://www.msk-ix.ru/)
    "EU.org",  # eu.org and its country subzones (https://eu.org/)
    "Service Online LLC",  # biz.ua, co.ua, pp.ua (http://drs.ua/)
    "V.UA Domain Registry",  # v.ua (https://www.v.ua/)
    "i-registry s.r.o.",  # co.cz (http://www.i-registry.cz/)
    "ZaNiC",  # za.net, za.org (http://www.za.net/)
    "UNIVERSAL DOMAIN REGISTRY",  # name.pm, org.yt, ... (https://www.udr.org.yt/)
    "HOSTBIP REGISTRY",  # biz.ng, col.ng, ... (https://www.hostbip.com/)
    "US REGISTRY LLC",  # us.org (http://us.org)
    "iDOT Services Limited",  # gr.com (http://www.domain.gr.com)
    "TechEdge Limited",  # uk.cc, us.cc, eu.cc, ... (https://www.nic.uk.cc/)
    ".pl domains (grandfathered)",  # krakow.pl, poznan.pl, ... (NASK regional domains)
    "Lodz University of Technology LODMAN regional domains",  # lodz.pl, ... (https://www.man.lodz.pl/dns)
    "TASK geographical domains",  # gda.pl, gdansk.pl, ... (https://task.gda.pl/en/services/for-entrepreneurs/)
})

#: Where a block header's operator name ends: before ": http(s)://".
_HEADER_URL = re.compile(r"\s*:\s*(?=https?://)")


@dataclass(frozen=True)
class _Snapshot:
    version: str
    rules: frozenset[str]
    #: ``ck`` for the rule ``*.ck``.
    wildcards: frozenset[str]
    #: ``www.ck`` for the rule ``!www.ck``.
    exceptions: frozenset[str]
    #: The same three, from the ICANN section and the public registries'
    #: private-section blocks (:data:`PUBLIC_REGISTRY_OPERATORS`).
    registry_rules: frozenset[str] = frozenset()
    registry_wildcards: frozenset[str] = frozenset()
    registry_exceptions: frozenset[str] = frozenset()
    #: Top-level labels the ICANN section names, as a rule or as ``*.tld``.
    icann_tlds: frozenset[str] = frozenset()
    #: Operator name -> the rules its private-section block holds.
    private_operators: tuple[tuple[str, frozenset[str]], ...] = ()


def _ascii_label(label: str) -> str:
    """The A-label for a U-label; ASCII passes through unchanged.

    List entries are already lower-case NFC, so raw RFC 3492 punycode is the
    IDNA A-label for them -- and it cannot fail the way the stdlib's IDNA 2003
    codec does on some newer labels.
    """
    if label.isascii():
        return label
    return "xn--" + label.encode("punycode").decode("ascii")


@functools.lru_cache(maxsize=1)
def _snapshot() -> _Snapshot:
    text = PSL_PATH.read_text(encoding="utf-8")
    missing = [marker for marker in _REQUIRED_MARKERS if marker not in text]
    if missing:
        raise ValueError(
            f"{PSL_PATH} is incomplete (no {', '.join(missing)}); "
            "re-run scripts/fetch-public-suffix-list.sh"
        )
    version = ""
    rules: set[str] = set()
    wildcards: set[str] = set()
    exceptions: set[str] = set()
    registry: tuple[set[str], set[str], set[str]] = (set(), set(), set())
    icann_tlds: set[str] = set()
    operators: dict[str, set[str]] = {}
    in_icann = False
    operator = ""
    previous_blank = True
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("// VERSION:") and not version:
            version = line.split(":", 1)[1].strip()
        if "===BEGIN ICANN DOMAINS===" in line:
            in_icann = True
        elif "===END ICANN DOMAINS===" in line:
            in_icann = False
        if not line:
            # A block ends at a blank line; whatever follows is somebody else's
            # until its own header says whose.
            previous_blank = True
            operator = ""
            continue
        if line.startswith("//"):
            # A private-section block opens with a header naming its operator:
            # "// <operator> : <url>", "// <operator>: <url>" or just
            # "// <operator>". Every block has its own; none inherits.
            if previous_blank and not in_icann:
                operator = _HEADER_URL.split(line[2:].strip(), maxsplit=1)[0].strip()
            previous_blank = False
            continue
        previous_blank = False
        # A rule ends at the first whitespace (the list's own format note).
        rule = line.split()[0].lower()
        index = 0
        if rule.startswith("!"):
            rule, index = rule[1:], 2
        elif rule.startswith("*."):
            rule, index = rule[2:], 1
        ascii_rule = ".".join(_ascii_label(label) for label in rule.split("."))
        (rules, wildcards, exceptions)[index].add(ascii_rule)
        if in_icann:
            registry[index].add(ascii_rule)
            if index in (0, 1) and "." not in ascii_rule:
                icann_tlds.add(ascii_rule)
        else:
            operators.setdefault(operator, set()).add(ascii_rule)
            if operator in PUBLIC_REGISTRY_OPERATORS:
                registry[index].add(ascii_rule)
    return _Snapshot(
        version,
        frozenset(rules),
        frozenset(wildcards),
        frozenset(exceptions),
        frozenset(registry[0]),
        frozenset(registry[1]),
        frozenset(registry[2]),
        frozenset(icann_tlds),
        tuple(sorted((name, frozenset(owned)) for name, owned in operators.items())),
    )


def snapshot_version() -> str:
    """The ``VERSION`` line of the bundled snapshot, for provenance."""
    return _snapshot().version


def _labels(name: str) -> tuple[list[str], list[str]] | None:
    """(labels as given, their A-labels), or None when ``name`` is not a host name."""
    candidate = (name or "").strip().rstrip(".").lower()
    if not candidate or len(candidate) > 253:
        return None
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        return None
    labels = candidate.split(".")
    ascii_labels = [_ascii_label(label) for label in labels]
    if not all(_LABEL_RE.match(label) for label in ascii_labels):
        return None
    return labels, ascii_labels


def _suffix_length(labels: list[str], *, registries_only: bool = False) -> int:
    """How many trailing labels form the public suffix (the PSL algorithm).

    An exception rule beats every other match; otherwise the longest matching
    rule wins; with no match at all the default rule ``*`` makes the last label
    the suffix.
    """
    snapshot = _snapshot()
    rules, wildcards, exceptions = (
        (snapshot.registry_rules, snapshot.registry_wildcards, snapshot.registry_exceptions)
        if registries_only
        else (snapshot.rules, snapshot.wildcards, snapshot.exceptions)
    )
    count = len(labels)
    for start in range(count):
        if ".".join(labels[start:]) in exceptions:
            return count - start - 1
    for start in range(count):
        if ".".join(labels[start:]) in rules:
            return count - start
        if start + 1 < count and ".".join(labels[start + 1 :]) in wildcards:
            return count - start
    return 1


def registrable_domain(name: str, *, registries_only: bool = False) -> str:
    """The registrable domain (eTLD+1) of ``name``, in the form it was given.

    ``www.bbc.co.uk`` → ``bbc.co.uk``; ``x.github.io`` → ``x.github.io``, or
    ``github.io`` with ``registries_only`` (and ``gone.com.ru`` either way:
    ``com.ru`` is a public registry's suffix). Empty for a public suffix itself, an IP
    literal, a wildcard, or anything else that is not a host name: none of
    those is a domain anybody holds.
    """
    parsed = _labels(name)
    if parsed is None:
        return ""
    labels, ascii_labels = parsed
    size = _suffix_length(ascii_labels, registries_only=registries_only)
    if len(labels) <= size:
        return ""
    return ".".join(labels[-(size + 1) :])


def has_icann_tld(name: str) -> bool:
    """True when the last label of ``name`` is a TLD in the list's ICANN section.

    A proxy for "delegated in the root zone": ``corp``, ``lan`` and ``home``
    are not on the list, and nothing under them can be bought. A TLD the list
    names only through a wildcard (``*.ck``, ``*.jm``) counts as well.
    """
    parsed = _labels(name)
    if parsed is None:
        return False
    _, ascii_labels = parsed
    return ascii_labels[-1] in _snapshot().icann_tlds


def private_operators() -> dict[str, frozenset[str]]:
    """Private-section operator name -> the rules its block holds (for tests and docs)."""
    return dict(_snapshot().private_operators)


def is_special_use(name: str) -> bool:
    """True when ``name`` is, or is under, one of :data:`SPECIAL_USE_DOMAINS`."""
    candidate = (name or "").strip().rstrip(".").lower()
    return any(
        candidate == domain or candidate.endswith("." + domain) for domain in SPECIAL_USE_DOMAINS
    )


def is_public_suffix(name: str) -> bool:
    """True when ``name`` is itself a public suffix (``co.uk``, ``github.io``, ``uk``)."""
    parsed = _labels(name)
    if parsed is None:
        return False
    _, ascii_labels = parsed
    return _suffix_length(ascii_labels) >= len(ascii_labels)
