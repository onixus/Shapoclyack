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


@dataclass(frozen=True)
class _Snapshot:
    version: str
    rules: frozenset[str]
    #: ``ck`` for the rule ``*.ck``.
    wildcards: frozenset[str]
    #: ``www.ck`` for the rule ``!www.ck``.
    exceptions: frozenset[str]


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
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("// VERSION:") and not version:
            version = line.split(":", 1)[1].strip()
        if not line or line.startswith("//"):
            continue
        # A rule ends at the first whitespace (the list's own format note).
        rule = line.split()[0].lower()
        target = rules
        if rule.startswith("!"):
            rule, target = rule[1:], exceptions
        elif rule.startswith("*."):
            rule, target = rule[2:], wildcards
        target.add(".".join(_ascii_label(label) for label in rule.split(".")))
    return _Snapshot(version, frozenset(rules), frozenset(wildcards), frozenset(exceptions))


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


def _suffix_length(labels: list[str]) -> int:
    """How many trailing labels form the public suffix (the PSL algorithm).

    An exception rule beats every other match; otherwise the longest matching
    rule wins; with no match at all the default rule ``*`` makes the last label
    the suffix.
    """
    snapshot = _snapshot()
    count = len(labels)
    for start in range(count):
        if ".".join(labels[start:]) in snapshot.exceptions:
            return count - start - 1
    for start in range(count):
        if ".".join(labels[start:]) in snapshot.rules:
            return count - start
        if start + 1 < count and ".".join(labels[start + 1 :]) in snapshot.wildcards:
            return count - start
    return 1


def registrable_domain(name: str) -> str:
    """The registrable domain (eTLD+1) of ``name``, in the form it was given.

    ``www.bbc.co.uk`` → ``bbc.co.uk``; ``x.github.io`` → ``x.github.io``.
    Empty for a public suffix itself, an IP literal, a wildcard, or anything
    else that is not a host name: none of those is a domain anybody holds.
    """
    parsed = _labels(name)
    if parsed is None:
        return ""
    labels, ascii_labels = parsed
    size = _suffix_length(ascii_labels)
    if len(labels) <= size:
        return ""
    return ".".join(labels[-(size + 1) :])


def is_public_suffix(name: str) -> bool:
    """True when ``name`` is itself a public suffix (``co.uk``, ``github.io``, ``uk``)."""
    parsed = _labels(name)
    if parsed is None:
        return False
    _, ascii_labels = parsed
    return _suffix_length(ascii_labels) >= len(ascii_labels)
