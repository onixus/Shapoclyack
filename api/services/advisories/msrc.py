"""Microsoft's Security Update Guide, as the thing Windows can actually be matched on (#358).

**Why this is not an ``AdvisoryProvider``.** Every other provider answers "what
does this distribution say about this *source package* in this *release*",
because that is the question a deb or an rpm can be asked. Windows cannot: the
uninstall registry lists products with marketing version numbers that no
Microsoft advisory refers to, and the thing an advisory *does* refer to is the
operating system's build. Forcing that into the package-shaped interface would
mean inventing a package name for the OS and pretending its `DisplayVersion` is
comparable to something. It is not, and the matcher would be confidently wrong
rather than honestly silent.

**What is matched instead.** A Windows host reports `os_version` as
`10.0.<build>.<ubr>` — `10.0.26100.9445`, say. Microsoft's remediations carry a
`FixedBuild` in exactly that form. Two numbers decide everything:

* the **build** (`26100`) identifies the product line — Windows 11 24H2,
  Server 2025, Windows 10 22H2 are different builds, and a fix for one says
  nothing about another;
* the **UBR** (`9445`) is the revision, and it only ever goes up. Windows
  servicing is cumulative: the update that raises a host to a given UBR
  contains every fix shipped for that build before it. So a host is patched
  against a CVE exactly when its UBR is at least the UBR of the remediation.

That is the whole model, and it is the correct one — not a heuristic standing in
for a version comparison. Its limits are stated in :func:`evaluate`, not hidden.

**Installed updates are consulted as well.** A `KB` the host reports is treated
as a fix even when the UBR does not show it: out-of-band updates, and hosts
whose servicing stack reports a build the registry disagrees with, are real.
The two signals can only make a host *more* patched, never less.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

LOG = logging.getLogger("shapoclyack.advisories")

#: Dataset shipped with the image and refreshed by ``scripts/fetch-advisories.py``,
#: overridable like every other enrichment overlay.
DATASET_ENV = "OCTO_MSRC_DATABASE"
DEFAULT_DATASET = "scanner/data/advisories/msrc-advisories.json"

PROVIDER_NAME = "msrc"

#: ``10.0.26100.9445``, and the three-part form a registry can produce.
_BUILD_PATTERN = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?$")

#: Windows NT versions still in service, as (major, minor). 6.0-6.3 is Vista
#: through Server 2012 R2; 10.0 is everything from Windows 10 and Server 2016
#: onward. Pinning the minor as well as the major is what keeps a product
#: versioned `10.19.10658` or `6.2511.7533` -- both real entries in a CVRF
#: month -- from being filed as a Windows build family. Those cannot produce a
#: false match, since no host reports such a version, but they are not Windows
#: and a dataset that claims they are is a dataset that misleads whoever reads
#: it.
_NT_VERSIONS = frozenset({(6, 0), (6, 1), (6, 2), (6, 3), (10, 0)})
#: The lowest NT build number any of those carries (7601 is Windows 7 SP1).
_MIN_NT_BUILD = 6000


@dataclass(frozen=True)
class WindowsBuild:
    """A Windows version, split into the two numbers that decide a match."""

    major: int
    minor: int
    build: int
    ubr: int

    @property
    def family(self) -> str:
        """The product line. ``10.0.26100`` — everything but the revision."""
        return f"{self.major}.{self.minor}.{self.build}"

    def __str__(self) -> str:
        return f"{self.family}.{self.ubr}"


def parse_build(value: str | None) -> WindowsBuild | None:
    """``"10.0.26100.9445"`` → a build, or ``None`` when it is not one.

    A missing UBR reads as ``0``: a host that reports `10.0.26100` has told us
    its product line and nothing about its revision, and treating that as
    "unpatched" is the conservative reading — it produces a finding an operator
    can check, where treating it as patched would hide one.
    """
    if not value:
        return None
    match = _BUILD_PATTERN.match(str(value).strip())
    if match is None:
        return None
    major, minor, build, ubr = (int(part or 0) for part in match.groups())
    # A CVRF month covers everything Microsoft ships, and plenty of it carries a
    # four-part numeric version that is not an OS build: Visual Studio's
    # `15.9.83.0` matched the shape exactly. Indexing those as build families
    # would inflate the dataset with statements no host can ever be compared
    # against, and is the kind of near-miss that looks like it works.
    if (major, minor) not in _NT_VERSIONS or build < _MIN_NT_BUILD:
        return None
    return WindowsBuild(major, minor, build, ubr)


@dataclass(frozen=True)
class MsrcRemediation:
    """One Microsoft statement: this CVE is fixed for this build at this UBR."""

    cve_id: str
    fixed_build: WindowsBuild
    kb: str
    product: str
    severity: str = "unknown"
    url: str | None = None


class MsrcDataset:
    """The loaded remediations, indexed by build family.

    Indexed rather than scanned because the question is always asked about one
    host's family and the dataset covers every supported Windows at once — a
    linear pass would read tens of thousands of statements to answer about the
    few hundred that can apply.
    """

    name = PROVIDER_NAME

    def __init__(self) -> None:
        self._by_family: dict[str, list[MsrcRemediation]] = {}
        self._feed_date: str | None = None
        self._source: str | None = None
        self._count = 0

    def load(self, path: str | Path | None = None) -> None:
        """Read the dataset file. Fail-soft, like every enrichment overlay.

        A missing or unreadable file leaves the dataset unavailable, and an
        unavailable dataset answers *nothing* rather than answering "no
        advisories" — which would render as a clean host.
        """
        resolved = Path(path or os.environ.get(DATASET_ENV) or DEFAULT_DATASET)
        try:
            payload = json.loads(resolved.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except OSError as exc:
            LOG.warning("msrc: cannot read %s: %s", resolved, exc)
            return
        except json.JSONDecodeError as exc:
            LOG.warning("msrc: %s is not valid JSON: %s", resolved, exc)
            return
        if not isinstance(payload, dict):
            LOG.warning("msrc: %s is not an object", resolved)
            return

        self._feed_date = str(payload.get("updated") or "") or None
        self._source = str(payload.get("source") or "") or None
        entries = payload.get("entries")
        if not isinstance(entries, (list, tuple)):
            LOG.warning("msrc: %s has no entries list", resolved)
            return

        dropped = 0
        for raw in entries:
            remediation = _coerce(raw)
            if remediation is None:
                dropped += 1
                continue
            self._by_family.setdefault(remediation.fixed_build.family, []).append(
                remediation
            )
            self._count += 1
        if dropped:
            LOG.warning("msrc: dropped %d unusable entries from %s", dropped, resolved)

    def available(self) -> bool:
        return self._count > 0

    def entry_count(self) -> int:
        return self._count

    def feed_date(self) -> str | None:
        return self._feed_date

    def source_label(self) -> str | None:
        return self._source

    def families(self) -> tuple[str, ...]:
        return tuple(sorted(self._by_family))

    def remediations_for(self, build: WindowsBuild) -> tuple[MsrcRemediation, ...]:
        return tuple(self._by_family.get(build.family, ()))


def _coerce(raw: Any) -> MsrcRemediation | None:
    """One dataset entry → a remediation, or ``None``.

    Dropped rather than raised, for the reason the distribution loader gives:
    one malformed entry in a third-party feed must not take every Windows match
    on the installation offline.
    """
    if not isinstance(raw, dict):
        return None
    cve_id = str(raw.get("cve_id") or "").strip().upper()
    fixed_build = parse_build(raw.get("fixed_build"))
    if not cve_id.startswith("CVE-") or fixed_build is None:
        return None
    kb = str(raw.get("kb") or "").strip().upper()
    if kb and not kb.startswith("KB"):
        kb = f"KB{kb.lstrip('KB')}"
    severity = str(raw.get("severity") or "unknown").strip().lower()
    return MsrcRemediation(
        cve_id=cve_id,
        fixed_build=fixed_build,
        kb=kb,
        product=str(raw.get("product") or "").strip(),
        severity=severity,
        url=(str(raw.get("url")).strip() or None) if raw.get("url") else None,
    )


@dataclass(frozen=True)
class WindowsVerdict:
    """What the dataset says about one CVE on one host."""

    cve_id: str
    status: str
    remediation: MsrcRemediation
    installed_build: WindowsBuild
    #: Set when the verdict came from a `KB` the host reports rather than from
    #: its revision number.
    fixed_by_installed_kb: bool = False


def evaluate(
    *,
    installed: WindowsBuild,
    installed_kbs: Iterable[str],
    dataset: MsrcDataset,
) -> list[WindowsVerdict]:
    """Every statement in the dataset that applies to this host.

    **What this does not claim.** A remediation for a build family the host is
    not on is not reported at all — not as "not applicable" — because the
    dataset covers every supported Windows and a host would otherwise carry
    thousands of rows about operating systems it is not running. A host whose
    family is absent from the dataset gets nothing, and the caller turns that
    into one honest `unknown` rather than into silence that reads as clean.

    Hotpatched hosts and hosts with an update installed that the servicing
    stack has not yet reflected in the UBR are why `installed_kbs` is consulted
    at all: it can only move a verdict from vulnerable to fixed.
    """
    known_kbs = {kb.strip().upper() for kb in installed_kbs if kb and kb.strip()}
    verdicts: list[WindowsVerdict] = []

    for remediation in dataset.remediations_for(installed):
        if installed.ubr >= remediation.fixed_build.ubr:
            verdicts.append(
                WindowsVerdict(
                    cve_id=remediation.cve_id,
                    status="fixed",
                    remediation=remediation,
                    installed_build=installed,
                )
            )
            continue
        if remediation.kb and remediation.kb in known_kbs:
            verdicts.append(
                WindowsVerdict(
                    cve_id=remediation.cve_id,
                    status="fixed",
                    remediation=remediation,
                    installed_build=installed,
                    fixed_by_installed_kb=True,
                )
            )
            continue
        verdicts.append(
            WindowsVerdict(
                cve_id=remediation.cve_id,
                status="vulnerable",
                remediation=remediation,
                installed_build=installed,
            )
        )

    return verdicts


_dataset: MsrcDataset | None = None


def get_dataset() -> MsrcDataset:
    """The process-wide dataset, loaded once."""
    global _dataset
    if _dataset is None:
        dataset = MsrcDataset()
        dataset.load()
        _dataset = dataset
    return _dataset


def reset_for_tests(dataset: MsrcDataset | None = None) -> None:
    global _dataset
    _dataset = dataset


# ---------------------------------------------------------------------------
# CVRF normalization
# ---------------------------------------------------------------------------

#: Remediation ``Type`` 2 is "Vendor Fix". The others -- workarounds, mitigations,
#: "none available" -- do not carry a build a host can be compared against.
_REMEDIATION_VENDOR_FIX = 2
#: Threat ``Type`` 3 is the severity Microsoft assigns, per product.
_THREAT_SEVERITY = 3

#: Microsoft's four words, in this project's vocabulary. ``Important`` is the
#: one that has to be translated rather than passed through: it is Microsoft's
#: second rung, which is ``high`` here, and leaving it as "important" would sort
#: as ``unknown`` and drop out of every severity filter.
_SEVERITY = {
    "critical": "critical",
    "important": "high",
    "moderate": "medium",
    "low": "low",
}


def normalize_cvrf(payload: Any) -> list[dict[str, Any]]:
    """One CVRF document → dataset entries.

    Only remediations that carry a Windows build are kept. A CVRF month covers
    everything Microsoft ships — Azure Linux packages, Edge, Office, firmware —
    and their ``FixedBuild`` values are that product's versioning, not a Windows
    revision (``1.10.7-1`` was in the September document). Matching those
    against a host's OS build would be comparing two unrelated number lines, so
    :func:`parse_build` rejects them and they are skipped rather than coerced.

    The KB is in ``Description.Value`` as bare digits, and the severity is a
    per-product ``Threats`` entry rather than a property of the CVE, so a CVE
    that is critical on one product and moderate on another says both.
    """
    if not isinstance(payload, dict):
        return []

    product_names = _product_names(payload.get("ProductTree"))
    entries: dict[tuple[str, str, str], dict[str, Any]] = {}

    for vulnerability in payload.get("Vulnerability") or ():
        if not isinstance(vulnerability, dict):
            continue
        cve_id = str(vulnerability.get("CVE") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        severities = _severity_by_product(vulnerability.get("Threats"))

        for remediation in vulnerability.get("Remediations") or ():
            if not isinstance(remediation, dict):
                continue
            if remediation.get("Type") != _REMEDIATION_VENDOR_FIX:
                continue
            fixed_build = parse_build(remediation.get("FixedBuild"))
            if fixed_build is None:
                continue

            kb_digits = _value_of(remediation.get("Description"))
            kb = f"KB{kb_digits}" if kb_digits.isdigit() else ""
            url = str(remediation.get("URL") or "").strip() or None
            product_ids = [
                str(pid) for pid in (remediation.get("ProductID") or ()) if str(pid)
            ]

            # One statement per (CVE, build, KB). The same remediation lists
            # every edition it covers, and they share a build: keeping one row
            # per edition would multiply the dataset by ten and change no
            # answer, since the match is decided by the build alone. The
            # product names are kept as evidence, capped, because "which
            # Windows is this about" is the first thing an operator asks.
            key = (cve_id, str(fixed_build), kb)
            existing = entries.get(key)
            products = [
                product_names[pid] for pid in product_ids if pid in product_names
            ]
            severity = _worst_severity(
                [severities.get(pid) for pid in product_ids]
                + ([existing.get("severity")] if existing else [])
            )
            if existing is None:
                entries[key] = {
                    "cve_id": cve_id,
                    "fixed_build": str(fixed_build),
                    "kb": kb,
                    "product": products[0] if products else "",
                    "severity": severity,
                    "url": url,
                }
            else:
                existing["severity"] = severity

    return sorted(entries.values(), key=lambda entry: (entry["cve_id"], entry["fixed_build"]))


def _value_of(node: Any) -> str:
    """CVRF wraps almost every string as ``{"Value": …}``, and leaves the
    wrapper empty rather than absent when there is nothing to say."""
    if isinstance(node, dict):
        return str(node.get("Value") or "").strip()
    return str(node or "").strip()


#: Microsoft names one product per architecture -- "Windows 11 Version 25H2 for
#: x64-based Systems", "... for ARM64-based Systems", "... for 32-bit Systems"
#: -- and they share a build number. So the build cannot tell them apart, and a
#: statement that names one of them is naming an architecture it does not know.
#: A live x64 host was shown a finding labelled ARM64 for exactly this reason.
_ARCH_SUFFIX = re.compile(
    r"\s+for\s+(?:x64|x86|ARM64|32-bit|64-bit|Itanium)(?:-based)?\s+Systems?\s*$",
    re.IGNORECASE,
)


def product_line(name: str) -> str:
    """The product without the architecture its build cannot establish."""
    return _ARCH_SUFFIX.sub("", name or "").strip()


def _product_names(tree: Any) -> dict[str, str]:
    if not isinstance(tree, dict):
        return {}
    names: dict[str, str] = {}
    for product in tree.get("FullProductName") or ():
        if not isinstance(product, dict):
            continue
        pid = str(product.get("ProductID") or "").strip()
        value = str(product.get("Value") or "").strip()
        if pid and value:
            names[pid] = product_line(value)
    return names


def _severity_by_product(threats: Any) -> dict[str, str]:
    severities: dict[str, str] = {}
    for threat in threats or ():
        if not isinstance(threat, dict) or threat.get("Type") != _THREAT_SEVERITY:
            continue
        word = _value_of(threat.get("Description")).lower()
        mapped = _SEVERITY.get(word)
        if mapped is None:
            continue
        for pid in threat.get("ProductID") or ():
            severities[str(pid)] = mapped
    return severities


def _worst_severity(values: Iterable[str | None]) -> str:
    """The most severe of several, because one remediation covers several
    products and an operator acts on the worst of them."""
    order = ("unknown", "low", "medium", "high", "critical")
    worst = "unknown"
    for value in values:
        if value in order and order.index(value) > order.index(worst):
            worst = value
    return worst
