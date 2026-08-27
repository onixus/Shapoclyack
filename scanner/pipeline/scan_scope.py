"""The approved scan scope, carried into the run and applied to what is scanned (#244).

#226 authorized targets at the API's door: ``parse_target_payload`` when they
are submitted and ``scan_scopes.assert_scan_allowed`` when the scan starts.
Both answer the question about *names*, and a name is not an address. The API
resolves the requested FQDNs to catch one that currently points into a denied
range — then this pipeline resolves them again, minutes or (for a schedule)
hours later, and scans whatever the second answer says. The record in between
belongs to the scanned party, who changes it at their own discretion. That is
the gap this module closes: the scope travels with the run, and the filter runs
on the addresses the scan is actually about to touch.

Two more holes close with it, because they are the same hole:

* **Discovery expands the scope after admission.** CT subdomains, Cloudflare
  zone imports and ASN ranges are targets nobody submitted and no API check
  ever saw.
* **A run on the installation's default target files.** The API does not open
  those files, so #226 could only require that the tenant *has* a scope, never
  compare it against their contents. Here the contents are in hand.

The rules are #226's, unchanged, because a second set of rules would be a
second answer: deny beats allow by overlap, allow is containment, and a scope
with no entries approves nothing at all. ``api/services/scan_scopes.ScanScope``
subclasses :class:`ScanScope` rather than restating the matching, so the two
barriers cannot drift.

**Resolved addresses are checked against deny entries only**, exactly as the
API checks them. Approving ``customer.example`` is its own permission and says
nothing about the addresses behind it, so demanding that they also sit inside an
approved CIDR would refuse every domain-only engagement — which is most of them.
Names and submitted or discovered ranges get the full check.

**A refusal here drops the target; it does not fail the run.** This is not an
authorization boundary — the agent host already runs whatever it is handed, and
an operator who wants to scan an address needs no help from this file to do it.
It is the last point at which the *real* target list is known, and its job is to
keep the scan off addresses the tenant was told not to touch. Failing the whole
run instead would let a third party's DNS change end an engagement, which is a
denial of service the deny rule never asked for. The refusals are written to
``scan_scope_denied.json`` in the run directory and logged; the artifact travels
back inside the results archive, and the API folds it into ``auth_events`` on
ingest — the journal the scanner itself has no path to.

The one thing that does stop a run is an *unapproved* scope: a document with no
entries is "this tenant scans nothing", and quietly scanning zero targets would
be indistinguishable from a clean empty result.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from .utils import load_json, save_json

#: Bumped only if the document stops being readable by an older scanner.
DOCUMENT_VERSION = 1

#: The artifact a filtered run leaves behind, read back by the API on ingest.
DENIED_ARTIFACT = "scan_scope_denied.json"

EFFECT_ALLOW = "allow"
EFFECT_DENY = "deny"

KIND_CIDR = "cidr"
KIND_DOMAIN = "domain"

#: The explicit any-value wildcard, spelled out rather than implied by an empty
#: scope — "this tenant may scan anything" is a decision someone made.
WILDCARD = "*"

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network

_log = logging.getLogger(__name__)


def normalize_domain(value: str) -> str:
    return value.strip().rstrip(".").lower()


def _network(value: str) -> _Network:
    return ipaddress.ip_network(value.strip(), strict=False)


def _suffix_matches(name: str, entry: str) -> bool:
    """Domain-suffix match: ``example.com`` covers itself and its subdomains."""
    if entry == WILDCARD:
        return True
    return name == entry or name.endswith("." + entry)


@dataclass(frozen=True)
class ScanScope:
    """One tenant's approved scope, in a form that can be matched.

    Pure: no database, no network, no settings — so the API service can build it
    from ``tenant_scan_scopes`` and this pipeline can build it from the document
    the run carries, and both get the same answers.
    """

    tenant_id: str
    allow_networks: tuple[_Network, ...] = ()
    deny_networks: tuple[_Network, ...] = ()
    allow_domains: tuple[str, ...] = ()
    deny_domains: tuple[str, ...] = ()
    #: Any entries at all. False is "nothing approved", not "nothing denied".
    approved: bool = False

    @property
    def has_deny_networks(self) -> bool:
        return bool(self.deny_networks)

    def rejects_network(self, value: str) -> str | None:
        """Why this IP/CIDR target is out of scope, or None when it is inside it."""
        try:
            target = _network(value)
        except ValueError:
            # Syntax is the caller's business; an unparseable value cannot be
            # matched against anything, so it is out of scope here.
            return "not an IP or CIDR"
        for denied in self.deny_networks:
            if denied.version == target.version and target.overlaps(denied):
                return f"denied by {denied}"
        for allowed in self.allow_networks:
            if allowed.version == target.version and target.subnet_of(allowed):
                return None
        return "not inside any allowed range"

    def rejects_domain(self, value: str) -> str | None:
        """Why this domain target is out of scope, or None when it is inside it."""
        name = normalize_domain(value)
        for denied in self.deny_domains:
            if _suffix_matches(name, denied):
                return f"denied by {denied}"
        for allowed in self.allow_domains:
            if _suffix_matches(name, allowed):
                return None
        return "not under any allowed domain"

    def to_document(self) -> dict[str, Any]:
        """The serialized form that travels to the agent and into the run."""
        entries = [
            {"effect": EFFECT_ALLOW, "kind": KIND_CIDR, "value": str(net)}
            for net in self.allow_networks
        ]
        entries += [
            {"effect": EFFECT_DENY, "kind": KIND_CIDR, "value": str(net)}
            for net in self.deny_networks
        ]
        entries += [
            {"effect": EFFECT_ALLOW, "kind": KIND_DOMAIN, "value": name}
            for name in self.allow_domains
        ]
        entries += [
            {"effect": EFFECT_DENY, "kind": KIND_DOMAIN, "value": name}
            for name in self.deny_domains
        ]
        return {
            "version": DOCUMENT_VERSION,
            "tenant_id": self.tenant_id,
            # Carried explicitly rather than inferred from ``entries``: a scope
            # whose every entry was unparseable is approved-but-empty, and that
            # is not the same thing as never approved.
            "approved": self.approved,
            "entries": entries,
        }


def from_document(data: Any) -> ScanScope | None:
    """Parse a scope document, or None when it is not one.

    A document that cannot be read is not turned into an empty scope: an empty
    scope stops the run, and a truncated file is a reason to say so rather than
    to invent a verdict.
    """
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        return None
    entries = data["entries"]

    allow_networks: list[_Network] = []
    deny_networks: list[_Network] = []
    allow_domains: list[str] = []
    deny_domains: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        effect = str(entry.get("effect", "")).strip().lower()
        kind = str(entry.get("kind", "")).strip().lower()
        value = str(entry.get("value", "")).strip()
        if effect not in (EFFECT_ALLOW, EFFECT_DENY) or not value:
            continue
        if kind == KIND_CIDR:
            if value == WILDCARD:
                # Stored as the wildcard for symmetry with domains; matched as
                # "every address of both families".
                bucket = deny_networks if effect == EFFECT_DENY else allow_networks
                bucket.extend((_network("0.0.0.0/0"), _network("::/0")))
                continue
            try:
                network = _network(value)
            except ValueError:
                # The API's rule, restated here because the document can also
                # be old: an allow entry that cannot be parsed is dropped, and
                # a deny entry that cannot be applied is loud, because it is a
                # control that is not working.
                _log.error("Ignoring unparseable %s scan-scope entry %r", effect, value)
                continue
            (deny_networks if effect == EFFECT_DENY else allow_networks).append(network)
        elif kind == KIND_DOMAIN:
            name = normalize_domain(value)
            (deny_domains if effect == EFFECT_DENY else allow_domains).append(name)

    return ScanScope(
        tenant_id=str(data.get("tenant_id") or ""),
        allow_networks=tuple(allow_networks),
        deny_networks=tuple(deny_networks),
        allow_domains=tuple(allow_domains),
        deny_domains=tuple(deny_domains),
        approved=bool(data.get("approved", bool(entries))),
    )


def load_scope_file(path: Path | str | None) -> ScanScope | None:
    """The scope document at ``path``, or None when the run carries no scope.

    None is *not* an empty scope. A pipeline invoked directly — from the CLI,
    from ``docker compose``, by an operator on the scanner host — has no API and
    no tenant behind it, and refusing to scan anything there would break the
    standalone mode over a control with nothing to enforce. Only a run started
    through the API carries a document, and every such run does.
    """
    if not path:
        return None
    scope_path = Path(path)
    if not scope_path.is_file():
        _log.warning("Scan-scope document %s does not exist; run is unfiltered", scope_path)
        return None
    try:
        scope = from_document(load_json(scope_path, fallback=None))
    except (OSError, ValueError) as exc:
        _log.error("Unreadable scan-scope document %s: %s", scope_path, exc)
        return None
    if scope is None:
        _log.error("Malformed scan-scope document %s; run is unfiltered", scope_path)
    return scope


@dataclass(frozen=True)
class FilterResult:
    """What survived the scope, and what did not and why."""

    kept: list[str]
    refused: list[str]


def _filter(
    values: Iterable[str],
    reason_for: Callable[[str], str | None],
    *,
    deny_only: bool,
    label: str,
) -> FilterResult:
    kept: list[str] = []
    refused: list[str] = []
    for value in values:
        reason = reason_for(value)
        if reason is None or (deny_only and not reason.startswith("denied by")):
            kept.append(value)
            continue
        refused.append(f"{label}{value} ({reason})")
    return FilterResult(kept=kept, refused=refused)


def filter_names(scope: ScanScope, names: Iterable[str]) -> FilterResult:
    """Drop the names the scope refuses. Full check — allow and deny both."""
    return _filter(names, scope.rejects_domain, deny_only=False, label="")


def filter_ranges(scope: ScanScope, ranges: Iterable[str]) -> FilterResult:
    """Drop the IP/CIDR targets the scope refuses. Full check.

    Applies to the submitted ranges (already checked by the API, so normally a
    no-op) and to the ranges discovery added after that check — ASN mapping and
    Cloudflare zone imports, which nothing else authorizes.
    """
    return _filter(ranges, scope.rejects_network, deny_only=False, label="")


def filter_resolved(scope: ScanScope, addresses: Iterable[str]) -> FilterResult:
    """Drop resolved addresses that land in a denied range. Deny only.

    The TOCTOU fix: these are the addresses the scan will actually reach, taken
    from the resolution that will actually be used. Deny-only for the reason in
    the module docstring — a domain approval does not speak about the addresses
    behind it, in either direction.
    """
    return _filter(addresses, scope.rejects_network, deny_only=True, label="resolved -> ")


def write_denials(output_dir: Path, scope: ScanScope, refused: list[str]) -> None:
    """Record the refusals as a run artifact, always — including none of them.

    Written even when nothing was refused so that "the filter ran and found
    nothing" is distinguishable from "the filter never ran", which is the only
    thing a reader of a finished run could otherwise not tell.
    """
    save_json(
        output_dir / DENIED_ARTIFACT,
        {
            "tenant_id": scope.tenant_id,
            "approved": scope.approved,
            "denied_count": len(refused),
            "denied": sorted(refused),
        },
    )
