"""Vendor structures -> explicitly scoped binary RPM fix statements.

CSAF product relationships are resolved by IDs, not by parsing display prose.
No network, version-range inference, source-to-binary expansion or OVAL engine.
"""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from urllib.parse import parse_qsl, unquote, urlsplit

from defusedxml import ElementTree as ET

from api.services import rpm_identity
from api.services.advisories.rpm import cve_id


def text(value: object, label: str, limit: int = 1024) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"invalid {label}")
    if any(ord(c) < 32 for c in value):
        raise ValueError(f"control character in {label}")
    value.encode("utf-8")
    return value.strip()


def sequence(value: object, label: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"expected {label} list")
    return value


def mapping(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"expected {label} object")
    return value


def ids(value: object) -> set[str]:
    return {text(v, "product ID") for v in sequence(value, "product IDs")}


def timestamp(value: object) -> str:
    """Keep the vendor timestamp; a fetch time is not a feed publication date."""
    raw = text(value, "vendor publication date", 64)
    date = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    # updateinfo commonly has a UTC date without an explicit timezone.
    if date.tzinfo is None:
        date = date.replace(tzinfo=UTC)
    return date.astimezone(UTC).isoformat().replace("+00:00", "Z")


def severity(value: object) -> str:
    return {
        "critical": "critical", "important": "high", "high": "high",
        "moderate": "medium", "medium": "medium", "low": "low",
    }.get(str(value or "").strip().lower(), "unknown")


def _unique_json(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def parse_json(content: bytes) -> dict:
    return mapping(json.loads(content.decode("utf-8"), object_pairs_hook=_unique_json), "document")


def _products(tree: dict) -> dict[str, dict]:
    products: dict[str, dict] = {}
    pending = [(b, 0) for b in sequence(tree.get("branches", []), "branches")]
    visited = 0
    while pending:
        branch, depth = pending.pop()
        mapping(branch, "branch")
        visited += 1
        if visited > 200_000 or depth > 64:
            raise ValueError("CSAF product tree exceeds limits")
        product = branch.get("product")
        if product is not None:
            mapping(product, "product")
            key = text(product.get("product_id"), "product ID")
            if key in products and products[key] != product:
                raise ValueError("ambiguous CSAF product ID")
            products[key] = product
        pending.extend((b, depth + 1) for b in sequence(branch.get("branches", []), "branches"))
    for product in sequence(tree.get("full_product_names", []), "full product names"):
        mapping(product, "product")
        key = text(product.get("product_id"), "product ID")
        if key in products and products[key] != product:
            raise ValueError("ambiguous CSAF product ID")
        products[key] = product
    return products


def _validate_platform(product: dict, *, vendor: str, release: str) -> None:
    """Require the declared vendor/release; channel choice stays explicit policy."""
    helper = mapping(product.get("product_identification_helper", {}), "platform helper")
    cpe = text(helper.get("cpe"), "platform CPE")
    if vendor == "rhel":
        # RHEL base and EUS/E4S are distinct bindings, never inferred from a host.
        match = re.fullmatch(r"cpe:/[ao]:redhat:(?:enterprise_linux|rhel(?:_eus|_e4s|_aus)?):([^:]+)(?::.*)?", cpe)
        if match is None or not (
            match[1] == release or ("." not in match[1] and match[1] == release.split(".")[0])
        ):
            raise ValueError("RHEL product/release does not match the binding")
    else:
        match = re.fullmatch(r"cpe:/o:suse:sles:(12|15|16)(?::sp([0-9]+))?(?::.*)?", cpe)
        version = f"{match[1]}.{int(match[2])}" if match and match[2] else (match[1] if match else None)
        if version != release:
            raise ValueError("SLES product/service pack does not match the binding")


def _rpm_component(product: dict, *, vendor: str) -> tuple[str, str, str] | None:
    helper = mapping(product.get("product_identification_helper", {}), "component helper")
    purl = helper.get("purl")
    if purl:
        parsed = urlsplit(text(purl, "RPM purl", 2048))
        parts = parsed.path.split("/")
        if parsed.scheme != "pkg" or len(parts) != 3 or parts[0] != "rpm":
            return None  # oci/rpmmod are not binary RPM statements.
        expected = "redhat" if vendor == "rhel" else "suse"
        if unquote(parts[1]) != expected or parsed.fragment or parsed.netloc:
            raise ValueError("RPM purl namespace mismatch")
        name_version = parts[2].split("@")
        if len(name_version) != 2:
            return None  # Unversioned VEX/source status is not a fix threshold.
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
        if len({key for key, _ in pairs}) != len(pairs):
            raise ValueError("duplicate RPM purl qualifier")
        qualifiers = dict(pairs)
        # Unknown qualifiers may change applicability; never discard them.
        if set(qualifiers) - {"arch", "epoch", "upstream"}:
            raise ValueError("unsupported RPM purl qualifier")
        arch = qualifiers.get("arch")
        if arch in ("src", "nosrc"):
            return None
        if arch not in rpm_identity.RPM_ARCHES:
            raise ValueError("missing/unsupported binary RPM architecture")
        name, fixed = map(unquote, name_version)
        epoch = qualifiers.get("epoch")
        if epoch is not None:
            if not re.fullmatch(r"[0-9]{1,10}", epoch) or ":" in fixed:
                raise ValueError("ambiguous RPM epoch")
            fixed = f"{int(epoch)}:{fixed}"
        fixed = rpm_identity.canonical_evr(fixed)
        # Vendor leaves use NEVRA names too. Cross-check any explicit epoch so
        # a malformed purl cannot silently reset a non-zero epoch to zero.
        display = str(product.get("name") or "")
        prefix, suffix = f"{name}-", f".{arch}"
        if display.startswith(prefix) and display.endswith(suffix):
            named_evr = display[len(prefix):-len(suffix)]
            if rpm_identity.canonical_evr(named_evr) != fixed:
                raise ValueError("RPM purl and NEVRA disagree")
    else:
        # Older SUSE documents may carry only a NEVRA leaf. Strictly split
        # from the right; names can contain hyphens, version/release cannot.
        raw = text(product.get("name"), "RPM NEVRA")
        nvra, separator, arch = raw.rpartition(".")
        if separator and arch in ("src", "nosrc"):
            return None
        if vendor != "suse" or arch not in rpm_identity.RPM_ARCHES:
            return None
        pieces = nvra.rsplit("-", 2)
        if len(pieces) != 3:
            raise ValueError("invalid RPM NEVRA")
        name, version, revision = pieces
        fixed = rpm_identity.canonical_evr(f"{version}-{revision}")
    if not rpm_identity.valid_name(name):
        raise ValueError("invalid binary RPM name")
    return name, fixed, arch


def normalize_csaf(payload: dict, *, vendor: str, release: str, product_ids: set[str],
                   source_url: str, source_sha256: str) -> list[dict]:
    """Import released fixes for selected CSAF platform IDs, not entire families."""
    document = mapping(payload.get("document"), "CSAF document")
    if document.get("csaf_version") != "2.0":
        raise ValueError("unsupported CSAF version")
    publisher = mapping(document.get("publisher"), "publisher")
    host = urlsplit(text(publisher.get("namespace"), "publisher namespace")).hostname
    expected = {"redhat.com", "www.redhat.com"} if vendor == "rhel" else {"suse.com", "www.suse.com"}
    if publisher.get("category") != "vendor" or host not in expected:
        raise ValueError("unexpected CSAF publisher")
    tracking = mapping(document.get("tracking"), "tracking")
    if tracking.get("status") != "final":
        raise ValueError("only final vendor advisories may be imported")
    advisory = text(tracking.get("id"), "advisory ID", 256)
    updated = timestamp(tracking.get("current_release_date"))
    tree = mapping(payload.get("product_tree"), "product tree")
    products = _products(tree)
    if not product_ids or not product_ids.issubset(products):
        raise ValueError("selected CSAF platform ID is absent")
    for key in product_ids:
        _validate_platform(products[key], vendor=vendor, release=release)
    targets: dict[str, tuple[str, tuple[str, str, str] | None]] = {}
    for relationship in sequence(tree.get("relationships", []), "relationships"):
        mapping(relationship, "relationship")
        parent = text(relationship.get("relates_to_product_reference"), "platform reference")
        if parent not in product_ids:
            continue
        if relationship.get("category") != "default_component_of":
            raise ValueError("unsupported selected CSAF relationship")
        component = products.get(text(relationship.get("product_reference"), "component reference"))
        if component is None:
            raise ValueError("dangling CSAF component reference")
        key = text(mapping(relationship.get("full_product_name"), "full product name").get("product_id"), "relationship ID")
        value = (parent, _rpm_component(component, vendor=vendor))
        if key in targets and targets[key] != value:
            raise ValueError("ambiguous CSAF relationship")
        targets[key] = value
    rows = []
    for vulnerability in sequence(payload.get("vulnerabilities", []), "vulnerabilities"):
        mapping(vulnerability, "vulnerability")
        if not vulnerability.get("cve"):
            continue
        cve = cve_id(vulnerability["cve"])
        statuses = mapping(vulnerability.get("product_status", {}), "product status")
        fixed_ids = ids(statuses.get("fixed", [])) | ids(statuses.get("first_fixed", []))
        if vendor == "suse":
            vendor_fixes: set[str] = set()
            for remediation in sequence(vulnerability.get("remediations", []), "remediations"):
                mapping(remediation, "remediation")
                if remediation.get("category") == "vendor_fix":
                    vendor_fixes |= ids(remediation.get("product_ids", []))
            fixed_ids |= ids(statuses.get("recommended", [])) & vendor_fixes
        conflicts = set().union(*(ids(statuses.get(key, [])) for key in
                                  ("known_affected", "known_not_affected", "under_investigation")))
        if fixed_ids & conflicts & targets.keys():
            raise ValueError("conflicting selected CSAF statuses")
        impacts = [severity(t.get("details")) for t in sequence(vulnerability.get("threats", []), "threats")
                   if isinstance(t, dict) and t.get("category") == "impact" and not t.get("product_ids")]
        rank = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        impact = max(impacts, key=rank.get) if impacts else severity(document.get("aggregate_severity", {}).get("text"))
        for key in sorted(fixed_ids & targets.keys()):
            platform, component = targets[key]
            if component is None:
                continue
            name, fixed, arch = component
            rows.append(dict(
                advisory_id=advisory, cve_ids=[cve], release=release, source_package=name,
                fixed_version=fixed, architecture=arch, state="resolved", severity=impact,
                product_id=platform, source_url=source_url, source_sha256=source_sha256,
                source_updated=updated,
            ))
    return rows


def normalize_alas(content: bytes, *, release: str, repository: str,
                   source_url: str, source_sha256: str) -> list[dict]:
    """ALAS core updateinfo; Extras/livepatch need collector channel context."""
    if repository != "core" or release not in ("2", "2023"):
        raise ValueError("ALAS requires an explicit AL2/AL2023 core repository binding")
    root = ET.fromstring(content, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    if root.tag != "updates":
        raise ValueError("expected updateinfo.xml updates root")
    rows = []
    for update in root.findall("update"):
        if update.get("status", "final") != "final" or update.get("type") != "security":
            continue
        advisory = text(update.findtext("id"), "advisory ID", 256)
        refs = {cve_id(r.get("id")) for r in update.findall("references/reference") if r.get("type") == "cve"}
        if not refs:
            continue
        stamp = update.find("updated")
        if stamp is None:
            stamp = update.find("issued")
        updated = timestamp(stamp.get("date") if stamp is not None else None)
        for collection in update.findall("pkglist/collection"):
            if collection.find("module") is not None:
                raise ValueError("ALAS modular update requires module context")
            for package in collection.findall("package"):
                arch = package.get("arch")
                if arch in ("src", "nosrc"):
                    continue
                name = text(package.get("name"), "binary RPM name", 256)
                if name.startswith("kernel-livepatch-"):
                    raise ValueError("livepatch metadata is not a core package fix threshold")
                epoch = package.get("epoch", "0")
                if not re.fullmatch(r"[0-9]{1,10}", epoch):
                    raise ValueError("invalid ALAS epoch")
                fixed = rpm_identity.canonical_evr(f"{epoch}:{text(package.get('version'), 'version')}-{text(package.get('release'), 'release')}")
                # Reject cross-major metadata even if the manifest was mistyped.
                suffix = r"\.amzn2(?:\.|$)" if release == "2" else r"\.amzn2023(?:\.|$)"
                if not re.search(suffix, fixed) or arch not in rpm_identity.RPM_ARCHES or not rpm_identity.valid_name(name):
                    raise ValueError("ALAS package does not match the release/architecture binding")
                rows.append(dict(
                    advisory_id=advisory, cve_ids=sorted(refs), release=release,
                    source_package=name, fixed_version=fixed, architecture=arch,
                    state="resolved", severity=severity(update.findtext("severity")),
                    product_id=f"amazonlinux:{release}:{repository}", source_url=source_url,
                    source_sha256=source_sha256, source_updated=updated,
                ))
    return rows
