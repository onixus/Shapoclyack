"""Offline binary-RPM advisories, using the existing provider cache/registry.

The versioned dataset is produced by rpm_import, not by weakening the Debian
source-package format. Product selection is operator-owned and recorded on
every statement. Missing architecture/channel/package evidence stays unknown.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from api.services import rpm_identity
from api.services.advisories.base import AdvisoryDataset, AdvisoryRecord, JsonAdvisoryProvider

FORMAT = "octo.rpm_advisories.v1"
MAX_DATASET_BYTES = 256 * 1024 * 1024
MAX_RECORDS = 1_000_000


@dataclass(frozen=True)
class RpmAdvisoryRecord(AdvisoryRecord):
    architecture: str = ""
    product_id: str = ""
    source_sha256: str = ""
    source_url: str = ""
    source_updated: str = ""


def public_url(value: object) -> str:
    """A provenance link, never an instruction to fetch or an embedded secret."""
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("invalid provenance URL")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or any(ord(c) < 32 for c in value)):
        raise ValueError("provenance requires a public HTTPS URL without credentials or query")
    return value


def cve_id(value: object) -> str:
    import re
    if not isinstance(value, str) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", value) or len(value) > 64:
        raise ValueError("invalid CVE identifier")
    return value


def _text(raw: dict, key: str, limit: int = 256) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 for c in value):
        raise ValueError(f"invalid RPM advisory field: {key}")
    value.encode("utf-8")
    return value


def coerce_record(raw: object, *, provider: str, distro: str) -> RpmAdvisoryRecord:
    if not isinstance(raw, dict) or raw.get("state") != "resolved":
        raise ValueError("RPM dataset accepts released fix thresholds only")
    release = _text(raw, "release")
    if rpm_identity.release_id(distro, release) != release:
        raise ValueError("non-canonical RPM release binding")
    package = _text(raw, "source_package")
    if not rpm_identity.valid_name(package):
        raise ValueError("invalid binary RPM name")
    arch = _text(raw, "architecture")
    if arch not in rpm_identity.RPM_ARCHES:
        raise ValueError("expected binary RPM architecture, not an SRPM")
    if not isinstance(raw.get("cve_ids"), list) or not raw["cve_ids"]:
        raise ValueError("missing CVE identifiers")
    cves = tuple(sorted({cve_id(c) for c in raw["cve_ids"]}))
    fixed = rpm_identity.canonical_evr(_text(raw, "fixed_version"))
    digest = _text(raw, "source_sha256", 64)
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("invalid source SHA-256")
    severity = _text(raw, "severity")
    if severity not in ("critical", "high", "medium", "low", "unknown"):
        raise ValueError("invalid vendor severity")
    updated = _text(raw, "source_updated", 64)
    if datetime.fromisoformat(updated.replace("Z", "+00:00")).tzinfo is None:
        raise ValueError("RPM provenance requires a timezone-qualified timestamp")
    return RpmAdvisoryRecord(
        advisory_id=_text(raw, "advisory_id"), cve_ids=cves, release=release,
        source_package=package, fixed_version=fixed, severity=severity,
        provider=provider, state="resolved", url=public_url(raw.get("source_url")),
        feed_date=updated, architecture=arch,
        product_id=_text(raw, "product_id", 1024), source_sha256=digest,
        source_url=public_url(raw.get("source_url")), source_updated=updated,
    )


def load_rpm_dataset(path: Path, *, provider: str, distro: str) -> AdvisoryDataset:
    """Reject a damaged/misbound dataset as a whole, never partly as clean."""
    try:
        with path.open("rb") as stream:
            content = stream.read(MAX_DATASET_BYTES + 1)
        if len(content) > MAX_DATASET_BYTES:
            raise ValueError("RPM dataset exceeds size limit")
        payload = json.loads(content.decode("utf-8"))
        if (not isinstance(payload, dict) or payload.get("format") != FORMAT
                or payload.get("vendor") != distro or type(payload.get("version")) is not int
                or payload["version"] != 1):
            raise ValueError("wrong RPM dataset vendor or schema")
        entries = payload.get("entries")
        if not isinstance(entries, list) or len(entries) > MAX_RECORDS:
            raise ValueError("invalid RPM entry list")
        records = tuple(coerce_record(r, provider=provider, distro=distro) for r in entries)
        index: dict[tuple[str, str], list[RpmAdvisoryRecord]] = {}
        for record in records:
            index.setdefault((record.release, record.source_package), []).append(record)
        canonical = sorted(json.dumps(asdict(r), sort_keys=True, separators=(",", ":")) for r in records)
        return AdvisoryDataset(
            source=provider, updated=str(payload.get("updated") or "") or None,
            present=True, records=records, index={k: tuple(v) for k, v in index.items()},
            releases=tuple(sorted({r.release for r in records})),
            digest=hashlib.sha256("\n".join(canonical).encode()).hexdigest()[:16],
        )
    except FileNotFoundError:
        return AdvisoryDataset(error="missing")
    except (OSError, ValueError, UnicodeError, RecursionError):
        return AdvisoryDataset(present=True, error="invalid or unreadable RPM advisory dataset")


class RpmAdvisoryProvider(JsonAdvisoryProvider):
    case_sensitive_packages = True

    def _load_dataset(self, path: Path) -> AdvisoryDataset:
        return load_rpm_dataset(path, provider=self.name, distro=self.distro)


def select_records(identity, provider) -> tuple[tuple[RpmAdvisoryRecord, ...], str | None]:
    """Do not generalise an SRPM, architecture or module into another subject."""
    arch = rpm_identity.architecture(identity.architecture)
    if arch is None:
        return (), "rpm_architecture_unknown"
    if ".module" in (identity.version or ""):
        return (), "rpm_module_context_required"
    records = provider.advisories_for(release=identity.distro_release or "", source_package=identity.name)
    if not records:
        return (), "rpm_package_not_covered"
    if any(not isinstance(r, RpmAdvisoryRecord) for r in records):
        return (), "rpm_advisory_context_missing"
    selected = tuple(r for r in records if r.architecture == arch)
    if not selected:
        return (), "rpm_architecture_not_covered"
    if any(".module" in (r.fixed_version or "") for r in selected):
        return (), "rpm_module_context_required"
    # Multiple branch-specific fixed EVRs for one binary/CVE must not be
    # reduced to min/max. The inventory does not carry module/channel identity.
    fixes: dict[str, set[str | None]] = {}
    for record in selected:
        for cve in record.cve_ids:
            fixes.setdefault(cve, set()).add(record.fixed_version)
    if any(len(versions) > 1 for versions in fixes.values()):
        return (), "rpm_advisory_ambiguous"
    return selected, None
