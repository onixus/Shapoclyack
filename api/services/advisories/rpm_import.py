"""Bounded, offline, atomic import of operator-verified vendor advisory files."""
from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import json
import os
import stat
import tempfile
from pathlib import Path

from api.services import rpm_identity
from api.services.advisories import rpm, rpm_normalize as normalize

MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_SOURCES = 4096
VENDORS = {"rhel": ("rhel", "redhat-csaf"), "suse": ("sles", "suse-csaf"),
           "alas": ("amazonlinux", "amazon-alas")}


def _read(path: Path, limit: int) -> bytes:
    # Refuse FIFOs/devices and final symlinks without blocking on them.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("advisory input must be a regular file")
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ValueError("advisory input exceeds size limit")
    return content


def _source(root: Path, relative: object) -> Path:
    path = Path(normalize.text(relative, "source path"))
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("source path must stay within the manifest directory")
    selected = root
    for part in path.parts:
        selected /= part
        if selected.is_symlink():
            raise ValueError("advisory source symlinks are not accepted")
    if not selected.resolve().is_relative_to(root):
        raise ValueError("advisory source escapes the manifest directory")
    return selected


def _expand(content: bytes, path: Path) -> bytes:
    if path.suffix not in (".gz", ".bz2"):
        return content
    with (gzip.GzipFile(fileobj=io.BytesIO(content)) if path.suffix == ".gz"
          else bz2.BZ2File(io.BytesIO(content))) as stream:
        result = stream.read(MAX_SOURCE_BYTES + 1)
    if len(result) > MAX_SOURCE_BYTES:
        raise ValueError("expanded advisory exceeds size limit")
    return result


def import_manifest(manifest_path: Path, output: Path, *, min_entries: int = 1,
                    allow_shrink: bool = False) -> dict[str, object]:
    """Build a complete replacement offline. Any error leaves the old file intact.

    URLs are provenance only. Source digests must come from an independently
    verified vendor/mirror manifest; this importer does not verify signatures.
    """
    manifest = normalize.parse_json(_read(manifest_path, 1024 * 1024))
    if (type(manifest.get("version")) is not int or manifest["version"] != 1
            or not isinstance(manifest.get("vendor"), str) or manifest["vendor"] not in VENDORS):
        raise ValueError("unsupported RPM import manifest")
    vendor = manifest["vendor"]
    distro, provider = VENDORS[vendor]
    sources = normalize.sequence(manifest.get("sources"), "sources")
    if not sources or len(sources) > MAX_SOURCES or min_entries < 1:
        raise ValueError("invalid source count or minimum entry count")
    root = manifest_path.parent.resolve()
    entries: list[dict] = []
    total = 0
    inputs = {manifest_path.resolve()}
    for source in sources:
        normalize.mapping(source, "source")
        path = _source(root, source.get("path"))
        inputs.add(path.resolve())
        content = _read(path, MAX_SOURCE_BYTES)
        digest = hashlib.sha256(content).hexdigest()
        if source.get("sha256") != digest:
            raise ValueError("source checksum mismatch")
        url = rpm.public_url(source.get("url"))
        release = normalize.text(source.get("release"), "release")
        if rpm_identity.release_id(distro, release) != release:
            raise ValueError("source needs a canonical release binding")
        expanded = _expand(content, path)
        total += len(content) + len(expanded)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("advisory import exceeds total size limit")
        if vendor == "alas":
            rows = normalize.normalize_alas(
                expanded, release=release, repository=source.get("repository"),
                source_url=url, source_sha256=digest,
            )
        else:
            rows = normalize.normalize_csaf(
                normalize.parse_json(expanded), vendor=vendor, release=release,
                product_ids=normalize.ids(source.get("product_ids")),
                source_url=url, source_sha256=digest,
            )
        entries.extend(rows)
        if len(entries) > rpm.MAX_RECORDS:
            raise ValueError("too many advisory records")
    if output.resolve() in inputs or output.is_symlink():
        raise ValueError("output must not replace an input or symlink")
    # Identical source bindings are idempotent and deterministic.
    entries = [json.loads(row) for row in sorted({json.dumps(r, sort_keys=True) for r in entries})]
    if len(entries) < min_entries:
        raise ValueError("too few supported fix statements; previous dataset retained")
    for entry in entries:
        rpm.coerce_record(entry, provider=provider, distro=distro)
    if output.exists():
        try:
            old_header = normalize.parse_json(_read(output, rpm.MAX_DATASET_BYTES))
        except (ValueError, UnicodeError, RecursionError):
            old_header = {}  # A good import may repair a damaged dataset.
        if old_header.get("format") == rpm.FORMAT and old_header.get("vendor") != distro:
            raise ValueError("output belongs to a different vendor")
    previous = rpm.load_rpm_dataset(output, provider=provider, distro=distro)
    coverage = {(r["release"], r["source_package"], r["architecture"], r["product_id"], c)
                for r in entries for c in r["cve_ids"]}
    prior = {(r.release, r.source_package, r.architecture, r.product_id, c)
             for r in previous.records for c in r.cve_ids}
    if not allow_shrink and prior - coverage:
        raise ValueError("import would drop existing coverage; review and use --allow-shrink explicitly")
    payload = dict(format=rpm.FORMAT, version=1, vendor=distro, source=provider,
                   updated=max(r["source_updated"] for r in entries),
                   origin_urls=sorted({r["source_url"] for r in entries}), entries=entries)
    encoded = (json.dumps(payload, indent=2, ensure_ascii=True) + "\n").encode()
    if len(encoded) > rpm.MAX_DATASET_BYTES:
        raise ValueError("normalised dataset exceeds size limit")
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=output.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        # Check with the runtime loader before publishing. Private mode 0600
        # is intentional; deployment grants the API read access explicitly.
        verified = rpm.load_rpm_dataset(Path(name), provider=provider, distro=distro)
        if verified.error or len(verified.records) != len(entries):
            raise ValueError("normalised dataset failed runtime validation")
        os.replace(name, output)
    finally:
        Path(name).unlink(missing_ok=True)
    return {"vendor": distro, "entries": len(entries), "releases": sorted({r["release"] for r in entries}),
            "source_files": len(sources), "sha256": hashlib.sha256(encoded).hexdigest()}
