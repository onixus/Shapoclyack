#!/usr/bin/env python3
"""Export, verify and import an independently trusted Mac CPU operator bundle.

Standard library only. Verification performs no Docker operation. Import never
overwrites a directory; fresh startup uses a new private Compose project.
"""
from __future__ import annotations

import argparse
import codecs
from datetime import UTC, datetime
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent.parent
HASH = re.compile(r"[a-f0-9]{64}")
REVISION = re.compile(r"[a-f0-9]{40}")
IMAGE_ID = re.compile(r"sha256:[a-f0-9]{64}")
IMAGE = re.compile(r"(?:sha256:[a-f0-9]{64}|[a-z0-9][a-z0-9._/:-]*:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64})")
MAX_TOTAL = 32 * 1024**3
MAX_FILE = 16 * 1024**3
MAX_TREE = 1024**3
MAX_FEED_TREE = 4 * 1024**3  # Same expanded bound as the native enrichment bundle.
MAX_MEMBERS = 30000
CORE = {"source": "source.tar", "ui": "ui.tar", "images": "images.tar",
        "model": "model.gguf", "embedding": "embedding.gguf", "sbom": "sbom.spdx.json",
        "image_sbom": "image-sbom.json", "feeds": "feeds.tar", "feed_inventory": "feed-inventory.json"}
OPTIONAL = {}
FEED_SPECS = {
    "cvss4": ("cvss4/cvss4.json", 1000, True), "epss": ("epss/epss-overlay.json", 1000, True),
    "kev": ("kev/kev-overlay.json", 100, True), "exploit": ("exploit/exploit-overlay.json", 1000, True),
    "advisories_debian": ("advisories/debian-advisories.json", 100000, False),
    "advisories_ubuntu": ("advisories/ubuntu-advisories.json", 10000, False),
    "advisories_msrc": ("advisories/msrc-advisories.json", 5000, False),
    "advisories_rhel": ("advisories/rhel-advisories.json", 1, False),
    "advisories_suse": ("advisories/suse-advisories.json", 1, False),
    "advisories_alas": ("advisories/alas-advisories.json", 1, False),
    "nvd_cpe": ("nvd-cpe/nvd-cpe-ranges.json", 5000, False), "bdu_fstec": ("bdu/bdu-overlay.json", 1000, False),
    "geoip": ("geoip/geoip.mmdb", 0, False), "asn": ("asn/asn.mmdb", 0, False)}
FEED_SUPPORT = {"geoip/geoip.mmdb", "geoip/geoip-overlay.json", "asn/asn.mmdb", "cvss4/cvss4.sha256",
    "wordlists/subdomains-small.txt", "wordlists/bucket-names-small.txt"}
FEED_REQUIRED = {relative for relative, _, required in FEED_SPECS.values() if required}
FEED_ALLOWED = {relative for relative, _, _ in FEED_SPECS.values()} | FEED_SUPPORT | {"enrichment-manifest.json"}
FEED_HEADER_BYTES = 65536
FEED_PARSE_BYTES = 32 * 1024 * 1024
FEED_ADMIN_FILES = {".enrichment-bundle.lock", "enrichment-bundle.json", "enrichment-bundle-history.jsonl"}
SOURCE_FILES = {"api/app.py", "api/db/migrate.py", "scanner/config/default.yaml", "scripts/operator-console-proxy.py"}
MANIFEST_KEYS = {"schema_version", "kind", "platform", "source_revision", "ui_source_revision",
    "runtime_reference", "runtime_revision", "image_ids", "model", "model_revision", "embedding", "embedding_revision", "context_tokens",
    "parallel", "artifacts", "created_at", "feed_status", "sbom_scope"}


class BundleError(ValueError):
    """Stable, sanitized CLI boundary."""


def run(args, *, timeout=900):
    result = subprocess.run(args, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise BundleError("bundle_command_failed_" + Path(args[0]).name)
    return result.stdout


def digest(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise BundleError("bundle_duplicate_json_key")
        value[key] = item
    return value


def regular(root, name):
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9.-]{0,95}", name):
        raise BundleError("bundle_invalid_path")
    path = root / name
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise BundleError("bundle_not_regular")
    return path


def checked_hash(value):
    if not HASH.fullmatch(value):
        raise argparse.ArgumentTypeError("A lowercase SHA-256 from trusted metadata is required")
    return value


def checked_image(value):
    if not IMAGE.fullmatch(value):
        raise argparse.ArgumentTypeError("Use a local image ID or name:tag@sha256 digest")
    return value


def checked_port(value):
    port = int(value)
    if not 1024 <= port <= 65535:
        raise argparse.ArgumentTypeError("Use an unprivileged port")
    return port


def checked_subnet(value):
    try:
        network = ipaddress.ip_network(value, strict=True)
        allowed = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        if network.version != 4 or network.prefixlen != 24 or not any(network.subnet_of(ipaddress.ip_network(a)) for a in allowed):
            raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError("Use a private IPv4 /24 subnet") from None
    return str(network)


def archive_members(path, *, limit=MAX_TREE):
    """Validate uncompressed tar headers without writing or following links."""
    seen, files, total = set(), set(), 0
    try:
        with tarfile.open(path, "r:") as archive:
            for count, member in enumerate(archive, 1):
                if count > MAX_MEMBERS:
                    raise BundleError("bundle_archive_members_exceeded")
                name = member.name.rstrip("/") if member.isdir() else member.name
                parts = PurePosixPath(name).parts
                if (not name or len(name) > 512 or name.startswith("/") or "\\" in name
                        or any(ord(char) < 32 or ord(char) == 127 for char in name)
                        or any(part in {"", ".", ".."} for part in name.split("/"))
                        or PurePosixPath(name).as_posix() != name or name in seen
                        or not (member.isfile() or member.isdir())):
                    raise BundleError("bundle_archive_unsafe_member")
                if any(PurePosixPath(*parts[:i]).as_posix() in files for i in range(1, len(parts))):
                    raise BundleError("bundle_archive_file_parent")
                if member.isfile():
                    if any(previous.startswith(name + "/") for previous in seen):
                        raise BundleError("bundle_archive_file_parent")
                    files.add(name)
                    total += member.size
                    if member.size < 0 or member.size > limit or total > limit:
                        raise BundleError("bundle_archive_size_exceeded")
                seen.add(name)
        return {"members": len(seen), "expanded_bytes": total, "files": sorted(files)}
    except (tarfile.TarError, OSError, EOFError):
        raise BundleError("bundle_archive_invalid") from None


def extract(path, target, *, limit=MAX_TREE):
    archive_members(path, limit=limit)
    target.mkdir(mode=0o755)
    with tarfile.open(path, "r:") as archive:
        archive.extractall(target, filter="data")


def tree_archive(source, target, *, limit=MAX_TREE):
    source = Path(source)
    if source.is_symlink() or not source.is_dir():
        raise BundleError("bundle_source_tree_invalid")
    total, count = 0, 0
    with tarfile.open(target, "w:") as archive:
        for path in sorted(source.rglob("*")):
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise BundleError("bundle_source_tree_symlink_or_special")
            count += 1
            if count > MAX_MEMBERS:
                raise BundleError("bundle_archive_members_exceeded")
            if path.is_file():
                total += path.stat().st_size
                if total > limit:
                    raise BundleError("bundle_archive_size_exceeded")
            info = archive.gettarinfo(str(path), path.relative_to(source).as_posix())
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            info.mode = 0o755 if path.is_dir() else 0o644
            if path.is_file():
                with path.open("rb") as handle:
                    archive.addfile(info, handle)
            else:
                archive.addfile(info)
    archive_members(target, limit=limit)


def image_info(reference):
    if not IMAGE.fullmatch(reference):
        raise BundleError("bundle_image_reference_invalid")
    value = json.loads(run(["docker", "image", "inspect", reference], timeout=30))[0]
    if not IMAGE_ID.fullmatch(value["Id"]) or value["Os"] != "linux" or value["Architecture"] != "arm64":
        raise BundleError("bundle_image_platform_mismatch")
    return value


def copy_checked(source, target, expected=None):
    source = Path(source)
    if source.is_symlink() or not stat.S_ISREG(source.stat().st_mode):
        raise BundleError("bundle_input_not_regular")
    if not 0 < source.stat().st_size <= MAX_FILE:
        raise BundleError("bundle_file_size_invalid")
    result = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    written = 0
    with os.fdopen(descriptor, "rb") as incoming, target.open("xb") as outgoing:
        while chunk := incoming.read(1024 * 1024):
            written += len(chunk)
            if written > MAX_FILE:
                raise BundleError("bundle_file_size_invalid")
            result.update(chunk)
            outgoing.write(chunk)
    target.chmod(0o444)
    if expected is not None and result.hexdigest() != expected:
        raise BundleError("bundle_input_hash_mismatch")
    return result.hexdigest()


def artifact(root, role, name):
    path = regular(root, name)
    return {"role": role, "path": name, "size": path.stat().st_size, "sha256": digest(path)}


def feed_freshness(updated, now):
    """The data stamp alone establishes age; packaging time never supplies it."""
    if not isinstance(updated, str) or not updated or len(updated) > 64:
        return "unknown"
    try:
        stamp = datetime.fromisoformat(updated.replace("Z", "+00:00"))
        stamp = stamp.replace(tzinfo=UTC) if stamp.tzinfo is None else stamp.astimezone(UTC)
    except ValueError:
        return "unknown"
    days = (now - stamp).total_seconds() / 86400
    return "unknown" if days < -1 else "stale" if days > 30 else "fresh_by_feed_date_only"


def feed_header(raw):
    """Parse only bounded top-level JSON metadata, stopping before entries."""
    text = codecs.getincrementaldecoder("utf-8")().decode(raw, final=False)
    decoder = json.JSONDecoder(object_pairs_hook=unique)
    position, values = 0, {}
    def whitespace():
        nonlocal position
        while position < len(text) and text[position].isspace():
            position += 1
    whitespace()
    if position >= len(text) or text[position] != "{":
        raise ValueError("JSON feed object required")
    position += 1
    while position < len(text):
        whitespace()
        key, position = decoder.raw_decode(text, position)
        if not isinstance(key, str) or key in values:
            raise ValueError("Duplicate feed metadata")
        whitespace()
        if position >= len(text) or text[position] != ":":
            raise ValueError("Invalid feed header")
        position += 1
        whitespace()
        if key == "entries":
            if position >= len(text) or text[position] not in "[{":
                raise ValueError("Feed entries required")
            end = "}" if text[position] == "{" else "]"
            position += 1
            whitespace()
            return values, position < len(text) and text[position] != end
        value, position = decoder.raw_decode(text, position)
        values[key] = value
        whitespace()
        if position >= len(text) or text[position] != ",":
            raise ValueError("Bounded feed entries unavailable")
        position += 1
    raise ValueError("Bounded feed entries unavailable")


def inspect_feed(path, *, minimum, origin, now):
    with path.open("rb") as handle:
        header, nonempty = feed_header(handle.read(FEED_HEADER_BYTES))
    count, checked = None, False
    if path.stat().st_size <= FEED_PARSE_BYTES:
        content = json.loads(path.read_bytes(), object_pairs_hook=unique)
        entries = content.get("entries") if isinstance(content, dict) else None
        count = len(entries) if isinstance(entries, (list, dict)) else None
        checked = count is not None
        header = content
    source = header.get("source")
    source = source if isinstance(source, str) and re.fullmatch(r"[A-Za-z0-9_.+ -]{1,128}", source) else None
    updated = header.get("updated") if isinstance(header.get("updated"), str) and len(header["updated"]) <= 64 else None
    seed = bool(source and "seed" in source.lower()) or origin == "seed"
    return {"source": source, "updated": updated, "origin": origin, "entries": count,
        "entry_count_checked": checked, "min_entries": minimum, "nonempty": nonempty,
        "usable": bool(checked and count >= minimum), "freshness_at_snapshot": feed_freshness(updated, now),
        "coverage": "seed_or_unknown" if seed or not checked or count < minimum else "not_assessed"}


def stage_feeds(source, destination, inventory_path):
    """Snapshot native local data only; never write or refresh the input tree."""
    source, destination = Path(source), Path(destination)
    if source.is_symlink() or not source.is_dir() or destination.exists():
        raise BundleError("bundle_feed_source_invalid")
    files = []
    for path in source.rglob("*"):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise BundleError("bundle_feed_source_unsafe")
        if path.is_file() and path.relative_to(source).as_posix() not in FEED_ADMIN_FILES:
            relative = path.relative_to(source).as_posix()
            if relative not in FEED_ALLOWED:
                raise BundleError("bundle_feed_file_unsupported")
            files.append((path, relative))
    names = {relative for _, relative in files}
    if not FEED_REQUIRED.issubset(names) or "enrichment-manifest.json" not in names:
        raise BundleError("bundle_feed_required_file_missing")
    if sum(path.stat().st_size for path, _ in files) > MAX_FEED_TREE:
        raise BundleError("bundle_feed_tree_too_large")
    previous_path = source / "enrichment-manifest.json"
    if previous_path.stat().st_size > 262144:
        raise BundleError("bundle_feed_manifest_too_large")
    try:
        previous = json.loads(previous_path.read_bytes(), object_pairs_hook=unique)["datasets"]
        if not isinstance(previous, dict):
            raise ValueError
    except (ValueError, KeyError, TypeError, RecursionError):
        raise BundleError("bundle_feed_manifest_invalid") from None
    destination.mkdir(mode=0o700)
    for path, relative in files:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        copy_checked(path, target)
    now, datasets = datetime.now(UTC), {}
    for name, (relative, minimum, required) in FEED_SPECS.items():
        path = destination / relative
        record = {"path": relative, "required": required, "present": path.is_file()}
        if path.is_file():
            before = previous.get(name) or {}
            origin = before.get("origin") if isinstance(before, dict) else None
            origin = origin if origin in {"seed", "fetch", "cached", "stale", "bundle"} else "unknown"
            try:
                if path.suffix == ".mmdb":
                    raise ValueError("Binary coverage is not established by JSON inspection")
                record.update(inspect_feed(path, minimum=minimum, origin=origin, now=now))
            except (ValueError, TypeError, RecursionError, UnicodeError):
                if required:
                    raise BundleError("bundle_feed_header_invalid") from None
                record.update(source=None, updated=None, origin=origin, usable=False, freshness_at_snapshot="unknown", coverage="unknown")
            carried = before.get("source_origin") if isinstance(before, dict) else None
            if carried in {"seed", "fetch", "cached", "stale", "bundle", "missing", "unknown"}:
                record["source_origin"] = carried
            if required and not record.get("nonempty"):
                raise BundleError("bundle_feed_required_dataset_empty")
        else:
            record.update(usable=False, freshness_at_snapshot="unknown", coverage="missing")
        datasets[name] = record
    regenerated = {"generated_at": now.isoformat(), "datasets": {
        name: {**record, "path": "/app/scanner/data/" + record["path"]} for name, record in datasets.items()},
        "inspection": "bounded local source data; packaging time is not feed date; no coverage completeness assertion"}
    manifest_path = destination / "enrichment-manifest.json"
    manifest_path.chmod(0o600)
    manifest_path.write_text(json.dumps(regenerated, sort_keys=True, indent=2) + "\n")
    manifest_path.chmod(0o444)
    inventory = {"schema_version": 1, "captured_at": now.isoformat(), "freshness_max_age_days": 30,
        "coverage_complete": False, "datasets": datasets,
        "files": [{"path": path.relative_to(destination).as_posix(), "size": path.stat().st_size, "sha256": digest(path)}
            for path in sorted(destination.rglob("*")) if path.is_file()]}
    inventory_path.write_text(json.dumps(inventory, sort_keys=True, indent=2) + "\n")
    inventory_path.chmod(0o444)
    return inventory


def verify_feeds(archive_path, inventory_path):
    archive_members(archive_path, limit=MAX_FEED_TREE)
    if inventory_path.stat().st_size > 262144:
        raise BundleError("bundle_feed_inventory_too_large")
    try:
        value = json.loads(inventory_path.read_bytes(), object_pairs_hook=unique)
        if (set(value) != {"schema_version", "captured_at", "freshness_max_age_days", "coverage_complete", "datasets", "files"}
                or type(value["schema_version"]) is not int or value["schema_version"] != 1
                or value["coverage_complete"] is not False or value["freshness_max_age_days"] != 30
                or not isinstance(value["datasets"], dict) or set(value["datasets"]) != set(FEED_SPECS)):
            raise ValueError
        captured = datetime.fromisoformat(value["captured_at"])
        if captured.tzinfo is None:
            raise ValueError
        records = value["files"]
        metadata_fields = {"path", "required", "present", "source", "updated", "origin", "source_origin", "entries",
            "entry_count_checked", "min_entries", "nonempty", "usable", "freshness_at_snapshot", "coverage"}
        for name, (relative, _, required) in FEED_SPECS.items():
            metadata = value["datasets"][name]
            if (not isinstance(metadata, dict) or set(metadata) - metadata_fields
                    or metadata.get("path") != relative or metadata.get("required") is not required
                    or type(metadata.get("present")) is not bool or type(metadata.get("usable")) is not bool
                    or metadata.get("freshness_at_snapshot") not in {"unknown", "stale", "fresh_by_feed_date_only"}
                    or metadata.get("coverage") not in {"missing", "unknown", "seed_or_unknown", "not_assessed"}
                    or "origin" in metadata and metadata["origin"] not in {"seed", "fetch", "cached", "stale", "bundle", "unknown"}
                    or "source_origin" in metadata and metadata["source_origin"] not in {"seed", "fetch", "cached", "stale", "bundle", "missing", "unknown"}):
                raise ValueError
        if not isinstance(records, list) or not 5 <= len(records) <= len(FEED_ALLOWED):
            raise ValueError
        expected = {}
        for record in records:
            if (not isinstance(record, dict) or set(record) != {"path", "size", "sha256"}
                    or record["path"] not in FEED_ALLOWED or record["path"] in expected
                    or type(record["size"]) is not int or not 0 < record["size"] <= MAX_FEED_TREE
                    or not isinstance(record["sha256"], str) or not HASH.fullmatch(record["sha256"])):
                raise ValueError
            expected[record["path"]] = record
        if not (FEED_REQUIRED | {"enrichment-manifest.json"}).issubset(expected):
            raise ValueError
        seen = set()
        native = {relative: name for name, (relative, _, _) in FEED_SPECS.items()}
        with tarfile.open(archive_path, "r:") as archive:
            for member in archive:
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ValueError
                record = expected.get(member.name)
                if record is None or member.name in seen or member.size != record["size"]:
                    raise ValueError
                seen.add(member.name)
                digest_value, header = hashlib.sha256(), bytearray()
                complete = bytearray() if member.name in native and not member.name.endswith(".mmdb") and member.size <= FEED_PARSE_BYTES or member.name == "enrichment-manifest.json" else None
                with archive.extractfile(member) as handle:
                    while chunk := handle.read(1024 * 1024):
                        digest_value.update(chunk)
                        if len(header) < FEED_HEADER_BYTES:
                            header.extend(chunk[:FEED_HEADER_BYTES - len(header)])
                        if complete is not None:
                            if len(complete) + len(chunk) > FEED_PARSE_BYTES:
                                raise ValueError
                            complete.extend(chunk)
                if digest_value.hexdigest() != record["sha256"]:
                    raise ValueError
                if member.name in native:
                    name = native[member.name]
                    metadata = value["datasets"][name]
                    try:
                        if member.name.endswith(".mmdb"):
                            raise ValueError("Binary coverage remains unknown")
                        actual, nonempty = feed_header(header)
                    except (ValueError, UnicodeError):
                        if (member.name in FEED_REQUIRED or metadata.get("coverage") != "unknown"
                                or metadata.get("usable") is not False or metadata.get("source") is not None
                                or metadata.get("updated") is not None or metadata.get("freshness_at_snapshot") != "unknown"):
                            raise ValueError from None
                        continue
                    count, checked = None, False
                    if complete is not None:
                        content = json.loads(complete, object_pairs_hook=unique)
                        entries = content.get("entries") if isinstance(content, dict) else None
                        count = len(entries) if isinstance(entries, (dict, list)) else None
                        checked = count is not None
                        actual = content
                    source = actual.get("source")
                    source = source if isinstance(source, str) and re.fullmatch(r"[A-Za-z0-9_.+ -]{1,128}", source) else None
                    updated = actual.get("updated") if isinstance(actual.get("updated"), str) and len(actual["updated"]) <= 64 else None
                    if (metadata.get("source") != source or metadata.get("updated") != updated
                            or metadata.get("freshness_at_snapshot") != feed_freshness(updated, captured)
                            or member.name in FEED_REQUIRED and not nonempty):
                        raise ValueError
                    minimum = FEED_SPECS[name][1]
                    coverage = "seed_or_unknown" if (source and "seed" in source.lower()) or metadata.get("origin") == "seed" or not checked or count < minimum else "not_assessed"
                    if (metadata.get("entries") != count or metadata.get("entry_count_checked") is not checked
                            or metadata.get("nonempty") is not nonempty or type(metadata.get("min_entries")) is not int
                            or metadata.get("min_entries") != minimum
                            or metadata.get("usable") is not bool(checked and count >= minimum)
                            or metadata.get("coverage") != coverage):
                        raise ValueError
                elif member.name == "enrichment-manifest.json":
                    enriched = json.loads(complete, object_pairs_hook=unique)
                    projected = {name: {**record, "path": "/app/scanner/data/" + record["path"]}
                        for name, record in value["datasets"].items()}
                    if enriched.get("datasets") != projected or enriched.get("generated_at") != value["captured_at"]:
                        raise ValueError
        if seen != set(expected):
            raise ValueError
        for name, (relative, _, _) in FEED_SPECS.items():
            metadata = value["datasets"][name]
            if metadata.get("path") != relative or metadata.get("present") is not (relative in expected):
                raise ValueError
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError, tarfile.TarError):
        raise BundleError("bundle_feed_inventory_invalid") from None
    return value


def image_sbom(path, image_ids):
    """Require a transitive inventory for every exact image, separate from file BOM."""
    if path.stat().st_size > 64 * 1024 * 1024:
        raise BundleError("bundle_image_sbom_too_large")
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=unique)
        if not isinstance(value, dict) or set(value) != {"schema_version", "images"} or value["schema_version"] != 1:
            raise ValueError
        if not isinstance(value["images"], dict) or set(value["images"]) != set(image_ids.values()):
            raise ValueError
        for inventory in value["images"].values():
            if not isinstance(inventory, dict):
                raise ValueError
            if inventory.get("spdxVersion") in {"SPDX-2.2", "SPDX-2.3"}:
                entries = inventory.get("packages")
            elif inventory.get("bomFormat") == "CycloneDX":
                entries = inventory.get("components")
            else:
                raise ValueError
            if not isinstance(entries, list) or not entries or any(not isinstance(entry, dict) or not entry.get("name") for entry in entries):
                raise ValueError
    except (ValueError, TypeError, RecursionError):
        raise BundleError("bundle_image_sbom_invalid") from None


def export_bundle(args):
    target = args.destination.absolute()
    if target.exists() or target.is_symlink():
        raise BundleError("bundle_destination_exists")
    if not (args.ui / "operator.html").is_file() or not (args.ui / "_next").is_dir():
        raise BundleError("bundle_compiled_ui_missing")
    if args.model.is_symlink() or args.embedding.is_symlink():
        raise BundleError("bundle_input_not_regular")
    if not re.fullmatch(r"ghcr\.io/ggml-org/llama\.cpp:server@sha256:[a-f0-9]{64}", args.runtime_image):
        raise BundleError("bundle_runtime_reference_invalid")
    revision = run(["git", "rev-parse", "--verify", "--end-of-options", args.source_ref + "^{commit}"], timeout=30).decode().strip()
    if (not REVISION.fullmatch(revision) or args.ui_source_revision != revision
            or not REVISION.fullmatch(args.model_revision) or not REVISION.fullmatch(args.embedding_revision)):
        raise BundleError("bundle_source_revision_mismatch")
    images = {role: image_info(reference) for role, reference in {
        "runtime": args.runtime_image, "application": args.app_image, "postgres": args.postgres_image}.items()}
    runtime_revision = images["runtime"].get("Config", {}).get("Labels", {}).get("org.opencontainers.image.revision")
    if not isinstance(runtime_revision, str) or not REVISION.fullmatch(runtime_revision):
        raise BundleError("bundle_runtime_revision_missing")
    image_sbom(args.image_sbom, {role: info["Id"] for role, info in images.items()})
    target.mkdir(mode=0o700)
    try:
        with tempfile.TemporaryDirectory(prefix="operator-feed-stage-") as temporary:
            snapshot = Path(temporary) / "feeds"
            stage_feeds(args.feeds, snapshot, target / "feed-inventory.json")
            tree_archive(snapshot, target / "feeds.tar", limit=MAX_FEED_TREE)
        run(["git", "archive", "--format=tar", "--output=" + str(target / "source.tar"), revision])
        archive_members(target / "source.tar")
        tree_archive(args.ui, target / "ui.tar")
        copy_checked(args.model, target / "model.gguf", args.model_sha256)
        copy_checked(args.embedding, target / "embedding.gguf", args.embedding_sha256)
        for name in ("model.gguf", "embedding.gguf"):
            with (target / name).open("rb") as handle:
                if handle.read(4) != b"GGUF":
                    raise BundleError("bundle_model_format_invalid")
        run(["docker", "image", "save", "--output", str(target / "images.tar"),
            args.runtime_image, args.app_image, args.postgres_image], timeout=1800)
        archive_members(target / "images.tar", limit=MAX_FILE)
        artifacts = [artifact(target, role, name) for role, name in CORE.items() if role not in {"sbom", "image_sbom"}]
        for index, license_file in enumerate(args.license):
            name = f"license-{index:03d}.txt"
            copy_checked(license_file, target / name)
            artifacts.append(artifact(target, "license", name))
        copy_checked(args.image_sbom, target / "image-sbom.json")
        artifacts.append(artifact(target, "image_sbom", "image-sbom.json"))
        sbom = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": "Shapoclyack offline bundle inventory", "documentNamespace": "urn:uuid:" + str(uuid.uuid4()),
            "creationInfo": {"creators": ["Tool: operator-offline-bundle"], "created": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")},
            "files": [{"SPDXID": f"SPDXRef-File-{i}", "fileName": item["path"],
                "checksums": [{"algorithm": "SHA256", "checksumValue": item["sha256"]}],
                "licenseConcluded": "NOASSERTION", "licenseInfoInFiles": ["NOASSERTION"], "copyrightText": "NOASSERTION"}
                for i, item in enumerate(artifacts)]}
        (target / "sbom.spdx.json").write_text(json.dumps(sbom, sort_keys=True, indent=2) + "\n")
        artifacts.append(artifact(target, "sbom", "sbom.spdx.json"))
        manifest = {"schema_version": 1, "kind": "shapoclyack-operator-mac-offline", "platform": "linux/arm64",
            "source_revision": revision, "ui_source_revision": revision, "runtime_reference": args.runtime_image,
            "runtime_revision": runtime_revision, "image_ids": {key: value["Id"] for key, value in images.items()},
            "model": "Qwen3.5-9B-Q4_K_M", "embedding": "Qwen3-Embedding-0.6B-Q8_0",
            "model_revision": args.model_revision, "embedding_revision": args.embedding_revision,
            "context_tokens": 8192, "parallel": 1, "artifacts": artifacts,
            "created_at": datetime.now(UTC).isoformat(),
            "feed_status": "local_snapshot_included_freshness_and_coverage_not_guaranteed",
            "sbom_scope": "bundle_files_and_required_separate_image_inventory"}
        raw = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
        (target / "manifest.json").write_bytes(raw)
        trusted = hashlib.sha256(raw).hexdigest()
        verify_bundle(target, trusted)
        return {"bundle": str(target), "manifest_sha256": trusted, "source_revision": revision,
            "trust_transfer": "Distribute this digest through a separately authenticated channel"}
    except Exception:
        shutil.rmtree(target)
        raise


def verify_bundle(root, trusted):
    if not HASH.fullmatch(trusted):
        raise BundleError("bundle_trusted_digest_required")
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise BundleError("bundle_root_invalid")
    root = root.resolve()
    path = regular(root, "manifest.json")
    if path.stat().st_size > 256 * 1024:
        raise BundleError("bundle_manifest_too_large")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != trusted:
        raise BundleError("bundle_manifest_mismatch")
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, TypeError, RecursionError):
        raise BundleError("bundle_manifest_invalid") from None
    if (not isinstance(value, dict) or set(value) != MANIFEST_KEYS or type(value["schema_version"]) is not int
            or value["schema_version"] != 1 or value["kind"] != "shapoclyack-operator-mac-offline"
            or value["platform"] != "linux/arm64" or not isinstance(value["source_revision"], str)
            or value["feed_status"] != "local_snapshot_included_freshness_and_coverage_not_guaranteed"
            or not REVISION.fullmatch(value["source_revision"]) or value["ui_source_revision"] != value["source_revision"]
            or not isinstance(value["runtime_revision"], str) or not REVISION.fullmatch(value["runtime_revision"])
            or not isinstance(value["runtime_reference"], str)
            or not re.fullmatch(r"ghcr\.io/ggml-org/llama\.cpp:server@sha256:[a-f0-9]{64}", value["runtime_reference"])
            or value["model"] != "Qwen3.5-9B-Q4_K_M" or value["embedding"] != "Qwen3-Embedding-0.6B-Q8_0"
            or any(not isinstance(value[name], str) or not REVISION.fullmatch(value[name]) for name in ("model_revision", "embedding_revision"))
            or type(value["context_tokens"]) is not int or value["context_tokens"] != 8192
            or type(value["parallel"]) is not int or value["parallel"] != 1
            or not isinstance(value["image_ids"], dict) or set(value["image_ids"]) != {"runtime", "application", "postgres"}
            or any(not isinstance(item, str) or not IMAGE_ID.fullmatch(item) for item in value["image_ids"].values())):
        raise BundleError("bundle_manifest_invalid")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or not 7 <= len(artifacts) <= 128:
        raise BundleError("bundle_artifacts_invalid")
    seen, roles, total = set(), {}, 0
    # Validate all metadata and then hash every byte before any tar operation.
    for item in artifacts:
        if (not isinstance(item, dict) or set(item) != {"role", "path", "size", "sha256"}
                or type(item["size"]) is not int or not 0 < item["size"] <= MAX_FILE
                or not isinstance(item["sha256"], str) or not HASH.fullmatch(item["sha256"])):
            raise BundleError("bundle_artifact_invalid")
        name, role = item["path"], item["role"]
        if not isinstance(name, str) or name in seen or name == "manifest.json" or not isinstance(role, str):
            raise BundleError("bundle_duplicate_or_invalid_artifact")
        if role in CORE | OPTIONAL:
            if name != (CORE | OPTIONAL)[role] or role in roles:
                raise BundleError("bundle_artifact_role_invalid")
            roles[role] = item
        elif role != "license" or not re.fullmatch(r"license-[0-9]{3}\.txt", name):
            raise BundleError("bundle_artifact_role_invalid")
        path = regular(root, name)
        if path.stat().st_size != item["size"]:
            raise BundleError("bundle_size_mismatch")
        total += item["size"]
        seen.add(name)
    if total > MAX_TOTAL or set(CORE) - roles.keys() or not any(a["role"] == "license" for a in artifacts):
        raise BundleError("bundle_required_artifact_or_size")
    actual = set()
    for path in root.iterdir():
        if path.is_symlink() or not path.is_file():
            raise BundleError("bundle_unlisted_or_special_file")
        actual.add(path.name)
    if actual != seen | {"manifest.json"}:
        raise BundleError("bundle_unlisted_or_special_file")
    for item in artifacts:
        if digest(regular(root, item["path"])) != item["sha256"]:
            raise BundleError("bundle_artifact_mismatch")
    image_sbom(regular(root, roles["image_sbom"]["path"]), value["image_ids"])
    verify_feeds(regular(root, roles["feeds"]["path"]), regular(root, roles["feed_inventory"]["path"]))
    for role in ("source", "ui", "feeds"):
        if role in roles:
            inspected = archive_members(root / roles[role]["path"], limit=MAX_FEED_TREE if role == "feeds" else MAX_TREE)
            if role == "source" and not SOURCE_FILES.issubset(inspected["files"]):
                raise BundleError("bundle_source_incomplete")
            if role == "ui" and ("operator.html" not in inspected["files"]
                    or not any(name.startswith("_next/") for name in inspected["files"])):
                raise BundleError("bundle_compiled_ui_missing")
    images = archive_members(root / roles["images"]["path"], limit=MAX_FILE)
    if not {"manifest.json", "index.json"}.intersection(images["files"]):
        raise BundleError("bundle_images_archive_invalid")
    for role in ("model", "embedding"):
        with regular(root, roles[role]["path"]).open("rb") as handle:
            if handle.read(4) != b"GGUF":
                raise BundleError("bundle_model_format_invalid")
    return value


def private_write(path, data):
    if path.exists() or path.is_symlink():
        raise BundleError("bundle_private_configuration_exists")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(data)


def deployment(root, manifest, *, port=8085, subnet="172.29.189.0/24"):
    checked_port(str(port))
    network = ipaddress.ip_network(checked_subnet(subnet))
    address = lambda n: str(network.network_address + n)  # noqa: E731
    private = root / ".offline"
    private.mkdir(mode=0o700)
    for name in ("state", "output", "postgres"):
        (private / name).mkdir(mode=0o777 if name != "postgres" else 0o700)
        if name != "postgres":
            (private / name).chmod(0o777)
    password, jwt = secrets.token_hex(24), secrets.token_hex(32)
    credentials = {"username": "operator-offline", "password": secrets.token_urlsafe(32)}
    env = {"OCTO_ENV": "dev", "PYTHONDONTWRITEBYTECODE": "1", "OCTO_API_HOST": "0.0.0.0",
        "OCTO_API_PORT": "8080", "OCTO_OUTPUT_DIR": "/operator/output", "OCTO_STATE_DIR": "/operator/state",
        "OCTO_POSTGRES_URL": "postgresql+psycopg://operator_offline:" + password + "@postgres:5432/operator_offline",
        "OCTO_API_USERS": json.dumps([{**credentials, "role": "admin"}]), "OCTO_JWT_SECRET": jwt,
        "OCTO_MASTER_KEY": secrets.token_hex(32), "OCTO_OPERATOR_ENABLED": "true",
        "OCTO_OPERATOR_WORKER_ENABLED": "true", "OCTO_OPERATOR_ALLOW_EXTERNAL": "false",
        "OCTO_OPERATOR_PROVIDER": "local", "OCTO_OPERATOR_MODEL": manifest["model"],
        "OCTO_OPERATOR_BASE_URL": "http://" + address(2) + ":8082/v1", "OCTO_OPERATOR_TIMEOUT_SECONDS": "120",
        "OCTO_OPERATOR_WORKER_LEASE_SECONDS": "180", "OCTO_OPERATOR_EMBEDDINGS_ENABLED": "true",
        "OCTO_OPERATOR_EMBEDDINGS_BASE_URL": "http://" + address(5) + ":8084/v1",
        "OCTO_OPERATOR_EMBEDDINGS_MODEL": "Qwen3-Embedding-0.6B", "OCTO_OPERATOR_EMBEDDINGS_DIMENSIONS": "1024",
        "OCTO_OPERATOR_EMBEDDINGS_REVISION": manifest["embedding_revision"],
        "OCTO_OPERATOR_EMBEDDINGS_MODEL_SHA256": next(a["sha256"] for a in manifest["artifacts"] if a["role"] == "embedding"),
        "OCTO_WEB_DIST": "/app/web/dist", "OCTO_ALLOW_SCAN_START": "false", "OCTO_JOB_EXECUTION_MODE": "agent",
        "OCTO_REFRESH_COOKIE_SECURE": "false", "OCTO_API_CORS": f"http://127.0.0.1:{port}",
        "OCTO_PUBLIC_BASE_URL": f"http://127.0.0.1:{port}", "OCTO_AGENT_TOKEN": ""}
    for feature in ("NATS_OUTBOX", "CH_INGEST", "SCHEDULER_DISPATCH", "REPORT_DISPATCH", "REPORTS", "SOFTWARE_MATCH",
            "RETRO_MATCH", "SLA_ESCALATION", "JOB_REAPER", "RUN_PUBLICATION_WORKER", "WEBHOOKS", "WEBHOOK_DISPATCH",
            "WEBHOOK_FANOUT", "TICKET_SYNC", "RUN_RETENTION", "RISK_SNAPSHOT_RETENTION", "SCREENSHOT_RETENTION",
            "ENDPOINT_RETENTION", "TENANT_PURGE"):
        env["OCTO_" + feature + "_ENABLED"] = "false"
    private_write(private / "app.env", "".join(key + "=" + value + "\n" for key, value in env.items()))
    private_write(private / "postgres.env", "POSTGRES_USER=operator_offline\nPOSTGRES_DB=operator_offline\nPOSTGRES_PASSWORD=" + password + "\n")
    private_write(private / "credentials.json", json.dumps(credentials))
    images = manifest["image_ids"]
    project = "shapo-offline-" + secrets.token_hex(6)
    control = {"image": images["application"], "pull_policy": "never", "working_dir": "/app", "user": "1000:1000",
        "read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "pids_limit": 256,
        "mem_limit": "768m", "cpus": 1, "env_file": [str(private / "app.env")],
        "tmpfs": ["/tmp:rw,noexec,nosuid,size=64m,mode=1777"], "networks": ["isolated"],
        "volumes": [f"{root}/source/{name}:/app/{name}:ro" for name in ("api", "scanner", "agent")]
            + [f"{root}/ui:/app/web/dist:ro", f"{private}/state:/operator/state", f"{private}/output:/operator/output"]}
    if any(a["role"] == "feeds" for a in manifest["artifacts"]):
        control["volumes"].append(f"{root}/feeds:/app/scanner/data:ro")
    model = {"image": images["runtime"], "pull_policy": "never", "platform": "linux/arm64", "user": "65532:65532",
        "read_only": True, "dns": ["127.0.0.1"],
        "sysctls": {"net.ipv6.conf.all.disable_ipv6": "1", "net.ipv6.conf.default.disable_ipv6": "1"},
        "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "pids_limit": 128,
        "mem_limit": "7g", "memswap_limit": "7g", "cpus": 4, "networks": {"isolated": {"ipv4_address": address(2)}},
        "tmpfs": ["/tmp:rw,noexec,nosuid,size=64m,mode=1777"],
        "environment": {"HF_HUB_OFFLINE": "1", "HF_HUB_DISABLE_TELEMETRY": "1", "DO_NOT_TRACK": "1"},
        "volumes": ["model_weights:/models:ro"],
        "command": ["--model", "/models/model.gguf", "--alias", manifest["model"], "--host", "0.0.0.0", "--port", "8082",
            "--ctx-size", "8192", "--parallel", "1", "--threads", "4", "--batch-size", "512", "--ubatch-size", "128",
            "--n-gpu-layers", "0", "--n-predict", "1024", "--temp", "0", "--seed", "42", "--reasoning", "off",
            "--offline", "--no-webui", "--no-agent", "--no-ui-mcp-proxy"],
        "healthcheck": {"test": ["CMD", "curl", "--fail", "--silent", "http://127.0.0.1:8082/health"],
            "interval": "10s", "timeout": "5s", "start_period": "90s", "retries": 12}}
    embedding = {**model, "mem_limit": "1536m", "memswap_limit": "1536m", "cpus": 2,
        "networks": {"isolated": {"ipv4_address": address(5)}},
        "volumes": ["model_weights:/models:ro"],
        "command": ["--model", "/models/embedding.gguf", "--alias", "Qwen3-Embedding-0.6B", "--host", "0.0.0.0",
            "--port", "8084", "--embedding", "--pooling", "last", "--ctx-size", "2048", "--batch-size", "2048",
            "--ubatch-size", "2048", "--threads", "2", "--n-gpu-layers", "0", "--parallel", "1", "--offline",
            "--no-webui", "--no-agent", "--no-ui-mcp-proxy"],
        "healthcheck": {"test": ["CMD", "curl", "--fail", "--silent", "http://127.0.0.1:8084/health"],
            "interval": "10s", "timeout": "5s", "start_period": "60s", "retries": 12}}
    compose = {"services": {
        "postgres": {"image": images["postgres"], "pull_policy": "never", "env_file": [str(private / "postgres.env")],
            "volumes": [f"{private}/postgres:/var/lib/postgresql/data"], "networks": ["isolated"],
            "mem_limit": "512m", "cpus": 1, "healthcheck": {"test": ["CMD", "pg_isready", "-U", "operator_offline", "-d", "operator_offline"],
                "interval": "3s", "timeout": "3s", "retries": 30}},
        "inference": model,
        "embeddings": embedding,
        "migrate": {**control, "command": ["python", "-m", "api.db.migrate"],
            "depends_on": {"postgres": {"condition": "service_healthy"}}},
        "api": {**control, "command": ["python", "-m", "api"],
            "depends_on": {"migrate": {"condition": "service_completed_successfully"}},
            "healthcheck": {"test": ["CMD", "python", "-c", "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/api/health',timeout=3)"],
                "interval": "5s", "timeout": "5s", "start_period": "15s", "retries": 30}},
        "worker": {**control, "command": ["python", "-m", "api.services.local_operator.worker"],
            "healthcheck": {"disable": True}, "depends_on": {"api": {"condition": "service_healthy"},
                "inference": {"condition": "service_healthy"}, "embeddings": {"condition": "service_healthy"}}},
        "gateway": {"image": images["application"], "pull_policy": "never", "user": "1000:1000", "read_only": True,
            "environment": {"OCTO_OPERATOR_CONSOLE_PORT": str(port)},
            "command": ["python", "/operator-proxy.py"], "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
            "pids_limit": 64, "mem_limit": "128m", "cpus": .5, "ports": [f"127.0.0.1:{port}:8080"],
            "volumes": [f"{root}/source/scripts/operator-console-proxy.py:/operator-proxy.py:ro"],
            "networks": ["isolated", "ingress"], "healthcheck": {"disable": True},
            "depends_on": {"api": {"condition": "service_healthy"}}}},
        "networks": {"isolated": {"internal": True, "ipam": {"config": [{"subnet": str(network)}]}}, "ingress": {}},
        "volumes": {"model_weights": {"name": project + "-weights", "external": True}}}
    private_write(private / "compose.json", json.dumps(compose, sort_keys=True, indent=2))
    private_write(private / "deployment.json", json.dumps({"project": project, "port": port}))
    return project, private / "compose.json", credentials


def native_models():
    """Use the same checksum-bound, network-free volume stager as Mac startup."""
    spec = importlib.util.spec_from_file_location("operator_native_models", Path(__file__).with_name("operator-runtime-manifest.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def native_model_pins(manifest):
    return {CORE[role]: next(item["sha256"] for item in manifest["artifacts"] if item["role"] == role)
            for role in ("model", "embedding")}


def stage_deployment_models(root, manifest, compose_file):
    root = Path(root)
    compose = json.loads(Path(compose_file).read_text())
    volume = compose["volumes"]["model_weights"]["name"]
    pins = native_model_pins(manifest)
    try:
        return native_models().stage_models({name: regular(root / "payloads", name) for name in pins}, pins,
            helper_image=manifest["image_ids"]["application"], volume=volume,
            receipt_path=root / ".offline/model-volume.json")
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        raise BundleError("bundle_native_model_stage_failed") from exc


def import_bundle(bundle, trusted, destination, *, load=True, start=False, port=8085, subnet="172.29.189.0/24"):
    manifest = verify_bundle(bundle, trusted)
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise BundleError("bundle_destination_exists")
    destination.mkdir(mode=0o700)
    payloads = destination / "payloads"
    payloads.mkdir(mode=0o700)
    try:
        for item in manifest["artifacts"]:
            copy_checked(Path(bundle) / item["path"], payloads / item["path"], item["sha256"])
        copy_checked(Path(bundle) / "manifest.json", payloads / "manifest.json", trusted)
        # Reverify the private copy before Docker sees a byte or code is extracted.
        verify_bundle(payloads, trusted)
        for role in ("source", "ui", "feeds"):
            if any(item["role"] == role for item in manifest["artifacts"]):
                extract(payloads / (CORE | OPTIONAL)[role], destination / role, limit=MAX_FEED_TREE if role == "feeds" else MAX_TREE)
        if load:
            run(["docker", "image", "load", "--input", str(payloads / "images.tar")], timeout=1800)
            for image in manifest["image_ids"].values():
                if image_info(image)["Id"] != image:
                    raise BundleError("bundle_loaded_image_mismatch")
        result = {"installation": str(destination), "manifest_sha256": trusted,
            "source_revision": manifest["source_revision"], "images_loaded": load, "started": False}
        if start:
            if not load:
                raise BundleError("bundle_start_requires_image_load")
            project, compose, credentials = deployment(destination, manifest, port=port, subnet=subnet)
            stage_deployment_models(destination, manifest, compose)
            run(["docker", "compose", "-p", project, "-f", str(compose), "up", "-d", "--pull", "never"], timeout=600)
            attest_deployment(destination, manifest, project, compose)
            run(["docker", "compose", "-p", project, "-f", str(compose), "up", "-d", "--no-deps",
                "--force-recreate", "--pull", "never", "api", "worker"], timeout=180)
            deadline, url = time.monotonic() + 180, f"http://127.0.0.1:{port}"
            while time.monotonic() < deadline:
                try:
                    with urllib.request.urlopen(url + "/api/health", timeout=3) as response:
                        if response.status == 200:
                            break
                except (OSError, urllib.error.HTTPError):
                    time.sleep(1)
            else:
                raise BundleError("bundle_startup_timeout")
            request = urllib.request.Request(url + "/api/auth/login", data=json.dumps(credentials).encode(),
                headers={"Content-Type": "application/json", "Origin": url})
            with urllib.request.urlopen(request, timeout=15) as response:
                token = json.load(response)["access_token"]
            request = urllib.request.Request(url + "/api/operator/status?tenant_id=default", headers={"Authorization": "Bearer " + token})
            with urllib.request.urlopen(request, timeout=15) as response:
                status = json.load(response)
            if status.get("runtime_status") != "ready" or status.get("analysis_available") is not True:
                raise BundleError("bundle_runtime_not_ready")
            with urllib.request.urlopen(url + "/operator", timeout=15) as response:
                if response.status != 200 or b"/_next/" not in response.read():
                    raise BundleError("bundle_compiled_ui_unavailable")
            result.update(started=True, project=project, console=url + "/operator",
                authenticated=status["enabled"], quality_status=status["quality_status"])
        return result
    except Exception:
        # Keep this new installation for diagnostics if startup created a
        # deployment; never remove files still mounted by running containers.
        if not (destination / ".offline").exists():
            shutil.rmtree(destination)
        raise


def attest_deployment(root, manifest, project, compose_file):
    """Inspect only the new project's actual model processes before attesting.

    Imported private payloads were completely hashed immediately before load
    and chmod444. This does not defend against a concurrent privileged writer.
    """
    root = Path(root)
    compose = json.loads(Path(compose_file).read_text())
    runtime_id = manifest["image_ids"]["runtime"]
    image = image_info(runtime_id)
    if image["Config"].get("Labels", {}).get("org.opencontainers.image.revision") != manifest["runtime_revision"]:
        raise BundleError("bundle_runtime_revision_mismatch")
    containers = {}
    weight_volume = compose["volumes"]["model_weights"]["name"]
    try:
        volume_proof = native_models().verify_volume(weight_volume, native_model_pins(manifest),
            helper_image=manifest["image_ids"]["application"])
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        raise BundleError("bundle_native_model_integrity_unavailable") from exc
    for role, artifact_role in (("inference", "model"), ("embeddings", "embedding")):
        container_id = run(["docker", "compose", "-p", project, "-f", str(compose_file), "ps", "-q", role], timeout=30).decode().strip()
        if not re.fullmatch(r"[a-f0-9]{12,64}", container_id):
            raise BundleError("bundle_runtime_container_missing")
        value = json.loads(run(["docker", "container", "inspect", container_id], timeout=30))[0]
        config, host = value["Config"], value["HostConfig"]
        if (value["Image"] != runtime_id or config["Image"] != runtime_id
                or value["State"]["Status"] != "running" or value["State"].get("Health", {}).get("Status") != "healthy"
                or not host["ReadonlyRootfs"] or config["User"] != "65532:65532"
                or host.get("PortBindings") or config["Cmd"] != compose["services"][role]["command"]
                or config.get("Entrypoint") != image["Config"].get("Entrypoint")
                or any(host.get("Sysctls", {}).get(key) != "1" for key in (
                    "net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6"))
                or host.get("Privileged") or not {"ALL"}.issubset(set(host.get("CapDrop") or []))):
            raise BundleError("bundle_runtime_deployment_mismatch")
        networks = value["NetworkSettings"]["Networks"]
        if len(networks) != 1:
            raise BundleError("bundle_runtime_network_mismatch")
        for name in networks:
            network = json.loads(run(["docker", "network", "inspect", name], timeout=30))[0]
            if not network.get("Internal") or network.get("Labels", {}).get("com.docker.compose.project") != project:
                raise BundleError("bundle_runtime_network_mismatch")
        artifact = next(item for item in manifest["artifacts"] if item["role"] == artifact_role)
        payload = regular(root / "payloads", artifact["path"])
        if payload.stat().st_size != artifact["size"] or payload.stat().st_mode & 0o222:
            raise BundleError("bundle_runtime_payload_not_immutable")
        mounts = [item for item in value["Mounts"] if item["Destination"] == "/models" or item["Destination"].startswith("/models/")]
        if (len(mounts) != 1 or mounts[0]["Type"] != "volume" or mounts[0]["Destination"] != "/models"
                or mounts[0].get("Name") != weight_volume or mounts[0].get("Driver") != "local" or mounts[0]["RW"]):
            raise BundleError("bundle_runtime_model_mount_mismatch")
        containers[role] = {"image_id": runtime_id, "arguments": config["Cmd"], "container_id": container_id}
    hashes = {item["role"]: item["sha256"] for item in manifest["artifacts"]}
    value = {"schema_version": 1, "profile": "mac-arm64-cpu", "model": manifest["model"],
        "application_source_revision": manifest["source_revision"],
        "model_sha256": hashes["model"], "runtime_image": manifest["runtime_reference"],
        "runtime_revision": manifest["runtime_revision"], "context_tokens": 8192, "parallel": 1,
        "embedding_sha256": hashes["embedding"], "embedding_revision": manifest["embedding_revision"],
        "embedding_dimensions": 1024, "verified_at": datetime.now(UTC).isoformat(), "containers": containers,
        "model_storage": volume_proof}
    private = root / ".offline"
    target = private / "verification.json"
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    descriptor, temporary = tempfile.mkstemp(prefix=".runtime-", dir=private)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
        Path(temporary).chmod(0o444)
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)
    env = private / "app.env"
    with env.open("a") as handle:
        handle.write("OCTO_OPERATOR_RUNTIME_MANIFEST_PATH=/operator-runtime.json\nOCTO_OPERATOR_RUNTIME_MANIFEST_SHA256="
            + hashlib.sha256(raw).hexdigest() + "\n")
    for service in ("api", "worker"):
        compose["services"][service]["volumes"].append(f"{target}:/operator-runtime.json:ro")
    Path(compose_file).write_text(json.dumps(compose, sort_keys=True, indent=2))
    return value


def stop_installation(root, trusted):
    root = Path(root).absolute()
    verify_bundle(root / "payloads", trusted)
    private = root / ".offline"
    state = json.loads((private / "deployment.json").read_text())
    if set(state) != {"project", "port"} or not re.fullmatch(r"shapo-offline-[a-f0-9]{12}", state["project"]):
        raise BundleError("bundle_deployment_state_invalid")
    run(["docker", "compose", "-p", state["project"], "-f", str(private / "compose.json"), "down", "--volumes"], timeout=180)
    return {"stopped_project": state["project"], "data_preserved": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export")
    export.add_argument("--destination", required=True, type=Path)
    export.add_argument("--source-ref", default="HEAD")
    export.add_argument("--ui-source-revision", required=True)
    export.add_argument("--ui", required=True, type=Path)
    export.add_argument("--model", required=True, type=Path)
    export.add_argument("--embedding", required=True, type=Path)
    export.add_argument("--model-revision", required=True)
    export.add_argument("--embedding-revision", required=True)
    export.add_argument("--model-sha256", required=True, type=checked_hash)
    export.add_argument("--embedding-sha256", required=True, type=checked_hash)
    export.add_argument("--runtime-image", required=True, type=checked_image)
    export.add_argument("--app-image", required=True, type=checked_image)
    export.add_argument("--postgres-image", required=True, type=checked_image)
    export.add_argument("--license", required=True, action="append", type=Path)
    export.add_argument("--feeds", type=Path, required=True)
    export.add_argument("--image-sbom", type=Path, required=True)
    for name in ("verify", "import", "stop"):
        command = commands.add_parser(name)
        command.add_argument("directory", type=Path)
        command.add_argument("--manifest-sha256", required=True, type=checked_hash)
        if name == "import":
            command.add_argument("--destination", type=Path, required=True)
            command.add_argument("--without-docker-load", action="store_true")
            command.add_argument("--start", action="store_true")
            command.add_argument("--port", type=checked_port, default=8085)
            command.add_argument("--subnet", type=checked_subnet, default="172.29.189.0/24")
    args = parser.parse_args()
    try:
        if args.command == "export":
            result = export_bundle(args)
        elif args.command == "verify":
            value = verify_bundle(args.directory, args.manifest_sha256)
            result = {"verified": True, "source_revision": value["source_revision"], "manifest_sha256": args.manifest_sha256}
        elif args.command == "import":
            result = import_bundle(args.directory, args.manifest_sha256, args.destination,
                load=not args.without_docker_load, start=args.start, port=args.port, subnet=args.subnet)
        else:
            result = stop_installation(args.directory, args.manifest_sha256)
    except (BundleError, OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        parser.exit(1, "Offline bundle operation failed; nothing unverified may be launched.\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
