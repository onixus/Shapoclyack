"""Bounded, deterministic Nuclei web plans. No discovery or network I/O.

The initial directed policy keeps ALL eligible HTTP templates as its fallback.
Technology hints explain selection, but cannot suppress a CVE or a check class.
Catalog identity hashes file bytes; cached parsing never trusts a mutable tag.
"""

from __future__ import annotations

import hashlib
import json
import re
import math
from collections import OrderedDict
from pathlib import Path
from typing import Any

import yaml

from .protocol import is_ipv6, parse_endpoint

_CACHE: OrderedDict[str, list[dict[str, Any]]] = OrderedDict()
TECHNOLOGIES = {
    "nginx": {"nginx"},
    "apache": {"apache"},
    "wordpress": {"wordpress", "wp"},
    "tomcat": {"tomcat"},
    "jenkins": {"jenkins"},
}


def catalog(
    directories: list[Path], limit: int, max_bytes: int = 100 * 1024 * 1024
) -> tuple[str, list[dict[str, Any]], str | None]:
    """Read bounded local files, parse once per immutable content digest.

    A bound exceeded or an unreadable/ambiguous template fails closed. No
    truncated catalog can masquerade as a full selection.
    """
    files = []
    paths = []
    inventory_entries = 0
    total_bytes = 0
    digest = hashlib.sha256()
    for index, directory in enumerate(directories):
        if directory.is_symlink() or not directory.is_dir():
            return "", [], "catalog_directory_missing_or_unsafe"
        # Bound inventory before sorting: rglob + sorted on an unbounded
        # tree can consume memory before the template count limit is applied.
        for path in directory.rglob("*"):
            inventory_entries += 1
            if inventory_entries > limit * 4 + 1000:
                return "", [], "catalog_inventory_limit"
            if path.is_symlink():
                return "", [], "catalog_unsafe_file"
            if path.suffix not in {".yaml", ".yml"} or not path.is_file():
                continue
            if len(paths) >= limit:
                return "", [], "catalog_limit"
            paths.append((index, str(path.relative_to(directory)), path))
    for index, relative, path in sorted(paths):
        with path.open("rb") as handle:
            content = handle.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            return "", [], "catalog_limit"
        total_bytes += len(content)
        if total_bytes > max_bytes:
            return "", [], "catalog_bytes_limit"
        digest.update(f"{index}:{relative}\0".encode() + content)
        files.append((index, relative, content))
    key = digest.hexdigest()
    if key in _CACHE:
        _CACHE.move_to_end(key)
        return key, _CACHE[key], None
    rows = []
    ids = set()
    for index, relative, content in files:
        try:
            document = yaml.safe_load(content)
        except yaml.YAMLError:
            return key, [], "catalog_invalid_yaml"
        if not isinstance(document, dict) or not isinstance(document.get("info"), dict):
            return key, [], "catalog_invalid_template"
        template_id = str(document.get("id") or "")
        if (
            re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", template_id) is None
            or template_id in ids
        ):
            return key, [], "catalog_ambiguous_id"
        ids.add(template_id)
        info = document["info"]
        tags = info.get("tags") or []
        tags = tags.split(",") if isinstance(tags, str) else tags
        classification = info.get("classification") or {}
        if not isinstance(tags, list) or not isinstance(classification, dict):
            return key, [], "catalog_invalid_metadata"
        requests = document.get("http") or document.get("requests") or []
        # A restricted input list does not constrain a literal external URL
        # or raw Host override in a template. Admit only root-relative HTTP
        # requests to this input, and report the rest as scope unproven.
        scope_safe = isinstance(requests, list) and bool(requests)
        for request in requests if isinstance(requests, list) else []:
            paths = request.get("path") if isinstance(request, dict) else None
            scope_safe = (
                scope_safe
                and isinstance(paths, list)
                and bool(paths)
                and not request.get("raw")
            )
            scope_safe = scope_safe and all(
                isinstance(path, str)
                and (path.startswith("{{BaseURL}}/") or path.startswith("{{RootURL}}/"))
                for path in paths or []
            )
            if isinstance(request, dict) and any(
                str(h).lower() == "host" for h in (request.get("headers") or {})
            ):
                scope_safe = False
        rows.append(
            {
                "id": template_id,
                "path": relative,
                "origin": "custom" if index else "pinned",
                "sha256": hashlib.sha256(content).hexdigest(),
                "scope_safe": scope_safe,
                "tags": sorted({str(t).strip().lower() for t in tags}),
                "severity": str(info.get("severity") or "").lower(),
                "http": ("http" in document or "requests" in document)
                and not any(
                    key in document
                    for key in (
                        "javascript",
                        "code",
                        "network",
                        "tcp",
                        "dns",
                        "headless",
                        "file",
                        "flow",
                    )
                ),
                "cve": bool(classification.get("cve-id")),
            }
        )
    _CACHE[key] = rows
    while len(_CACHE) > 2:
        _CACHE.popitem(last=False)
    return key, rows, None


def build_plan(
    open_ports: list[str],
    services: list[dict[str, Any]],
    config: Any,
    digest: str,
    templates: list[dict[str, Any]],
    forward_names: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Intersect service observations with open TCP scope; never add a port.

    Missing confidence is unknown. Conflicting observations retain both
    schemes. All unknown open TCP endpoints receive the bounded HTTP/HTTPS
    fallback, including nonstandard ports; reliable non-web evidence is not
    sufficient to remove the fallback until capture acceptance exists.
    """
    forward_names = forward_names or {}
    observations: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for row in services:
        if not isinstance(row, dict) or str(row.get("protocol", "tcp")) != "tcp":
            continue
        try:
            endpoint = (str(row.get("ip") or row.get("host") or ""), int(row["port"]))
        except (KeyError, TypeError, ValueError):
            continue
        observations.setdefault(endpoint, []).append(row)
    eligible = [
        t
        for t in templates
        if t["http"]
        and t["scope_safe"]
        and (not config.severities or t["severity"] in config.severities)
        and not set(t["tags"]) & set(config.exclude_tags)
        and (not config.tags or set(t["tags"]) & set(config.tags))
    ]
    ids = sorted(t["id"] for t in eligible)
    targets = []
    seen = set()
    skipped = []
    for entry in sorted(set(open_ports)):
        endpoint = parse_endpoint(entry)
        if endpoint is None or endpoint.protocol != "tcp":
            continue
        host, port = endpoint.host, int(endpoint.port)
        if (host, port) in seen:
            continue
        seen.add((host, port))
        rows = observations.get((host, port), [])
        reliable = []
        for row in rows:
            confidence = row.get("confidence", 0)
            if (
                type(confidence) in (int, float)
                and math.isfinite(confidence)
                and config.planner_min_confidence <= confidence <= 100
            ):
                service = str(row.get("service") or "").lower()
                if service in {"http", "https", "ssl/http"}:
                    reliable.append("https" if service != "http" else "http")
        schemes = (
            sorted(set(reliable)) if len(set(reliable)) == 1 else ["http", "https"]
        )
        reason = (
            "reliable_protocol"
            if len(schemes) == 1
            else "unknown_or_conflicting_protocol_fallback"
        )
        products = sorted({str(r.get("product") or "").lower() for r in rows})
        technologies = sorted(
            name for name in TECHNOLOGIES if any(name in p for p in products)
        )
        for scheme in schemes:
            hostpart = f"[{host}]" if is_ipv6(host) else host
            # Only input-forward names are authorized; banners, certificate
            # SANs and PTR never introduce scan targets. Dial remains the IP.
            names = sorted(
                {
                    name.lower().rstrip(".")
                    for name in forward_names.get(host, [])
                    if isinstance(name, str)
                    and re.fullmatch(r"[A-Za-z0-9.-]{1,253}", name)
                    and "." in name
                    and not name.startswith("-")
                }
            )
            for name in [None, *names]:
                authority = (name or hostpart) + (
                    f":{port}" if port not in {80, 443} else ""
                )
                targets.append(
                    {
                        "url": f"{scheme}://{hostpart}:{port}/",
                        "ip": host,
                        "port": port,
                        "authority": authority,
                        "sni": name if scheme == "https" else None,
                        "host_header": authority if name else None,
                        "reason": reason,
                        "technologies": technologies,
                        "template_set": "safe_http_fallback",
                    }
                )
    considered = len(targets)
    if considered > config.max_targets:
        skipped.append(
            {"reason": "max_targets", "count": considered - config.max_targets}
        )
    targets = targets[: config.max_targets]
    return {
        "schema_version": "octo.nuclei_plan.v1",
        "mode": "directed",
        "catalog_sha256": digest,
        "template_policy": "safe_http_fallback_preserves_all_eligible_http_templates",
        "template_sets": {"safe_http_fallback": ids},
        "catalog": eligible,
        "targets": targets,
        "targets_considered": considered,
        "skipped": skipped,
        "excluded_templates": [
            {
                "id": t["id"],
                "reason": "scope_unproven"
                if not t["scope_safe"]
                else "non_http_or_policy",
            }
            for t in templates
            if t not in eligible
        ],
        "planned_checks": len(targets) * len(ids),
        "executed_checks": None,
        "completed_targets": None,
        "complete": False,
        "versions": {
            "products": sorted(
                {str(r.get("product") or "") for r in services if isinstance(r, dict)}
            ),
            "service_versions": sorted(
                {str(r.get("version") or "") for r in services if isinstance(r, dict)}
            ),
        },
    }


def forward_names(output_dir: Path) -> dict[str, list[str]]:
    try:
        document = json.loads((output_dir / "dns_resolution.json").read_text())
    except (OSError, ValueError):
        return {}
    result: dict[str, list[str]] = {}
    for row in document.get("records", []) if isinstance(document, dict) else []:
        if not isinstance(row, dict) or not isinstance(row.get("host"), str):
            continue
        for ip in [*(row.get("a") or []), *(row.get("aaaa") or [])]:
            result.setdefault(str(ip), []).append(row["host"])
    return result


def snapshot_catalog(
    directories: list[Path], rows: list[dict[str, Any]], destination: Path
) -> None:
    """Execute only bytes identified in the plan, never the mutable originals."""
    for row in rows:
        original = directories[1 if row["origin"] == "custom" else 0] / row["path"]
        with original.open("rb") as handle:
            content = handle.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise ValueError("catalog_changed_before_execution")
        if hashlib.sha256(content).hexdigest() != row["sha256"]:
            raise ValueError("catalog_changed_before_execution")
        (destination / (row["id"] + ".yaml")).write_bytes(content)


def read_services(output_dir: Path) -> list[dict[str, Any]]:
    try:
        rows = json.loads((output_dir / "services.json").read_text())
        return rows if isinstance(rows, list) else []
    except (OSError, ValueError):
        return []
