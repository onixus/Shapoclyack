from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from api.schemas import AliveHostItem, PortAggregateItem, RunDetail, RunSummary, VulnerabilityItem
from api.services import pagination
from api.services import tenants as tenants_service
from api.services.risk_scoring import FOOTHOLD, LOCAL, get_scorer, index_cdn_waf, path_role
from scanner.pipeline.asset_identity import registrable_domain
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.runs")

# Marker file written into a run directory naming the tenant the run belongs to
# (ROADMAP P0). Runs produced before this shipped have no marker and are read as
# belonging to the default tenant — the tenant every pre-P0 install scanned as.
RUN_TENANT_FILE = "tenant.json"


def _load_json(path: Path) -> Any | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _parse_endpoint(value: str) -> tuple[str, str, str | None]:
    """Return (host, port, protocol) from ``host:port[/proto]`` (IPv6 bracketed)."""
    raw = value.strip()
    protocol: str | None = None
    if raw.endswith("/tcp"):
        protocol = "tcp"
        raw = raw[: -len("/tcp")]
    elif raw.endswith("/udp"):
        protocol = "udp"
        raw = raw[: -len("/udp")]
    if raw.startswith("[") and "]" in raw:
        host, _, rest = raw.partition("]")
        host = host[1:]
        port = rest[1:] if rest.startswith(":") else rest
        return host, port, protocol
    if ":" in raw:
        host, _, port = raw.rpartition(":")
        return host, port, protocol
    return raw, "", protocol


def _coordinate(value: Any, *, limit: float) -> float | None:
    """A finite coordinate inside ``±limit``, or None.

    Re-validated here rather than trusted from the artifact: a run directory is
    a file on disk that an operator (or an older scanner version) may have
    written, and an out-of-range latitude plots a marker off the map instead of
    failing where it can be seen.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if number != number or number in (float("inf"), float("-inf")):
        return None
    if abs(number) > limit:
        return None
    return number


def _geo_map(run_dir: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    geo = _load_json(run_dir / "geoip.json")
    if isinstance(geo, dict):
        for host, value in geo.items():
            if isinstance(value, dict):
                out[str(host)] = {
                    "country": value.get("country") or None,
                    "city": value.get("city") or None,
                    "country_iso": value.get("country_iso") or None,
                    "latitude": _coordinate(value.get("latitude"), limit=90.0),
                    "longitude": _coordinate(value.get("longitude"), limit=180.0),
                }
    alive = _load_json(run_dir / "alive_hosts.json")
    if isinstance(alive, list):
        for row in alive:
            if not isinstance(row, dict) or not row.get("host"):
                continue
            host = str(row["host"])
            current = out.setdefault(
                host,
                {
                    "country": None,
                    "city": None,
                    "country_iso": None,
                    "latitude": None,
                    "longitude": None,
                },
            )
            if not current.get("country") and row.get("country"):
                current["country"] = row.get("country")
            if not current.get("city") and row.get("city"):
                current["city"] = row.get("city")
            if not current.get("country_iso") and row.get("country_iso"):
                current["country_iso"] = row.get("country_iso")
            # `is None` rather than falsy: 0.0 is a coordinate, not a gap, and
            # a run predating this field simply has neither key.
            if current.get("latitude") is None:
                current["latitude"] = _coordinate(row.get("latitude"), limit=90.0)
            if current.get("longitude") is None:
                current["longitude"] = _coordinate(row.get("longitude"), limit=180.0)
    return out


def _run_dirs(settings: Settings) -> list[Path]:
    runs_root = settings.output_dir / "runs"
    if runs_root.is_dir():
        dirs = [path for path in runs_root.iterdir() if path.is_dir()]
        return sorted(dirs, key=lambda path: path.name, reverse=True)

    # Flat layout fallback (per_run_output=false)
    if (settings.output_dir / "summary.json").exists() or (settings.output_dir / "alive_ips.txt").exists():
        return [settings.output_dir]
    return []


def _run_id_for(path: Path, settings: Settings) -> str:
    if path == settings.output_dir:
        return "default"
    return path.name


def read_run_tenant(run_dir: Path) -> str:
    """Tenant that owns ``run_dir``.

    Falls back to the default tenant when the marker is missing or unreadable —
    runs written before P0, and any run produced by the plain ``scanner.main``
    CLI outside the API, have no marker.
    """
    meta = _load_json(run_dir / RUN_TENANT_FILE)
    if isinstance(meta, dict):
        tenant_id = str(meta.get("tenant_id") or "").strip()
        if tenant_id:
            return tenant_id
    return tenants_service.DEFAULT_TENANT_ID


def write_run_tenant(
    settings: Settings, run_id: str, tenant_id: str, *, job_id: str | None = None
) -> bool:
    """Tag a run directory with its owning tenant. Best-effort: returns False
    when the run directory doesn't exist or the write fails, since losing the
    marker must never fail a scan that otherwise succeeded (the run then reads
    back as the default tenant)."""
    run_dir = settings.output_dir / "runs" / run_id if run_id != "default" else settings.output_dir
    if not run_dir.is_dir():
        return False
    payload: dict[str, Any] = {"tenant_id": tenant_id}
    if job_id:
        payload["job_id"] = job_id
    try:
        (run_dir / RUN_TENANT_FILE).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    except OSError:
        return False
    return True


def list_runs(
    settings: Settings,
    *,
    offset: int = 0,
    limit: int = pagination.DEFAULT_LIMIT,
    q: str | None = None,
    order: str | None = None,
    tenant_id: str | None = None,
) -> tuple[list[RunSummary], int]:
    """Return ``(page, total_after_filtering)``.

    Runs are ordered by ``run_id`` — the timestamped directory name — which is
    the only key available without opening every run's JSON. Filtering and
    slicing therefore happen on directory names, and ``run_meta.json`` /
    ``summary.json`` are read for the requested page only, so listing stays
    O(page) instead of O(all runs). Sorting by a summary column would require
    reading every run and is deliberately not offered server-side.

    ``tenant_id`` restricts the listing to runs owned by that tenant. Unlike the
    other filters this one can't be answered from the directory name, so it
    costs one small ``tenant.json`` read per run *before* slicing; pass ``None``
    (platform admin, fleet-wide view) to skip those reads entirely.
    """
    run_dirs = _run_dirs(settings)
    if q:
        needle = q.strip().lower()
        run_dirs = [d for d in run_dirs if needle in _run_id_for(d, settings).lower()]
    if tenant_id:
        run_dirs = [d for d in run_dirs if read_run_tenant(d) == tenant_id]
    if (order or "").lower() == "asc":
        run_dirs = list(reversed(run_dirs))
    page_dirs, total = pagination.slice_page(run_dirs, offset=offset, limit=limit)

    results: list[RunSummary] = []
    for run_dir in page_dirs:
        run_id = _run_id_for(run_dir, settings)
        meta = _load_json(run_dir / "run_meta.json") or {}
        summary = _load_json(run_dir / "summary.json") or {}
        results.append(
            RunSummary(
                run_id=run_id,
                tenant_id=tenant_id or read_run_tenant(run_dir),
                profile=meta.get("profile") if isinstance(meta, dict) else None,
                started_at=meta.get("started_at") if isinstance(meta, dict) else None,
                config=meta.get("config") if isinstance(meta, dict) else None,
                alive_hosts=summary.get("alive_hosts") if isinstance(summary, dict) else None,
                open_host_port_pairs=summary.get("open_host_port_pairs") if isinstance(summary, dict) else None,
                potential_vulnerabilities=(
                    summary.get("potential_vulnerabilities") if isinstance(summary, dict) else None
                ),
                unconfirmed_findings=(
                    summary.get("unconfirmed_findings") if isinstance(summary, dict) else None
                ),
                vulnerable_hosts=summary.get("vulnerable_hosts") if isinstance(summary, dict) else None,
                has_diff=(run_dir / "diff.json").exists(),
                has_summary=(run_dir / "summary.json").exists(),
                path=str(run_dir),
            )
        )
    return results, total


def get_run_dir(settings: Settings, run_id: str, *, tenant_id: str | None = None) -> Path | None:
    """Resolve a run directory, or ``None`` when it doesn't exist.

    With ``tenant_id`` set, a run owned by another tenant also resolves to
    ``None`` — callers turn that into the same 404 as a missing run, so an id
    from a foreign tenant isn't confirmed to exist. Every run sub-resource
    (hosts/ports/vulns/diff/artifacts) goes through here, so scoping this one
    function scopes all of them.
    """
    if run_id == "default":
        candidate = settings.output_dir
        if not candidate.is_dir():
            return None
    else:
        candidate = settings.output_dir / "runs" / run_id
        if not candidate.is_dir():
            return None
    if tenant_id and read_run_tenant(candidate) != tenant_id:
        return None
    return candidate


def get_run_detail(settings: Settings, run_id: str, *, tenant_id: str | None = None) -> RunDetail | None:
    run_dir = get_run_dir(settings, run_id, tenant_id=tenant_id)
    if run_dir is None:
        return None
    artifacts = sorted(
        str(path.relative_to(run_dir))
        for path in run_dir.rglob("*")
        if path.is_file()
        and path.stat().st_size < 50_000_000
        and not is_screenshot_path(str(path.relative_to(run_dir)))
        and not is_restricted_artifact(str(path.relative_to(run_dir)))
    )
    return RunDetail(
        run_id=run_id,
        tenant_id=read_run_tenant(run_dir),
        meta=_load_json(run_dir / "run_meta.json") or {},
        summary=_load_json(run_dir / "summary.json"),
        diff=_load_json(run_dir / "diff.json"),
        artifacts=artifacts[:500],
    )


_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "unknown": 4,
}


def get_vulnerabilities(
    settings: Settings,
    run_id: str,
    *,
    limit: int = 5000,
    host: str | None = None,
    port: str | None = None,
    tenant_id: str | None = None,
) -> list[VulnerabilityItem] | None:
    run_dir = get_run_dir(settings, run_id, tenant_id=tenant_id)
    if run_dir is None:
        return None
    raw = _load_json(run_dir / "vulnerabilities.json")
    if raw is None:
        return []
    if not isinstance(raw, list):
        return []
    host_filter = host.strip().lower() if host else None
    port_filter = port.strip() if port else None
    geo = _geo_map(run_dir)
    # Prioritisation is computed here rather than read back from ClickHouse so
    # it is available on every deployment, CH or not. The operator-set asset
    # criticality is deliberately not looked up: that would be one Postgres
    # query per distinct host on an interactive endpoint. The CH rows written
    # at ingest do carry it, so their contextual_score can be the stricter of
    # the two — the explanation says which criticality it used.
    scorer = get_scorer()
    cdn_waf = index_cdn_waf(_load_json(run_dir / "fingerprint.json"))
    foothold_hosts = {
        str(entry.get("host") or "")
        for entry in raw
        if isinstance(entry, dict) and path_role(entry) == FOOTHOLD
    }
    items: list[VulnerabilityItem] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        entry_host = entry.get("host")
        entry_port = str(entry.get("port")) if entry.get("port") is not None else None
        if host_filter and str(entry_host or "").lower() != host_filter:
            continue
        if port_filter and (entry_port or "") != port_filter:
            continue
        host_key = str(entry_host or "")
        geo_hit = geo.get(host_key, {})
        scored = scorer.score_vulnerability(
            entry,
            cdn_waf_index=cdn_waf,
            same_asset_foothold=path_role(entry) == LOCAL and host_key in foothold_hosts,
        )
        confidence = entry.get("confidence")
        items.append(
            VulnerabilityItem(
                host=entry_host,
                port=entry_port,
                cve=entry.get("cve"),
                cvss=entry.get("cvss"),
                cvss4=entry.get("cvss4"),
                cvss4_vector=entry.get("cvss4_vector"),
                cvss4_severity=entry.get("cvss4_severity"),
                severity=entry.get("severity"),
                script_id=entry.get("script_id"),
                country=entry.get("country") or geo_hit.get("country"),
                city=entry.get("city") or geo_hit.get("city"),
                country_iso=entry.get("country_iso") or geo_hit.get("country_iso"),
                finding_class=entry.get("finding_class"),
                confidence=int(confidence) if isinstance(confidence, (int, float)) else None,
                requires_confirmation=bool(entry.get("requires_confirmation")),
                epss=scored["epss_score"] or None,
                in_kev=bool(scored["exploit_active"]),
                contextual_score=scored["contextual_score"],
                cisa_decision=scored["cisa_decision"],
                risk_explanation=scored["risk_explanation"],
                risk_level=scored.get("risk_level"),
                likelihood=scored.get("likelihood"),
                impact=scored.get("impact"),
                exploit_maturity=scored.get("exploit_maturity"),
                exploit_evidence=list(scored.get("exploit_evidence") or []),
                exploit_verified_on_host=bool(scored.get("exploit_verified_on_host")),
                network_exposure=scored.get("network_exposure"),
                network_exposure_source=scored.get("network_exposure_source"),
                cdn_waf=list(scored.get("cdn_waf") or []),
                compensating_control_source=scored.get("compensating_control_source"),
            )
        )
    # Contextual score leads: it already folds in severity, EPSS, KEV, and the
    # confidence discount, so an unconfirmed "critical" no longer outranks a
    # confirmed exploited one. Severity/CVSS stay as tie-breakers for findings
    # with no score at all.
    items.sort(
        key=lambda item: (
            -(item.contextual_score or 0.0),
            _SEVERITY_RANK.get(str(item.severity or "unknown").lower(), 4),
            -(float(item.cvss4) if item.cvss4 is not None else (float(item.cvss) if item.cvss is not None else -1.0)),
            str(item.host or ""),
            str(item.cve or ""),
        )
    )
    return items[:limit]


def get_hosts(
    settings: Settings, run_id: str, *, limit: int = 10000, tenant_id: str | None = None
) -> list[AliveHostItem] | None:
    run_dir = get_run_dir(settings, run_id, tenant_id=tenant_id)
    if run_dir is None:
        return None
    geo = _geo_map(run_dir)
    vulns = _load_json(run_dir / "vulnerabilities.json")
    vuln_counts: dict[str, int] = {}
    if isinstance(vulns, list):
        for entry in vulns:
            if isinstance(entry, dict) and entry.get("host"):
                vuln_counts[str(entry["host"])] = vuln_counts.get(str(entry["host"]), 0) + 1

    rows: list[AliveHostItem] = []
    alive = _load_json(run_dir / "alive_hosts.json")
    if isinstance(alive, list) and alive:
        for entry in alive:
            if not isinstance(entry, dict) or not entry.get("host"):
                continue
            host = str(entry["host"])
            geo_hit = geo.get(host, {})
            names = entry.get("names") if isinstance(entry.get("names"), list) else []
            rows.append(
                AliveHostItem(
                    host=host,
                    hostname=entry.get("hostname") or None,
                    names=[str(n) for n in names],
                    country=entry.get("country") or geo_hit.get("country"),
                    city=entry.get("city") or geo_hit.get("city"),
                    country_iso=entry.get("country_iso") or geo_hit.get("country_iso"),
                    latitude=_coordinate(entry.get("latitude"), limit=90.0)
                    if entry.get("latitude") is not None
                    else geo_hit.get("latitude"),
                    longitude=_coordinate(entry.get("longitude"), limit=180.0)
                    if entry.get("longitude") is not None
                    else geo_hit.get("longitude"),
                    os_name=entry.get("os_name") or None,
                    os_accuracy=entry.get("os_accuracy"),
                    asn=entry.get("asn") or None,
                    asn_org=entry.get("asn_org") or None,
                    vulnerability_count=vuln_counts.get(host, 0),
                )
            )
    else:
        for host in _read_lines(run_dir / "alive_ips.txt"):
            geo_hit = geo.get(host, {})
            rows.append(
                AliveHostItem(
                    host=host,
                    country=geo_hit.get("country"),
                    city=geo_hit.get("city"),
                    country_iso=geo_hit.get("country_iso"),
                    latitude=geo_hit.get("latitude"),
                    longitude=geo_hit.get("longitude"),
                    vulnerability_count=vuln_counts.get(host, 0),
                )
            )
    rows.sort(key=lambda item: (-item.vulnerability_count, item.host))
    trimmed = rows[:limit]
    _apply_host_ownership(settings, tenant_id, trimmed)
    return trimmed


def _apply_host_ownership(
    settings: Settings, tenant_id: str | None, rows: list[AliveHostItem]
) -> None:
    """Fill P4.3 owner fields. Domain clustering works without Postgres."""
    for row in rows:
        names = [n for n in [row.hostname, *row.names] if n]
        domain = ""
        for name in names:
            domain = registrable_domain(name)
            if domain:
                break
        row.registrable_domain = domain or None
        row.ownership_source = "domain" if domain else "none"
    if not tenant_id or not settings.postgres_url.strip():
        return
    try:
        from api.services import assets as assets_service

        ips = [row.host for row in rows]
        names = [n for row in rows for n in [row.hostname, *row.names] if n]
        by_ip, by_name = assets_service.ownership_for_hosts(
            settings, tenant_id, ips=ips, names=names
        )
    except Exception:  # noqa: BLE001
        LOG.warning("host ownership attach failed tenant=%s", tenant_id, exc_info=True)
        return
    for row in rows:
        hit = by_ip.get(row.host)
        if hit is None:
            for name in [row.hostname, *row.names]:
                if name:
                    hit = by_name.get(name.lower())
                    if hit is not None:
                        break
        if hit and (hit.get("owner_email") or hit.get("business_unit")):
            row.owner_email = hit.get("owner_email")
            row.business_unit = hit.get("business_unit")
            row.asset_id = hit.get("asset_id")
            row.ownership_source = "operator"


def get_ports(
    settings: Settings, run_id: str, *, limit: int = 10000, tenant_id: str | None = None
) -> list[PortAggregateItem] | None:
    run_dir = get_run_dir(settings, run_id, tenant_id=tenant_id)
    if run_dir is None:
        return None

    # port_key -> {protocol, hosts}
    buckets: dict[str, dict[str, Any]] = {}
    for line in _read_lines(run_dir / "open_ports.txt"):
        host, port, protocol = _parse_endpoint(line)
        if not port:
            continue
        key = f"{port}/{(protocol or 'tcp')}"
        bucket = buckets.setdefault(
            key, {"port": port, "protocol": protocol or "tcp", "hosts": set(), "services": set()}
        )
        if host:
            bucket["hosts"].add(host)

    findings = _load_json(run_dir / "findings.json")
    if isinstance(findings, list):
        for entry in findings:
            if not isinstance(entry, dict):
                continue
            port = str(entry.get("port") or "")
            if not port:
                continue
            protocol = str(entry.get("protocol") or "tcp")
            host = str(entry.get("host") or "")
            key = f"{port}/{protocol}"
            bucket = buckets.setdefault(
                key, {"port": port, "protocol": protocol, "hosts": set(), "services": set()}
            )
            if host:
                bucket["hosts"].add(host)
            service = str(entry.get("service") or "").strip()
            if service and service != "unknown":
                bucket["services"].add(service)

    vulns = _load_json(run_dir / "vulnerabilities.json")
    vuln_by_port: dict[str, int] = {}
    if isinstance(vulns, list):
        for entry in vulns:
            if isinstance(entry, dict) and entry.get("port") is not None:
                p = str(entry["port"])
                vuln_by_port[p] = vuln_by_port.get(p, 0) + 1

    items: list[PortAggregateItem] = []
    for bucket in buckets.values():
        hosts = sorted(bucket["hosts"])
        port = str(bucket["port"])
        items.append(
            PortAggregateItem(
                port=port,
                protocol=bucket.get("protocol"),
                host_count=len(hosts),
                vulnerability_count=vuln_by_port.get(port, 0),
                hosts=hosts[:200],
                services=sorted(bucket.get("services", set())),
            )
        )
    items.sort(
        key=lambda item: (
            -item.host_count,
            -item.vulnerability_count,
            int(item.port) if item.port.isdigit() else 0,
            item.port,
        )
    )
    return items[:limit]


def is_screenshot_path(relative: str) -> bool:
    """PNG pixels under screenshots/ — operator-only (P4.4)."""
    parts = Path(relative).parts
    return len(parts) >= 2 and parts[0] == "screenshots" and parts[-1].lower().endswith(".png")


# Run artifacts that carry owner or subject identifiers rather than scan
# results: an RDAP abuse address (org_profile M1, #182) is a contactable human
# at the target organization, which is not the same class of data as an open
# port. Listed by exact run-relative name so a new stage has to opt in
# deliberately; org_profile M5 adds credential_leaks.* here.
_RESTRICTED_ARTIFACTS = frozenset(
    {
        "ownership.json",
        "ownership_findings.txt",
    }
)


def is_restricted_artifact(relative: str) -> bool:
    """Artifacts an operator may read but a viewer may not (org_profile #182).

    Same treatment as screenshot PNGs: hidden from the artifact listing,
    ``404`` for a viewer on both the preview and the download endpoint. Unlike
    screenshots these are readable text, so an operator gets them through the
    preview endpoint too.
    """
    parts = Path(relative).parts
    return len(parts) == 1 and parts[0].lower() in _RESTRICTED_ARTIFACTS


def resolve_artifact(
    settings: Settings,
    run_id: str,
    relative: str,
    *,
    tenant_id: str | None = None,
    allow_screenshots: bool = False,
) -> Path | None:
    """Resolve a run-relative artifact path to a real file, or ``None`` if the
    run/file doesn't exist or the path escapes the run directory. Rejects
    absolute paths and ``..`` segments (even if the HTTP layer normalizes URLs)
    and confirms the resolved target stays under ``run_dir``. Shared by the
    text-preview and binary-download endpoints. ``tenant_id`` additionally
    scopes the run itself, so artifacts of another tenant's run read as
    missing."""
    run_dir = get_run_dir(settings, run_id, tenant_id=tenant_id)
    if run_dir is None:
        return None
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        return None
    if is_screenshot_path(relative) and not allow_screenshots:
        return None
    target = (run_dir / rel).resolve()
    try:
        target.relative_to(run_dir.resolve())
    except ValueError:
        return None
    if not target.is_file():
        return None
    return target


def read_artifact_text(
    settings: Settings,
    run_id: str,
    relative: str,
    *,
    max_bytes: int = 1_000_000,
    tenant_id: str | None = None,
) -> str | None:
    target = resolve_artifact(settings, run_id, relative, tenant_id=tenant_id)
    if target is None:
        return None
    data = target.read_bytes()[:max_bytes]
    return data.decode("utf-8", errors="replace")


def list_screenshots(
    settings: Settings, run_id: str, *, tenant_id: str | None = None
) -> dict[str, Any] | None:
    """Operator-facing manifest of captured (already-redacted) screenshots.

    Pixels that the retention reaper already deleted stay in the list with
    ``available: false`` so the operator can tell "never captured" from
    "captured, then expired". Failed captures are omitted.
    """
    run_dir = get_run_dir(settings, run_id, tenant_id=tenant_id)
    if run_dir is None:
        return None
    raw = _load_json(run_dir / "screenshots.json")
    empty: dict[str, Any] = {
        "skipped_reason": None,
        "captured_count": 0,
        "redacted_fields": 0,
        "truncated": False,
        "retention_days": settings.screenshot_retention_days,
        "items": [],
    }
    if not isinstance(raw, dict):
        return empty
    items: list[dict[str, Any]] = []
    findings = raw.get("findings")
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict) or finding.get("error"):
                continue
            rel = str(finding.get("file") or "")
            target = resolve_artifact(
                settings, run_id, rel, tenant_id=tenant_id, allow_screenshots=True
            )
            items.append(
                {
                    "host": finding.get("host"),
                    "port": finding.get("port"),
                    "scheme": finding.get("scheme"),
                    "url": finding.get("url"),
                    "file": rel,
                    "redacted_fields": int(finding.get("redacted_fields") or 0),
                    "available": target is not None,
                }
            )
    return {
        "skipped_reason": raw.get("skipped_reason"),
        "captured_count": int(raw.get("captured_count") or 0),
        "redacted_fields": int(raw.get("redacted_fields") or 0),
        "truncated": bool(raw.get("truncated")),
        "retention_days": settings.screenshot_retention_days,
        "items": items,
    }
