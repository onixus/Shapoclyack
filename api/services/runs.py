from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from api.schemas import AliveHostItem, PortAggregateItem, RunDetail, RunSummary, VulnerabilityItem
from api.services import artifact_store
from api.services import pagination
from api.services import promoted_domains as promoted_service
from api.services import tenants as tenants_service
from api.services.artifact_store import keys as artifact_keys
from api.services.artifact_store import workspace
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


def _run_ids(settings: Settings) -> list[str]:
    """Every run this installation can see, newest first.

    Ids rather than directories since #336: on an object-storage backend a run
    is not a directory until somebody asks for one, and enumerating the runs
    must not fetch them. The ordering is unchanged — ids are timestamps, so the
    name sorts the way the clock does.
    """
    ids = workspace.run_ids(settings)
    if ids:
        return ids
    # Flat layout fallback (per_run_output=false), local backend only: there is
    # no ``runs/`` subtree, the artifacts sit in output_dir itself.
    if (settings.output_dir / "summary.json").exists() or (
        settings.output_dir / "alive_ips.txt"
    ).exists():
        return [workspace.FLAT_RUN_ID]
    return []


def read_run_tenant(run_dir: Path) -> str:
    """Tenant that owns the run materialised at ``run_dir``.

    Falls back to the default tenant when the marker is missing or unreadable —
    runs written before P0, and any run produced by the plain ``scanner.main``
    CLI outside the API, have no marker.

    Takes a path rather than a run id because every caller already holds the
    run's working copy: they went through :func:`get_run_dir`, which is what
    materialised it. The listing, which has no working copy and must not make
    one, uses :func:`run_tenant_of` instead.
    """
    return _tenant_from_marker(_load_json(run_dir / RUN_TENANT_FILE))


def read_run_surface(run_dir: Path) -> str | None:
    """Surface this run scanned — external/internal/mixed — or ``None``.

    ``None`` is "not recorded", not a fourth surface: runs written before this
    shipped carry no key, and neither does a scan of the server's default input
    files, which the classifier never sees (see api.services.scan_surface).
    """
    return _surface_from_marker(_load_json(run_dir / RUN_TENANT_FILE))


def _tenant_from_marker(meta: Any) -> str:
    if isinstance(meta, dict):
        tenant_id = str(meta.get("tenant_id") or "").strip()
        if tenant_id:
            return tenant_id
    return tenants_service.DEFAULT_TENANT_ID


def _surface_from_marker(meta: Any) -> str | None:
    if isinstance(meta, dict):
        surface = str(meta.get("surface") or "").strip()
        if surface:
            return surface
    return None


def run_tenant_of(settings: Settings, run_id: str) -> str:
    """Owner of a run, without materialising it.

    One small object read (cached), which is what makes the tenant filter in
    the listing affordable on a remote backend: the alternative is fetching
    every run in the installation to look at one file in each.
    """
    return _tenant_from_marker(workspace.read_run_marker(settings, run_id))


def run_surface_of(settings: Settings, run_id: str) -> str | None:
    return _surface_from_marker(workspace.read_run_marker(settings, run_id))


def _run_tenant_marker(
    tenant_id: str, *, job_id: str | None = None, surface: str | None = None
) -> bytes:
    payload: dict[str, Any] = {"tenant_id": tenant_id}
    if job_id:
        payload["job_id"] = job_id
    if surface:
        payload["surface"] = surface
    return (json.dumps(payload, indent=2) + "\n").encode("utf-8")


def stage_run_tenant(
    staging: Path,
    tenant_id: str,
    *,
    job_id: str | None = None,
    surface: str | None = None,
) -> None:
    """Tag an upload that has not been published yet, in its staging tree.

    The counterpart of :func:`write_run_tenant` for the agent ingest, and not
    best-effort: the marker goes in *before* the run is promoted and uploaded,
    so both copies carry their owner from the moment anything can read them.
    Written afterwards, a failure would leave a published run with no marker —
    and :func:`read_run_tenant` reads that as the default tenant, i.e. as one
    tenant's scan sitting in every tenant's run list. The caller lets an error
    here cost the upload its outcome instead.
    """
    (Path(staging) / RUN_TENANT_FILE).write_bytes(
        _run_tenant_marker(tenant_id, job_id=job_id, surface=surface)
    )


def write_run_tenant(
    settings: Settings,
    run_id: str,
    tenant_id: str,
    *,
    job_id: str | None = None,
    surface: str | None = None,
) -> bool:
    """Tag a run directory with its owning tenant. Best-effort: returns False
    when the run directory doesn't exist or the write fails, since losing the
    marker must never fail a scan that otherwise succeeded (the run then reads
    back as the default tenant).

    ``surface`` rides along in the same file rather than a second one: it is
    known at the same moment, written by the same two call sites, and a run
    listing already pays for this read.
    """
    run_dir = workspace.scratch_run_dir(settings, run_id)
    if not run_dir.is_dir():
        return False
    try:
        # Through the workspace, so the marker reaches the artifact store and
        # not only this pod: a run whose owner is recorded on one replica's
        # disk reads back as the default tenant everywhere else, which is the
        # run list of every tenant on the installation (#336).
        workspace.publish_run_file(
            settings,
            run_id,
            RUN_TENANT_FILE,
            _run_tenant_marker(tenant_id, job_id=job_id, surface=surface),
        )
    except (OSError, artifact_store.ArtifactStoreError):
        LOG.warning("Could not tag run %s with tenant %s", run_id, tenant_id, exc_info=True)
        return False
    workspace.forget_run_marker(run_id)
    return True


def list_runs(
    settings: Settings,
    *,
    offset: int = 0,
    limit: int = pagination.DEFAULT_LIMIT,
    q: str | None = None,
    order: str | None = None,
    tenant_id: str | None = None,
    surface: str | None = None,
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

    ``surface`` (external/internal/mixed, or ``"unknown"`` for runs carrying no
    marker) reads the same file and is the same cost class: one read per run
    before slicing, paid only when the filter is asked for.
    """
    ids = _run_ids(settings)
    if q:
        needle = q.strip().lower()
        ids = [run for run in ids if needle in run.lower()]
    if tenant_id:
        ids = [run for run in ids if run_tenant_of(settings, run) == tenant_id]
    if surface:
        wanted = None if surface == "unknown" else surface
        ids = [run for run in ids if run_surface_of(settings, run) == wanted]
    if (order or "").lower() == "asc":
        ids = list(reversed(ids))
    page_ids, total = pagination.slice_page(ids, offset=offset, limit=limit)

    results: list[RunSummary] = []
    for run_id in page_ids:
        # Only the page is materialised — which is the same promise the
        # docstring above always made about run_meta.json and summary.json,
        # now enforced by the cost of fetching rather than by care.
        run_dir = workspace.run_dir(settings, run_id)
        meta = _load_json(run_dir / "run_meta.json") or {}
        summary = _load_json(run_dir / "summary.json") or {}
        results.append(
            RunSummary(
                run_id=run_id,
                tenant_id=tenant_id or run_tenant_of(settings, run_id),
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
                surface=run_surface_of(settings, run_id),
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
    # Checked before the run is fetched: an id from another tenant must not
    # cost a transfer, and on a remote backend materialising first would let an
    # unauthorised caller fill this pod's cache with runs they cannot read.
    if tenant_id and run_tenant_of(settings, run_id) != tenant_id:
        return None
    candidate = workspace.run_dir(settings, run_id)
    if not candidate.is_dir():
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
        # org_profile.json embeds ownership.json verbatim (registrant org,
        # abuse contacts), so leaving it open would hand a viewer through the
        # artifact endpoints exactly what GET /runs/{id}/org-profile withholds.
        "org_profile.json",
        "credential_leaks.json",
        "credential_leaks_findings.txt",
        "credential_leaks_identifiers.json",
        "credential_leaks_identifiers.txt",
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
    allow_restricted: bool = False,
) -> Path | None:
    """Resolve a run-relative artifact path to a real file, or ``None`` if the
    run/file doesn't exist or the path escapes the run directory. Rejects
    absolute paths and ``..`` segments (even if the HTTP layer normalizes URLs)
    and confirms the resolved target stays under ``run_dir``. Shared by the
    text-preview and binary-download endpoints. ``tenant_id`` additionally
    scopes the run itself, so artifacts of another tenant's run read as
    missing.

    Restricted artifacts (:func:`is_restricted_artifact`) are refused here as
    well as in the routes, the same belt-and-braces as ``allow_screenshots``.
    The route check alone would mean the next endpoint that reaches for an
    artifact inherits no protection at all -- and org_profile M5 is already
    scheduled to put credential-leak identifiers behind this predicate."""
    run_dir = get_run_dir(settings, run_id, tenant_id=tenant_id)
    if run_dir is None:
        return None
    rel = _safe_relative(
        relative, allow_screenshots=allow_screenshots, allow_restricted=allow_restricted
    )
    if rel is None:
        return None
    target = (run_dir / rel).resolve()
    try:
        target.relative_to(run_dir.resolve())
    except ValueError:
        return None
    if not target.is_file():
        return None
    return target


def _safe_relative(
    relative: str, *, allow_screenshots: bool, allow_restricted: bool
) -> Path | None:
    """The shared half of artifact resolution: is this path allowed at all?

    Split out when artifacts moved to the store (#336) so the two resolvers --
    one answering a filesystem path, one answering a storage key -- cannot
    drift on which artifacts they refuse. A check that exists twice is a check
    that will eventually exist once.
    """
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        return None
    if is_screenshot_path(relative) and not allow_screenshots:
        return None
    if is_restricted_artifact(relative) and not allow_restricted:
        return None
    return rel


def artifact_key(
    settings: Settings,
    run_id: str,
    relative: str,
    *,
    tenant_id: str | None = None,
    allow_screenshots: bool = False,
    allow_restricted: bool = False,
) -> str | None:
    """Storage key for one run artifact, or ``None``.

    The same refusals as :func:`resolve_artifact`, without materialising the
    run: a download of one screenshot should not pull down the scan it came
    from. ``None`` also for the flat single-run layout
    (``per_run_output=false``), whose artifacts have no ``runs/<id>`` subtree
    to be keyed under — callers fall back to the path resolver, which is the
    only thing that layout has ever had.
    """
    if run_id == workspace.FLAT_RUN_ID:
        return None
    rel = _safe_relative(
        relative, allow_screenshots=allow_screenshots, allow_restricted=allow_restricted
    )
    if rel is None:
        return None
    if tenant_id and run_tenant_of(settings, run_id) != tenant_id:
        return None
    key = artifact_keys.run_artifact(run_id, rel.as_posix())
    if not artifact_store.get_store(settings).exists(key):
        return None
    return key


def read_artifact_text(
    settings: Settings,
    run_id: str,
    relative: str,
    *,
    max_bytes: int = 1_000_000,
    tenant_id: str | None = None,
    allow_restricted: bool = False,
) -> str | None:
    target = resolve_artifact(
        settings, run_id, relative, tenant_id=tenant_id, allow_restricted=allow_restricted
    )
    if target is None:
        return None
    data = target.read_bytes()[:max_bytes]
    return data.decode("utf-8", errors="replace")


def artifact_size(settings: Settings, key: str) -> int | None:
    """Bytes at a run-artifact key, or ``None`` when it is gone."""
    return artifact_store.get_store(settings).size(key)


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


def get_controls(
    settings: Settings, run_id: str, *, tenant_id: str | None = None
) -> Any | None:
    """Read controls matrix summary for this run."""
    run_dir = get_run_dir(settings, run_id, tenant_id=tenant_id)
    if run_dir is None:
        return None
    raw = _load_json(run_dir / "controls.json")
    if not isinstance(raw, dict):
        return None
    return raw


def get_org_profile(
    settings: Settings,
    run_id: str,
    *,
    tenant_id: str | None = None,
    allow_restricted: bool = False,
) -> dict[str, Any] | None:
    """Read combined organization profile (ownership + related domains + controls) for this run.

    ``ownership.json`` is a restricted artifact (:func:`is_restricted_artifact`):
    it carries RDAP registrant and abuse contacts, and a viewer gets a ``404``
    for it on the artifact endpoints. Returning it inline here regardless of role
    would route straight around that gate, so the ownership block is only
    included when the caller is allowed restricted artifacts (operator+).
    """
    run_dir = get_run_dir(settings, run_id, tenant_id=tenant_id)
    if run_dir is None:
        return None

    ownership_data = (
        _load_json(run_dir / "ownership.json") if allow_restricted else None
    )
    related_data = _load_json(run_dir / "related_domains.json")
    controls_data = _load_json(run_dir / "controls.json")
    if not ownership_data and not related_data and not controls_data:
        # A viewer on a run that only produced ownership.json still gets a 404
        # rather than a hint that the restricted artifact exists.
        return None

    # The tenant's whole promoted list, not just this run's candidates: a
    # promoted domain is a seed on the next run and is never proposed again,
    # so an intersection would hide every promotion from every later run —
    # and with it the only place the operator sees what widens their scans.
    promoted_lines = promoted_service.promoted_names(settings, read_run_tenant(run_dir))

    seed_domains: list[str] = []
    if isinstance(related_data, dict):
        seed_domains = related_data.get("seed_domains") or []
    elif isinstance(ownership_data, dict):
        seed_domains = list((ownership_data.get("domains") or {}).keys())

    return {
        "run_id": run_id,
        "seed_domains": seed_domains,
        "ownership": ownership_data if isinstance(ownership_data, dict) else None,
        "ownership_restricted": not allow_restricted,
        "related_domains": related_data if isinstance(related_data, dict) else None,
        "controls": controls_data if isinstance(controls_data, dict) else None,
        "promoted_domains": promoted_lines,
        "generated_at": (
            (related_data.get("evaluated_at") if isinstance(related_data, dict) else None)
            or (controls_data.get("evaluated_at") if isinstance(controls_data, dict) else None)
        ),
    }


#: A promoted entry becomes scope for every later scan of the tenant, so the
#: value that is stored has to be a single hostname and nothing else. The path
#: parameter arrives URL-decoded, so ``%0A`` would otherwise smuggle a second
#: name into the target list the scanner is handed.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


class PromoteDomainError(ValueError):
    """Raised when a promote request names something that may not be promoted."""


def _clean_domain(domain: str) -> str:
    name = promoted_service.normalize_domain(domain)
    if not _DOMAIN_RE.match(name):
        raise PromoteDomainError(f"'{domain}' is not a valid domain name")
    return name


def _candidate_domains(run_dir: Path) -> set[str]:
    """The related-domain candidates this run proposed, normalised the way
    promotions are stored — one parser for the gate and the display."""
    related_data = _load_json(run_dir / "related_domains.json")
    names: set[str] = set()
    if isinstance(related_data, dict):
        for candidate in related_data.get("candidates") or []:
            if isinstance(candidate, dict) and candidate.get("domain"):
                names.add(promoted_service.normalize_domain(str(candidate["domain"])))
    return names


def _promotable_candidate(
    settings: Settings, run_id: str, domain: str, *, tenant_id: str | None
) -> tuple[Path, str] | None:
    """``(run_dir, domain)`` when ``domain`` is a candidate this run proposed.

    Only a syntactically valid domain that this run actually discovered as a
    related-domain candidate may be promoted: the list feeds the scope of
    every later scan, and an operator should not be able to authorize a host
    the scanner never proposed by typing it into the URL. Withdrawal is not
    gated this way — see :func:`withdraw_related_domain`.
    """
    run_dir = get_run_dir(settings, run_id, tenant_id=tenant_id)
    if run_dir is None:
        return None

    domain_clean = _clean_domain(domain)
    if domain_clean not in _candidate_domains(run_dir):
        raise PromoteDomainError(
            f"'{domain_clean}' is not a related-domain candidate discovered by this run"
        )
    return run_dir, domain_clean


def promote_related_domain(
    settings: Settings,
    run_id: str,
    domain: str,
    *,
    tenant_id: str | None = None,
    username: str = "",
) -> dict[str, Any] | None:
    """Record the operator's decision that a discovered domain is the tenant's.

    Stored on the tenant (``tenant_promoted_domains``), not in the run: every
    scan the tenant starts afterwards carries it. Raises
    ``scan_scopes.ScanScopeDenied`` when the approved scope does not cover the
    domain — attribution is the operator's call, authorization is the admin's.
    """
    found = _promotable_candidate(settings, run_id, domain, tenant_id=tenant_id)
    if found is None:
        return None
    run_dir, domain_clean = found
    record = promoted_service.promote(
        settings,
        tenant_id=read_run_tenant(run_dir),
        domain=domain_clean,
        source_run_id=run_id,
        promoted_by=username,
    )
    return {
        "domain": domain_clean,
        "promoted": True,
        "message": f"Domain '{domain_clean}' promoted to scope of tenant {record.tenant_id}",
        "promoted_at": record.promoted_at.isoformat(),
    }


def withdraw_related_domain(
    settings: Settings,
    run_id: str,
    domain: str,
    *,
    tenant_id: str | None = None,
    username: str = "",
) -> dict[str, Any] | None:
    """Withdraw a promotion from the run's Org Profile tab.

    The run only names the tenant; the undo itself is keyed on ``(tenant,
    domain)`` and deliberately does *not* require the domain to still be a
    candidate of this run — a promoted domain is a seed on the next run and
    is never proposed again, and the run that proposed it expires with
    retention. ``DELETE /api/promoted-domains/{domain}`` is the same undo
    without a run at all.
    """
    run_dir = get_run_dir(settings, run_id, tenant_id=tenant_id)
    if run_dir is None:
        return None
    domain_clean = _clean_domain(domain)
    removed = promoted_service.withdraw(
        settings, tenant_id=read_run_tenant(run_dir), domain=domain_clean, withdrawn_by=username
    )
    return {
        "domain": domain_clean,
        "promoted": False,
        "message": (
            f"Domain '{domain_clean}' withdrawn from scope"
            if removed
            else f"Domain '{domain_clean}' was not promoted"
        ),
        "promoted_at": None,
    }


def get_leak_identifiers(
    settings: Settings, run_id: str, *, tenant_id: str | None = None
) -> dict[str, Any] | None:
    """Read full unmasked corporate leak identifiers for this run (operator-only, org_profile M5)."""
    run_dir = get_run_dir(settings, run_id, tenant_id=tenant_id)
    if run_dir is None:
        return None
    raw = _load_json(run_dir / "credential_leaks_identifiers.json")
    if not isinstance(raw, dict):
        return None
    return {
        "run_id": run_id,
        "total_identifiers": int(raw.get("total_identifiers") or 0),
        "domains": raw.get("domains") if isinstance(raw.get("domains"), dict) else {},
        "revealed": bool(raw.get("revealed", True)),
        "withheld_reason": raw.get("withheld_reason"),
        "withheld_identifiers": int(raw.get("withheld_identifiers") or 0),
        "generated_at": raw.get("generated_at"),
    }



