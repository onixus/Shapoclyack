from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from api.schemas import AliveHostItem, PortAggregateItem, RunDetail, RunSummary, VulnerabilityItem
from api.settings import Settings


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


def _geo_map(run_dir: Path) -> dict[str, dict[str, str | None]]:
    out: dict[str, dict[str, str | None]] = {}
    geo = _load_json(run_dir / "geoip.json")
    if isinstance(geo, dict):
        for host, value in geo.items():
            if isinstance(value, dict):
                out[str(host)] = {
                    "country": value.get("country") or None,
                    "city": value.get("city") or None,
                    "country_iso": value.get("country_iso") or None,
                }
    alive = _load_json(run_dir / "alive_hosts.json")
    if isinstance(alive, list):
        for row in alive:
            if not isinstance(row, dict) or not row.get("host"):
                continue
            host = str(row["host"])
            current = out.setdefault(host, {"country": None, "city": None, "country_iso": None})
            if not current.get("country") and row.get("country"):
                current["country"] = row.get("country")
            if not current.get("city") and row.get("city"):
                current["city"] = row.get("city")
            if not current.get("country_iso") and row.get("country_iso"):
                current["country_iso"] = row.get("country_iso")
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


def list_runs(settings: Settings) -> list[RunSummary]:
    results: list[RunSummary] = []
    for run_dir in _run_dirs(settings):
        run_id = _run_id_for(run_dir, settings)
        meta = _load_json(run_dir / "run_meta.json") or {}
        summary = _load_json(run_dir / "summary.json") or {}
        results.append(
            RunSummary(
                run_id=run_id,
                profile=meta.get("profile") if isinstance(meta, dict) else None,
                started_at=meta.get("started_at") if isinstance(meta, dict) else None,
                config=meta.get("config") if isinstance(meta, dict) else None,
                alive_hosts=summary.get("alive_hosts") if isinstance(summary, dict) else None,
                open_host_port_pairs=summary.get("open_host_port_pairs") if isinstance(summary, dict) else None,
                potential_vulnerabilities=(
                    summary.get("potential_vulnerabilities") if isinstance(summary, dict) else None
                ),
                vulnerable_hosts=summary.get("vulnerable_hosts") if isinstance(summary, dict) else None,
                has_diff=(run_dir / "diff.json").exists(),
                has_summary=(run_dir / "summary.json").exists(),
                path=str(run_dir),
            )
        )
    return results


def get_run_dir(settings: Settings, run_id: str) -> Path | None:
    if run_id == "default":
        candidate = settings.output_dir
        if candidate.is_dir():
            return candidate
        return None
    candidate = settings.output_dir / "runs" / run_id
    return candidate if candidate.is_dir() else None


def get_run_detail(settings: Settings, run_id: str) -> RunDetail | None:
    run_dir = get_run_dir(settings, run_id)
    if run_dir is None:
        return None
    artifacts = sorted(
        str(path.relative_to(run_dir))
        for path in run_dir.rglob("*")
        if path.is_file() and path.stat().st_size < 50_000_000
    )
    return RunDetail(
        run_id=run_id,
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
) -> list[VulnerabilityItem] | None:
    run_dir = get_run_dir(settings, run_id)
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
            )
        )
    items.sort(
        key=lambda item: (
            _SEVERITY_RANK.get(str(item.severity or "unknown").lower(), 4),
            -(float(item.cvss4) if item.cvss4 is not None else (float(item.cvss) if item.cvss is not None else -1.0)),
            str(item.host or ""),
            str(item.cve or ""),
        )
    )
    return items[:limit]


def get_hosts(settings: Settings, run_id: str, *, limit: int = 10000) -> list[AliveHostItem] | None:
    run_dir = get_run_dir(settings, run_id)
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
                    os_name=entry.get("os_name") or None,
                    os_accuracy=entry.get("os_accuracy"),
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
                    vulnerability_count=vuln_counts.get(host, 0),
                )
            )
    rows.sort(key=lambda item: (-item.vulnerability_count, item.host))
    return rows[:limit]


def get_ports(settings: Settings, run_id: str, *, limit: int = 10000) -> list[PortAggregateItem] | None:
    run_dir = get_run_dir(settings, run_id)
    if run_dir is None:
        return None

    # port_key -> {protocol, hosts}
    buckets: dict[str, dict[str, Any]] = {}
    for line in _read_lines(run_dir / "open_ports.txt"):
        host, port, protocol = _parse_endpoint(line)
        if not port:
            continue
        key = f"{port}/{(protocol or 'tcp')}"
        bucket = buckets.setdefault(key, {"port": port, "protocol": protocol or "tcp", "hosts": set()})
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
            bucket = buckets.setdefault(key, {"port": port, "protocol": protocol, "hosts": set()})
            if host:
                bucket["hosts"].add(host)

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


def resolve_artifact(settings: Settings, run_id: str, relative: str) -> Path | None:
    """Resolve a run-relative artifact path to a real file, or ``None`` if the
    run/file doesn't exist or the path escapes the run directory. Rejects
    absolute paths and ``..`` segments (even if the HTTP layer normalizes URLs)
    and confirms the resolved target stays under ``run_dir``. Shared by the
    text-preview and binary-download endpoints."""
    run_dir = get_run_dir(settings, run_id)
    if run_dir is None:
        return None
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        return None
    target = (run_dir / rel).resolve()
    try:
        target.relative_to(run_dir.resolve())
    except ValueError:
        return None
    if not target.is_file():
        return None
    return target


def read_artifact_text(settings: Settings, run_id: str, relative: str, *, max_bytes: int = 1_000_000) -> str | None:
    target = resolve_artifact(settings, run_id, relative)
    if target is None:
        return None
    data = target.read_bytes()[:max_bytes]
    return data.decode("utf-8", errors="replace")
