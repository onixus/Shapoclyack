"""ClickHouse-backed analytical diffs (Phase 3.4 helper).

Filesystem ``report_diff.compute_report_diff`` remains the scanner default.
These helpers query ClickHouse when ``OCTO_CLICKHOUSE_URL`` is configured.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from api.services import clickhouse_client as ch
from api.services.ch_transform import tenant_to_uuid

# Both fetches materialize a whole tenant's history into a Python set, because
# the diff below is a set difference — there is no correct way to answer it
# from a truncated page. So the cap *refuses* instead of silently returning a
# short set, which would report every missing key as "removed" and every later
# re-observation as "new". Measured at 50k assets the two fetches pull 183k +
# 200k rows in ~260 ms combined (ROADMAP P3.8, docs/scale-profile.md); the
# tables accumulate across runs, so this grows with history, not just with
# asset count. Callers that trip the cap should narrow with ``since``.
MAX_DIFF_ROWS = 500_000


def _guard(rows: list, max_rows: int, table: str) -> list:
    if len(rows) > max_rows:
        raise ch.ClickHouseError(
            f"{table} returned more than max_rows={max_rows} for this tenant. "
            "Refusing to build a diff from a truncated result — it would report "
            "the dropped keys as removed. Narrow the window with `since`, or "
            "raise max_rows deliberately."
        )
    return rows


def fetch_tenant_cves(
    clickhouse_url: str,
    tenant_id: str,
    *,
    since: datetime | None = None,
    max_rows: int = MAX_DIFF_ROWS,
) -> set[str]:
    """Return set of ``asset_ip|cve_id`` keys for a tenant from ClickHouse."""
    client = ch.get_client(clickhouse_url)
    tid = str(tenant_to_uuid(tenant_id))
    sql = (
        "SELECT asset_ip, cve_id FROM shapoclyack.shapoclyack_vulnerabilities "
        "WHERE tenant_id = {tid:UUID}"
    )
    params: dict[str, Any] = {"tid": tid}
    if since is not None:
        sql += " AND timestamp >= {since:DateTime}"
        params["since"] = since.replace(tzinfo=None)
    # +1 so the cap can be detected rather than inferred from a full page.
    sql += f" LIMIT {int(max_rows) + 1}"
    result = client.query(sql, parameters=params)
    rows = _guard(result.result_rows, max_rows, "shapoclyack_vulnerabilities")
    return {f"{row[0]}|{row[1]}" for row in rows}


def fetch_tenant_ports(
    clickhouse_url: str,
    tenant_id: str,
    *,
    since: datetime | None = None,
    max_rows: int = MAX_DIFF_ROWS,
) -> set[str]:
    """Return set of ``target_ip:port/protocol`` keys for a tenant."""
    client = ch.get_client(clickhouse_url)
    tid = str(tenant_to_uuid(tenant_id))
    sql = (
        "SELECT target_ip, port, protocol FROM shapoclyack.shapoclyack_open_ports "
        "WHERE tenant_id = {tid:UUID}"
    )
    params: dict[str, Any] = {"tid": tid}
    if since is not None:
        sql += " AND timestamp >= {since:DateTime}"
        params["since"] = since.replace(tzinfo=None)
    sql += f" LIMIT {int(max_rows) + 1}"
    result = client.query(sql, parameters=params)
    rows = _guard(result.result_rows, max_rows, "shapoclyack_open_ports")
    return {f"{row[0]}:{row[1]}/{row[2]}" for row in rows}


def _cve_key_to_event(key: str) -> dict[str, Any]:
    host, _, cve = key.partition("|")
    return {"kind": "new_cve", "host": host, "cve": cve}


def _port_key_to_event(key: str) -> dict[str, Any]:
    host_port, _, protocol = key.partition("/")
    host, _, port = host_port.partition(":")
    return {"kind": "new_open_port", "host": host, "port": port, "protocol": protocol}


def compute_clickhouse_diff(
    clickhouse_url: str,
    *,
    tenant_id: str,
    previous_cves: set[str],
    previous_ports: set[str],
) -> dict[str, Any]:
    """Diff current CH state vs provided previous key sets (e.g. from prior snapshot)."""
    current_cves = fetch_tenant_cves(clickhouse_url, tenant_id)
    current_ports = fetch_tenant_ports(clickhouse_url, tenant_id)
    cves_added = sorted(current_cves - previous_cves)
    cves_removed = sorted(previous_cves - current_cves)
    ports_added = sorted(current_ports - previous_ports)
    ports_removed = sorted(previous_ports - current_ports)

    # Normalized asset-level events (Phase 10.1), same {"kind": ...} shape as
    # scanner/pipeline/report_diff.py's events list — new_asset/cert_expiring/
    # decommissioned_host aren't derivable from these two CH tables alone, so
    # this tenant-wide path only ever emits new_cve/new_open_port.
    events: list[dict[str, Any]] = [_cve_key_to_event(key) for key in cves_added]
    events.extend(_port_key_to_event(key) for key in ports_added)

    return {
        "source": "clickhouse",
        "tenant_id": tenant_id,
        "has_changes": bool(cves_added or cves_removed or ports_added or ports_removed),
        "vulnerabilities": {
            "added": cves_added,
            "removed": cves_removed,
            "added_count": len(cves_added),
            "removed_count": len(cves_removed),
        },
        "ports": {
            "added": ports_added,
            "removed": ports_removed,
        },
        "events": events,
        "counts": {
            "vulns_added": len(cves_added),
            "vulns_removed": len(cves_removed),
            "ports_added": len(ports_added),
            "ports_removed": len(ports_removed),
            "events": len(events),
        },
    }
