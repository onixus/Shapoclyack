"""ClickHouse client helpers (Phase 3 analytics)."""

from __future__ import annotations

import logging
from typing import Any, Sequence

LOG = logging.getLogger("octo-man.clickhouse")

VULN_TABLE = "shapoclyack.shapoclyack_vulnerabilities"
PORTS_TABLE = "shapoclyack.shapoclyack_open_ports"

VULN_COLUMNS = [
    "tenant_id",
    "asset_ip",
    "cve_id",
    "base_cvss",
    "epss_score",
    "asset_criticality",
    "exploit_active",
    "cisa_decision",
    "contextual_score",
    "scoring_model_version",
    "timestamp",
]

PORT_COLUMNS = [
    "tenant_id",
    "target_ip",
    "port",
    "protocol",
    "run_id",
    "timestamp",
]


class ClickHouseError(RuntimeError):
    """Raised when ClickHouse operations fail."""


def get_client(url: str, *, database: str = "shapoclyack"):
    """Create a clickhouse-connect client from ``OCTO_CLICKHOUSE_URL``.

    Accepted forms:
      - ``http://host:8123``
      - ``clickhouse://host:8123/shapoclyack``
      - ``host:8123``
    """
    import clickhouse_connect

    host, port, db, username, password = _parse_url(url, default_db=database)
    try:
        return clickhouse_connect.get_client(
            host=host,
            port=port,
            database=db,
            username=username,
            password=password,
        )
    except Exception as exc:  # noqa: BLE001
        raise ClickHouseError(f"ClickHouse connect failed: {exc}") from exc


def _parse_url(
    url: str,
    *,
    default_db: str,
) -> tuple[str, int, str, str, str]:
    raw = (url or "").strip()
    if not raw:
        raise ClickHouseError("ClickHouse URL is empty")
    username = "default"
    password = ""
    database = default_db
    host = "localhost"
    port = 8123

    remainder = raw
    if "://" in remainder:
        scheme, remainder = remainder.split("://", 1)
        if scheme in {"https"}:
            port = 8443
    if "@" in remainder:
        creds, remainder = remainder.rsplit("@", 1)
        if ":" in creds:
            username, password = creds.split(":", 1)
        else:
            username = creds
    if "/" in remainder:
        hostport, db_part = remainder.split("/", 1)
        if db_part:
            database = db_part.split("?")[0] or database
        remainder = hostport
    if ":" in remainder:
        host, port_s = remainder.rsplit(":", 1)
        port = int(port_s)
    else:
        host = remainder or host
    return host, port, database, username, password


def ping(url: str) -> bool:
    if not (url or "").strip():
        return False
    try:
        client = get_client(url)
        client.query("SELECT 1")
        return True
    except Exception:  # noqa: BLE001
        LOG.debug("ClickHouse ping failed", exc_info=True)
        return False


def insert_rows(
    client: Any,
    table: str,
    columns: Sequence[str],
    rows: list[list[Any]],
) -> int:
    if not rows:
        return 0
    client.insert(table, rows, column_names=list(columns))
    return len(rows)
