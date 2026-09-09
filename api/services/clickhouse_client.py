"""ClickHouse client helpers (Phase 3 analytics)."""

from __future__ import annotations

import logging
from typing import Any, Sequence

LOG = logging.getLogger("shapoclyack.clickhouse")

VULN_TABLE = "shapoclyack.shapoclyack_vulnerabilities"
PORTS_TABLE = "shapoclyack.shapoclyack_open_ports"
CONTROLS_TABLE = "shapoclyack.shapoclyack_controls"

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

# One row per control per run (EPIC #182): the artifact holds the snapshot, these
# rows hold the trend. overall_verdict/overall_risk are denormalised onto every
# row so the run-level posture can be read without a second query.
CONTROL_COLUMNS = [
    "tenant_id",
    "run_id",
    "control",
    "title",
    "status",
    "impact",
    "risk_level",
    "coverage_checked",
    "coverage_total",
    "findings_critical",
    "findings_high",
    "findings_medium",
    "findings_low",
    "overall_verdict",
    "overall_risk",
    "timestamp",
]


class ClickHouseError(RuntimeError):
    """Raised when ClickHouse operations fail."""


def get_client(url: str, *, database: str = "shapoclyack"):
    """Create a clickhouse-connect client from ``OCTO_CLICKHOUSE_URL``.

    Accepted forms:
      - ``http://host:8123``
      - ``https://host:8443``
      - ``clickhouse://host:8123/shapoclyack``
      - ``host:8123``

    ``secure`` is passed explicitly, from the scheme (#309). Left unset,
    clickhouse-connect infers TLS from the port, so ``https://host:8123`` —
    a perfectly ordinary URL for a TLS-terminating proxy — sent the password
    and every row of scan data in cleartext without a word.
    """
    import clickhouse_connect

    host, port, db, username, password, secure = _parse_url(url, default_db=database)
    try:
        return clickhouse_connect.get_client(
            host=host,
            port=port,
            database=db,
            username=username,
            password=password,
            secure=secure,
        )
    except Exception as exc:  # noqa: BLE001
        raise ClickHouseError(f"ClickHouse connect failed: {exc}") from exc


def _parse_url(
    url: str,
    *,
    default_db: str,
) -> tuple[str, int, str, str, str, bool]:
    raw = (url or "").strip()
    if not raw:
        raise ClickHouseError("ClickHouse URL is empty")
    username = "default"
    password = ""
    database = default_db
    host = "localhost"
    port = 8123
    # No scheme at all (``host:8123``) keeps the historical plaintext default;
    # only ``https://`` asks for TLS, and it asks for it whatever the port.
    secure = False

    remainder = raw
    if "://" in remainder:
        scheme, remainder = remainder.split("://", 1)
        if scheme.lower() in {"https", "clickhouses"}:
            secure = True
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
    return host, port, database, username, password, secure


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


# Mirrors the CREATE TABLE in k8s/shapoclyack/base/clickhouse/init-local.sql and
# the ConfigMap next to it. That DDL only runs on ClickHouse's first boot, so an
# installation upgraded into EPIC #182 would otherwise have no controls table and
# every ingest message would fail on the insert. The worker runs this once at
# connect instead; it is a no-op where the init script already created the table.
CONTROLS_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS shapoclyack.shapoclyack_controls (
    tenant_id UUID,
    run_id String,
    control LowCardinality(String),
    title String,
    status LowCardinality(String),
    impact LowCardinality(String),
    risk_level LowCardinality(String),
    coverage_checked UInt32,
    coverage_total UInt32,
    findings_critical UInt32,
    findings_high UInt32,
    findings_medium UInt32,
    findings_low UInt32,
    overall_verdict LowCardinality(String),
    overall_risk LowCardinality(String),
    timestamp DateTime
) ENGINE = ReplacingMergeTree()
ORDER BY (tenant_id, control, timestamp, run_id)
TTL timestamp + INTERVAL 365 DAY
"""


def ensure_controls_table(client: Any) -> bool:
    """Create the controls table if missing. False when the DDL was refused.

    A read-only ClickHouse user is a legitimate deployment: the caller then skips
    control rows rather than failing the whole ingest, so vulnerability and port
    ingest keeps working on an installation that cannot run DDL.
    """
    try:
        client.command(CONTROLS_TABLE_DDL)
        return True
    except Exception:  # noqa: BLE001
        LOG.warning(
            "Could not ensure %s; control-matrix rows will be skipped",
            CONTROLS_TABLE,
            exc_info=True,
        )
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
