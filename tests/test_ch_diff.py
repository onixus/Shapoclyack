"""Phase 10.1: normalized event helpers in the ClickHouse-backed diff path."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from api.services import ch_diff


def test_cve_key_to_event():
    assert ch_diff._cve_key_to_event("10.0.0.1|CVE-2020-1") == {
        "kind": "new_cve",
        "host": "10.0.0.1",
        "cve": "CVE-2020-1",
    }


def test_port_key_to_event():
    assert ch_diff._port_key_to_event("10.0.0.1:443/tcp") == {
        "kind": "new_open_port",
        "host": "10.0.0.1",
        "port": "443",
        "protocol": "tcp",
    }


def test_compute_clickhouse_diff_emits_events_for_added_only():
    with (
        patch.object(ch_diff, "fetch_tenant_cves", return_value={"10.0.0.1|CVE-2020-1", "10.0.0.2|CVE-2020-2"}),
        patch.object(ch_diff, "fetch_tenant_ports", return_value={"10.0.0.1:443/tcp"}),
    ):
        diff = ch_diff.compute_clickhouse_diff(
            "http://ch:8123",
            tenant_id="ten_acme",
            previous_cves={"10.0.0.2|CVE-2020-2"},
            previous_ports=set(),
        )
    assert diff["has_changes"] is True
    kinds = {(e["kind"], e.get("cve") or e.get("port")) for e in diff["events"]}
    assert kinds == {("new_cve", "CVE-2020-1"), ("new_open_port", "443")}
    assert diff["counts"]["events"] == 2
    # Removed-only deltas (none here) would not produce an event — matches
    # report_diff.py's convention of events being new/positive occurrences only.


# --- P3.8: bounded fetches -------------------------------------------------


class _FakeResult:
    def __init__(self, rows):
        self.result_rows = rows


class _FakeClient:
    """Records the SQL it was handed and replays a canned result."""

    def __init__(self, rows):
        self._rows = rows
        self.last_sql = ""
        self.last_params: dict = {}

    def query(self, sql, parameters=None):
        self.last_sql = sql
        self.last_params = parameters or {}
        return _FakeResult(self._rows)


def test_fetch_tenant_cves_applies_a_limit():
    client = _FakeClient([("10.0.0.1", "CVE-2020-1")])
    with patch.object(ch_diff.ch, "get_client", return_value=client):
        keys = ch_diff.fetch_tenant_cves("http://ch:8123", "ten_acme", max_rows=10)
    assert keys == {"10.0.0.1|CVE-2020-1"}
    # max_rows + 1, so exceeding the cap is detected rather than inferred from
    # a result that happens to be exactly max_rows long.
    assert "LIMIT 11" in client.last_sql


def test_fetch_tenant_ports_accepts_since():
    client = _FakeClient([("10.0.0.1", 443, "tcp")])
    with patch.object(ch_diff.ch, "get_client", return_value=client):
        keys = ch_diff.fetch_tenant_ports(
            "http://ch:8123", "ten_acme", since=datetime(2026, 1, 1, tzinfo=UTC)
        )
    assert keys == {"10.0.0.1:443/tcp"}
    assert "timestamp >=" in client.last_sql
    assert client.last_params["since"].tzinfo is None  # DateTime column is naive


@pytest.mark.parametrize(
    "fetch, rows",
    [
        (ch_diff.fetch_tenant_cves, [("10.0.0.1", f"CVE-2020-{i}") for i in range(4)]),
        (ch_diff.fetch_tenant_ports, [("10.0.0.1", 400 + i, "tcp") for i in range(4)]),
    ],
)
def test_fetch_refuses_a_truncated_result(fetch, rows):
    """A short set would report every dropped key as removed — worse than an
    error, so the cap raises instead of silently truncating."""
    client = _FakeClient(rows)
    with patch.object(ch_diff.ch, "get_client", return_value=client):
        with pytest.raises(ch_diff.ch.ClickHouseError, match="max_rows=3"):
            fetch("http://ch:8123", "ten_acme", max_rows=3)


def test_fetch_allows_exactly_max_rows():
    client = _FakeClient([("10.0.0.1", f"CVE-2020-{i}") for i in range(3)])
    with patch.object(ch_diff.ch, "get_client", return_value=client):
        assert len(ch_diff.fetch_tenant_cves("http://ch:8123", "ten_acme", max_rows=3)) == 3
