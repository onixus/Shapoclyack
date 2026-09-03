"""Per-tenant usage metering and quotas (ROADMAP Track E, MSSP operations).

The failure this covers is commercial rather than technical: before it, "how
much of what we sold is this customer using" had no answer, and an upgrade
that guessed wrong at the answer is worse than no meter at all. So the
assertions here are as much about *when the platform refuses* as about the
numbers:

* A tenant nobody has configured is unlimited — a quota that failed closed on
  an empty table would turn a release into an outage for every customer.
* A stored row wins over the platform default *including when it is NULL*,
  which is how one customer is exempted without disabling metering globally.
* Scans are refused at admission (429 + ``Retry-After``, because the refusal
  expires by itself), assets are capped at ingest (a number the ingest path
  can honour partially, never an exception that would discard the findings for
  the assets inside the quota).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from api.db import models
from api.db.engine import get_session
from api.schemas import StartScanRequest
from api.services import metrics as metrics_service
from api.services import quotas
from api.services import tenants as tenants_service
from api.settings import Settings
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres

pytestmark = requires_postgres

DEFAULT = tenants_service.DEFAULT_TENANT_ID


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    """A clean control plane with the default tenant and no stored quota."""
    s = make_settings(tmp_path)
    tenants_service.configure(s)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(s)
    quotas.reset_for_tests(s)
    return s


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _job(
    settings: Settings,
    tenant_id: str,
    *,
    queued_at: datetime,
    job_id: str,
    quota_exempt: bool = False,
) -> None:
    with get_session(settings.postgres_url) as session:
        session.add(
            models.Job(
                job_id=job_id,
                tenant_id=tenant_id,
                status="succeeded",
                queued_at=queued_at,
                finished_at=queued_at,
                quota_exempt=quota_exempt,
            )
        )


def _asset(settings: Settings, tenant_id: str, asset_id: str, *, status: str = "active") -> None:
    now = _now()
    with get_session(settings.postgres_url) as session:
        session.add(
            models.Asset(
                asset_id=asset_id,
                tenant_id=tenant_id,
                status=status,
                first_seen=now,
                last_seen=now,
            )
        )


def _denied(resource: str) -> float:
    """The current value of ``octo_quota_denied_total`` for one resource."""
    return metrics_service.QUOTA_DENIED_TOTAL.labels(resource)._value.get()  # noqa: SLF001


# --------------------------------------------------------------------------
# 1-2. Where the numbers come from: default, tenant row, and "unlimited"
# --------------------------------------------------------------------------


def test_a_tenant_nobody_configured_is_unlimited_not_zero(settings: Settings):
    """No row plus a default of 0 must not mean "no scans" — it means no limit.

    This is the upgrade-day case: the table is empty for every customer, and a
    quota that failed closed here would be an outage caused by billing.
    """
    _asset(settings, DEFAULT, "asset-1")
    _job(settings, DEFAULT, queued_at=_now(), job_id="job-1")

    quota = quotas.get_quota(settings, DEFAULT)
    assert quota.source == "default"
    assert quota.max_assets is None
    assert quota.max_scans_per_month is None

    report = quotas.usage(settings, DEFAULT)
    assert report["quota_source"] == "default"
    for resource in ("assets", "scans"):
        shape = report[resource]
        assert shape["used"] == 1
        assert shape["limit"] is None
        # A share with nothing to divide by is null, never 0% or 100%.
        assert shape["remaining"] is None
        assert shape["used_ratio"] is None
        assert shape["over_limit"] is False

    assert quotas.asset_capacity(settings, DEFAULT) is None
    quotas.assert_scan_quota(settings, tenant_id=DEFAULT)


def test_the_platform_default_applies_until_a_row_overrides_it(settings: Settings):
    settings.quota_default_max_assets = 10
    settings.quota_default_max_scans_per_month = 4

    inherited = quotas.get_quota(settings, DEFAULT)
    assert (inherited.max_assets, inherited.max_scans_per_month) == (10, 4)
    assert inherited.source == "default"

    stored = quotas.set_quota(
        settings, DEFAULT, max_assets=2, max_scans_per_month=1, note="SOW-7", updated_by="admin"
    )
    assert stored.source == "tenant"

    effective = quotas.get_quota(settings, DEFAULT)
    assert (effective.max_assets, effective.max_scans_per_month) == (2, 1)
    assert effective.source == "tenant"
    assert effective.note == "SOW-7"
    assert effective.updated_by == "admin"
    assert effective.updated_at is not None

    quotas.clear_quota(settings, DEFAULT)
    assert quotas.get_quota(settings, DEFAULT).source == "default"
    assert quotas.get_quota(settings, DEFAULT).max_assets == 10


def test_a_stored_null_exempts_one_tenant_from_the_platform_default(settings: Settings):
    """NULL in the row is an override, not an absence — that is the whole point
    of distinguishing ``tenant`` from ``default``."""
    settings.quota_default_max_assets = 1
    settings.quota_default_max_scans_per_month = 1
    _asset(settings, DEFAULT, "asset-1")
    _asset(settings, DEFAULT, "asset-2")

    quotas.set_quota(settings, DEFAULT, max_assets=None, max_scans_per_month=None)

    quota = quotas.get_quota(settings, DEFAULT)
    assert quota.source == "tenant"
    assert quota.max_assets is None
    assert quota.max_scans_per_month is None
    assert quotas.asset_capacity(settings, DEFAULT) is None
    quotas.assert_scan_quota(settings, tenant_id=DEFAULT)


def test_zero_is_stored_and_read_back_as_unlimited(settings: Settings):
    """0 is the "unset" spelling everywhere else in Settings, so it cannot mean
    "refuse everything" here without making an empty form an outage."""
    quotas.set_quota(settings, DEFAULT, max_assets=0, max_scans_per_month=0)
    quota = quotas.get_quota(settings, DEFAULT)
    assert (quota.max_assets, quota.max_scans_per_month) == (None, None)
    assert quota.source == "tenant"


# --------------------------------------------------------------------------
# 3-5. Refusing a scan
# --------------------------------------------------------------------------


def test_scan_quota_refuses_at_the_limit_and_counts_the_refusal(settings: Settings):
    quotas.set_quota(settings, DEFAULT, max_assets=None, max_scans_per_month=2)
    _job(settings, DEFAULT, queued_at=_now(), job_id="job-1")

    # One under the limit: still allowed.
    quotas.assert_scan_quota(settings, tenant_id=DEFAULT)

    _job(settings, DEFAULT, queued_at=_now(), job_id="job-2")
    before = _denied(quotas.RESOURCE_SCANS)

    with pytest.raises(quotas.QuotaExceeded) as excinfo:
        quotas.assert_scan_quota(settings, tenant_id=DEFAULT)

    exc = excinfo.value
    assert exc.tenant_id == DEFAULT
    assert exc.resource == quotas.RESOURCE_SCANS
    assert (exc.limit, exc.used) == (2, 2)
    # The refusal expires on its own, so it can say when.
    assert exc.retry_after_seconds is not None and exc.retry_after_seconds > 0
    assert "2/2" in str(exc)
    assert _denied(quotas.RESOURCE_SCANS) == before + 1


def test_an_exempt_scan_is_neither_refused_nor_counted(settings: Settings):
    """Quota-refusing the machine check that closes a finding would strand it
    in VERIFYING — a billing limit turning into a correctness bug (#183).

    The exemption is carried by the dispatch (``jobs.quota_exempt``), not by
    the requester's name: the verification route passes the *analyst's*
    username, so a name-keyed exemption would never have fired.
    """
    quotas.set_quota(settings, DEFAULT, max_assets=None, max_scans_per_month=1)
    _job(settings, DEFAULT, queued_at=_now(), job_id="job-1", quota_exempt=True)

    # The exempt job did not spend the entitlement, so an operator's scan is
    # still admitted afterwards.
    assert quotas.scans_used(settings, DEFAULT) == 0
    quotas.assert_scan_quota(settings, tenant_id=DEFAULT)

    _job(settings, DEFAULT, queued_at=_now(), job_id="job-2")
    assert quotas.scans_used(settings, DEFAULT) == 1
    with pytest.raises(quotas.QuotaExceeded):
        quotas.assert_scan_quota(settings, tenant_id=DEFAULT)


def test_verification_dispatch_survives_an_exhausted_scan_quota(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The whole point of the exemption, exercised through the real path.

    ``trigger_verification`` always passes the operator's username, so this is
    the test that a name-based exemption would have failed while still
    reporting the constant as present.
    """
    from api.services import jobs as jobs_service

    settings = make_settings(tmp_path, job_execution_mode="agent")
    configured_client(tmp_path, monkeypatch, settings=settings)
    quotas.set_quota(settings, DEFAULT, max_assets=None, max_scans_per_month=1)
    _job(settings, DEFAULT, queued_at=_now(), job_id="job-1")

    # An ordinary scan is refused at this point...
    with pytest.raises(quotas.QuotaExceeded):
        quotas.assert_scan_quota(settings, tenant_id=DEFAULT)

    # ...while the dispatch the platform owns goes through under the operator's
    # own username, and is not billed. This is the case a name-keyed exemption
    # got wrong: trigger_verification passes the analyst's name, never the
    # platform's.
    job = jobs_service.start_scan(
        settings,
        StartScanRequest(tenant_id=DEFAULT, ranges="192.0.2.10/32"),
        username="operator",
        quota_exempt=True,
    )
    assert job.job_id
    assert quotas.scans_used(settings, DEFAULT) == 1


def test_enforcement_disabled_still_meters_but_never_refuses(settings: Settings):
    """The observe-only rollout: an MSSP measures for a month before selling a
    limit, and the numbers have to be real before anybody is refused."""
    settings.quota_enforcement_enabled = False
    quotas.set_quota(settings, DEFAULT, max_assets=1, max_scans_per_month=1)
    _job(settings, DEFAULT, queued_at=_now(), job_id="job-1")
    _job(settings, DEFAULT, queued_at=_now(), job_id="job-2")
    _asset(settings, DEFAULT, "asset-1")
    _asset(settings, DEFAULT, "asset-2")

    quotas.assert_scan_quota(settings, tenant_id=DEFAULT)
    assert quotas.asset_capacity(settings, DEFAULT) is None

    report = quotas.usage(settings, DEFAULT)
    assert report["enforced"] is False
    # Metered, and visibly over: the console can show the overage that would
    # have been refused had enforcement been on.
    assert report["scans"]["used"] == 2
    assert report["scans"]["over_limit"] is True
    assert report["assets"]["used"] == 2
    assert report["assets"]["over_limit"] is True


def test_starting_a_scan_over_http_answers_429_with_retry_after(tmp_path, monkeypatch):
    base = make_settings(tmp_path, job_execution_mode="agent")
    client = configured_client(tmp_path, monkeypatch, settings=base)
    quotas.set_quota(base, DEFAULT, max_assets=None, max_scans_per_month=1)
    auth = auth_headers(client, "operator")

    first = client.post("/api/jobs", headers=auth, json={"mode": "safe"})
    assert first.status_code == 202

    refused = client.post("/api/jobs", headers=auth, json={"mode": "safe"})
    # 429, not 403: unlike a scope refusal this one stops being true on its own.
    assert refused.status_code == 429
    assert int(refused.headers["Retry-After"]) > 0
    assert "quota" in refused.json()["detail"].lower()

    # And the refused scan was not queued.
    listed = client.get("/api/jobs", headers=auth)
    assert listed.json()["total"] == 1


# --------------------------------------------------------------------------
# 6. Capping assets
# --------------------------------------------------------------------------


def test_asset_capacity_floors_at_zero_and_ignores_decommissioned_assets(settings: Settings):
    quotas.set_quota(settings, DEFAULT, max_assets=2, max_scans_per_month=None)
    _asset(settings, DEFAULT, "asset-1")
    assert quotas.asset_capacity(settings, DEFAULT) == 1

    # Retired inventory is history, not capacity in use — billing for it would
    # make deletion the customer's only way to stop paying for a dead machine.
    _asset(settings, DEFAULT, "asset-gone", status="decommissioned")
    assert quotas.asset_capacity(settings, DEFAULT) == 1

    _asset(settings, DEFAULT, "asset-2", status="stale")
    assert quotas.asset_capacity(settings, DEFAULT) == 0
    at_limit = quotas.usage(settings, DEFAULT)["assets"]
    assert at_limit == {
        "used": 2,
        "limit": 2,
        "remaining": 0,
        "used_ratio": 1.0,
        # *at* the limit is not *over* it.
        "over_limit": False,
    }

    # Over the limit (the row was written after the assets existed): never
    # negative, or the ingest path would read it as "create some more".
    _asset(settings, DEFAULT, "asset-3")
    assert quotas.asset_capacity(settings, DEFAULT) == 0
    over = quotas.usage(settings, DEFAULT)["assets"]
    assert over["used"] == 3
    assert over["remaining"] == 0
    assert over["used_ratio"] == 1.5
    assert over["over_limit"] is True


def test_asset_refusal_is_counted_because_nobody_is_told_interactively(settings: Settings):
    before = _denied(quotas.RESOURCE_ASSETS)
    quotas.record_asset_refusal(DEFAULT, 0)
    assert _denied(quotas.RESOURCE_ASSETS) == before
    quotas.record_asset_refusal(DEFAULT, 3)
    assert _denied(quotas.RESOURCE_ASSETS) == before + 1


# --------------------------------------------------------------------------
# 7. The billing period and the history
# --------------------------------------------------------------------------


def test_period_bounds_is_one_utc_calendar_month_and_december_rolls_the_year():
    start, end = quotas.period_bounds(datetime(2025, 6, 17, 13, 45, 30, 12))
    assert start == datetime(2025, 6, 1)
    assert end == datetime(2025, 7, 1)

    start, end = quotas.period_bounds(datetime(2025, 12, 31, 23, 59, 59))
    assert start == datetime(2025, 12, 1)
    assert end == datetime(2026, 1, 1)


def test_scans_used_counts_this_month_and_not_last(settings: Settings):
    start, _ = quotas.period_bounds()
    last_month = quotas._shift_months(start, -1)  # noqa: SLF001

    _job(settings, DEFAULT, queued_at=start, job_id="this-month")
    _job(settings, DEFAULT, queued_at=last_month, job_id="last-month")

    # Counted from queued_at, so a still-queued scan counts: the entitlement is
    # consumed by asking for the work.
    assert quotas.scans_used(settings, DEFAULT) == 1


def test_scan_history_is_oldest_first_with_empty_months_present(settings: Settings):
    start, _ = quotas.period_bounds()
    two_back = quotas._shift_months(start, -2)  # noqa: SLF001
    _job(settings, DEFAULT, queued_at=two_back, job_id="old-1")
    _job(settings, DEFAULT, queued_at=two_back, job_id="old-2")
    _job(settings, DEFAULT, queued_at=start, job_id="new-1")

    history = quotas.scan_history(settings, DEFAULT, months=3)
    assert [row["month"] for row in history] == [
        two_back.strftime("%Y-%m"),
        quotas._shift_months(start, -1).strftime("%Y-%m"),  # noqa: SLF001
        start.strftime("%Y-%m"),
    ]
    # A quiet month is a zero, not a gap a chart has to guess at.
    assert [row["scans"] for row in history] == [2, 0, 1]

    # Even a month whose year rolls over is contiguous, and the window clamps.
    assert len(quotas.scan_history(settings, DEFAULT, months=14)) == 14
    assert len(quotas.scan_history(settings, DEFAULT, months=999)) == 36
    assert len(quotas.scan_history(settings, DEFAULT, months=0)) == 1


def test_december_history_rolls_into_january(settings: Settings):
    """``_shift_months`` is hand-rolled arithmetic, and off-by-one there is how
    a December window silently reports month 0."""
    december = datetime(2025, 12, 1)
    assert quotas._shift_months(december, 1) == datetime(2026, 1, 1)  # noqa: SLF001
    assert quotas._shift_months(december, -12) == datetime(2024, 12, 1)  # noqa: SLF001
    assert quotas._shift_months(datetime(2026, 1, 1), -1) == december  # noqa: SLF001


def test_tenant_summaries_cover_every_tenant_with_its_source(settings: Settings):
    other = tenants_service.create_tenant(name="Beta Corp", tenant_id="ten_beta")["tenant_id"]
    _asset(settings, DEFAULT, "asset-1")
    _job(settings, other, queued_at=_now(), job_id="job-beta")
    quotas.set_quota(settings, other, max_assets=50, max_scans_per_month=5)

    summary = quotas.tenant_summaries(settings)
    rows = {row["tenant_id"]: row for row in summary["tenants"]}
    assert set(rows) == {DEFAULT, other}
    assert rows[DEFAULT]["quota_source"] == "default"
    assert rows[DEFAULT]["assets"]["used"] == 1
    assert rows[DEFAULT]["assets"]["limit"] is None
    assert rows[other]["quota_source"] == "tenant"
    assert rows[other]["scans"] == {
        "used": 1,
        "limit": 5,
        "remaining": 4,
        "used_ratio": 0.2,
        "over_limit": False,
    }
    assert summary["period_start"] == quotas.period_bounds()[0]


# --------------------------------------------------------------------------
# 8. The routes
# --------------------------------------------------------------------------


def test_usage_is_readable_by_a_viewer_and_nobody_else(tmp_path, monkeypatch):
    base = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=base)
    quotas.set_quota(base, DEFAULT, max_assets=100, max_scans_per_month=10, note="SOW-7")
    _asset(base, DEFAULT, "asset-1")

    assert client.get("/api/usage").status_code == 401

    # A number the person doing the work cannot open is a number that gets
    # estimated in a slide, so this is viewer-gated, not operator-gated.
    body = client.get("/api/usage", headers=auth_headers(client, "viewer"))
    assert body.status_code == 200
    payload = body.json()
    assert payload["tenant_id"] == DEFAULT
    assert payload["quota_source"] == "tenant"
    assert payload["note"] == "SOW-7"
    assert payload["enforced"] is True
    assert payload["assets"]["used"] == 1
    assert payload["assets"]["limit"] == 100
    assert payload["assets"]["remaining"] == 99
    assert payload["scans"]["limit"] == 10
    assert len(payload["scan_history"]) == 12
    assert payload["scan_history"][-1]["month"] == quotas.period_bounds()[0].strftime("%Y-%m")


def test_usage_history_window_is_bounded(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    auth = auth_headers(client, "viewer")

    assert client.get("/api/usage?history_months=1", headers=auth).status_code == 200
    assert len(client.get("/api/usage?history_months=1", headers=auth).json()["scan_history"]) == 1
    assert client.get("/api/usage?history_months=36", headers=auth).status_code == 200
    # Rejected at the edge rather than clamped: a client asking for 120 months
    # is wrong about something, and silently answering 36 hides it.
    assert client.get("/api/usage?history_months=0", headers=auth).status_code == 422
    assert client.get("/api/usage?history_months=37", headers=auth).status_code == 422


def test_the_provider_wide_view_is_platform_admin_only(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)

    assert client.get("/api/usage/tenants").status_code == 401
    assert client.get("/api/usage/tenants", headers=auth_headers(client, "viewer")).status_code == 403
    assert (
        client.get("/api/usage/tenants", headers=auth_headers(client, "operator")).status_code == 403
    )

    allowed = client.get("/api/usage/tenants", headers=auth_headers(client, "admin"))
    assert allowed.status_code == 200
    assert [row["tenant_id"] for row in allowed.json()["tenants"]] == [DEFAULT]


def test_writing_a_quota_is_admin_only_and_round_trips_with_an_author(tmp_path, monkeypatch):
    base = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=base)
    admin = auth_headers(client, "admin")
    path = f"/api/tenants/{DEFAULT}/quota"

    # A tenant operator who could raise their own quota is the control
    # removing itself.
    assert client.get(path).status_code == 401
    assert client.get(path, headers=auth_headers(client, "operator")).status_code == 403
    assert (
        client.put(path, headers=auth_headers(client, "operator"), json={"max_assets": 5}).status_code
        == 403
    )

    before = client.get(path, headers=admin)
    assert before.status_code == 200
    assert before.json()["quota_source"] == "default"
    assert before.json()["max_assets"] is None

    written = client.put(
        path,
        headers=admin,
        json={"max_assets": 2000, "max_scans_per_month": 40, "note": "SOW-7 renewal"},
    )
    assert written.status_code == 200
    assert written.json()["updated_by"] == "admin"

    after = client.get(path, headers=admin).json()
    assert after["max_assets"] == 2000
    assert after["max_scans_per_month"] == 40
    assert after["quota_source"] == "tenant"
    assert after["note"] == "SOW-7 renewal"
    assert after["updated_by"] == "admin"
    assert after["updated_at"] is not None
    # And the service agrees with the API that wrote it.
    assert quotas.get_quota(base, DEFAULT).max_assets == 2000

    # null is a deliberate "unlimited for this tenant", not a dropped field.
    cleared = client.put(
        path, headers=admin, json={"max_assets": None, "max_scans_per_month": None}
    )
    assert cleared.json()["max_assets"] is None
    assert cleared.json()["quota_source"] == "tenant"


def test_quota_routes_answer_404_for_a_tenant_that_does_not_exist(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")

    assert client.get("/api/tenants/ten_nope/quota", headers=admin).status_code == 404
    assert (
        client.put("/api/tenants/ten_nope/quota", headers=admin, json={"max_assets": 5}).status_code
        == 404
    )


# --------------------------------------------------------------------------
# The ingest paths honouring the cap (assets are capped, never refused)
# --------------------------------------------------------------------------


def _identifier(
    settings: Settings, tenant_id: str, asset_id: str, kind: str, value: str
) -> None:
    with get_session(settings.postgres_url) as session:
        session.add(
            models.AssetIdentifier(
                asset_id=asset_id,
                tenant_id=tenant_id,
                identifier_type=kind,
                identifier_value=value,
            )
        )


def _write_run(settings: Settings, run_id: str, hosts: list[dict]) -> None:
    run_dir = settings.output_dir / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "alive_hosts.json").write_text(json.dumps(hosts), encoding="utf-8")


def test_ingest_creates_what_fits_and_keeps_updating_what_exists(settings: Settings):
    """A tenant at its limit still gets fresh data about the estate it paid
    for; only the discovery of further hosts stops."""
    from api.services import assets as assets_service

    settings.output_dir.mkdir(parents=True, exist_ok=True)
    quotas.set_quota(settings, DEFAULT, max_assets=1, max_scans_per_month=None)
    _write_run(
        settings,
        "run-1",
        [
            {"host": "10.0.0.5", "hostname": "app.example.com"},
            {"host": "10.0.0.6", "hostname": "db.example.com"},
        ],
    )

    before = _denied(quotas.RESOURCE_ASSETS)
    first = assets_service.upsert_assets_from_run(settings, tenant_id=DEFAULT, run_id="run-1")
    assert first.hosts_seen == 2
    assert first.assets_created == 1
    assert first.quota_skipped == 1
    assert _denied(quotas.RESOURCE_ASSETS) == before + 1
    assert quotas.assets_used(settings, DEFAULT) == 1

    # The scan itself succeeded, and the next run still refreshes the asset
    # inside the quota rather than failing the whole result set.
    second = assets_service.upsert_assets_from_run(settings, tenant_id=DEFAULT, run_id="run-1")
    assert second.assets_created == 0
    assert second.assets_updated == 1
    assert second.quota_skipped == 1
    assert quotas.assets_used(settings, DEFAULT) == 1

    # Raise the limit and the host that was skipped is registered on the next
    # run — a quota is a cap, not a permanent exclusion.
    quotas.set_quota(settings, DEFAULT, max_assets=5, max_scans_per_month=None)
    third = assets_service.upsert_assets_from_run(settings, tenant_id=DEFAULT, run_id="run-1")
    assert third.quota_skipped == 0
    assert third.assets_created == 1
    assert quotas.assets_used(settings, DEFAULT) == 2


def test_reviving_a_decommissioned_asset_spends_capacity(settings: Settings):
    """Only ``active``/``stale`` assets are billed, so bringing a retired one
    back adds to the count exactly as creating one does.

    Without this the ceiling is bypassable by re-observing retired hosts: each
    revival is an "update" that lands the tenant one asset further over a limit
    ``asset_capacity`` had already reported as full.
    """
    from api.services import assets as assets_service

    settings.output_dir.mkdir(parents=True, exist_ok=True)
    _asset(settings, DEFAULT, "10.0.0.5", status="decommissioned")
    _identifier(settings, DEFAULT, "10.0.0.5", "ip", "10.0.0.5")
    _asset(settings, DEFAULT, "asset-live")
    quotas.set_quota(settings, DEFAULT, max_assets=1, max_scans_per_month=None)
    assert quotas.assets_used(settings, DEFAULT) == 1
    assert quotas.asset_capacity(settings, DEFAULT) == 0

    _write_run(settings, "run-revive", [{"host": "10.0.0.5"}])
    stats = assets_service.upsert_assets_from_run(settings, tenant_id=DEFAULT, run_id="run-revive")

    assert stats.quota_skipped == 1
    assert quotas.assets_used(settings, DEFAULT) == 1

    # With room, the same run revives it and the count moves by one.
    quotas.set_quota(settings, DEFAULT, max_assets=2, max_scans_per_month=None)
    revived = assets_service.upsert_assets_from_run(settings, tenant_id=DEFAULT, run_id="run-revive")
    assert revived.quota_skipped == 0
    assert quotas.assets_used(settings, DEFAULT) == 2
