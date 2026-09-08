"""Noise and coverage on the adoption page (ROADMAP Track E).

Two things are under test, and both are about a number telling the truth rather
than about it being computed at all.

**False-positive closures are not remediation.** They are excluded from the
verification rate, from MTTR and from SLA adherence, and counted in their own
block. Without that, the quarterly control question ROADMAP asks — did
closed-and-verified per analyst go up — is answerable by marking things as
noise, which is the one way it must not be answerable.

**Coverage is read from a column an agent cannot move.** ``assets.last_seen``
is touched by an endpoint agent checking in, so reading it as "scanned
recently" made a fleet of agents reporting on schedule look like a scanned
estate. That is the metric saying the opposite of the truth in exactly the case
it exists to catch.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update

from api.db import models
from api.db.engine import get_session
from api.services import adoption, coverage, vuln_states
from api.services import vulnerabilities as vulns
from tests.conftest import requires_postgres
from tests.test_vuln_lifecycle import _FINDINGS, _HOSTS, _seed, _settings, _write_run

pytestmark = requires_postgres


def _ids(settings, tenant_id: str) -> dict[str, str]:
    items, _ = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)
    return {item["cve"]: item["vuln_id"] for item in items}


def _age(settings, vuln_id: str, **values) -> None:
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.Vulnerability)
            .where(models.Vulnerability.vuln_id == vuln_id)
            .values(**values)
        )


# --------------------------------------------------------------------------
# False positives are counted apart from remediation
# --------------------------------------------------------------------------


def test_a_false_positive_is_not_counted_as_a_closure_or_as_a_fix(tmp_path):
    """The metric-gaming guard: marking noise must not move remediation numbers."""
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    ids = _ids(settings, tenant_id)
    vulns.transition(
        settings,
        tenant_id=tenant_id,
        vuln_id=ids["CVE-2024-0001"],
        to_state=vuln_states.CLOSED,
        actor="alice",
    )
    vulns.mark_false_positive(
        settings,
        tenant_id=tenant_id,
        vuln_id=ids["CVE-2024-0002"],
        reason="the banner is the load balancer, not the origin",
        actor="admin",
    )

    report = adoption.metrics(settings, tenant_id=tenant_id, window_days=30)

    findings = report["findings"]
    # One real closure and one verdict — not two closures.
    assert findings["closed_in_window"] == 1
    assert findings["false_positive_in_window"] == 1
    # The verification rate is over remediation only. Were the verdict in the
    # denominator this would be 0.0 and honest triage would look like failure.
    assert findings["machine_verified_share"] == 0.0
    assert findings["mttr_hours_by_severity"]["medium"] is None
    assert [item["analyst"] for item in report["analysts"]] == [adoption.UNASSIGNED]
    assert report["analysts"][0]["closed"] == 1

    noise = report["false_positives"]
    assert noise["in_window"] == 1
    assert noise["share_of_closures"] == 50.0
    assert noise["by_severity"]["medium"] == 1
    assert noise["suppressions_active"] == 1
    assert noise["suppressions_lapsed"] == 0
    assert noise["median_hours_to_verdict"] is not None


def test_sla_adherence_ignores_findings_that_were_never_real(tmp_path):
    """A verdict delivered after the deadline is not a missed remediation SLA."""
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vuln_id = _ids(settings, tenant_id)["CVE-2024-0001"]
    _age(settings, vuln_id, due_at=datetime.now(UTC).replace(tzinfo=None) - timedelta(days=5))
    vulns.mark_false_positive(
        settings, tenant_id=tenant_id, vuln_id=vuln_id, reason="not our stack", actor="admin"
    )

    report = adoption.metrics(settings, tenant_id=tenant_id, window_days=30)

    # No remediation closures at all, so there is no adherence to report.
    assert report["findings"]["closed_within_sla_share"] is None
    assert report["findings"]["mttr_hours"] is None


def test_a_lapsed_verdict_shows_up_as_a_review_queue(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vuln_id = _ids(settings, tenant_id)["CVE-2024-0001"]
    vulns.mark_false_positive(
        settings, tenant_id=tenant_id, vuln_id=vuln_id, reason="noise", actor="admin"
    )
    _age(
        settings,
        vuln_id,
        fp_suppress_until=datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=1),
    )

    noise = adoption.metrics(settings, tenant_id=tenant_id)["false_positives"]

    assert (noise["suppressions_active"], noise["suppressions_lapsed"]) == (0, 1)


def test_an_override_is_counted_from_the_trail_after_the_verdict_is_gone(tmp_path):
    """The row no longer says it happened, so the count comes from the events."""
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vuln_id = _ids(settings, tenant_id)["CVE-2024-0002"]
    vulns.mark_false_positive(
        settings, tenant_id=tenant_id, vuln_id=vuln_id, reason="noise", actor="admin"
    )

    worse = [_FINDINGS[0], {**_FINDINGS[1], "severity": "critical"}]
    _write_run(settings.output_dir, "run-2", _HOSTS, worse)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-2")

    noise = adoption.metrics(settings, tenant_id=tenant_id)["false_positives"]

    assert noise["overridden_in_window"] == 1
    assert noise["suppressions_active"] == 0


def test_a_detector_below_the_threshold_reports_counts_but_no_rate(tmp_path):
    """One false positive out of one closure is not a 100% error rate."""
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vuln_id = _ids(settings, tenant_id)["CVE-2024-0001"]
    vulns.mark_false_positive(
        settings, tenant_id=tenant_id, vuln_id=vuln_id, reason="noise", actor="admin"
    )

    sources = adoption.metrics(settings, tenant_id=tenant_id)["false_positives"]["by_source"]

    assert len(sources) == 1
    # A CVE with no script_id came from advisory matching, which is its own
    # bucket — never folded into a named detector's rate.
    assert sources[0]["source"] == adoption.UNKNOWN_SOURCE
    assert sources[0]["false_positive"] == 1
    assert sources[0]["false_positive_share"] is None


def test_noise_is_split_by_observer_and_the_quiet_one_is_listed_too(tmp_path):
    """``by_origin`` only became computable when M3 added ``vulnerabilities.source``.

    It is the coarse cut and the actionable one — a rate on
    ``endpoint_software`` says to tune version matching, a rate on ``scan``
    says to tune the scripts. Unlike ``by_source`` the origin with no verdicts
    is still listed: without it the noisy one is a number with nothing to be
    compared against.
    """
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    ids = _ids(settings, tenant_id)
    _age(settings, ids["CVE-2024-0002"], source="endpoint_software")
    vulns.transition(
        settings,
        tenant_id=tenant_id,
        vuln_id=ids["CVE-2024-0001"],
        to_state=vuln_states.CLOSED,
        actor="alice",
    )
    vulns.mark_false_positive(
        settings,
        tenant_id=tenant_id,
        vuln_id=ids["CVE-2024-0002"],
        reason="the installed version carries a distro backport",
        actor="admin",
    )

    origins = adoption.metrics(settings, tenant_id=tenant_id)["false_positives"]["by_origin"]

    assert {row["source"]: row["false_positive"] for row in origins} == {
        "endpoint_software": 1,
        "scan": 0,
    }
    # One closure each, so neither share is earned — the counts still are.
    assert {row["source"]: row["closed"] for row in origins} == {
        "endpoint_software": 1,
        "scan": 1,
    }
    assert all(row["false_positive_share"] is None for row in origins)


# --------------------------------------------------------------------------
# Coverage: the column an agent cannot move
# --------------------------------------------------------------------------


def test_a_scan_sets_the_coverage_columns_and_the_run_that_did_it(tmp_path):
    settings, tenant_id = _seed(tmp_path)

    report = adoption.metrics(settings, tenant_id=tenant_id)

    with get_session(settings.postgres_url) as session:
        asset = session.scalars(
            select(models.Asset).where(models.Asset.tenant_id == tenant_id)
        ).first()
    assert asset.last_scan_run_id == "run-1"
    assert asset.last_scanned_at is not None
    # _seed's run carries vulnerabilities.json, so it covers the asset for
    # findings too, not only for inventory.
    assert asset.last_vuln_scan_at is not None
    assert report["coverage"]["scanned_share"] == 100.0
    assert report["coverage"]["vuln_scanned_share"] == 100.0


def test_a_discovery_only_run_does_not_claim_vulnerability_coverage(tmp_path):
    """Enumerating a host says nothing about whether it was assessed."""
    from api.services import assets as assets_service

    settings = _settings(tmp_path)
    from api.services import tenants as tenants_service

    tenant_id = tenants_service.DEFAULT_TENANT_ID
    run_dir = settings.output_dir / "runs" / "run-discovery"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "alive_hosts.json").write_text('[{"host": "10.0.0.9"}]', encoding="utf-8")

    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-discovery")

    report = adoption.metrics(settings, tenant_id=tenant_id)
    assert report["coverage"]["scanned_share"] == 100.0
    assert report["coverage"]["vuln_scanned_share"] == 0.0


def test_an_endpoint_check_in_does_not_make_an_asset_look_scanned(tmp_path, monkeypatch):
    """The honesty defect: coverage read `last_seen`, which an agent moves.

    A fleet of endpoint agents reporting on schedule made an estate nobody had
    scanned in months report full coverage — the metric saying the opposite of
    the truth in the one case it exists to catch.
    """
    from api.schemas import EndpointInventorySnapshotRequest
    from api.services import endpoint_inventory

    settings, tenant_id = _seed(tmp_path)
    endpoint_inventory.configure(settings)
    endpoint_inventory.reset_for_tests()

    stale = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=90)
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.Asset)
            .where(models.Asset.tenant_id == tenant_id)
            .values(last_seen=stale, last_scanned_at=stale, last_vuln_scan_at=stale)
        )

    # Reconciliation links this device to the seeded asset by its FQDN, so the
    # ingest path really does reach the `asset.last_seen = now` write.
    endpoint_inventory.ingest_snapshot(
        tenant_id=tenant_id,
        agent_id="lariska-1",
        request=EndpointInventorySnapshotRequest(
            schema_version=1,
            snapshot_id="snap-coverage-1",
            agent_id="lariska-1",
            collected_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            hostname="app.example.com",
            os_family="linux",
            agent_version="1.2.0",
            software=[{"name": "nginx", "version": "1.24.0", "source": "dpkg"}],
        ),
    )

    with get_session(settings.postgres_url) as session:
        asset = session.scalars(
            select(models.Asset).where(models.Asset.tenant_id == tenant_id)
        ).first()
    # The columns are `timestamptz`, so Postgres hands them back aware.
    def _naive(value):
        return value.replace(tzinfo=None)

    # The check-in is an observation, so `last_seen` moves...
    assert _naive(asset.last_seen) > stale
    # ...but it is not a scan, so coverage does not.
    assert _naive(asset.last_scanned_at) == stale
    assert _naive(asset.last_vuln_scan_at) == stale

    report = adoption.metrics(settings, tenant_id=tenant_id)
    assert report["coverage"]["scanned_share"] == 0.0
    assert report["assets"]["scanned_recently_share"] == 0.0
    # It is still a dual-source asset — that reading is about the agent, and it
    # is the one the check-in is entitled to move.
    assert report["assets"]["dual_source_share"] == 100.0


def test_coverage_is_unknown_rather_than_zero_before_the_column_has_data(tmp_path):
    """Migration 0035 has no backfill; 0% would be an alarm about the upgrade."""
    settings, tenant_id = _seed(tmp_path)
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.Asset)
            .where(models.Asset.tenant_id == tenant_id)
            .values(last_scanned_at=None, last_vuln_scan_at=None, last_scan_run_id=None)
        )

    report = adoption.metrics(settings, tenant_id=tenant_id)

    assert report["coverage"]["assets_with_scan_history"] == 0
    assert report["coverage"]["scanned_share"] is None
    assert report["assets"]["scanned_recently_share"] is None


# --------------------------------------------------------------------------
# Scope coverage: a share needs a finite denominator
# --------------------------------------------------------------------------


def _scope(settings, tenant_id: str, entries: list[tuple[str, str, str]]) -> None:
    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        for effect, kind, value in entries:
            session.add(
                models.TenantScanScope(
                    tenant_id=tenant_id,
                    effect=effect,
                    kind=kind,
                    value=value,
                    approved_by="test",
                    approved_at=now,
                )
            )


def test_scope_coverage_counts_known_addresses_against_the_approval(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    _scope(settings, tenant_id, [("allow", "cidr", "10.0.0.0/29")])

    block = adoption.metrics(settings, tenant_id=tenant_id)["coverage"]

    assert block["approved_addresses"] == 8
    assert block["assets_in_scope"] == 1
    assert block["scope_covered_share"] == 12.5
    assert block["scope_unbounded_reason"] is None


def test_a_wildcard_or_domain_scope_has_no_share_to_report(tmp_path):
    """A suffix approval says nothing about how many hosts are behind it."""
    settings, tenant_id = _seed(tmp_path)
    _scope(settings, tenant_id, [("allow", "domain", "example.com")])

    block = adoption.metrics(settings, tenant_id=tenant_id)["coverage"]

    assert block["scope_covered_share"] is None
    assert block["scope_unbounded_reason"] == "domain"


def test_an_approval_too_large_to_be_a_target_list_reports_no_share(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    _scope(settings, tenant_id, [("allow", "cidr", "10.0.0.0/8")])

    block = adoption.metrics(settings, tenant_id=tenant_id)["coverage"]

    assert block["approved_addresses"] > coverage.MAX_SCOPE_ADDRESSES
    assert block["scope_covered_share"] is None
    assert block["scope_unbounded_reason"] == "too_large"


def test_a_tenant_with_no_approved_scope_reports_no_share(tmp_path):
    settings, tenant_id = _seed(tmp_path)

    block = adoption.metrics(settings, tenant_id=tenant_id)["coverage"]

    assert block["approved_entries"] == 0
    assert block["scope_covered_share"] is None
    assert block["scope_unbounded_reason"] == "no_scope"


def test_deny_entries_do_not_raise_coverage(tmp_path):
    """Carving holes in an approval must not make reach look better."""
    settings, tenant_id = _seed(tmp_path)
    _scope(
        settings,
        tenant_id,
        [("allow", "cidr", "10.0.0.0/29"), ("deny", "cidr", "10.0.0.6/32")],
    )

    block = adoption.metrics(settings, tenant_id=tenant_id)["coverage"]

    assert block["approved_addresses"] == 8
    assert block["scope_covered_share"] == 12.5


def test_coverage_never_reaches_into_another_tenant(tmp_path):
    """Both halves are per-tenant, and neither is an aggregate over the install.

    Coverage is the one block on the page whose denominators come from tables
    another tenant also writes — ``assets``, ``asset_identifiers`` and
    ``tenant_scan_scopes``. A missing ``tenant_id`` filter there would not fail
    loudly; it would quietly report a neighbour's estate as this one's reach.
    """
    from api.services import assets as assets_service
    from api.services import tenants as tenants_service

    settings, tenant_id = _seed(tmp_path)
    other = tenants_service.create_tenant(tenant_id="ten_neighbour", name="Neighbour")["tenant_id"]
    # The neighbour has the same host, scanned, and an approval covering it.
    assets_service.upsert_assets_from_run(settings, tenant_id=other, run_id="run-1")
    _scope(settings, other, [("allow", "cidr", "10.0.0.0/29")])
    # This tenant's own asset was never scan-ingested and it approved nothing.
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.Asset)
            .where(models.Asset.tenant_id == tenant_id)
            .values(last_scanned_at=None, last_vuln_scan_at=None, last_scan_run_id=None)
        )

    block = adoption.metrics(settings, tenant_id=tenant_id)["coverage"]

    assert block["assets_with_scan_history"] == 0
    assert block["scanned_share"] is None
    assert block["approved_entries"] == 0
    assert block["scope_unbounded_reason"] == "no_scope"
    # ...and the neighbour still sees its own, so the filter is a filter and
    # not an empty read.
    neighbour = adoption.metrics(settings, tenant_id=other)["coverage"]
    assert neighbour["assets_with_scan_history"] == 1
    assert neighbour["scope_covered_share"] == 12.5
