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

import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update

from api.db import models
from api.db.engine import get_session
from api.services import adoption, vuln_states
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


def _closures(settings, tenant_id: str, *, script_id: str, closed: int, noise: int) -> None:
    """``closed`` closures for one detector inside the window, ``noise`` of them verdicts.

    Written straight to the table because the point is the arithmetic at the
    threshold, and driving twenty findings through the run path to reach it
    would test the run path instead.
    """
    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        asset_id = session.scalars(
            select(models.Asset.asset_id).where(models.Asset.tenant_id == tenant_id)
        ).first()
        for index in range(closed):
            is_noise = index < noise
            session.add(
                models.Vulnerability(
                    vuln_id=f"vln_{script_id}_{index}",
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    finding_key=f"{script_id}-{index}",
                    source="scan",
                    script_id=script_id,
                    cve=f"CVE-2024-9{index:03d}",
                    severity="medium",
                    state=vuln_states.CLOSED,
                    state_changed_at=now,
                    first_seen_at=now - timedelta(days=2),
                    last_seen_at=now - timedelta(days=1),
                    sla_started_at=now - timedelta(days=2),
                    closed_at=now,
                    closure_reason=vulns.FALSE_POSITIVE if is_noise else "manual",
                    fp_marked_at=now if is_noise else None,
                    fp_reason="noise" if is_noise else None,
                    fp_suppress_until=now + timedelta(days=30) if is_noise else None,
                    created_at=now,
                    updated_at=now,
                )
            )


def test_a_detector_rate_appears_at_the_threshold_and_not_below_it(tmp_path):
    """The threshold itself, exercised — no backend test ever reached it.

    Every assertion about ``false_positive_share`` in this file was ``is None``
    with at most two closures in the window behind it, so the branch that
    computes a share had never run: the guard was pinned by the console's
    rendering test on mocked numbers and by nothing that computed it.
    """
    settings, tenant_id = _seed(tmp_path)
    _closures(settings, tenant_id, script_id="ssl-dh-params", closed=20, noise=5)
    _closures(settings, tenant_id, script_id="http-title", closed=19, noise=4)

    rows = {
        row["source"]: row
        for row in adoption.metrics(settings, tenant_id=tenant_id)["false_positives"]["by_source"]
    }

    assert rows["ssl-dh-params"]["closed"] == adoption.MIN_SOURCE_OBSERVATIONS
    assert rows["ssl-dh-params"]["false_positive"] == 5
    assert rows["ssl-dh-params"]["false_positive_share"] == 25.0
    # One closure short of the threshold: the counts are the honest answer, a
    # rate computed from them is not.
    assert rows["http-title"]["closed"] == adoption.MIN_SOURCE_OBSERVATIONS - 1
    assert rows["http-title"]["false_positive"] == 4
    assert rows["http-title"]["false_positive_share"] is None


def test_a_verdict_is_not_dated_by_the_database_session_timezone(tmp_path):
    """``fp_marked_at`` has to be the same kind of timestamp as ``first_seen_at``.

    Nothing in this repo pins the Postgres session ``TimeZone``, and the
    services write naive UTC. A ``timestamptz`` column filled that way is
    reinterpreted as local time, so on an installation running anything but UTC
    the verdict's timestamp lands hours away from the ``timestamp`` column
    beside it — and "median hours to a verdict", which subtracts one from the
    other, reads **-9.0** for a verdict made the same minute the finding
    appeared. The columns are naive to match ``0015_vuln_lifecycle``, and this
    test drives the whole path through a session that is not on UTC so the
    mismatch would show rather than being hidden by a test box in UTC.
    """
    from api.services import assets as assets_service
    from api.services import tenants as tenants_service
    from api.settings import Settings
    from tests.conftest import POSTGRES_URL

    separator = "&" if "?" in POSTGRES_URL else "?"
    settings = Settings(
        output_dir=tmp_path / "output",
        state_dir=tmp_path / "state",
        postgres_url=f"{POSTGRES_URL}{separator}options=-c%20timezone%3DAsia/Tokyo",
    )
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(settings)
    tenant_id = tenants_service.DEFAULT_TENANT_ID
    _write_run(settings.output_dir, "run-tz", _HOSTS, _FINDINGS)
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-tz")
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-tz")
    vuln_id = _ids(settings, tenant_id)["CVE-2024-0001"]
    vulns.mark_false_positive(
        settings, tenant_id=tenant_id, vuln_id=vuln_id, reason="noise", actor="admin"
    )

    with get_session(settings.postgres_url) as session:
        row = session.get(models.Vulnerability, vuln_id)
        marked, first_seen = row.fp_marked_at, row.first_seen_at
        scanned = session.scalars(
            select(models.Asset.last_scanned_at).where(models.Asset.tenant_id == tenant_id)
        ).first()

    # One kind of timestamp, here and on the asset's coverage columns.
    assert marked.tzinfo is None and first_seen.tzinfo is None
    assert scanned.tzinfo is None
    assert marked >= first_seen

    report = adoption.metrics(settings, tenant_id=tenant_id)
    hours_to_verdict = report["false_positives"]["median_hours_to_verdict"]
    assert hours_to_verdict is not None
    assert hours_to_verdict >= 0.0


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
    # _seed's run produced findings, so it covers the asset for vulnerabilities
    # too, not only for inventory.
    assert asset.last_vuln_scan_at is not None
    assert report["coverage"]["scanned_share"] == 100.0
    assert report["coverage"]["vuln_scanned_share"] == 100.0


def _pipeline_run(
    settings,
    run_id: str,
    *,
    findings: list[dict],
    stages: list[tuple[str, str]],
    nuclei_skipped: str | None = "nuclei.disabled",
) -> None:
    """A run directory in the shape ``scanner/main.py`` really leaves behind.

    Which matters, because the shape is the thing under test. ``report.py``
    exports ``vulnerabilities.json`` unconditionally — "OS and vulnerability
    findings are core deliverables and always exported" — and the ``report``
    stage runs in every pipeline, so *every* run has that file whether or not
    anything looked for a vulnerability. A fixture that writes only
    ``alive_hosts.json`` is a directory the pipeline never produces, and a test
    built on one cannot tell the two cases apart.
    """
    run_dir = settings.output_dir / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "alive_hosts.json").write_text(
        json.dumps([{"host": "10.0.0.9", "hostname": "edge.example.com"}]), encoding="utf-8"
    )
    for name in ("os_findings.json", "script_findings.json"):
        (run_dir / name).write_text("[]", encoding="utf-8")
    (run_dir / "vulnerabilities.json").write_text(json.dumps(findings), encoding="utf-8")
    (run_dir / "stage_timings.json").write_text(
        json.dumps(
            {
                "pipeline_wall_sec": 12.0,
                "stages_sum_sec": 11.0,
                "stages": [
                    {"name": name, "duration_sec": 1.0, "status": status}
                    for name, status in stages
                ],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "nuclei.json").write_text(
        json.dumps({"cve_findings": [], "skipped_reason": nuclei_skipped}), encoding="utf-8"
    )


def test_a_run_that_never_looked_for_vulnerabilities_claims_no_coverage(tmp_path):
    """The file exists on every run; only the estate's assessment is at stake.

    ``nuclei.enabled: false`` is a supported opt-out and nmap-vulners is not
    always installed, so this is an ordinary installation and not a corner:
    nobody assessed anything, and the tile used to answer 100%.
    """
    from api.services import assets as assets_service
    from api.services import tenants as tenants_service

    settings = _settings(tmp_path)
    tenant_id = tenants_service.DEFAULT_TENANT_ID
    _pipeline_run(
        settings,
        "run-discovery",
        findings=[],
        stages=[("discover", "ok"), ("ports", "ok"), ("nuclei", "ok"), ("report", "ok")],
        nuclei_skipped="nuclei.disabled",
    )

    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-discovery")

    with get_session(settings.postgres_url) as session:
        asset = session.scalars(
            select(models.Asset).where(models.Asset.tenant_id == tenant_id)
        ).first()
    assert asset.last_scanned_at is not None
    assert asset.last_vuln_scan_at is None

    report = adoption.metrics(settings, tenant_id=tenant_id)
    assert report["coverage"]["scanned_share"] == 100.0
    assert report["coverage"]["vuln_scanned_share"] == 0.0


def test_a_stage_that_ran_and_found_nothing_is_still_coverage(tmp_path):
    """"Assessed and clean" and "never assessed" must not read the same.

    An empty ``vulnerabilities.json`` is the good outcome as often as it is the
    empty one, so the manifest — not the findings — is what separates them.
    """
    from api.services import assets as assets_service
    from api.services import tenants as tenants_service

    settings = _settings(tmp_path)
    tenant_id = tenants_service.DEFAULT_TENANT_ID
    _pipeline_run(
        settings,
        "run-clean",
        findings=[],
        stages=[("ports", "ok"), ("nse", "ok"), ("nuclei", "ok"), ("report", "ok")],
        nuclei_skipped="nuclei.disabled",
    )

    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-clean")

    report = adoption.metrics(settings, tenant_id=tenant_id)
    assert report["coverage"]["vuln_scanned_share"] == 100.0


def test_a_skipped_stage_is_not_an_assessment(tmp_path):
    """``skip_nse`` and a ``--resume`` checkpoint both record ``skipped``."""
    from api.services import assets as assets_service
    from api.services import tenants as tenants_service

    settings = _settings(tmp_path)
    tenant_id = tenants_service.DEFAULT_TENANT_ID
    _pipeline_run(
        settings,
        "run-ports-only",
        findings=[],
        stages=[("ports", "ok"), ("pulse", "skipped"), ("nse", "skipped"), ("report", "ok")],
        nuclei_skipped="no_web_ports",
    )

    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-ports-only")

    report = adoption.metrics(settings, tenant_id=tenant_id)
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
    # Naive UTC, like `last_seen` beside them and like every lifecycle column
    # in the schema — so they compare with each other and with the values this
    # test wrote, without a conversion in the middle.
    assert asset.last_scanned_at.tzinfo is None
    # The check-in is an observation, so `last_seen` moves...
    assert asset.last_seen > stale
    # ...but it is not a scan, so coverage does not.
    assert asset.last_scanned_at == stale
    assert asset.last_vuln_scan_at == stale

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
    assert report["coverage"]["scan_history_reason"] == "no_scan_history"


def test_one_scanned_subnet_out_of_an_estate_is_not_a_one_percent_reading(tmp_path):
    """The guard fired only at a clean zero, which is one instant long.

    50,000 assets and one 500-host subnet scanned reads "Scanned in 30 days:
    1%", and nothing on the page separates that from scanning having fallen
    over — while the reason it is 1% is that migration 0035 has no backfill and
    the columns are still filling, which is what the guard was written for.
    """
    settings, tenant_id = _seed(tmp_path)
    # Ten more active assets, none of them ever scan-ingested: fewer than one
    # in ten has any scan history at all.
    for index in range(10):
        _bare_asset(settings, tenant_id, asset_id=f"ast_dark_{index}")

    report = adoption.metrics(settings, tenant_id=tenant_id)

    assert report["coverage"]["assets_with_scan_history"] == 1
    assert report["coverage"]["scan_history_share"] == 9.1
    assert report["coverage"]["scan_history_reason"] == "partial_scan_history"
    assert report["coverage"]["scanned_share"] is None
    assert report["coverage"]["vuln_scanned_share"] is None
    assert report["assets"]["scanned_recently_share"] is None


def _bare_asset(settings, tenant_id: str, *, asset_id: str) -> None:
    """An active asset the scan-ingest path has never written to."""
    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        session.add(
            models.Asset(
                asset_id=asset_id,
                tenant_id=tenant_id,
                status="active",
                first_seen=now,
                last_seen=now,
            )
        )


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


def _asset(
    settings,
    tenant_id: str,
    *,
    asset_id: str,
    ip: str,
    scanned: bool,
    status: str = "active",
) -> None:
    """One more asset, with the two properties scope coverage is made of."""
    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        session.add(
            models.Asset(
                asset_id=asset_id,
                tenant_id=tenant_id,
                status=status,
                first_seen=now,
                last_seen=now,
                last_scanned_at=now if scanned else None,
                last_scan_run_id="run-1" if scanned else None,
            )
        )
        session.add(
            models.AssetIdentifier(
                asset_id=asset_id,
                tenant_id=tenant_id,
                identifier_type="ip",
                identifier_value=ip,
            )
        )


def test_an_approval_is_covered_when_a_scan_reached_something_inside_it(tmp_path):
    """Reach, not discovery. The unit is the approval somebody wrote down.

    Dividing known addresses by the approved *address space* answered 2.9% for
    a fully scanned /22 with thirty live hosts, and could not tell an estate
    that is mostly empty address space from one nobody had scanned — which is
    the one distinction the tile exists to draw.
    """
    settings, tenant_id = _seed(tmp_path)
    _scope(
        settings,
        tenant_id,
        [("allow", "cidr", "10.0.0.0/29"), ("allow", "cidr", "10.9.0.0/29")],
    )

    block = adoption.metrics(settings, tenant_id=tenant_id)["coverage"]

    assert block["approved_entries"] == 2
    assert block["measurable_entries"] == 2
    assert block["scope_covered_entries"] == 1
    assert block["scope_covered_share"] == 50.0
    # The actionable half: the range nobody has pointed the scanner at, by name.
    assert block["scope_uncovered_entries"] == ["10.9.0.0/29"]
    assert block["scope_unbounded_reason"] is None


def test_an_asset_nobody_has_scanned_does_not_cover_the_range_it_is_in(tmp_path):
    """The defect: coverage was satisfied by having *discovered* a host.

    A tenant that enumerated its estate once and never scanned it again read as
    covered — the exact case the block promises to catch.
    """
    settings, tenant_id = _seed(tmp_path)
    _asset(settings, tenant_id, asset_id="ast_seen_only", ip="10.9.0.3", scanned=False)
    _scope(
        settings,
        tenant_id,
        [("allow", "cidr", "10.0.0.0/29"), ("allow", "cidr", "10.9.0.0/29")],
    )

    block = adoption.metrics(settings, tenant_id=tenant_id)["coverage"]

    assert block["scope_covered_entries"] == 1
    assert block["scope_covered_share"] == 50.0
    assert block["scope_uncovered_entries"] == ["10.9.0.0/29"]


def test_a_decommissioned_asset_stops_covering_the_range_it_was_retired_from(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    _asset(
        settings,
        tenant_id,
        asset_id="ast_retired",
        ip="10.9.0.3",
        scanned=True,
        status="decommissioned",
    )
    _scope(
        settings,
        tenant_id,
        [("allow", "cidr", "10.0.0.0/29"), ("allow", "cidr", "10.9.0.0/29")],
    )

    block = adoption.metrics(settings, tenant_id=tenant_id)["coverage"]

    assert block["scope_covered_share"] == 50.0
    assert block["scope_uncovered_entries"] == ["10.9.0.0/29"]


def test_overlapping_approvals_do_not_inflate_the_denominator(tmp_path):
    """``10.0.0.0/24`` plus ``10.0.0.128/25`` used to be 384 addresses.

    The uniqueness constraint on the scope table stops duplicate rows, not
    overlapping ones, and the address-space denominator counted the overlap
    twice — a third of the reading, silently in the flattering direction for a
    tenant with a tidy approval and against one whose ranges nest.
    """
    settings, tenant_id = _seed(tmp_path)
    _scope(
        settings,
        tenant_id,
        [("allow", "cidr", "10.0.0.0/24"), ("allow", "cidr", "10.0.0.128/25")],
    )

    block = adoption.metrics(settings, tenant_id=tenant_id)["coverage"]

    # 10.0.0.5 is in the /24 and not in the /25: one approval reached, one not.
    assert block["measurable_entries"] == 2
    assert block["scope_covered_share"] == 50.0


def test_a_wildcard_or_domain_approval_is_reported_apart_rather_than_as_missed(tmp_path):
    """A suffix approval says nothing about which hosts are behind it."""
    settings, tenant_id = _seed(tmp_path)
    _scope(settings, tenant_id, [("allow", "domain", "example.com"), ("allow", "cidr", "*")])

    block = adoption.metrics(settings, tenant_id=tenant_id)["coverage"]

    assert block["approved_entries"] == 2
    assert block["measurable_entries"] == 0
    assert sorted(block["unmeasurable_entries"]) == ["*", "example.com"]
    assert block["scope_covered_share"] is None
    assert block["scope_unbounded_reason"] == "no_measurable_scope"


def test_a_very_large_approval_is_still_a_readable_number(tmp_path):
    """A /8 has no address-space share worth printing; as an approval it does.

    The old reading capped out at ``too_large`` and printed nothing, which left
    the tenants with the biggest approvals — the ones most likely to have an
    unscanned corner — with no reading at all.
    """
    settings, tenant_id = _seed(tmp_path)
    _scope(settings, tenant_id, [("allow", "cidr", "10.0.0.0/8")])

    block = adoption.metrics(settings, tenant_id=tenant_id)["coverage"]

    assert block["scope_covered_share"] == 100.0
    assert block["scope_uncovered_entries"] == []


def test_a_tenant_with_no_approved_scope_reports_no_share(tmp_path):
    settings, tenant_id = _seed(tmp_path)

    block = adoption.metrics(settings, tenant_id=tenant_id)["coverage"]

    assert block["approved_entries"] == 0
    assert block["scope_covered_share"] is None
    assert block["scope_unbounded_reason"] == "no_scope"


def test_deny_entries_neither_raise_coverage_nor_count_as_approvals(tmp_path):
    """Carving holes in an approval must not make reach look better.

    And the page's "Approved entries" must not be a count of every row in the
    table while the docstring beside it says deny rows are ignored.
    """
    settings, tenant_id = _seed(tmp_path)
    _scope(
        settings,
        tenant_id,
        [("allow", "cidr", "10.0.0.0/29"), ("deny", "cidr", "10.0.0.6/32")],
    )

    block = adoption.metrics(settings, tenant_id=tenant_id)["coverage"]

    assert block["approved_entries"] == 1
    assert block["denied_entries"] == 1
    assert block["scope_covered_share"] == 100.0


def test_scope_coverage_is_unknown_while_the_scan_columns_are_still_filling(tmp_path):
    """The two blocks must not disagree about whether there is data to divide.

    0% here beside an honest "n/a" next door is the same withheld number
    wearing the other tile's clothes.
    """
    settings, tenant_id = _seed(tmp_path)
    _scope(settings, tenant_id, [("allow", "cidr", "10.0.0.0/29")])
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.Asset)
            .where(models.Asset.tenant_id == tenant_id)
            .values(last_scanned_at=None, last_vuln_scan_at=None, last_scan_run_id=None)
        )

    block = adoption.metrics(settings, tenant_id=tenant_id)["coverage"]

    assert block["scanned_share"] is None
    assert block["scope_covered_share"] is None
    assert block["scope_unbounded_reason"] == "no_scan_history"


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
    assert neighbour["scope_covered_share"] == 100.0
