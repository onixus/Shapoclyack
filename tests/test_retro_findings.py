"""Retro CVE matching end to end: fingerprints → worker → tracked findings.

The pure matcher is ``tests/test_retro_match.py``. What is here is every seam
with something that already existed, because that is where this feature can
lose or invent a finding without a single unit test noticing:

* the scan path and the retro path share one ``finding_key`` — neither order of
  arrival may leave two rows;
* a retro finding that somebody closed stays closed;
* the worker's queue moves when the dataset moves and only then;
* two replicas do not both sweep;
* one tenant's fingerprints never become another tenant's findings, and the
  routes do not show one tenant another's listeners.
"""

from __future__ import annotations

import json
import shutil
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select

from api.db import models
from api.db.engine import get_session
from api.services import asset_services, cpe_ranges, retro_findings, retro_match_worker
from api.services import assets as assets_service
from api.services import runs as runs_service
from api.services import tenants as tenants_service
from api.services import vuln_states
from api.services import vulnerabilities as vulns
from tests.conftest import (
    POSTGRES_URL,
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres

REPO_ROOT = Path(__file__).resolve().parent.parent
SEED = REPO_ROOT / "scanner" / "data" / "nvd-cpe" / "nvd-cpe-ranges.json"

#: OpenSSH 7.4 with nmap's CPE: four seed CVEs by range, no distribution hint.
#: Apache 2.4.49 with a Debian revision the seed advisories say nothing about:
#: every NVD hit is ``possible`` and none is a finding.
NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="{ip}" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4" extrainfo="protocol 2.0">
          <cpe>cpe:/a:openbsd:openssh:7.4</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49" extrainfo="(Debian)">
          <cpe>cpe:/a:apache:http_server:2.4.49</cpe>
        </service>
      </port>
    </ports>
  </host>
</nmaprun>
"""

OPENSSH_74_CVES = {"CVE-2018-15473", "CVE-2021-41617", "CVE-2023-38408", "CVE-2023-48795"}


@pytest.fixture()
def settings(tmp_path: Path, monkeypatch):
    # A private copy of the seed, so a test can move the dataset under the
    # worker without touching the committed file.
    dataset = tmp_path / "nvd-cpe.json"
    shutil.copy(SEED, dataset)
    monkeypatch.setenv(cpe_ranges.ENV_VAR, str(dataset))
    cpe_ranges.reload()
    s = make_settings(tmp_path)
    s.output_dir.mkdir(parents=True, exist_ok=True)
    s.state_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(s)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(s)
    yield s
    cpe_ranges.reload()


def write_run(
    settings,
    run_id: str,
    *,
    ip: str = "10.0.0.5",
    tenant_id: str = tenants_service.DEFAULT_TENANT_ID,
    xml: str = NMAP_XML,
    findings: list[dict] | None = None,
) -> str:
    """A finished run on disk, its assets upserted — what a projection sees."""
    run_dir = settings.output_dir / "runs" / run_id
    (run_dir / "nmap").mkdir(parents=True, exist_ok=True)
    (run_dir / "alive_hosts.json").write_text(json.dumps([{"host": ip}]), encoding="utf-8")
    (run_dir / "nmap" / f"{ip}.xml").write_text(xml.format(ip=ip), encoding="utf-8")
    (run_dir / "vulnerabilities.json").write_text(json.dumps(findings or []), encoding="utf-8")
    if tenant_id != tenants_service.DEFAULT_TENANT_ID:
        runs_service.write_run_tenant(settings, run_id, tenant_id)
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id=run_id)
    return run_id


def add_tenant(tenant_id: str) -> None:
    tenants_service.create_tenant(name=tenant_id.title(), tenant_id=tenant_id)


def retro_rows(settings, tenant_id: str = "default") -> list[models.Vulnerability]:
    with get_session(settings.postgres_url) as session:
        rows = session.scalars(
            select(models.Vulnerability).where(models.Vulnerability.tenant_id == tenant_id)
        ).all()
        session.expunge_all()
        return list(rows)


# --------------------------------------------------------------------------
# Fingerprints
# --------------------------------------------------------------------------


def test_a_run_records_its_listeners_with_cpe_and_the_distribution_hint(settings) -> None:
    write_run(settings, "run-1")
    stats = asset_services.record_run(settings, tenant_id="default", run_id="run-1")

    assert (stats["created"], stats["skipped"]) == (2, 0)
    with get_session(settings.postgres_url) as session:
        rows = {
            row.port: row
            for row in session.scalars(select(models.AssetService)).all()
        }
        assert rows[22].product == "OpenSSH"
        assert rows[22].cpe == ["cpe:/a:openbsd:openssh:7.4"]
        # nmap's extrainfo is where "(Debian)" lives; it has to survive.
        assert rows[80].banner == "(Debian)"
        assert rows[22].matched_dataset_version is None


def test_recording_the_same_run_twice_changes_nothing(settings) -> None:
    write_run(settings, "run-1")
    asset_services.record_run(settings, tenant_id="default", run_id="run-1")
    again = asset_services.record_run(settings, tenant_id="default", run_id="run-1")
    assert (again["created"], again["changed"], again["unchanged"]) == (0, 0, 2)


def test_a_changed_version_requeues_the_listener_and_an_older_run_does_not_overwrite_it(
    settings,
) -> None:
    write_run(settings, "run-1")
    asset_services.record_run(settings, tenant_id="default", run_id="run-1")
    retro_match_worker.sweep_tenant(settings, "default")

    newer = NMAP_XML.replace('version="7.4"', 'version="9.8p1"').replace(":7.4<", ":9.8p1<")
    write_run(settings, "run-2", xml=newer)
    stats = asset_services.record_run(settings, tenant_id="default", run_id="run-2")
    assert stats["changed"] == 1

    # A backfill reaching the June run after the September one.
    old = asset_services._now() - timedelta(days=30)  # noqa: SLF001
    stale = asset_services.record_run(
        settings, tenant_id="default", run_id="run-1", observed_at=old
    )
    assert stale["stale"] == 2
    with get_session(settings.postgres_url) as session:
        ssh = session.scalars(
            select(models.AssetService).where(models.AssetService.port == 22)
        ).one()
        assert ssh.version == "9.8p1"
        assert ssh.matched_dataset_version is None
        assert ssh.first_seen_at <= old + timedelta(seconds=1)


def test_the_backfill_reads_succeeded_runs_oldest_first_and_counts_the_pruned(settings) -> None:
    from api.services import job_states

    now = asset_services._now()  # noqa: SLF001
    write_run(settings, "run-old")
    newer = NMAP_XML.replace('version="7.4"', 'version="9.8p1"').replace(":7.4<", ":9.8p1<")
    write_run(settings, "run-new", xml=newer)
    with get_session(settings.postgres_url) as session:
        for job_id, run_id, status, age in (
            ("job-new", "run-new", job_states.SUCCEEDED, 1),
            ("job-old", "run-old", job_states.SUCCEEDED, 20),
            ("job-gone", "run-pruned", job_states.SUCCEEDED, 40),
            ("job-failed", "run-failed", job_states.FAILED, 2),
        ):
            session.add(
                models.Job(
                    job_id=job_id,
                    tenant_id="default",
                    status=status,
                    run_id=run_id,
                    queued_at=now - timedelta(days=age),
                    finished_at=now - timedelta(days=age),
                )
            )

    totals = asset_services.backfill_tenant(settings, tenant_id="default")

    assert (totals["runs"], totals["missing"], totals["failed"]) == (3, 1, 0)
    with get_session(settings.postgres_url) as session:
        ssh = session.scalars(
            select(models.AssetService).where(models.AssetService.port == 22)
        ).one()
        # The newer run's fingerprint, with the older run's first sighting.
        assert ssh.version == "9.8p1"
        assert ssh.first_seen_at < ssh.last_seen_at - timedelta(days=15)
        assert ssh.last_run_id == "run-new"


def test_the_projection_records_fingerprints_for_a_succeeded_run_only(settings) -> None:
    from api.services import job_states, run_completion

    write_run(settings, "run-ok")
    run_completion.project_published_run(
        settings, "job-x", run_id="run-ok", tenant_id="default", status=job_states.SUCCEEDED
    )
    write_run(settings, "run-failed", ip="10.0.0.9")
    run_completion.project_published_run(
        settings, "job-y", run_id="run-failed", tenant_id="default", status=job_states.FAILED
    )
    with get_session(settings.postgres_url) as session:
        hosts = set(session.scalars(select(models.AssetService.host)).all())
    assert hosts == {"10.0.0.5"}


# --------------------------------------------------------------------------
# The fold
# --------------------------------------------------------------------------


def test_a_sweep_creates_version_range_findings_with_evidence_and_an_sla(settings) -> None:
    write_run(settings, "run-1")
    asset_services.record_run(settings, tenant_id="default", run_id="run-1")

    result = retro_match_worker.sweep_tenant(settings, "default")

    assert result["created"] == len(OPENSSH_74_CVES)
    rows = retro_rows(settings)
    assert {row.cve for row in rows} == OPENSSH_74_CVES
    for row in rows:
        assert row.source == retro_findings.SOURCE
        assert row.port == "22"
        assert row.match_confidence == "version_range"
        assert row.match_evidence["cpe"] == "a:openbsd:openssh"
        assert row.match_evidence["upstream_version"] == "7.4"
        assert row.due_at is not None and row.sla_days is not None
    # Apache: a Debian build the seed advisories do not cover — possible only.
    with get_session(settings.postgres_url) as session:
        apache = session.scalars(
            select(models.AssetService).where(models.AssetService.port == 80)
        ).one()
        assert apache.match_summary["counts"]["possible"] == 5
        assert apache.match_summary["counts"]["vulnerable"] == 0


def test_retro_then_scan_is_one_finding_and_the_scan_takes_it_over(settings) -> None:
    write_run(settings, "run-1")
    asset_services.record_run(settings, tenant_id="default", run_id="run-1")
    retro_match_worker.sweep_tenant(settings, "default")

    write_run(
        settings,
        "run-2",
        findings=[{"host": "10.0.0.5", "port": "22", "cve": "CVE-2023-48795", "severity": "medium"}],
    )
    stats = vulns.register_findings_from_run(settings, tenant_id="default", run_id="run-2")

    assert (stats.created, stats.reobserved) == (0, 1)
    rows = [row for row in retro_rows(settings) if row.cve == "CVE-2023-48795"]
    assert len(rows) == 1
    assert rows[0].source == "scan"
    assert rows[0].match_confidence is None
    assert rows[0].match_evidence["range"] == "< 9.6"


def test_scan_then_retro_leaves_the_scan_finding_alone(settings) -> None:
    write_run(
        settings,
        "run-1",
        findings=[{"host": "10.0.0.5", "port": "22", "cve": "CVE-2023-48795", "severity": "high"}],
    )
    vulns.register_findings_from_run(settings, tenant_id="default", run_id="run-1")
    asset_services.record_run(settings, tenant_id="default", run_id="run-1")

    result = retro_match_worker.sweep_tenant(settings, "default")

    assert result["already_tracked"] == 1
    assert result["created"] == len(OPENSSH_74_CVES) - 1
    terrapin = [row for row in retro_rows(settings) if row.cve == "CVE-2023-48795"]
    assert len(terrapin) == 1
    assert (terrapin[0].source, terrapin[0].severity) == ("scan", "high")
    assert terrapin[0].match_confidence is None


def test_a_closed_retro_finding_stays_closed_when_the_dataset_says_it_again(settings) -> None:
    write_run(settings, "run-1")
    asset_services.record_run(settings, tenant_id="default", run_id="run-1")
    retro_match_worker.sweep_tenant(settings, "default")
    target = next(row for row in retro_rows(settings) if row.cve == "CVE-2023-38408")
    vulns.transition(
        settings,
        tenant_id="default",
        vuln_id=target.vuln_id,
        to_state=vuln_states.CLOSED,
        actor="operator",
        note="compensating control",
    )

    retro_match_worker.request_refresh(settings, tenant_id="default", actor="operator")
    result = retro_match_worker.sweep_tenant(settings, "default")

    assert result["held_closed"] == 1
    assert result["created"] == 0
    closed = next(row for row in retro_rows(settings) if row.vuln_id == target.vuln_id)
    assert closed.state == vuln_states.CLOSED
    assert closed.reopen_count == 0


def test_absence_never_closes_a_retro_finding(settings) -> None:
    """The host was upgraded: the new fingerprint matches nothing. The finding
    is not closed by the matcher — closure is the scan path's."""
    write_run(settings, "run-1")
    asset_services.record_run(settings, tenant_id="default", run_id="run-1")
    retro_match_worker.sweep_tenant(settings, "default")

    upgraded = NMAP_XML.replace('version="7.4"', 'version="9.8p1"').replace(":7.4<", ":9.8p1<")
    write_run(settings, "run-2", xml=upgraded)
    asset_services.record_run(settings, tenant_id="default", run_id="run-2")
    retro_match_worker.sweep_tenant(settings, "default")

    assert {row.state for row in retro_rows(settings)} == {vuln_states.OPEN}
    assert len(retro_rows(settings)) == len(OPENSSH_74_CVES)


def test_a_retro_finding_refuses_machine_verification(settings) -> None:
    write_run(settings, "run-1")
    asset_services.record_run(settings, tenant_id="default", run_id="run-1")
    retro_match_worker.sweep_tenant(settings, "default")
    row = retro_rows(settings)[0]

    with pytest.raises(vulns.VerificationDispatchError, match="retro matching"):
        vulns.trigger_verification(settings, tenant_id="default", vuln_id=row.vuln_id)
    assert next(r for r in retro_rows(settings) if r.vuln_id == row.vuln_id).state == vuln_states.OPEN


def test_a_listener_not_seen_for_months_is_not_matched(settings) -> None:
    write_run(settings, "run-1")
    old = asset_services._now() - timedelta(days=settings.retro_match_max_age_days + 5)  # noqa: SLF001
    asset_services.record_run(settings, tenant_id="default", run_id="run-1", observed_at=old)

    result = retro_match_worker.sweep_tenant(settings, "default")

    assert (result["too_old"], result["created"]) == (2, 0)
    # ... and seeing it again today puts it back on the queue.
    stats = asset_services.record_run(settings, tenant_id="default", run_id="run-1")
    assert stats["unchanged"] == 2
    assert retro_match_worker.sweep_tenant(settings, "default")["created"] == len(OPENSSH_74_CVES)


# --------------------------------------------------------------------------
# The queue
# --------------------------------------------------------------------------


def test_the_worker_runs_on_a_new_dataset_and_not_again_without_one(settings) -> None:
    write_run(settings, "run-1")
    asset_services.record_run(settings, tenant_id="default", run_id="run-1")
    assert retro_match_worker.sweep_tenant(settings, "default")["services"] == 2

    # Nothing moved: nothing is due, and a tick is one query.
    marker = retro_match_worker.current_marker(cpe_ranges.dataset())
    assert retro_match_worker.pending_service_ids(
        settings, tenant_id="default", marker=marker, limit=10
    ) == []
    assert retro_match_worker.sweep_tenant(settings, "default") == {"services": 0}

    # Tonight's refresh adds a range for OpenSSH 7.4. The file changes, the
    # marker moves, every listener is due exactly once, and the new CVE lands.
    path = cpe_ranges.dataset_path()
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["updated"] = "2026-09-24"
    payload["cves"]["CVE-2099-0001"] = {"cvss": 9.1, "severity": "critical"}
    payload["entries"]["a:openbsd:openssh"].append({"cve": "CVE-2099-0001", "ei": "7.9"})
    path.write_text(json.dumps(payload), encoding="utf-8")

    second = retro_match_worker.sweep_tenant(settings, "default")
    assert second["services"] == 2
    assert second["created"] == 1
    assert "CVE-2099-0001" in {row.cve for row in retro_rows(settings)}
    assert retro_match_worker.sweep_tenant(settings, "default") == {"services": 0}


def test_no_dataset_means_no_matching_and_nothing_marked(settings, monkeypatch, tmp_path) -> None:
    write_run(settings, "run-1")
    asset_services.record_run(settings, tenant_id="default", run_id="run-1")
    monkeypatch.setenv(cpe_ranges.ENV_VAR, str(tmp_path / "absent.json"))

    assert retro_match_worker.sweep_tenant(settings, "default")["skipped"] == "no_dataset"
    with get_session(settings.postgres_url) as session:
        assert session.scalar(
            select(func.count()).select_from(models.AssetService).where(
                models.AssetService.matched_dataset_version.is_not(None)
            )
        ) == 0


def test_one_poisonous_listener_is_held_off_and_the_rest_are_matched(settings, monkeypatch) -> None:
    write_run(settings, "run-1")
    asset_services.record_run(settings, tenant_id="default", run_id="run-1")
    real = retro_findings._fold_service  # noqa: SLF001

    def exploding(session, *, service, **kwargs):
        if service.port == 80:
            raise RuntimeError("poison")
        return real(session, service=service, **kwargs)

    monkeypatch.setattr(retro_findings, "_fold_service", exploding)
    result = retro_match_worker.sweep_tenant(settings, "default")

    assert result["errors"] == 1
    assert result["created"] == len(OPENSSH_74_CVES)
    with get_session(settings.postgres_url) as session:
        apache = session.scalars(
            select(models.AssetService).where(models.AssetService.port == 80)
        ).one()
        assert apache.matched_dataset_version is None
        assert apache.match_retry_after is not None
        assert apache.match_failure_count == 1


def test_two_replicas_do_not_both_sweep(settings) -> None:
    write_run(settings, "run-1")
    asset_services.record_run(settings, tenant_id="default", run_id="run-1")
    first = retro_match_worker.RetroMatchWorker(settings=settings)
    second = retro_match_worker.RetroMatchWorker(settings=settings)
    try:
        assert first.tick()["created"] == len(OPENSSH_74_CVES)
        assert second.tick() is None
        assert second.stats["skipped_not_leader"] == 1
        # The leader goes away; the follower takes over and finds the queue
        # already drained rather than matching everything again.
        first.release()
        assert second.tick()["services"] == 0
    finally:
        first.release()
        second.release()
    assert len(retro_rows(settings)) == len(OPENSSH_74_CVES)


# --------------------------------------------------------------------------
# Tenants
# --------------------------------------------------------------------------


def test_one_tenants_fingerprints_never_become_another_tenants_findings(settings) -> None:
    add_tenant("ten_other")
    write_run(settings, "run-other", ip="10.9.9.9", tenant_id="ten_other")
    asset_services.record_run(settings, tenant_id="ten_other", run_id="run-other")

    assert retro_match_worker.sweep_tenant(settings, "default") == {"services": 0}
    assert retro_rows(settings, "default") == []
    assert retro_match_worker.sweep_tenant(settings, "ten_other")["created"] == len(OPENSSH_74_CVES)
    assert {row.tenant_id for row in retro_rows(settings, "ten_other")} == {"ten_other"}


def test_a_listener_id_from_another_tenant_is_not_folded(settings) -> None:
    add_tenant("ten_other")
    write_run(settings, "run-other", ip="10.9.9.9", tenant_id="ten_other")
    asset_services.record_run(settings, tenant_id="ten_other", run_id="run-other")
    with get_session(settings.postgres_url) as session:
        foreign = list(session.scalars(select(models.AssetService.id)).all())

    dataset = cpe_ranges.dataset()
    stats, created = retro_findings.fold_services(
        settings,
        tenant_id="default",
        service_ids=foreign,
        dataset=dataset,
        marker=retro_match_worker.current_marker(dataset),
        lookup=lambda _distro: None,
    )
    assert (stats.services, created) == (0, [])
    assert retro_rows(settings, "ten_other") == []


# --------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------


def test_new_findings_announce_as_new_cve_and_the_overflow_as_one_aggregate(
    settings, monkeypatch
) -> None:
    from api.services import asset_events

    sent: list[dict] = []
    monkeypatch.setattr(
        asset_events,
        "publish_events",
        lambda url, envelopes, settings=None: sent.extend(envelopes) or len(envelopes),
    )
    settings.nats_url = "nats://example.invalid:4222"
    settings.asset_events_enabled = True
    settings.retro_match_max_events = 2
    write_run(settings, "run-1")
    asset_services.record_run(settings, tenant_id="default", run_id="run-1")

    result = retro_match_worker.sweep_tenant(settings, "default")

    assert (result["published"], result["summarised"]) == (3, 2)
    single = [e for e in sent if not e["data"].get("aggregate")]
    aggregate = [e for e in sent if e["data"].get("aggregate")]
    assert len(single) == 2 and len(aggregate) == 1
    assert {e["kind"] for e in sent} == {"new_cve"}
    assert {e["source"] for e in sent} == {"retro_match"}
    # Worst first: the critical CVE is announced individually.
    assert single[0]["data"]["cve"] == "CVE-2023-38408"
    assert aggregate[0]["data"]["count"] == 2
    with get_session(settings.postgres_url) as session:
        state = session.get(models.RetroMatchState, "default")
        assert (state.events_published, state.events_suppressed) == (3, 2)


def test_no_bus_no_events_but_the_findings_are_there(settings, monkeypatch) -> None:
    from api.services import asset_events

    monkeypatch.setattr(
        asset_events, "publish_events", lambda *a, **k: pytest.fail("published without a bus")
    )
    settings.nats_url = ""
    write_run(settings, "run-1")
    asset_services.record_run(settings, tenant_id="default", run_id="run-1")
    assert retro_match_worker.sweep_tenant(settings, "default")["created"] == len(OPENSSH_74_CVES)


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------


@pytest.fixture()
def client(tmp_path: Path, monkeypatch, settings):
    return configured_client(tmp_path, monkeypatch, settings=settings)


def test_services_route_shows_the_listeners_and_hides_other_tenants(client, settings) -> None:
    write_run(settings, "run-1")
    asset_services.record_run(settings, tenant_id="default", run_id="run-1")
    retro_match_worker.sweep_tenant(settings, "default")
    add_tenant("ten_other")
    write_run(settings, "run-other", ip="10.9.9.9", tenant_id="ten_other")
    asset_services.record_run(settings, tenant_id="ten_other", run_id="run-other")
    with get_session(settings.postgres_url) as session:
        own = session.scalars(
            select(models.AssetService.asset_id).where(models.AssetService.tenant_id == "default")
        ).first()
        foreign = session.scalars(
            select(models.AssetService.asset_id).where(models.AssetService.tenant_id == "ten_other")
        ).first()
    viewer = auth_headers(client, "viewer")

    response = client.get(f"/api/assets/{own}/services", headers=viewer)
    assert response.status_code == 200
    body = {row["port"]: row for row in response.json()}
    assert body[22]["match_status"] == "matched"
    assert body[22]["match_counts"]["vulnerable"] == len(OPENSSH_74_CVES)
    assert {c["cve"] for c in body[80]["possible_cves"]} >= {"CVE-2021-41773"}

    assert client.get(f"/api/assets/{foreign}/services", headers=viewer).status_code == 404


def test_status_route_is_per_tenant_and_refresh_needs_operator(client, settings) -> None:
    write_run(settings, "run-1")
    asset_services.record_run(settings, tenant_id="default", run_id="run-1")
    add_tenant("ten_other")
    write_run(settings, "run-other", ip="10.9.9.9", tenant_id="ten_other")
    asset_services.record_run(settings, tenant_id="ten_other", run_id="run-other")
    retro_match_worker.sweep_tenant(settings, "default")
    retro_match_worker.sweep_tenant(settings, "ten_other")

    viewer = auth_headers(client, "viewer")
    status = client.get("/api/retro-match/status", headers=viewer)
    assert status.status_code == 200
    body = status.json()
    assert body["services_total"] == 2  # not the other tenant's two
    assert body["services_pending"] == 0
    # Not the other tenant's four either.
    assert body["open_findings"] == {"version_range": len(OPENSSH_74_CVES)}
    assert body["possible_matches"] == 5
    assert body["dataset"]["products"] == 8
    assert body["dataset_version"].startswith("2026-09-23:")

    assert client.post("/api/retro-match/refresh", headers=viewer).status_code == 403
    operator = auth_headers(client, "operator")
    refreshed = client.post("/api/retro-match/refresh", headers=operator)
    assert refreshed.status_code == 200
    assert refreshed.json()["queued"] == 2
    after = client.get("/api/retro-match/status", headers=viewer).json()
    assert after["services_pending"] == 2
    assert after["refresh_requested_by"] == "operator"
    # The other tenant's queue was not touched by this tenant's refresh.
    with get_session(settings.postgres_url) as session:
        other_due = session.scalar(
            select(func.count()).select_from(models.AssetService).where(
                models.AssetService.tenant_id == "ten_other",
                models.AssetService.matched_dataset_version.is_(None),
            )
        )
    assert other_due == 0


def test_vulnerability_list_filters_and_carries_retro_confidence(client, settings) -> None:
    write_run(settings, "run-1")
    asset_services.record_run(settings, tenant_id="default", run_id="run-1")
    retro_match_worker.sweep_tenant(settings, "default")

    response = client.get(
        "/api/vulnerabilities?source=retro_match", headers=auth_headers(client, "viewer")
    )
    assert response.status_code == 200
    items = response.json()["items"]
    assert {item["cve"] for item in items} == OPENSSH_74_CVES
    assert {item["match_confidence"] for item in items} == {"version_range"}
    assert all(item["match_evidence"]["via"] == "cpe" for item in items)


def test_reset_for_tests_empties_the_new_tables(settings) -> None:
    """Both tables are FK'd to tenants with CASCADE, and listed in the reset
    anyway: a row that outlives the session is the flake memory describes."""
    write_run(settings, "run-1")
    asset_services.record_run(settings, tenant_id="default", run_id="run-1")
    retro_match_worker.sweep_tenant(settings, "default")
    tenants_service.reset_for_tests()
    with get_session(POSTGRES_URL) as session:
        assert session.scalar(select(func.count()).select_from(models.AssetService)) == 0
        assert session.scalar(select(func.count()).select_from(models.RetroMatchState)) == 0
