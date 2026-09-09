"""External vs. internal scan surface: classification, and the filters over it.

The classifier itself needs nothing but its inputs; the job and schedule tests
below need a migrated Postgres (see tests/conftest.py), so they carry the mark
individually rather than the whole module.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from api.schemas import StartScanRequest
from api.services import agents as agents_service
from api.services import jobs as jobs_service
from api.services import runs as runs_service
from api.services import scan_schedules
from api.services import scan_surface
from api.services import tenants as tenants_service
from tests.conftest import approve_scan_scope, make_settings, requires_postgres


@pytest.mark.parametrize(
    ("ranges", "domains", "expected"),
    [
        ("10.0.0.0/24", None, "internal"),
        ("192.168.1.5", None, "internal"),
        ("172.16.4.0/22", None, "internal"),
        ("127.0.0.1", None, "internal"),
        ("169.254.0.0/16", None, "internal"),
        # RFC6598 shared space: a customer behind carrier NAT, not the internet.
        ("100.64.0.0/10", None, "internal"),
        ("fd00:1234::/64", None, "internal"),
        ("fe80::1", None, "internal"),
        ("::1", None, "internal"),
        ("8.8.8.8", None, "external"),
        ("203.0.113.0/24", None, "external"),
        ("2606:4700::/32", None, "external"),
        (None, "example.com", "external"),
        ("10.0.0.0/24", "example.com", "mixed"),
        ("10.0.0.1, 1.1.1.1", None, "mixed"),
        # A supernet is not internal for containing private space: scanning
        # everything is an internet-facing scan.
        ("0.0.0.0/0", None, "external"),
        (None, None, None),
        ("", "   ", None),
        # Comments and blanks are dropped the way split_target_lines drops them.
        ("# nothing here\n\n", None, None),
    ],
)
def test_classify_targets(ranges, domains, expected):
    assert scan_surface.classify(ranges, domains) == expected


def test_classify_ignores_malformed_targets():
    """A typo is parse_target_payload's to refuse — classification skips it.

    Left to raise, a bad target would be reported twice: once correctly as an
    invalid target, and once as a failure to classify it.
    """
    assert scan_surface.classify("999.1.1.1\nnot a range", "!!!") is None
    assert scan_surface.classify("999.1.1.1\n10.0.0.0/8", None) == "internal"


def test_resolve_prefers_the_operators_declaration():
    """A tenant whose internal estate is public address space is not wrong, and
    no address-based rule can know that — so the explicit choice wins."""
    assert scan_surface.resolve("internal", "8.8.8.8", None) == "internal"
    assert scan_surface.resolve(None, "8.8.8.8", None) == "external"
    assert scan_surface.resolve(None, None, None) is None


def _write_run(root: Path, run_id: str, *, surface: str | None) -> None:
    run_dir = root / "runs" / run_id
    run_dir.mkdir(parents=True)
    marker: dict[str, str] = {"tenant_id": "default"}
    if surface:
        marker["surface"] = surface
    (run_dir / "tenant.json").write_text(json.dumps(marker), encoding="utf-8")


def test_list_runs_filters_by_surface_and_reports_it(tmp_path):
    settings = make_settings(tmp_path)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    _write_run(settings.output_dir, "20260901T000000Z", surface="external")
    _write_run(settings.output_dir, "20260902T000000Z", surface="internal")
    _write_run(settings.output_dir, "20260903T000000Z", surface="mixed")
    # A run from before the marker carried a surface at all.
    _write_run(settings.output_dir, "20260904T000000Z", surface=None)

    items, total = runs_service.list_runs(settings)
    assert total == 4
    assert {item.run_id: item.surface for item in items} == {
        "20260901T000000Z": "external",
        "20260902T000000Z": "internal",
        "20260903T000000Z": "mixed",
        "20260904T000000Z": None,
    }

    for wanted, run_id in (
        ("external", "20260901T000000Z"),
        ("internal", "20260902T000000Z"),
        ("mixed", "20260903T000000Z"),
        ("unknown", "20260904T000000Z"),
    ):
        page, count = runs_service.list_runs(settings, surface=wanted)
        assert count == 1, wanted
        assert page[0].run_id == run_id


def test_write_run_tenant_records_the_surface(tmp_path):
    settings = make_settings(tmp_path)
    run_dir = settings.output_dir / "runs" / "20260905T000000Z"
    run_dir.mkdir(parents=True)

    assert runs_service.write_run_tenant(
        settings, "20260905T000000Z", "default", job_id="j1", surface="internal"
    )
    assert runs_service.read_run_surface(run_dir) == "internal"
    assert runs_service.read_run_tenant(run_dir) == "default"

    # A scan of the server's default input files classifies to nothing, and the
    # marker must not gain an empty key that reads as a fourth surface.
    assert runs_service.write_run_tenant(
        settings, "20260905T000000Z", "default", job_id="j1"
    )
    assert runs_service.read_run_surface(run_dir) is None


@pytest.fixture()
def settings(tmp_path: Path):
    """Test settings over a clean control plane, in agent mode.

    Agent execution keeps ``start_scan`` from spawning a real scanner thread —
    these tests are about the row it writes, not about running a scan.
    """
    base = make_settings(tmp_path, job_execution_mode="agent")
    base.state_dir.mkdir(parents=True, exist_ok=True)
    base.output_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(base)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(base)
    approve_scan_scope(base)
    agents_service.configure(base)
    scan_schedules.configure(base)
    scan_schedules.reset_for_tests()
    return base


@requires_postgres
def test_start_scan_records_the_surface_and_list_jobs_filters_on_it(settings):
    internal = jobs_service.start_scan(
        settings, StartScanRequest(ranges="10.0.0.0/24"), username="admin"
    )
    external = jobs_service.start_scan(
        settings, StartScanRequest(domains="example.com"), username="admin"
    )
    mixed = jobs_service.start_scan(
        settings,
        StartScanRequest(ranges="10.0.0.1", domains="example.com"),
        username="admin",
    )
    # No targets: the server's default input files, which nothing here reads.
    unknown = jobs_service.start_scan(settings, StartScanRequest(), username="admin")
    declared = jobs_service.start_scan(
        settings,
        StartScanRequest(ranges="8.8.8.8", surface="internal"),
        username="admin",
    )

    assert internal.surface == "internal"
    assert internal.scan_options["surface"] == "internal"
    assert external.surface == "external"
    assert mixed.surface == "mixed"
    assert unknown.surface is None
    assert declared.surface == "internal"

    for wanted, expected in (
        ("internal", {internal.job_id, declared.job_id}),
        ("external", {external.job_id}),
        ("mixed", {mixed.job_id}),
        ("unknown", {unknown.job_id}),
    ):
        page, total = jobs_service.list_jobs(settings, surface=wanted)
        assert {job.job_id for job in page} == expected, wanted
        assert total == len(expected)


@requires_postgres
def test_schedule_round_trips_surface_into_the_dispatched_request(settings):
    sched = scan_schedules.create_schedule(
        tenant_id="default",
        name="nightly internal",
        cron=None,
        interval_seconds=3600,
        scan_options={"mode": "balanced", "surface": "internal"},
        targets={"ranges": "10.0.0.0/24"},
        created_by="admin",
    )
    assert sched["scan_options"]["surface"] == "internal"

    updated = scan_schedules.update_schedule(
        sched["schedule_id"], scan_options={"surface": "mixed"}
    )
    assert updated["scan_options"]["surface"] == "mixed"

    # What schedule_dispatcher._dispatch does with the stored blob.
    request = StartScanRequest(
        tenant_id=updated["tenant_id"], **updated["scan_options"], **updated["targets"]
    )
    assert request.surface == "mixed"


@requires_postgres
def test_schedule_written_before_surface_existed_still_dispatches(settings):
    """An old row simply has no key; the request default carries it."""
    sched = scan_schedules.create_schedule(
        tenant_id="default",
        name="legacy",
        cron=None,
        interval_seconds=3600,
        scan_options={"mode": "balanced"},
        targets={"ranges": "10.0.0.0/24"},
        created_by="admin",
    )
    assert "surface" not in sched["scan_options"]

    request = StartScanRequest(
        tenant_id=sched["tenant_id"], **sched["scan_options"], **sched["targets"]
    )
    assert request.surface is None
    assert (
        jobs_service.start_scan(settings, request, username="admin").surface
        == "internal"
    )


@requires_postgres
def test_start_scan_records_where_the_surface_came_from(settings):
    """Risk scoring treats a *declared* external scan as network-exposure
    evidence and a derived one as nothing, so the stored job has to say which
    it is (``scan_surface.declared_surface_for_job``)."""
    derived = jobs_service.start_scan(
        settings, StartScanRequest(domains="example.com"), username="admin"
    )
    declared = jobs_service.start_scan(
        settings,
        StartScanRequest(ranges="10.0.0.0/24", surface="external"),
        username="admin",
    )
    # No targets at all: nothing was derived, so there is no source either.
    unknown = jobs_service.start_scan(settings, StartScanRequest(), username="admin")

    assert derived.surface_source == "derived"
    assert derived.scan_options["surface_source"] == "derived"
    assert declared.surface_source == "operator"
    assert declared.surface == "external"
    assert unknown.surface_source is None

    assert scan_surface.declared_surface_for_job(declared.scan_options) == "external"
    assert scan_surface.declared_surface_for_job(derived.scan_options) is None
