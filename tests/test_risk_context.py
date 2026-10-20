"""Real PostgreSQL consumer/correlation/immutable receipt contracts (#453)."""
from __future__ import annotations

import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, event, select, update
from sqlalchemy.exc import DBAPIError

from api.db import models, tenant_scope
from api.db.engine import get_engine, get_session
from api.services import ch_transform, risk_context, risk_scoring, runs, vulnerabilities
from tests.conftest import POSTGRES_URL, make_settings, requires_postgres

NOW = datetime(2026, 9, 29, 12, tzinfo=UTC)


@pytest.fixture
def estate(tmp_path, monkeypatch):
    if not POSTGRES_URL:
        pytest.skip("requires migrated PostgreSQL")
    settings = make_settings(tmp_path)
    settings.output_dir.mkdir(parents=True)
    settings.state_dir.mkdir(parents=True)
    suffix = uuid.uuid4().hex[:12]
    a, b = "risk-a-" + suffix, "risk-b-" + suffix
    asset, neighbor, unmapped = "asset-a-" + suffix, "asset-b-" + suffix, "asset-u-" + suffix
    entries = [
        {"host": "10.42.0.1", "port": "443", "script_id": "pulse:entry", "finding_class": "exposure", "cvss": 5.0},
        {"host": "10.42.0.2", "port": "445", "cve": "CVE-2020-10000", "cvss": 8.0, "cvss4_vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "in_kev": True},
        {"host": "APP.EXAMPLE.TEST", "port": "22", "cve": "CVE-2020-10001", "cvss": 5.0},
    ]
    fingerprint = {"findings": [{"host": "10.42.0.2", "port": 445, "cdn_waf": ["cloudflare"]}]}
    scorer = risk_scoring.RiskScoring()
    monkeypatch.setattr(runs, "get_scorer", lambda: scorer)
    monkeypatch.setattr(ch_transform, "get_scorer", lambda: scorer)
    monkeypatch.setattr(vulnerabilities, "get_scorer", lambda: scorer)
    monkeypatch.setattr(vulnerabilities, "_now", lambda: NOW.replace(tzinfo=None))
    with get_session(POSTGRES_URL) as session:
        session.add_all([models.Tenant(tenant_id=t, name=t, created_at=NOW) for t in (a, b)])
        session.flush()
        for aid, tenant, criticality in ((asset, a, 0), (neighbor, b, 4), (unmapped, a, None)):
            session.add(models.Asset(asset_id=aid, tenant_id=tenant, first_seen=NOW, last_seen=NOW, asset_criticality=criticality, exposure_level="internet" if aid == asset else None, context_source="operator"))
        session.flush()
        for tenant, aid in ((a, asset), (b, neighbor)):
            for kind, value in (("ip", "10.42.0.1"), ("ip", "10.42.0.2"), ("fqdn", "app.example.test")):
                session.add(models.AssetIdentifier(asset_id=aid, tenant_id=tenant, identifier_type=kind, identifier_value=value))
        session.add(models.AssetIdentifier(asset_id=unmapped, tenant_id=a, identifier_type="ip", identifier_value="203.0.113.3"))
        session.add(models.Job(job_id="risk-job-" + suffix, tenant_id=a, run_id="risk-run", queued_at=NOW, status="succeeded", scan_options={"surface": "external", "surface_source": "operator"}))
    from api.services.artifact_store import keys, workspace
    directory = workspace.run_dir(settings, keys.run_ref("risk-run", a), refresh=False)
    directory.mkdir(parents=True)
    (directory / "tenant.json").write_text(json.dumps({"tenant_id": a}))
    (directory / "vulnerabilities.json").write_text(json.dumps(entries))
    (directory / "fingerprint.json").write_text(json.dumps(fingerprint))
    with get_session(POSTGRES_URL) as session:
        session.add(models.RunPublication(publication_id="risk-pub-" + a, tenant_id=a,
            job_id="risk-job-" + suffix, run_id="risk-run", job_status="succeeded",
            risk_assessment_contract=risk_context.CONTEXT_VERSION, created_at=NOW, updated_at=NOW))
    runs.stage_run_tenant(directory, a, job_id="risk-job-" + suffix, publication_id="risk-pub-" + a)
    members = {"vulnerabilities.json": json.dumps(entries).encode(), "fingerprint.json": json.dumps(fingerprint).encode(), "run_meta.json": json.dumps({"started_at": NOW.isoformat()}).encode()}
    try:
        yield settings, a, b, asset, neighbor, entries, fingerprint, scorer, members
    finally:
        tenant_scope.reset_for_tests()
        with get_session(POSTGRES_URL) as session:
            for model in (models.VulnerabilityEvent, models.Vulnerability, models.RiskScoreSnapshot, models.RunRiskAssessment, models.RunPublication, models.Job, models.AssetIdentifier, models.Asset):
                session.execute(delete(model).where(model.tenant_id.in_((a, b))))
            session.execute(delete(models.Tenant).where(models.Tenant.tenant_id.in_((a, b))))


def _register(settings, tenant_id, publication_id=None):
    publication_id = publication_id or "risk-pub-" + tenant_id
    with get_session(POSTGRES_URL) as session:
        row = session.get(models.RunPublication, publication_id)
        job_id = row.job_id
    directory = runs.get_run_dir(settings, "risk-run", tenant_id=tenant_id)
    runs.stage_run_tenant(directory, tenant_id, job_id=job_id, publication_id=publication_id)
    return vulnerabilities.register_findings_from_run(settings, tenant_id=tenant_id,
        run_id="risk-run", publication_id=publication_id)


def _count(settings, call):
    statements = []
    def record(_conn, _cursor, statement, *_):
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)
    engine = get_engine(settings.postgres_url)
    event.listen(engine, "before_cursor_execute", record)
    try:
        result = call()
    finally:
        event.remove(engine, "before_cursor_execute", record)
    return result, statements


@requires_postgres
def test_tenant_multi_address_batch_and_three_consumers_share_captured_score(estate):
    settings, a, b, asset, neighbor, entries, fp, scorer, members = estate
    stats = _register(settings, a)
    assert stats.created == 3
    api, queries = _count(settings, lambda: runs.get_vulnerabilities(settings, "risk-run", tenant_id=a))
    assert len(queries) == 1  # immutable receipt, no asset re-read for historical view
    rows, ch_queries = _count(settings, lambda: ch_transform.vulnerabilities_to_rows({"tenant_id": a, "run_id": "risk-run", "job_id": "risk-job-" + a.removeprefix("risk-a-")}, members, settings=settings))
    assert len(ch_queries) == 1
    by_cve = {item.cve or item.script_id: item for item in api}
    with get_session(POSTGRES_URL) as session:
        tracker = session.scalars(select(models.Vulnerability).where(models.Vulnerability.tenant_id == a)).all()
        for row in tracker:
            item = by_cve[row.cve or row.script_id]
            assert row.contextual_score == item.contextual_score
            assert row.risk_assessment["risk_explanation"] == item.risk_explanation
            assert row.risk_assessment["risk_assessment"] == item.risk_assessment
            assert item.asset_id == asset and item.asset_criticality == 0
        snapshot = session.scalars(select(models.RunRiskAssessment).where(models.RunRiskAssessment.tenant_id == a)).one()
        assert snapshot.scores[1]["attack_path"] == "same-asset"
        assert snapshot.scores[1]["cdn_waf"] == ["cloudflare"]
        assert snapshot.scores[0]["cdn_waf"] == []
    for row in rows:
        scored = json.loads(row[11])
        item = by_cve[row[2]]
        assert scored["risk_explanation"] == item.risk_explanation
        assert scored["risk_assessment"] == item.risk_assessment
        assert row[8] == item.contextual_score
    with get_session(POSTGRES_URL) as session:
        context = risk_context.load_batch(session, tenant_id=b, run_id="risk-run", entries=entries)
        assert context.asset_for(entries[0]).asset_id == neighbor
        assert context.asset_for({**entries[0], "asset_id": asset}) is None


@requires_postgres
def test_events_reference_the_receipt_instead_of_copying_it(estate):
    settings, a, *_ = estate
    _register(settings, a)
    with get_session(POSTGRES_URL) as session:
        receipt = session.scalars(select(models.RunRiskAssessment).where(
            models.RunRiskAssessment.tenant_id == a)).one()
        events = session.scalars(select(models.VulnerabilityEvent).where(
            models.VulnerabilityEvent.tenant_id == a)).all()
    referenced = [e.detail["risk_assessment"] for e in events if "risk_assessment" in (e.detail or {})]
    assert referenced
    for ref in referenced:
        assert ref["assessment_id"] == receipt.assessment_id
        assert ref["execution_id"] == receipt.execution_id
        assert "inputs" not in ref and "risk_explanation" not in ref
        assert set(ref) <= set(risk_context._REFERENCE_KEYS)  # noqa: SLF001


@requires_postgres
def test_current_is_read_only_and_historical_receipt_remains_immutable(estate):
    settings, a, _, asset, _, entries, fp, scorer, _ = estate
    _register(settings, a)
    old = runs.get_vulnerabilities(settings, "risk-run", tenant_id=a)
    with get_session(POSTGRES_URL) as session:
        session.get(models.Asset, asset).asset_criticality = 4
        row = session.scalars(select(models.Vulnerability).where(models.Vulnerability.tenant_id == a)).first()
        row.assignee = "risk-owner"
        row.owner_team = "payments"
        due, key, owner = row.due_at, row.finding_key, row.assignee
    current = runs.get_vulnerabilities(settings, "risk-run", tenant_id=a, assessment_mode="current")
    historical = runs.get_vulnerabilities(settings, "risk-run", tenant_id=a)
    assert [item.model_dump() for item in old] == [item.model_dump() for item in historical]
    assert all(item.risk_assessment["mode"] == "current" and item.asset_criticality == 4 for item in current)
    assert any(new.contextual_score != prior.contextual_score for new, prior in zip(current, old, strict=True))
    with get_session(POSTGRES_URL) as session:
        row = session.scalars(select(models.Vulnerability).where(models.Vulnerability.tenant_id == a, models.Vulnerability.finding_key == key)).one()
        assert (row.due_at, row.finding_key, row.assignee, row.owner_team) == (due, key, owner, "payments")
        assert len(session.scalars(select(models.RunRiskAssessment).where(models.RunRiskAssessment.tenant_id == a)).all()) == 1
    _register(settings, a)
    assert [item.model_dump() for item in old] == [item.model_dump() for item in runs.get_vulnerabilities(settings, "risk-run", tenant_id=a)]


@requires_postgres
def test_context_query_budget_constant_for_all_consumer_paths(estate, monkeypatch):
    settings, a, _, _, _, entries, fp, scorer, _ = estate
    counts = []
    for count in (3, 300):
        many = entries * (count // 3)
        _, queries = _count(settings, lambda: risk_context.assess_operation(settings, tenant_id=a, run_id="risk-run", entries=many, fingerprint=fp, scorer=scorer, mode="current", now=NOW))
        counts.append(len(queries))
    assert counts == [3, 3]
    # Real consumer calls load one batch, regardless of repeated observations.
    api, queries = _count(settings, lambda: runs.get_vulnerabilities(settings, "risk-run", tenant_id=a, assessment_mode="current"))
    assert len(api) == 3 and len(queries) == 3
    for count in (3, 300):
        members = {"vulnerabilities.json": json.dumps(entries * (count // 3)).encode(), "fingerprint.json": json.dumps(fp).encode()}
        _, queries = _count(settings, lambda: ch_transform.vulnerabilities_to_rows({"tenant_id": a, "run_id": "legacy-run"}, members, settings=settings))
        assert len(queries) == 4  # no execution hint: obligation lookup plus batch
    _, queries = _count(settings, lambda: _register(settings, a))
    assert sum("FROM asset_identifiers" in query for query in queries) == 1
    assert sum("FROM assets" in query for query in queries) == 1


@requires_postgres
def test_canonical_receipt_concurrent_capture_and_tenant_rls(estate):
    settings, a, b, _, _, entries, fp, scorer, _ = estate
    with get_session(POSTGRES_URL) as session:
        context = risk_context.load_batch(session, tenant_id=a, run_id="risk-run", entries=entries)
        scores = risk_context.score_batch(entries, context=context, fingerprint=fp, scorer=scorer, now=NOW, mode="historical")
    def capture(index):
        with get_session(POSTGRES_URL) as session:
            return risk_context.capture_snapshot(session, tenant_id=a, run_id="race", entries=entries, fingerprint=fp, scores=json.loads(json.dumps(scores)), now=NOW + timedelta(seconds=index), publication_id="race-test-pub")
    with ThreadPoolExecutor(max_workers=2) as executor:
        receipts = list(executor.map(capture, (0, 1)))
    assert receipts[0] == receipts[1]
    tenant_scope.configure(make_settings(settings.state_dir, tenant_rls="enforce"))
    with tenant_scope.tenant(b), get_session(POSTGRES_URL) as session:
        assert session.scalars(select(models.RunRiskAssessment)).all() == []
    with pytest.raises(DBAPIError):
        with tenant_scope.tenant(a), get_session(POSTGRES_URL) as session:
            session.execute(update(models.RunRiskAssessment).values(scores=[]))
    with tenant_scope.tenant(a), get_session(POSTGRES_URL) as session:
        rows = session.scalars(select(models.RunRiskAssessment)).all()
        assert len(rows) == 1 and rows[0].scores == receipts[0]


def test_offline_unknown_context_host_fallback_never_invents_exposure_or_asset():
    entries = [{"host": "8.8.8.8", "port": "443", "cve": "CVE-2020-2", "cvss": 7.0}]
    scores = risk_context.assess_operation(None, tenant_id="tenant-a", run_id="offline", entries=entries, fingerprint=None, scorer=risk_scoring.RiskScoring(), now=NOW)
    scored = scores[0]
    assert scored["network_exposure"] == "unknown"
    assert scored["risk_assessment"]["mode"] == "uncaptured-current"
    assert scored["risk_assessment"]["complete"] is False
    assert scored["risk_assessment"]["inputs"]["asset_id"] is None
    assert scored["risk_assessment"]["criticality_source"] == "heuristic"
    assert scored["risk_assessment"]["context_status"] == "unavailable"
    assert scored["cdn_waf"] == []
    assert risk_context.BatchContext("a", {}, {}, None, False).correlation(entries[0]) != risk_context.BatchContext("b", {}, {}, None, False).correlation(entries[0])
    with pytest.raises(ValueError):
        risk_context.assess_operation(None, tenant_id="a", run_id="r", entries=entries, fingerprint=None, scorer=risk_scoring.RiskScoring(), mode="bogus")


@requires_postgres
def test_declared_surface_unknown_exposure_and_explicit_identity_are_honest(estate):
    settings, a, _, asset, neighbor, entries, fp, scorer, _ = estate
    with get_session(POSTGRES_URL) as session:
        session.get(models.Asset, asset).exposure_level = None
        finding = {"asset_id": asset, "host": "8.8.8.8", "port": "443", "cve": "CVE-2020-2", "cvss": 5.0}
        context = risk_context.load_batch(session, tenant_id=a, run_id="risk-run", entries=[finding])
        scored = risk_context.score_batch([finding], context=context, fingerprint=None, scorer=scorer, now=NOW, mode="current")[0]
        assert scored["network_exposure"] == "external"
        assert scored["network_exposure_source"] == "scan-surface"
        assert scored["asset_criticality"] == 0
        assert scored["risk_assessment"]["inputs"]["asset_id"] == asset
        context = risk_context.load_batch(session, tenant_id=a, run_id="unmanaged", entries=[finding])
        scored = risk_context.score_batch([finding], context=context, fingerprint=None, scorer=scorer, now=NOW, mode="legacy-current")[0]
        assert scored["network_exposure"] == "unknown"
        assert scored["risk_assessment"]["complete"] is False
        assert context.asset_for({**finding, "asset_id": neighbor}) is None


@requires_postgres
def test_managed_clickhouse_waits_for_canonical_capture_not_current_heuristic(estate):
    settings, a, _, _, _, _, _, _, members = estate
    with pytest.raises(risk_context.RiskAssessmentPending):
        ch_transform.vulnerabilities_to_rows({"tenant_id": a, "run_id": "risk-run", "job_id": "risk-job-" + a.removeprefix("risk-a-")}, members, settings=settings)
    pending = runs.get_vulnerabilities(settings, "risk-run", tenant_id=a)
    assert all(item.risk_assessment["mode"] == "pending-current" and not item.risk_assessment["complete"] for item in pending)
    _register(settings, a)
    rows = ch_transform.vulnerabilities_to_rows({"tenant_id": a, "run_id": "risk-run", "job_id": "risk-job-" + a.removeprefix("risk-a-")}, members, settings=settings)
    assert rows and all(json.loads(row[11])["risk_assessment"]["mode"] == "historical" for row in rows)


def test_fixed_operation_clock_and_intelligence_content_version():
    scorer = risk_scoring.RiskScoring(epss={"CVE-2020-2": .01})
    entries = [{"host": "8.8.8.8", "cve": "CVE-2020-2", "cvss": 8.0, "cve_published": "2020-01-01T00:00:00Z", "in_kev": True}]
    kwargs = dict(context=risk_context.BatchContext("a", {}, {}, None, False), fingerprint=None, now=NOW, mode="current")
    prior = risk_context.score_batch(entries, scorer=scorer, **kwargs)
    later = risk_context.score_batch(entries, scorer=scorer, **{**kwargs, "now": NOW + timedelta(days=365 * 5)})
    assert prior[0]["risk_assessment"]["evaluated_at"] != later[0]["risk_assessment"]["evaluated_at"]
    assert prior[0]["risk_assessment"]["data_version"] == later[0]["risk_assessment"]["data_version"]
    assert prior[0]["risk_explanation"] != later[0]["risk_explanation"]
    changed = risk_context.score_batch(entries, scorer=risk_scoring.RiskScoring(epss={"CVE-2020-2": .99}), **kwargs)
    assert changed[0]["risk_assessment"]["data_version"] != prior[0]["risk_assessment"]["data_version"]


@requires_postgres
def test_live_clickhouse_expands_existing_schema_and_preserves_full_receipt(estate, monkeypatch):
    import os
    from api.services import clickhouse_client as ch
    url = os.environ.get("OCTO_CLICKHOUSE_URL", "").strip()
    if not url:
        pytest.skip("OCTO_CLICKHOUSE_URL required for actual ClickHouse receipt roundtrip")
    settings, a, _, _, _, _, _, _, members = estate
    _register(settings, a)
    rows = ch_transform.vulnerabilities_to_rows({"tenant_id": a, "run_id": "risk-run", "job_id": "risk-job-" + a.removeprefix("risk-a-")}, members, settings=settings)
    # Only the CVE on an IPv4 host reaches the CVE-keyed analytics table: the
    # pulse exposure has no CVE (#565) and the third entry's host is a name.
    assert [row[2] for row in rows] == ["CVE-2020-10000"]
    table = "shapoclyack.risk_receipt_test_" + uuid.uuid4().hex[:12]
    client = ch.get_client(url)
    monkeypatch.setattr(ch, "VULN_TABLE", table)
    try:
        # Simulate an upgraded installation: all original columns, no receipt.
        client.command(f"""CREATE TABLE {table} (
            tenant_id UUID, asset_ip IPv4, cve_id String, base_cvss Float32,
            epss_score Float32, asset_criticality UInt8, exploit_active UInt8,
            cisa_decision Enum8('Track'=1,'Attend'=2,'Act'=3,'Immediate'=4),
            contextual_score Float32, scoring_model_version String, timestamp DateTime
        ) ENGINE=MergeTree ORDER BY (tenant_id,asset_ip,cve_id)""")
        with pytest.raises(ch.ClickHouseError, match="migrate-clickhouse-risk-context.sql"):
            ch.insert_rows(client, table, ch.VULN_COLUMNS, rows)
        # Expansion is an explicit administrator action, not a runtime grant.
        client.command(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS risk_assessment String DEFAULT ''")
        assert ch.insert_rows(client, table, ch.VULN_COLUMNS, rows) == 1
        loaded = client.query(f"SELECT cve_id,risk_assessment FROM {table} ORDER BY cve_id").result_rows
        assert {cve: json.loads(receipt) for cve, receipt in loaded} == {row[2]: json.loads(row[11]) for row in rows}
        # Actual SELECT+INSERT-only user, with no ALTER/CREATE privileges.
        from urllib.parse import urlsplit, urlunsplit
        restricted_user = "risk_ingest_" + uuid.uuid4().hex[:12]
        password = uuid.uuid4().hex
        client.command(f"CREATE USER {restricted_user} IDENTIFIED BY '{password}'")
        try:
            client.command(f"GRANT SELECT,INSERT ON {table} TO {restricted_user}")
            parts = urlsplit(url)
            restricted_url = urlunsplit((parts.scheme, f"{restricted_user}:{password}@{parts.hostname}:{parts.port}", parts.path, "", ""))
            restricted = ch.get_client(restricted_url)
            try:
                grants = restricted.query("SHOW GRANTS").result_rows
                assert all("ALTER" not in grant[0] for grant in grants)
                assert ch.insert_rows(restricted, table, ch.VULN_COLUMNS, rows) == 1
                assert restricted.query(f"SELECT count() FROM {table}").result_rows[0][0] == 2
            finally:
                restricted.close()
        finally:
            client.command(f"DROP USER IF EXISTS {restricted_user}")
    finally:
        client.command(f"DROP TABLE IF EXISTS {table}")
        client.close()


@requires_postgres
def test_legacy_job_and_untrusted_contract_flags_do_not_create_capture_obligation(estate):
    settings, a, b, _, _, _, _, _, members = estate
    # An old managed Job exists. A NULL legacy publication adds no obligation.
    with get_session(POSTGRES_URL) as session:
        session.execute(delete(models.RunPublication).where(models.RunPublication.tenant_id == a))
        session.add(models.RunPublication(publication_id="legacy-risk-" + a, tenant_id=a, job_id="legacy", run_id="risk-run", job_status="succeeded", created_at=NOW, updated_at=NOW))
        session.add(models.RunPublication(publication_id="foreign-risk-" + b, tenant_id=b, job_id="foreign", run_id="risk-run", job_status="succeeded", risk_assessment_contract=risk_context.CONTEXT_VERSION, created_at=NOW, updated_at=NOW))
    members["risk_assessment.json"] = json.dumps({"mode": "historical", "asset_criticality": 4}).encode()
    payload = {"tenant_id": a, "run_id": "risk-run", "risk_assessment_contract": risk_context.CONTEXT_VERSION}
    rows = ch_transform.vulnerabilities_to_rows(payload, members, settings=settings)
    assert all(json.loads(row[11])["risk_assessment"]["mode"] == "legacy-current" for row in rows)
    assert all(row[5] == 0 for row in rows)


@requires_postgres
def test_receipt_obligation_is_scoped_to_the_named_execution(estate):
    settings, a, *_ = estate
    with get_session(POSTGRES_URL) as session:
        session.add(models.RunPublication(publication_id="other-risk-" + a, tenant_id=a,
            job_id="other-job", run_id="risk-run", job_status="succeeded",
            risk_assessment_contract=risk_context.CONTEXT_VERSION, created_at=NOW, updated_at=NOW))
    _register(settings, a)  # captures the receipt of risk-pub-<a>
    with get_session(POSTGRES_URL) as session:
        # Each execution's obligation comes from its own rows: an execution
        # with none owes no receipt, though its siblings on the run do.
        assert risk_context.receipt_required(session, tenant_id=a, run_id="risk-run",
            execution_id="publication:risk-pub-" + a)
        assert risk_context.receipt_required(session, tenant_id=a, run_id="risk-run",
            execution_id="publication:other-risk-" + a)
        assert not risk_context.receipt_required(session, tenant_id=a, run_id="risk-run",
            execution_id="publication:never-published-" + a)


@requires_postgres
def test_publication_cannot_forget_new_receipt_after_failed_projection(estate, monkeypatch):
    from contextlib import nullcontext
    from api.services import run_publisher
    settings, a, _, _, _, _, _, _, _ = estate
    publication = models.RunPublication(publication_id="obligated-risk-" + a, tenant_id=a,
        job_id="test-obligation", run_id="risk-run", job_status="succeeded",
        risk_assessment_contract=risk_context.CONTEXT_VERSION, created_at=NOW, updated_at=NOW)
    with get_session(POSTGRES_URL) as session:
        session.add(publication)
    calls = []
    monkeypatch.setattr(run_publisher, "_Lease", lambda *_: nullcontext())
    monkeypatch.setattr(run_publisher, "_publish", lambda *_: calls.append("bus"))
    monkeypatch.setattr(run_publisher, "_project", lambda *_: calls.append("project-failed"))
    monkeypatch.setattr(run_publisher, "_record_failure", lambda *args, **kwargs: calls.append("retry"))
    monkeypatch.setattr(run_publisher, "_record_success", lambda *_: calls.append("success"))
    assert run_publisher._attempt(settings, publication) is False
    assert calls == ["bus", "project-failed", "retry"]
    # Actual fold makes its immutable receipt; retry may now close safely.
    _register(settings, a, publication.publication_id)
    calls.clear()
    assert run_publisher._attempt(settings, publication) is True
    assert calls == ["bus", "project-failed", "success"]


@requires_postgres
def test_new_successful_empty_run_captures_empty_receipt(estate):
    settings, a, _, _, _, _, _, _, _ = estate
    directory = runs.get_run_dir(settings, "risk-run", tenant_id=a)
    (directory / "vulnerabilities.json").write_text("[]")
    stats = _register(settings, a)
    assert stats.findings_seen == stats.created == 0
    with get_session(POSTGRES_URL) as session:
        snapshot = session.scalars(select(models.RunRiskAssessment).where(models.RunRiskAssessment.tenant_id == a)).one()
        assert snapshot.scores == []


@requires_postgres
def test_successful_outbox_close_retains_obligation_for_missing_or_changed_receipt(estate):
    from types import SimpleNamespace
    from api.services import run_publisher
    settings, a, _, _, _, entries, fp, _, members = estate
    with get_session(POSTGRES_URL) as session:
        job = session.scalars(select(models.Job).where(models.Job.tenant_id == a, models.Job.run_id == "risk-run")).one()
        publication_id = "durable-risk-" + a
        session.add(models.RunPublication(publication_id=publication_id, tenant_id=a, job_id=job.job_id,
            run_id="risk-run", job_status="succeeded", risk_assessment_contract=risk_context.CONTEXT_VERSION,
            created_at=NOW, updated_at=NOW))
    _register(settings, a, publication_id)
    # Actual close-out transaction deletes outbox and persists exact job binding.
    publication = SimpleNamespace(publication_id=publication_id, archive_path=None, attempts=0)
    run_publisher._record_success(settings, publication)
    with get_session(POSTGRES_URL) as session:
        assert session.get(models.RunPublication, publication_id) is None
        job = session.scalars(select(models.Job).where(models.Job.tenant_id == a)).one()
        assert job.risk_assessment_contract == risk_context.CONTEXT_VERSION
    changed = {**members, "vulnerabilities.json": json.dumps([{**entries[0], "cvss": 9.0}]).encode()}
    with pytest.raises(risk_context.RiskAssessmentPending):
        ch_transform.vulnerabilities_to_rows({"tenant_id": a, "run_id": "risk-run", "job_id": "risk-job-" + a.removeprefix("risk-a-")}, changed, settings=settings)
    with get_session(POSTGRES_URL) as session:
        session.execute(delete(models.RunRiskAssessment).where(models.RunRiskAssessment.tenant_id == a))
    with pytest.raises(risk_context.RiskAssessmentPending):
        ch_transform.vulnerabilities_to_rows({"tenant_id": a, "run_id": "risk-run", "job_id": "risk-job-" + a.removeprefix("risk-a-")}, members, settings=settings)
    pending = runs.get_vulnerabilities(settings, "risk-run", tenant_id=a)
    assert all(item.risk_assessment["mode"] == "pending-current" for item in pending)


@requires_postgres
def test_endpoint_software_adapter_keeps_local_evidence_and_needs_real_foothold(estate):
    settings, a, _, asset, _, _, fp, scorer, _ = estate
    local = {"asset_id": asset, "host": "app.example.test", "cve": "CVE-2020-10000",
        "source": "endpoint_software", "finding_class": "version_cve", "cvss": 8.0,
        "cvss4_vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}
    with get_session(POSTGRES_URL) as session:
        session.get(models.Asset, asset).exposure_level = None
        isolated = risk_context.load_batch(session, tenant_id=a, run_id="legacy", entries=[local])
        one = risk_context.score_batch([local], context=isolated, fingerprint=fp, scorer=scorer, now=NOW, mode="current")[0]
        assert one["attack_path"] is None
        assert one["cdn_waf"] == []  # another endpoint's WAF is not a local package control
        foothold = {"host": "10.42.0.1", "port": "443", "script_id": "pulse:entry", "finding_class": "exposure"}
        context = risk_context.load_batch(session, tenant_id=a, run_id="legacy", entries=[local, foothold])
        linked = risk_context.score_batch([local, foothold], context=context, fingerprint=fp, scorer=scorer, now=NOW, mode="current")[0]
        assert linked["attack_path"] == "same-asset"
        assert local["source"] == "endpoint_software"  # adapter does not rewrite proofs
        assert linked["risk_assessment"]["inputs"]["asset_id"] == asset


@requires_postgres
def test_two_jobs_reusing_run_and_identical_bytes_capture_separate_risk_and_exact_views(estate, monkeypatch):
    settings, a, _, asset, _, entries, fp, _, members = estate
    first_job = "risk-job-" + a.removeprefix("risk-a-")
    first_pub = "risk-pub-" + a
    with get_session(POSTGRES_URL) as session:
        session.get(models.Asset, asset).exposure_level = None
    _register(settings, a)
    old_api = runs.get_vulnerabilities(settings, "risk-run", tenant_id=a)
    old_rows = ch_transform.vulnerabilities_to_rows({"tenant_id": a, "run_id": "risk-run", "job_id": first_job}, members, settings=settings)
    with get_session(POSTGRES_URL) as session:
        tracked = session.scalars(select(models.Vulnerability).where(models.Vulnerability.tenant_id == a)).first()
        tracked.assignee, tracked.owner_team = "operator-owner", "payments"
        due = tracked.due_at
        session.get(models.Asset, asset).asset_criticality = 4
        session.add(models.Job(job_id="job-b-" + a, tenant_id=a, run_id="risk-run", queued_at=NOW + timedelta(days=1), status="succeeded", scan_options={"surface": "internal", "surface_source": "operator"}))
        session.add(models.RunPublication(publication_id="pub-b-" + a, tenant_id=a, job_id="job-b-" + a, run_id="risk-run", job_status="succeeded", risk_assessment_contract=risk_context.CONTEXT_VERSION, created_at=NOW + timedelta(days=1), updated_at=NOW + timedelta(days=1)))
    monkeypatch.setattr(vulnerabilities, "_now", lambda: (NOW + timedelta(days=1)).replace(tzinfo=None))
    _register(settings, a, "pub-b-" + a)
    new_api = runs.get_vulnerabilities(settings, "risk-run", tenant_id=a)
    new_rows = ch_transform.vulnerabilities_to_rows({"tenant_id": a, "run_id": "risk-run", "job_id": "job-b-" + a}, members, settings=settings)
    assert all(item.asset_criticality == 0 and item.risk_assessment["inputs"]["declared_surface"] == "external" for item in old_api)
    assert next(item for item in old_api if item.host == "APP.EXAMPLE.TEST").network_exposure == "external"
    assert all(item.asset_criticality == 4 and item.network_exposure == "internal" for item in new_api)
    assert all(item.risk_assessment["execution_id"] == "publication:pub-b-" + a for item in new_api)
    assert {item.risk_assessment["evaluated_at"] for item in old_api} != {item.risk_assessment["evaluated_at"] for item in new_api}
    assert old_rows == ch_transform.vulnerabilities_to_rows({"tenant_id": a, "run_id": "risk-run", "job_id": first_job}, members, settings=settings)
    for rows, api in ((old_rows, old_api), (new_rows, new_api)):
        by_cve = {item.cve or item.script_id: item for item in api}
        for row in rows:
            assert json.loads(row[11])["risk_assessment"] == by_cve[row[2]].risk_assessment
            assert row[8] == by_cve[row[2]].contextual_score
    # Folder points back to A (a delayed publish), regardless of newest Job time.
    directory = runs.get_run_dir(settings, "risk-run", tenant_id=a)
    runs.stage_run_tenant(directory, a, job_id=first_job, publication_id=first_pub)
    assert [item.model_dump() for item in runs.get_vulnerabilities(settings, "risk-run", tenant_id=a)] == [item.model_dump() for item in old_api]
    with get_session(POSTGRES_URL) as session:
        snapshots = session.scalars(select(models.RunRiskAssessment).where(models.RunRiskAssessment.tenant_id == a)).all()
        assert len(snapshots) == 2 and {row.execution_id for row in snapshots} == {"publication:" + first_pub, "publication:pub-b-" + a}
        tracked = session.scalars(select(models.Vulnerability).where(models.Vulnerability.tenant_id == a, models.Vulnerability.assignee == "operator-owner")).one()
        assert tracked.risk_assessment["asset_criticality"] == 4
        assert tracked.due_at == due and tracked.owner_team == "payments"
    # A captured old execution remains complete even after folder replacement.
    with get_session(POSTGRES_URL) as session:
        old_publication = session.get(models.RunPublication, first_pub)
    runs.stage_run_tenant(directory, a, job_id="job-b-" + a, publication_id="pub-b-" + a)
    risk_context.ensure_publication_receipt(settings, old_publication)
    # An uncaptured older intent must not consume B's folder under its own key.
    with get_session(POSTGRES_URL) as session:
        session.add(models.RunPublication(publication_id="uncaptured-old-" + a, tenant_id=a, job_id=first_job,
            run_id="risk-run", job_status="succeeded", risk_assessment_contract=risk_context.CONTEXT_VERSION,
            created_at=NOW, updated_at=NOW))
    with pytest.raises(risk_context.RiskAssessmentPending, match="generation"):
        vulnerabilities.register_findings_from_run(settings, tenant_id=a, run_id="risk-run", publication_id="uncaptured-old-" + a)
    with get_session(POSTGRES_URL) as session:
        assert session.scalars(select(models.RunRiskAssessment).where(models.RunRiskAssessment.execution_id == "publication:uncaptured-old-" + a)).all() == []
        assert session.get(models.RunPublication, "uncaptured-old-" + a).projected == []
