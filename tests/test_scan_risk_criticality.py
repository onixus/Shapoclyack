"""Scan fold uses operator criticality without changing lifecycle identity (#453).

SQLite exercises the real ORM/scorer/fold on the infrastructure-free PR gate;
Postgres concurrency and the shared run/ClickHouse context remain separate work.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest
from sqlalchemy import event, select

from api.db import engine as db_engine
from api.db import models
from api.db.engine import get_session
from api.services import assets, risk_scoring, tenants, vuln_states
from api.services import vulnerabilities as vulns
from tests.conftest import make_settings


NOW = datetime(2026, 9, 29, 12)
HOST = "10.0.0.5"
FINDING = {
    "host": HOST,
    "port": "443",
    "cve": "CVE-2026-99999",
    "cvss": 5.0,
    "severity": "medium",
    "in_kev": True,
}


def _write_run(settings, run_id, finding=None):
    directory = settings.output_dir / "runs" / run_id
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "alive_hosts.json").write_text(
        json.dumps([{"host": HOST, "hostname": "app.example.test"}]), encoding="utf-8"
    )
    (directory / "vulnerabilities.json").write_text(
        json.dumps([FINDING if finding is None else finding]), encoding="utf-8"
    )


@pytest.fixture
def context(tmp_path, monkeypatch):
    db_engine.reset_for_tests()
    settings = make_settings(tmp_path, postgres_url=f"sqlite:///{tmp_path / 'risk.db'}")
    settings.output_dir.mkdir(parents=True)
    settings.state_dir.mkdir(parents=True)
    tenants.configure(settings)
    tenants.load_tenants(settings)
    tenant_id = tenants.DEFAULT_TENANT_ID
    scorer = risk_scoring.RiskScoring()
    score = scorer.score_vulnerability
    spy = Mock(wraps=score)
    monkeypatch.setattr(scorer, "score_vulnerability", spy)
    monkeypatch.setattr(vulns, "get_scorer", lambda: scorer)
    monkeypatch.setattr(vulns, "_now", lambda: NOW)
    monkeypatch.setattr(risk_scoring, "resolve_cve_age", lambda **_: (1.0, "fixture"))
    _write_run(settings, "first")
    assets.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="first")
    with get_session(settings.postgres_url) as session:
        asset = vulns._asset_for_finding(session, tenant_id=tenant_id, host=HOST)
        assert asset is not None
        asset.exposure_level = "internet"
        asset_id = asset.asset_id
    try:
        yield settings, tenant_id, asset_id, score, spy
    finally:
        db_engine.reset_for_tests()


def _criticality(context, value):
    settings, _, asset_id, _, _ = context
    with get_session(settings.postgres_url) as session:
        session.get(models.Asset, asset_id).asset_criticality = value


def _register(context, run_id="first"):
    settings, tenant_id, _, _, _ = context
    stats = vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id=run_id)
    with get_session(settings.postgres_url) as session:
        rows = session.scalars(
            select(models.Vulnerability).where(models.Vulnerability.tenant_id == tenant_id)
        ).all()
        assert len(rows) == 1
        return stats, vulns._to_dict(rows[0], now=NOW)


def _expected(context, value, finding=FINDING):
    return context[3](finding, asset_criticality_override=value, operator_exposure="internet")


@pytest.mark.parametrize("criticality", [None, 0, 1, 2, 3, 4])
def test_scan_fold_uses_asset_criticality_in_the_persisted_score(context, criticality):
    _criticality(context, criticality)
    stats, row = _register(context)
    expected = _expected(context, criticality)
    assert context[4].call_args.kwargs["asset_criticality_override"] == criticality
    assert row["contextual_score"] == expected["contextual_score"]
    assert row["risk_level"] == expected["risk_level"]
    assert stats.created == 1 and stats.reopened == 0
    assert row["machine_verified"] is False
    origin = "heuristic" if criticality is None else "operator-set"
    assert f"({origin})" in expected["risk_explanation"]


def test_zero_operator_criticality_beats_a_finding_supplied_value(context):
    settings = context[0]
    finding = {**FINDING, "asset_criticality": 4}
    _write_run(settings, "first", finding)
    _criticality(context, 0)
    _, row = _register(context)
    assert context[4].call_args.kwargs["asset_criticality_override"] == 0
    assert row["contextual_score"] == _expected(context, 0, finding)["contextual_score"]
    assert row["contextual_score"] < _expected(context, 4, finding)["contextual_score"]


PRESERVED = (
    "vuln_id", "finding_key", "asset_id", "tenant_id", "state", "state_changed_at",
    "state_changed_by", "assignee", "owner_team", "due_at", "sla_started_at",
    "sla_days", "sla_source", "first_seen_at", "first_seen_run_id", "reopen_count",
    "exception_state", "exception_until", "exception_reason", "exception_by",
    "ticket_system", "ticket_key", "ticket_url", "machine_verified",
)


@pytest.mark.parametrize("before,after", [(0, 4), (4, 0)])
def test_reobservation_updates_risk_but_preserves_identity_sla_and_decisions(context, before, after):
    settings, tenant_id, _, _, _ = context
    _criticality(context, before)
    _, original = _register(context)
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Vulnerability, original["vuln_id"])
        row.state = vuln_states.PLANNED
        row.state_changed_by = "analyst"
        row.assignee = "owner@example.test"
        row.owner_team = "payments"
        row.ticket_system, row.ticket_key = "jira", "SEC-453"
        row.ticket_url = "https://tickets.example.test/browse/SEC-453"
        row.exception_state = vuln_states.EXCEPTION_APPROVED
        row.exception_until = NOW + timedelta(days=180)
        row.exception_reason, row.exception_by = "Compensating control", "approver"
        original = vulns._to_dict(row, now=NOW)
    _criticality(context, after)
    _write_run(settings, "second")
    stats, updated = _register(context, "second")
    assert stats.created == stats.reopened == 0 and stats.reobserved == 1
    assert {key: updated[key] for key in PRESERVED} == {key: original[key] for key in PRESERVED}
    assert updated["contextual_score"] == _expected(context, after)["contextual_score"]
    assert updated["contextual_score"] != original["contextual_score"]
    assert updated["last_seen_run_id"] == "second"
    assert updated["observation_count"] == original["observation_count"] + 1
    with get_session(settings.postgres_url) as session:
        kinds = session.scalars(select(models.VulnerabilityEvent.kind).where(
            models.VulnerabilityEvent.tenant_id == tenant_id,
            models.VulnerabilityEvent.vuln_id == original["vuln_id"],
        )).all()
        assert kinds == ["observed", "observed"]


def test_criticality_only_change_does_not_break_false_positive_suppression(context):
    settings = context[0]
    _criticality(context, 0)
    _, original = _register(context)
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Vulnerability, original["vuln_id"])
        row.state = vuln_states.CLOSED
        row.closure_reason = "false_positive"
        row.closed_at = NOW
        row.fp_suppress_until = NOW + timedelta(days=90)
        row.fp_reason = "Reviewed evidence"
        row.fp_marked_by = "analyst"
        row.fp_marked_at = NOW
        row.fp_evidence = {"note": "Local fixture"}
        original = vulns._to_dict(row, now=NOW)
    _criticality(context, 4)
    _write_run(settings, "second")
    stats, updated = _register(context, "second")
    assert stats.fp_suppressed == 1 and stats.fp_overridden == stats.reopened == 0
    for key in (*PRESERVED, "closure_reason", "closed_at", "fp_reason", "fp_marked_by",
                "fp_marked_at", "fp_evidence", "fp_suppress_until"):
        assert updated[key] == original[key]
    assert updated["contextual_score"] > original["contextual_score"]
    assert updated["fp_observations"] == original["fp_observations"] + 1


def test_criticality_change_does_not_add_a_context_query(context):
    settings = context[0]
    _criticality(context, 0)
    _register(context)
    engine = db_engine.get_engine(settings.postgres_url)
    statements = []

    def record(_connection, _cursor, statement, _parameters, _execution_context, _many):
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    try:
        queries = []
        for run_id, criticality in [("second", 0), ("third", 4)]:
            _criticality(context, criticality)
            _write_run(settings, run_id)
            statements.clear()
            _register(context, run_id)
            queries.append(list(statements))
        assert queries[0] and queries[0] == queries[1]
        assert context[4].call_args.kwargs["asset_criticality_override"] == 4
    finally:
        event.remove(engine, "before_cursor_execute", record)
