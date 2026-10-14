"""Production consumer compatibility, provenance and conservative closure."""
import copy
import hashlib
import itertools
import json

import pytest

from scanner.pipeline.production_evidence import attach_raw, closure_gaps, combine, merge, scoped
from scanner.pipeline.report import build_reports
from tests.conftest import requires_postgres

BASE = dict(host='10.0.0.5', port='443', cve='CVE-2024-0001', severity='high', cvss=7.5,
            source='pulse', script_id='pulse:local', protocol='tcp')


def rows():
    return [{**BASE, 'observed_at': '2026-10-01T00:00:00Z', 'confidence': 90},
            {**BASE, 'source': 'nuclei', 'script_id': 'nuclei:test', 'severity': 'low',
             'observed_at': '2026-10-02T00:00:00Z', 'confidence': 10}]


def test_permutation_replay_retains_latest_cohort_and_conflicts():
    original = rows()
    untouched = copy.deepcopy(original)
    for permutation in itertools.permutations(original):
        result = combine(list(permutation) * 2)
        assert len(result) == 1
        assert result[0]['severity'] == 'low'
        evidence = result[0]['finding_evidence']
        assert evidence['observation_count'] == 2
        assert evidence['finding_count'] == 1
        group = evidence['findings'][0]
        assert group['assessment']['latest_observed_at'].startswith('2026-10-02')
        assert group['assessment']['differing_fields'] == ['confidence', 'severity']
    assert original == untouched


@pytest.mark.parametrize('change', [{'protocol': 'udp'}, {'protocol': 'unknown'},
    {'sni': 'a.example'}, {'affected_object': 'a'}, {'matched_at': 'https://10.0.0.5/a'}])
def test_legacy_task_is_not_a_precise_subject_equivalence(change):
    result = combine([BASE, {**BASE, **change}])
    assert len(result) == 1
    assert result[0]['finding_evidence']['finding_count'] == 2


def test_authenticated_scope_replaces_uploaded_tenant_run_and_ids():
    source = combine(rows())[0]['finding_evidence']
    a = scoped(source, tenant_id='tenant-a', run_id='run-a')
    b = scoped(source, tenant_id='tenant-b', run_id='run-b')
    assert a['findings'][0]['evidence_id'] != b['findings'][0]['evidence_id']
    for item in a['findings'][0]['observations']:
        assert (item['tenant_id'], item['run_id']) == ('tenant-a', 'run-a')
    tampered = copy.deepcopy(source)
    tampered['findings'][0]['observations'][0]['severity'] = 'critical'
    invalid = scoped(tampered, tenant_id='tenant-a', run_id='run-a')
    assert invalid['projection_incomplete']
    assert closure_gaps(invalid)
    assert merge(a, a)['observation_count'] == 2
    assert merge(a, b)['finding_count'] == 2


def test_incomplete_and_object_evidence_cannot_close_by_legacy_endpoint_coverage():
    evidence = combine([BASE])[0]['finding_evidence']
    assert closure_gaps(evidence) == []
    assert closure_gaps(None) == []  # old artifacts keep #451 checks
    evidence['projection_incomplete'] = True
    assert closure_gaps(evidence)[0]['reason'] == 'evidence_incomplete'
    precise = combine([{**BASE, 'matched_at': 'https://10.0.0.5/a'}])[0]['finding_evidence']
    assert closure_gaps(precise)[0]['reason'] == 'precise_subject_coverage_unproven'


def test_report_references_exact_source_bytes_and_raw_object_observations(tmp_path):
    raw = {'host': '10.0.0.5', 'port': '443', 'matched-at': 'https://10.0.0.5/a',
           'template-id': 'test', 'matcher-name': 'body', 'type': 'http',
           'timestamp': '2026-10-03T00:00:00Z', 'info': {'severity': 'medium',
           'classification': {'cve-id': ['CVE-2024-0001']}}, 'response': 'secret body'}
    (tmp_path / 'nuclei_raw.jsonl').write_text(json.dumps(raw) + '\n')
    build_reports(tmp_path, 1, ['10.0.0.5'], [], tmp_path / 'nmap', False, False, False, True,
                  extra_vulnerabilities=rows(), cvss4_enabled=False, geoip_enabled=False, asn_enabled=False)
    exported = json.loads((tmp_path / 'vulnerabilities.json').read_text())
    assert len(exported) == 1
    evidence = exported[0]['finding_evidence']
    assert evidence['observation_count'] == 3
    assert evidence['finding_count'] == 2
    source_sha = hashlib.sha256((tmp_path / 'report_sources.json').read_bytes()).hexdigest()
    observations = [o for g in evidence['findings'] for o in g['observations']]
    assert all(o['artifact_refs'][0]['sha256'] == source_sha for o in observations if o['artifact_refs'][0]['path'] == 'report_sources.json')
    raw_sha = hashlib.sha256((tmp_path / 'nuclei_raw.jsonl').read_bytes()).hexdigest()
    assert any(o['artifact_refs'] == [{'path': 'nuclei_raw.jsonl', 'sha256': raw_sha, 'locator': 'line:1'}] for o in observations)
    assert 'secret body' not in json.dumps(evidence)


@requires_postgres
def test_tracker_api_analytics_keep_one_task_preserve_workflow_and_history(tmp_path):
    from tests.test_vuln_lifecycle import _seed, _write_run, _HOSTS
    from api.services import vulnerabilities as vulns, runs, ch_transform
    from api.db.engine import get_session
    from api.db import models
    from sqlalchemy import select

    settings, tenant = _seed(tmp_path, findings=combine(rows()))
    vulns.register_findings_from_run(settings, tenant_id=tenant, run_id='run-1')
    items, total = vulns.list_vulnerabilities(settings, tenant_id=tenant)
    assert total == 1
    old = items[0]
    with get_session(settings.postgres_url) as session:
        row = session.scalar(select(models.Vulnerability).where(models.Vulnerability.vuln_id == old['vuln_id']))
        row.assignee = 'human@example.com'
        row.owner_team = 'security'
    later = combine([{**BASE, 'severity': 'low', 'observed_at': '2026-10-04T00:00:00Z'}])
    _write_run(settings.output_dir, 'run-2', _HOSTS, later)
    vulns.register_findings_from_run(settings, tenant_id=tenant, run_id='run-2')
    items, total = vulns.list_vulnerabilities(settings, tenant_id=tenant)
    current = items[0]
    assert total == 1
    assert current['finding_key'] == old['finding_key']
    assert current['due_at'] == old['due_at']
    assert current['assignee'] == 'human@example.com'
    assert current['owner_team'] == 'security'
    assert current['finding_evidence']['observation_count'] == 3
    api_rows = runs.get_vulnerabilities(settings, 'run-2', tenant_id=tenant)
    assert len(api_rows) == 1
    assert api_rows[0].finding_evidence['observation_count'] == 1
    assert api_rows[0].finding_evidence['findings'][0]['identity']['tenant_id'] == tenant
    members = {'vulnerabilities.json': json.dumps(later).encode()}
    ch_rows = ch_transform.vulnerabilities_to_rows({'tenant_id': tenant, 'run_id': 'run-2'}, members, settings=settings, require_captured=False)
    assert len(ch_rows) == 1
    assert json.loads(ch_rows[0][-1])['finding_evidence']['observation_count'] == 1


def test_invalid_provided_evidence_differs_from_legacy_absence():
    assert scoped(None, tenant_id='t', run_id='r') is None
    for invalid in ('garbage', {'projection_incomplete': False}, {'findings': [{'observations': [{}]}]}):
        assert closure_gaps(scoped(invalid, tenant_id='t', run_id='r'))


def test_bounded_history_explicitly_blocks_negative_coverage(monkeypatch):
    import scanner.pipeline.production_evidence as pe
    monkeypatch.setattr(pe, 'MAX_HISTORY_OBSERVATIONS', 1)
    current = scoped(combine(rows())[0]['finding_evidence'], tenant_id='t', run_id='r')
    assert current['projection_incomplete']
    a = scoped(combine([BASE])[0]['finding_evidence'], tenant_id='t', run_id='a')
    b = scoped(combine([BASE])[0]['finding_evidence'], tenant_id='t', run_id='b')
    bounded = merge(a, b)
    assert bounded['observation_count'] == 1
    assert closure_gaps(bounded)
    corrupted = merge({'findings': [{'observations': [{}]}]}, a)
    assert corrupted['observation_count'] == 1
    assert closure_gaps(corrupted)


def test_actual_pinned_nuclei_capture_projects_into_production(tmp_path):
    from pathlib import Path
    from scanner.pipeline.evidence_artifacts import EvidenceReader
    capture = Path('tests/fixtures/finding_evidence/nuclei_v3_11_1/loopback.jsonl').read_bytes()
    (tmp_path / 'nuclei_raw.jsonl').write_bytes(capture)
    projection = EvidenceReader(tmp_path, 'unpublished', 'unpublished').build()
    assert projection['observation_count'] == 1
    observed = projection['findings'][0]['observations'][0]
    assert observed['cve'] == 'CVE-2099-9999'
    task = combine([{'host': observed['subject']['host'], 'port': observed['subject']['port'],
                     'cve': observed['cve'], 'source': 'nuclei', 'script_id': 'nuclei:local-fixture-cve'}])
    attach_raw(task, projection)
    assert task[0]['finding_evidence']['observation_count'] == 2
    assert task[0]['finding_evidence']['finding_count'] == 2
    assert closure_gaps(task[0]['finding_evidence'])


def test_new_raw_source_artifacts_keep_operator_download_guard():
    from api.services.runs import is_restricted_artifact
    assert is_restricted_artifact('report_sources.json')
    assert is_restricted_artifact('finding_evidence.json')
