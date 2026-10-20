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
    assert task[0]['finding_evidence']['observation_count'] == 1
    assert task[0]['finding_evidence']['finding_count'] == 1
    refs = task[0]['finding_evidence']['findings'][0]['observations'][0]['artifact_refs']
    assert {ref['path'] for ref in refs} == {'report_sources.json', 'nuclei_raw.jsonl'}
    assert closure_gaps(task[0]['finding_evidence'])


def test_new_raw_source_artifacts_keep_operator_download_guard():
    from api.services.runs import is_restricted_artifact
    assert is_restricted_artifact('report_sources.json')
    assert is_restricted_artifact('finding_evidence.json')


@pytest.mark.parametrize('mutation', [
    {'source': 'x' * 10000}, {'preview': 'password: visible_secret'},
    {'unexpected': {'request_body': 'RAW_SECRET'}}, {'confidence': {'malformed': 'dict'}},
    {'requires_confirmation': 'no'}, {'observed_at': 'not-a-date'},
    {'subject': {'host': '10.0.0.5', 'port': 80, 'protocol': 'unknown',
        'scheme': 'https', 'authority': 'user:password@evil.example:443', 'sni': None, 'object_id': 'raw_secret_path'}},
    {'artifact_refs': [{'path': 'raw.json', 'sha256': 'a' * 64, 'locator': str(i)} for i in range(10000)]},
])
def test_self_consistent_uploaded_hash_does_not_authorize_unsafe_fields(mutation):
    from scanner.pipeline.finding_evidence import digest
    original = combine([BASE])[0]['finding_evidence']
    item = original['findings'][0]['observations'][0]
    item.update(mutation)
    item['observation_id'] = 'obs:' + digest({k: v for k, v in item.items() if k not in {'observation_id', 'artifact_refs', 'artifact_refs_truncated'}})
    result = scoped(original, tenant_id='t', run_id='r')
    assert result['projection_incomplete']
    assert closure_gaps(result)
    assert not result['findings']
    assert 'visible_secret' not in json.dumps(result)
    assert 'RAW_SECRET' not in json.dumps(result)


def test_raw_representation_deduplication_preserves_conflicting_subjects_and_times(tmp_path):
    from scanner.pipeline.evidence_artifacts import EvidenceReader
    raw = {'host': '10.0.0.5', 'port': 443, 'template-id': 'test', 'type': 'http',
           'matched-at': 'https://10.0.0.5/a', 'timestamp': '2026-10-03T00:00:00Z',
           'info': {'classification': {'cve-id': ['CVE-2024-0001']}}}
    (tmp_path / 'nuclei_raw.jsonl').write_text(json.dumps(raw) + '\n')
    projection = EvidenceReader(tmp_path, 'unpublished', 'unpublished').build()
    baseline = {**BASE, 'source': 'nuclei', 'script_id': 'nuclei:test'}
    task = combine([baseline])
    attach_raw(task, projection)
    assert task[0]['finding_evidence']['observation_count'] == 1
    for conflict in ({'protocol': 'udp'}, {'sni': 'other.example'},
                     {'observed_at': '2026-10-01T00:00:00Z'}, {'script_id': 'nuclei:other'}):
        task = combine([{**baseline, **conflict}])
        attach_raw(task, projection)
        assert task[0]['finding_evidence']['observation_count'] == 2


def _vhost_raw(name):
    return {'host': '10.0.0.5', 'port': '443', 'template-id': 'test', 'type': 'http',
            'matched-at': 'https://10.0.0.5/a', 'timestamp': '2026-10-03T00:00:00Z',
            'info': {'classification': {'cve-id': ['CVE-2024-0001']}},
            'shapoclyack_input': {'schema': 'octo.nuclei_input.v1', 'ip': '10.0.0.5',
                'port': 443, 'authority': name, 'sni': name}}


def test_invocation_owned_vhosts_same_ip_path_preserve_groups_and_counts(tmp_path):
    from scanner.pipeline.evidence_artifacts import EvidenceReader
    records = [_vhost_raw(name) for name in ('a.example', 'b.example')]
    (tmp_path / 'nuclei_raw.jsonl').write_text('\n'.join(json.dumps(r) for r in records) + '\n')
    projection = EvidenceReader(tmp_path, 'unpublished', 'unpublished').build()
    assert projection['finding_count'] == projection['observation_count'] == 2
    subjects = [g['identity']['subject'] for g in projection['findings']]
    assert {s['host'] for s in subjects} == {'10.0.0.5'}
    assert {s['authority'] for s in subjects} == {'a.example:443', 'b.example:443'}
    assert {s['sni'] for s in subjects} == {'a.example', 'b.example'}
    assert len({s['object_id'] for s in subjects}) == 2
    task = combine([{**BASE, 'source': 'nuclei', 'script_id': 'nuclei:test'}])
    attach_raw(task, projection)
    assert len(task) == 1
    assert task[0]['finding_evidence']['observation_count'] == 2
    assert task[0]['finding_evidence']['finding_count'] == 2
    rebound = scoped(task[0]['finding_evidence'], tenant_id='authenticated', run_id='published')
    assert not rebound['projection_incomplete']
    assert rebound['finding_count'] == 2
    assert closure_gaps(rebound)


@pytest.mark.parametrize('binding_change', [
    {'ip': '10.0.0.6'}, {'ip': 'other.example'}, {'port': 8443}, {'port': True},
    {'authority': 'user:password@a.example'}, {'authority': 'https://a.example/a'},
    {'authority': 'a.example:8443'}, {'authority': 'a.example\nAuthorization: secret'},
    {'authority': 10}, {'sni': 'b.example'}, {'sni': 'password: exposed'},
    {'schema': 'unknown'}, {'unexpected': 'secret'},
])
def test_unbound_or_malformed_vhost_context_never_falls_back_to_collapsed_subject(tmp_path, binding_change):
    from scanner.pipeline.evidence_artifacts import EvidenceReader
    raw = _vhost_raw('a.example')
    raw['shapoclyack_input'].update(binding_change)
    (tmp_path / 'nuclei_raw.jsonl').write_text(json.dumps(raw) + '\n')
    projection = EvidenceReader(tmp_path, 't', 'r').build()
    assert projection['projection_incomplete']
    assert not projection['findings']


def test_explicit_http_authority_keeps_original_transport_subject_hashes():
    from scanner.pipeline.finding_evidence import subject
    row = {'host': 'https://10.0.0.5/a'}
    old = subject(row)
    same = subject({**row, 'http_authority': '10.0.0.5:443'})
    assert old == same
    vhost = subject({**row, 'http_authority': 'a.example', 'sni': 'a.example'})
    assert vhost['host'] == old['host']
    assert vhost['authority'] == 'a.example:443'
    assert vhost['object_id'] != old['object_id']


@requires_postgres
def test_cve_replay_and_out_of_order_publication_preserve_workflow(tmp_path):
    from tests.test_vuln_lifecycle import _seed, _write_run, _HOSTS
    from api.services import vulnerabilities as vulns, vuln_states

    latest = combine([{**BASE, 'observed_at': '2026-10-10T00:00:00Z', 'severity': 'medium'}])
    settings, tenant = _seed(tmp_path, findings=latest)
    vulns.register_findings_from_run(settings, tenant_id=tenant, run_id='run-1')
    original = vulns.list_vulnerabilities(settings, tenant_id=tenant)[0][0]
    closed = vulns.transition(settings, tenant_id=tenant, vuln_id=original['vuln_id'],
                              to_state=vuln_states.CLOSED, actor='admin')
    events_before = vulns.list_events(settings, tenant_id=tenant, vuln_id=original['vuln_id'])[1]
    assert vulns.register_findings_from_run(settings, tenant_id=tenant, run_id='run-1').reopened == 0
    replay = vulns.get_vulnerability(settings, tenant_id=tenant, vuln_id=original['vuln_id'])
    assert replay['state'] == vuln_states.CLOSED
    assert replay['observation_count'] == 1
    assert vulns.list_events(settings, tenant_id=tenant, vuln_id=original['vuln_id'])[1] == events_before

    historical = combine([{**BASE, 'observed_at': '2026-10-01T00:00:00Z', 'severity': 'critical'}])
    _write_run(settings.output_dir, 'old-run', _HOSTS, historical)
    stats = vulns.register_findings_from_run(settings, tenant_id=tenant, run_id='old-run')
    assert stats.reopened == 0
    current = vulns.get_vulnerability(settings, tenant_id=tenant, vuln_id=original['vuln_id'])
    for field in ('state', 'severity', 'last_seen_run_id', 'due_at', 'closed_at', 'finding_key'):
        assert current[field] == closed[field]
    assert current['observation_count'] == 2
    assert current['finding_evidence']['observation_count'] == 2
    assert current['detectors'] == closed['detectors']
    vulns.register_findings_from_run(settings, tenant_id=tenant, run_id='old-run')
    assert vulns.get_vulnerability(settings, tenant_id=tenant, vuln_id=original['vuln_id'])['observation_count'] == 2
    events, _ = vulns.list_events(settings, tenant_id=tenant, vuln_id=original['vuln_id'])
    assert sum(e['detail'].get('historical', False) for e in events) == 1

    # A genuinely later weaker positive may reopen; no strongest-forever rule.
    newer = combine([{**BASE, 'observed_at': '2026-10-11T00:00:00Z', 'severity': 'low'}])
    _write_run(settings.output_dir, 'new-run', _HOSTS, newer)
    assert vulns.register_findings_from_run(settings, tenant_id=tenant, run_id='new-run').reopened == 1
    current = vulns.get_vulnerability(settings, tenant_id=tenant, vuln_id=original['vuln_id'])
    assert current['severity'] == 'low'
    assert current['finding_evidence']['observation_count'] == 3


@pytest.mark.parametrize('change', [{'protocol': 'udp'}, {'sni': 'new.example'},
                                  {'affected_object': 'new'}, {'observed_at': None}])
def test_historical_publication_requires_same_known_subject_and_time(change):
    from scanner.pipeline.production_evidence import publication_disposition
    prior = scoped(combine([{**BASE, 'observed_at': '2026-10-10T00:00:00Z'}])[0]['finding_evidence'],
                   tenant_id='t', run_id='current')
    incoming = scoped(combine([{**BASE, 'observed_at': '2026-10-01T00:00:00Z', **change}])[0]['finding_evidence'],
                      tenant_id='t', run_id='incoming')
    assert publication_disposition(prior, incoming) == 'current'


@requires_postgres
def test_captured_nuclei_report_reaches_consumers_without_changing_legacy_workflow(tmp_path):
    from pathlib import Path
    from datetime import UTC, datetime, timedelta
    from tests.test_vuln_lifecycle import _seed, _write_run
    from api.services import vulnerabilities as vulns, runs, ch_transform, assets

    raw_dir = tmp_path / 'captured'
    raw_dir.mkdir()
    capture = Path('tests/fixtures/finding_evidence/nuclei_v3_11_1/loopback.jsonl').read_bytes()
    raw_record = json.loads(capture)
    (raw_dir / 'nuclei_raw.jsonl').write_bytes(capture)
    host, port = raw_record['ip'], str(raw_record['port'])
    legacy = {**BASE, 'host': host, 'port': port, 'cve': 'CVE-2099-9999',
              'source': 'nuclei', 'script_id': 'nuclei:local-fixture-cve'}
    settings, tenant = _seed(tmp_path, findings=[])
    hosts = [{'host': host}]
    _write_run(settings.output_dir, 'legacy', hosts, [legacy])
    assets.upsert_assets_from_run(settings, tenant_id=tenant, run_id='legacy')
    vulns.register_findings_from_run(settings, tenant_id=tenant, run_id='legacy')
    original = vulns.list_vulnerabilities(settings, tenant_id=tenant)[0][0]
    assert original['finding_evidence'] is None
    vulns.request_exception(settings, tenant_id=tenant, vuln_id=original['vuln_id'],
                            until=datetime.now(UTC) + timedelta(days=30), reason='vendor window', actor='requester')
    approved = vulns.approve_exception(settings, tenant_id=tenant, vuln_id=original['vuln_id'], actor='approver')

    build_reports(raw_dir, 1, [host], [], raw_dir / 'nmap', False, False, False, True,
                  extra_vulnerabilities=[legacy], cvss4_enabled=False, geoip_enabled=False, asn_enabled=False)
    exported = json.loads((raw_dir / 'vulnerabilities.json').read_text())
    _write_run(settings.output_dir, 'captured', hosts, exported)
    vulns.register_findings_from_run(settings, tenant_id=tenant, run_id='captured')
    api_rows = runs.get_vulnerabilities(settings, 'captured', tenant_id=tenant)
    tracker, total = vulns.list_vulnerabilities(settings, tenant_id=tenant)
    ch_rows = ch_transform.vulnerabilities_to_rows({'tenant_id': tenant, 'run_id': 'captured'},
                {'vulnerabilities.json': (raw_dir / 'vulnerabilities.json').read_bytes()},
                settings=settings, require_captured=False)
    assert len(exported) == len(api_rows) == total == len(ch_rows) == 1
    for field in ('finding_key', 'due_at', 'exception_state', 'exception_reason', 'exception_until', 'exception_by'):
        assert tracker[0][field] == approved[field]
    for evidence in (tracker[0]['finding_evidence'], api_rows[0].finding_evidence,
                     json.loads(ch_rows[0][-1])['finding_evidence']):
        assert evidence['observation_count'] == evidence['finding_count'] == 1
        observation = evidence['findings'][0]['observations'][0]
        assert (observation['tenant_id'], observation['run_id']) == (tenant, 'captured')
        assert {r['path'] for r in observation['artifact_refs']} == {'nuclei_raw.jsonl', 'report_sources.json'}
        assert not evidence['findings'][0]['assessment']['machine_verified']
    # Another authenticated tenant cannot retrieve the run projection.
    assert runs.get_vulnerabilities(settings, 'captured', tenant_id='unrelated-tenant') is None


@requires_postgres
def test_incomplete_same_run_replay_marks_gap_without_reopening(tmp_path):
    from tests.test_vuln_lifecycle import _seed, _write_run, _HOSTS
    from api.services import vulnerabilities as vulns, vuln_states
    findings = combine([BASE])
    settings, tenant = _seed(tmp_path, findings=findings)
    vulns.register_findings_from_run(settings, tenant_id=tenant, run_id='run-1')
    original = vulns.list_vulnerabilities(settings, tenant_id=tenant)[0][0]
    vulns.transition(settings, tenant_id=tenant, vuln_id=original['vuln_id'],
                     to_state=vuln_states.CLOSED, actor='admin')
    findings[0]['finding_evidence'] = {'invalid': True}
    _write_run(settings.output_dir, 'run-1', _HOSTS, findings)
    assert vulns.register_findings_from_run(settings, tenant_id=tenant, run_id='run-1').reopened == 0
    current = vulns.get_vulnerability(settings, tenant_id=tenant, vuln_id=original['vuln_id'])
    assert current['state'] == vuln_states.CLOSED
    assert current['observation_count'] == 1
    assert current['finding_evidence']['observation_count'] == 1
    assert current['finding_evidence']['projection_incomplete']
