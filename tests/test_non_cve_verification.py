"""Exact HTTP objects cannot be closed by endpoint-only negative evidence."""
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.conftest import requires_postgres

from api.services.verification_coverage import RunCoverage
from api.services.vulnerabilities import VerificationDispatchError, _verification_plan
from scanner.pipeline import config_overlay, nuclei_scan
from scanner.pipeline.config_schema import NucleiConfig
from scanner.pipeline.non_cve_verification import metadata, target_subject, validate_target, exact_template
from scanner.pipeline.production_evidence import closure_gaps

URL = 'https://10.0.0.5/private/config?edition=one'
TEMPLATE = 'exposed-config'


def _metadata(url=URL):
    return metadata({'host': '10.0.0.5', 'port': '443', 'protocol': 'tcp',
                     'matched_at': url, 'template_id': TEMPLATE})


def _target(url=URL):
    return {'url': url, 'subject': target_subject(url), 'template_id': TEMPLATE}


def _scan(tmp_path, monkeypatch, *, returncode=0, errors='', loaded=1, template_path='{{BaseURL}}', planner_mode='legacy'):
    templates = tmp_path / 'templates'
    templates.mkdir()
    (templates / 'rule.yaml').write_text(f'id: {TEMPLATE}\ninfo:\n  name: example\n  severity: high\n  tags: misconfig\nhttp:\n  - method: GET\n    path: [\"{{{{BaseURL}}}}\"]\n    matchers:\n      - type: word\n        words: [secret]\n')
    if template_path != '{{BaseURL}}':
        rule = templates / 'rule.yaml'
        rule.write_text(rule.read_text().replace('{{BaseURL}}', template_path))
    called = []
    monkeypatch.setattr(nuclei_scan.shutil, 'which', lambda _: '/usr/bin/nuclei')
    def run(command, **kwargs):
        called.append(command)
        assert Path(command[command.index('-list') + 1]).read_text().strip() == URL
        assert '-disable-redirects' in command
        Path(command[command.index('-jsonl-export') + 1]).write_text('')
        Path(command[command.index('-elog') + 1]).write_text(errors)
        return subprocess.CompletedProcess(command, returncode, '', f'Templates loaded for current scan: {loaded}\n')
    monkeypatch.setattr(nuclei_scan, 'run_command', run)
    config = NucleiConfig(templates_dir=str(templates), template_ids=[TEMPLATE],
                          verification_targets=[_target()], network_templates=False, planner_mode=planner_mode)
    result = nuclei_scan.run_nuclei_scan(['10.0.0.5:443/tcp'], config, tmp_path)
    if template_path == '{{BaseURL}}':
        assert called
    else:
        assert not called
    return result


def test_exact_input_requires_a_new_overlay_version():
    assert config_overlay.required_version({'nuclei': {'template_ids': [TEMPLATE]}}) == 2
    assert config_overlay.required_version({'nuclei': {'verification_targets': [_target()]}}) == 3
    with pytest.raises(config_overlay.ConfigOverlayError):
        config_overlay.check_config({'nuclei': {'verification_targets': [_target()]}}, version=2)


@pytest.mark.parametrize('url', ['https://user:pass@10.0.0.5/x', 'https://10.0.0.5/x#secret',
                                 'file:///private/config', 'https://10.0.0.5/\nheader'])
def test_unsafe_urls_are_not_verification_inputs(url):
    with pytest.raises(ValueError):
        target_subject(url)


def test_different_path_scheme_and_vhost_cannot_reuse_a_subject():
    for url in [URL.replace('/private/', '/public/'), URL.replace('https:', 'http:'),
                URL.replace('10.0.0.5', 'other.example')]:
        with pytest.raises(ValueError):
            validate_target({**_target(), 'url': url})


def test_exact_input_dispatch_is_private_and_scoped():
    row = SimpleNamespace(cve=None, non_cve=_metadata(), detectors=[
        {'detector': 'nuclei', 'ref': TEMPLATE, 'host': '10.0.0.5'}], vuln_id='vln_example')
    plan = _verification_plan(None, row)
    assert plan.overlay_version == 3
    assert plan.config_extra()['nuclei']['verification_targets'] == [_target()]
    assert URL not in json.dumps(plan.as_detail())
    row.non_cve = {**row.non_cve, 'verification_target': None}
    with pytest.raises(VerificationDispatchError, match='exact HTTP subject'):
        _verification_plan(None, row)


def test_completed_exact_input_earns_receipt_and_covers_only_its_subject(tmp_path, monkeypatch):
    result = _scan(tmp_path, monkeypatch)
    receipt = result['coverage']['verification_targets'][0]
    assert receipt['subject'] == target_subject(URL)
    assert receipt['template_id'] == TEMPLATE
    assert receipt['complete'] is True
    assert receipt['input_contract'] == 'exact-baseurl-v1'
    assert len(receipt['template_sha256']) == 64
    assert URL not in json.dumps(receipt)
    coverage = RunCoverage(tmp_path)
    assert coverage.non_cve_gaps(_metadata()) == []
    assert coverage.non_cve_gaps(_metadata(URL.replace('/private/', '/public/')))
    evidence = {'projection_incomplete': False, 'findings': [{'identity': {'subject': target_subject(URL)}}]}
    assert closure_gaps(evidence)
    assert closure_gaps(evidence, covered_subjects=[target_subject(URL)]) == []
    evidence['projection_incomplete'] = True
    assert closure_gaps(evidence, covered_subjects=[target_subject(URL)])


@pytest.mark.parametrize('kwargs', [{'returncode': 1}, {'loaded': 0}, {'errors': '{"kind":"timeout"}\n'}])
def test_failed_partial_and_erroring_scans_do_not_earn_receipts(tmp_path, monkeypatch, kwargs):
    _scan(tmp_path, monkeypatch, **kwargs)
    assert RunCoverage(tmp_path).non_cve_gaps(_metadata())


def test_endpoint_only_coverage_does_not_cover_the_http_object(tmp_path, monkeypatch):
    result = _scan(tmp_path, monkeypatch)
    result['coverage'].pop('verification_targets')
    (tmp_path / 'nuclei.json').write_text(json.dumps(result))
    assert RunCoverage(tmp_path).non_cve_gaps(_metadata())


@pytest.mark.parametrize('path', ['{{BaseURL}}/backup.zip', '{{RootURL}}/backup.zip',
                                  'https://external.example/secret'])
def test_transformed_template_paths_never_probe_or_close_the_original_object(tmp_path, monkeypatch, path):
    result = _scan(tmp_path, monkeypatch, template_path=path)
    assert result['skipped_reason'] == 'verification_template_exact_input_unproven'
    assert not result['coverage'].get('verification_targets')
    assert RunCoverage(tmp_path).non_cve_gaps(_metadata())


@pytest.mark.parametrize('extra', ['variables: {BaseURL: \"https://external.example\"}',
                                  'dns: [{name: external.example}]', 'flow: http(1)',
                                  'constants: {target: external.example}'])
def test_additional_template_protocols_or_overrides_are_not_exact_input_coverage(extra):
    content = ('id: example\ninfo: {name: example}\nhttp:\n  - path: [\"{{BaseURL}}\"]\n'
               '    matchers: [{type: status, status: [200]}]\n' + extra + '\n').encode()
    assert not exact_template(content)




@requires_postgres
@pytest.mark.parametrize('outcome', ['covered', 'endpoint_only', 'different_object', 'error', 'rediscovered', 'unclassified_positive'])
def test_exact_object_closure_uses_the_existing_state_machine(tmp_path, monkeypatch, outcome):
    from api.services import vulnerabilities as vulns
    from scanner.pipeline.production_evidence import combine
    from tests.test_non_cve_workflow import fixture_row
    from tests.test_vuln_lifecycle import _seed, _write_run, _HOSTS
    from tests.test_vuln_verification import _park_in_verifying, _job_for_run
    row = fixture_row(url=URL)[1]
    settings, tenant = _seed(tmp_path, findings=combine([row]))
    vulns.register_findings_from_run(settings, tenant_id=tenant, run_id='run-1')
    finding = vulns.list_vulnerabilities(settings, tenant_id=tenant)[0][0]
    run = 'verify-exact'
    _write_run(settings.output_dir, run, _HOSTS, combine([row]) if outcome == 'rediscovered' else [])
    run_dir = settings.output_dir / 'runs' / run
    result = _scan(run_dir, monkeypatch, errors='timeout\n' if outcome == 'error' else '')
    if outcome == 'endpoint_only':
        result['coverage'].pop('verification_targets')
    if outcome == 'different_object':
        result['coverage']['verification_targets'][0]['subject'] = target_subject(URL + '-other')
    if outcome == 'unclassified_positive':
        result['findings'] = [{'host': '10.0.0.5', 'port': '443', 'protocol': 'tcp',
                               'matched_at': URL, 'template_id': TEMPLATE}]
        result['actionable_findings'] = []
    (run_dir / 'nuclei.json').write_text(json.dumps(result))
    _job_for_run(settings, tenant, 'job-exact', run)
    _park_in_verifying(settings, tenant, finding['vuln_id'], 'job-exact')
    stats = vulns.register_findings_from_run(settings, tenant_id=tenant, run_id=run)
    current = vulns.get_vulnerability(settings, tenant_id=tenant, vuln_id=finding['vuln_id'])
    if outcome == 'covered':
        assert current['state'] == 'CLOSED'
        assert current['machine_verified'] is True
        assert stats.verification_passed == 1
    else:
        assert current['state'] == 'FIXING'
        assert current['machine_verified'] is False


@pytest.mark.parametrize('path', ['{{BaseURL}}', '{{BaseURL}}/backup.zip'])
def test_directed_sensor_uses_the_same_exact_snapshot_contract(tmp_path, monkeypatch, path):
    result = _scan(tmp_path, monkeypatch, template_path=path, planner_mode='directed')
    if path == '{{BaseURL}}':
        assert result['coverage']['verification_targets'][0]['complete'] is True
    else:
        assert result['skipped_reason'] == 'verification_template_exact_input_unproven'


@requires_postgres
def test_real_pinned_engine_capture_completes_tracked_remediation(tmp_path):
    """Actual local Nuclei output reaches the same PostgreSQL lifecycle gate."""
    from api.services import assets, vulnerabilities as vulns
    from scanner.pipeline.production_evidence import combine
    from tests.test_vuln_lifecycle import _settings, _write_run
    from tests.test_vuln_verification import _park_in_verifying, _job_for_run
    from api.services.tenants import DEFAULT_TENANT_ID
    capture = Path(__file__).parent / 'fixtures' / 'non_cve_verification' / 'nuclei_v3_11_1'
    positive = json.loads((capture / 'positive.json').read_text())
    remediated = json.loads((capture / 'remediated.json').read_text())
    settings = _settings(tmp_path)
    tenant = DEFAULT_TENANT_ID
    hosts = [{'host': '127.0.0.1'}]
    _write_run(settings.output_dir, 'run-1', hosts, combine(positive['actionable_findings']))
    assets.upsert_assets_from_run(settings, tenant_id=tenant, run_id='run-1')
    vulns.register_findings_from_run(settings, tenant_id=tenant, run_id='run-1')
    finding = vulns.list_vulnerabilities(settings, tenant_id=tenant)[0][0]
    assert finding['cve'] is None
    _write_run(settings.output_dir, 'run-clean', hosts, [])
    (settings.output_dir / 'runs' / 'run-clean' / 'nuclei.json').write_text(json.dumps(remediated))
    _job_for_run(settings, tenant, 'job-real-exact', 'run-clean')
    _park_in_verifying(settings, tenant, finding['vuln_id'], 'job-real-exact')
    stats = vulns.register_findings_from_run(settings, tenant_id=tenant, run_id='run-clean')
    current = vulns.get_vulnerability(settings, tenant_id=tenant, vuln_id=finding['vuln_id'])
    assert stats.verification_passed == 1
    assert current['state'] == 'CLOSED' and current['machine_verified'] is True


@requires_postgres
@pytest.mark.parametrize('scenario', ['allowed', 'scope_removed', 'old_sensor'])
def test_precise_dispatch_checks_current_scope_and_v3_sensor(tmp_path, scenario):
    from api.services import vulnerabilities as vulns
    from scanner.pipeline.production_evidence import combine
    from tests.conftest import approve_scan_scope
    from tests.test_non_cve_workflow import fixture_row
    from tests.test_vuln_lifecycle import _seed
    from tests.test_vuln_verification import _advance_to_fixing
    from tests.test_vuln_verification_coverage import _agent_mode
    row = fixture_row(url=URL)[1]
    settings, tenant = _seed(tmp_path, findings=combine([row]))
    approve_scan_scope(settings, entries=[{'effect': 'allow', 'kind': 'cidr',
                                         'value': '192.0.2.0/24' if scenario == 'scope_removed' else '10.0.0.0/8'}])
    vulns.register_findings_from_run(settings, tenant_id=tenant, run_id='run-1')
    finding = vulns.list_vulnerabilities(settings, tenant_id=tenant)[0][0]
    _advance_to_fixing(settings, tenant, finding['vuln_id'])
    capabilities = ['scan_policy', 'config_overlay.v1', 'config_overlay.v2']
    if scenario != 'old_sensor':
        capabilities.append('config_overlay.v3')
    _agent_mode(settings, tenant, capabilities=capabilities)
    if scenario == 'allowed':
        result = vulns.trigger_verification(settings, tenant_id=tenant, vuln_id=finding['vuln_id'])
        from api.db.engine import get_session
        from api.db.models import Job
        with get_session(settings.postgres_url) as session:
            job = session.get(Job, result['verification_job_id'])
        assert job.scan_options['config_overlay_capability'] == 'config_overlay.v3'
        assert job.scan_options['config_overlay']['nuclei']['verification_targets'] == [_target()]
    else:
        with pytest.raises(VerificationDispatchError):
            vulns.trigger_verification(settings, tenant_id=tenant, vuln_id=finding['vuln_id'])
        current = vulns.get_vulnerability(settings, tenant_id=tenant, vuln_id=finding['vuln_id'])
        assert current['state'] == 'FIXING' and current['verification_job_id'] is None
