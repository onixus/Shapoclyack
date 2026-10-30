import json
import subprocess
from pathlib import Path

from scanner.pipeline import nuclei_scan as ns


def test_authority_is_forward_name_but_connection_remains_ip():
    targets = ns._sweep_authorities([('192.0.2.1', 443, 'https')],
        {'192.0.2.1': ['one.example', 'two.example', 'bad\r\nHost:x', '-bad.example']})
    assert [t['sni'] for t in targets] == [None, 'one.example', 'two.example']
    assert {t['url'] for t in targets} == {'https://192.0.2.1:443/'}
    assert ns._sweep_authorities([('192.0.2.2', 80, 'http')], {})[0]['host_header'] is None


def test_invocations_isolate_authority_and_preserve_partial_failure(tmp_path, monkeypatch):
    calls = []
    def run(cmd, **kw):
        calls.append(cmd)
        Path(cmd[cmd.index('-jsonl-export') + 1]).write_text(json.dumps({'host':'192.0.2.1', 'port':'443'})+'\n')
        Path(cmd[cmd.index('-elog') + 1]).write_text('')
        return subprocess.CompletedProcess(cmd, 0 if len(calls) == 1 else 1, '', '')
    monkeypatch.setattr(ns, 'run_command', run)
    targets = ns._sweep_authorities([('192.0.2.1',443,'https')], {'192.0.2.1':['one.example','two.example']})
    cmd=['nuclei','-list',str(tmp_path/'targets'),'-jsonl-export',str(tmp_path/'raw'),'-elog',str(tmp_path/'errors')]
    result, receipts = ns._run_authority_sweep(cmd,targets,tmp_path,60)
    assert result.returncode == 1
    assert [r['status'] for r in receipts] == ['complete', 'failed', 'failed']
    assert '-sni' not in calls[0] and '-H' not in calls[0]
    assert [c[c.index('-sni')+1] for c in calls[1:]] == ['one.example','two.example']
    assert [c[c.index('-H')+1] for c in calls[1:]] == ['Host: one.example','Host: two.example']
    rows=[json.loads(x) for x in (tmp_path/'raw').read_text().splitlines()]
    assert [r['shapoclyack_input']['authority'] for r in rows] == [
        '192.0.2.1:443', 'one.example:443', 'two.example:443']


def test_each_authority_must_load_the_expected_catalog(tmp_path, monkeypatch):
    responses = iter(['[INF] Templates loaded for current scan: 1'] * 2 + [''])
    monkeypatch.setattr(ns, 'run_command', lambda cmd, **kw:
        subprocess.CompletedProcess(cmd, 0, '', next(responses)))
    targets = ns._sweep_authorities([('192.0.2.1',443,'https')],
        {'192.0.2.1':['one.example','two.example']})
    cmd=['nuclei','-list',str(tmp_path/'targets'),'-jsonl-export',str(tmp_path/'raw'),'-elog',str(tmp_path/'errors')]
    result, receipts = ns._run_authority_sweep(cmd, targets, tmp_path, 60, expected_templates=1)
    assert result.returncode != 0
    assert [r['status'] for r in receipts] == ['complete', 'complete', 'failed']


def test_expired_budget_never_launches_nuclei(tmp_path, monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError('Must not launch after deadline')
    monkeypatch.setattr(ns, 'run_command', unexpected)
    targets = ns._sweep_authorities([('192.0.2.1',443,'https')], {})
    cmd=['nuclei','-list',str(tmp_path/'targets'),'-jsonl-export',str(tmp_path/'raw'),'-elog',str(tmp_path/'errors')]
    result, receipts = ns._run_authority_sweep(cmd, targets, tmp_path, 0)
    assert result.returncode != 0
    assert [r['status'] for r in receipts] == ['skipped_deadline']


def test_capped_authorities_never_claim_complete_pinned_coverage(tmp_path, monkeypatch):
    from scanner.pipeline.config_schema import NucleiConfig
    templates = tmp_path / 'templates'
    templates.mkdir()
    (templates / 'check.yaml').write_text(
        'id: test-check\ninfo:\n  name: check\n  author: tests\n  severity: medium\n'
        "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/'\n")
    out = tmp_path / 'out'
    out.mkdir()
    (out / 'dns_resolution.json').write_text(json.dumps({'records': [
        {'host': 'one.example', 'a': ['192.0.2.1']},
        {'host': 'two.example', 'a': ['192.0.2.1']},
    ]}))
    monkeypatch.setattr(ns.shutil, 'which', lambda _: '/usr/bin/nuclei')
    monkeypatch.setattr(ns, 'run_command', lambda cmd, **kw:
        subprocess.CompletedProcess(cmd, 0, '', '[INF] Templates loaded for current scan: 1'))
    result = ns.run_nuclei_scan(['192.0.2.1:443/tcp'], NucleiConfig(
        templates_dir=str(templates), template_ids=['test-check'], max_targets=1), out)
    assert result['truncated'] is True
    assert result['checked_count'] == 0
    assert len(result['coverage']['authorities']) == 1


def _sweep_cmd(tmp_path):
    return ['nuclei', '-list', str(tmp_path / 'targets'), '-jsonl-export', str(tmp_path / 'raw'),
            '-elog', str(tmp_path / 'errors')]


def _sweep(*args, **kwargs):
    # Older revisions returned the process only; receipts are the contract now.
    outcome = ns._run_authority_sweep(*args, **kwargs)
    return outcome if isinstance(outcome, tuple) else (outcome, None)


def test_default_port_host_header_matches_what_a_client_sends():
    # Exact-match vhost routers (Envoy domains, HAProxy hdr(host)) do not
    # strip ":443"; a browser never sends a default port.
    https = ns._sweep_authorities([('192.0.2.1', 443, 'https')], {'192.0.2.1': ['one.example']})
    http = ns._sweep_authorities([('192.0.2.1', 80, 'http')], {'192.0.2.1': ['one.example']})
    other = ns._sweep_authorities([('192.0.2.1', 8443, 'https')], {'192.0.2.1': ['one.example']})
    assert [t['host_header'] for t in https if t['host_header']] == ['one.example']
    assert [t['host_header'] for t in http if t['host_header']] == ['one.example']
    assert [t['host_header'] for t in other if t['host_header']] == ['one.example:8443']
    # Evidence keeps the explicit authority the invocation was bound to.
    assert [t['authority'] for t in https if t['host_header']] == ['one.example:443']


def test_named_ip_still_scans_its_default_virtual_host():
    targets = ns._sweep_authorities([('192.0.2.1', 443, 'https')], {'192.0.2.1': ['one.example']})
    assert [(t['host_header'], t['sni']) for t in targets] == [(None, None), ('one.example', 'one.example')]


def test_names_are_canonicalised_and_never_ip_literals():
    targets = ns._sweep_authorities([('192.0.2.1', 443, 'https')], {'192.0.2.1': [
        'One.Example.', 'one.example', 'xn--bcher-kva.example', 'bücher.example',
        '192.0.2.9', 'a..example', 'one.example..', 'x' * 64 + '.example', 'under_score.example']})
    assert [t['sni'] for t in targets if t['sni']] == ['one.example', 'xn--bcher-kva.example']
    assert {t['url'] for t in targets} == {'https://192.0.2.1:443/'}


def test_blank_lines_in_raw_output_are_not_malformed_results(tmp_path, monkeypatch):
    def run(cmd, **kw):
        record = json.dumps({'host': '192.0.2.1', 'port': '443'})
        Path(cmd[cmd.index('-jsonl-export') + 1]).write_text(record + '\n\n' + record + '\n')
        return subprocess.CompletedProcess(cmd, 0, '', '[INF] Templates loaded for current scan: 1')
    monkeypatch.setattr(ns, 'run_command', run)
    targets = ns._sweep_authorities([('192.0.2.1', 443, 'https')], {'192.0.2.1': ['one.example']})
    completed, _ = _sweep(_sweep_cmd(tmp_path), targets, tmp_path, 30, expected_templates=1)
    assert completed.returncode == 0
    assert len((tmp_path / 'raw').read_text().splitlines()) == 2 * len(targets)


def test_truncated_raw_part_drops_the_partial_line(tmp_path, monkeypatch):
    def run(cmd, **kw):
        # Over the per-part cap, and nothing after the first record ends a line.
        Path(cmd[cmd.index('-jsonl-export') + 1]).write_bytes(
            b'{"host":"192.0.2.1"}\n{"host":"' + b'x' * (9 * 1024 * 1024))
        return subprocess.CompletedProcess(cmd, 0, '', '')
    monkeypatch.setattr(ns, 'run_command', run)
    targets = ns._sweep_authorities([('192.0.2.1', 80, 'http')], {})
    completed, receipts = _sweep(_sweep_cmd(tmp_path), targets, tmp_path, 30)
    assert completed.returncode == 1
    rows = (tmp_path / 'raw').read_text().splitlines()
    assert [json.loads(r)['host'] for r in rows] == ['192.0.2.1']
    assert receipts[0]['artifact_truncated'] is True


def test_deadline_skipped_authorities_are_explicit_and_not_covered(tmp_path, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(ns.time, 'monotonic', lambda: clock[0])
    def run(cmd, **kw):
        clock[0] += 25
        return subprocess.CompletedProcess(cmd, 0, '', '[INF] Templates loaded for current scan: 1')
    monkeypatch.setattr(ns, 'run_command', run)
    targets = ns._sweep_authorities([('192.0.2.1', 443, 'https')],
                                    {'192.0.2.1': ['one.example', 'two.example']})
    completed, receipts = _sweep(_sweep_cmd(tmp_path), targets, tmp_path, 30, expected_templates=1)
    assert completed.returncode == 1
    assert [r['status'] for r in receipts] == ['complete', 'skipped_deadline', 'skipped_deadline']
    assert [r['authority'] for r in receipts] == ['192.0.2.1:443', 'one.example:443', 'two.example:443']


def test_run_reports_per_authority_receipts_and_never_claims_skipped(tmp_path, monkeypatch):
    from scanner.pipeline.config_schema import NucleiConfig
    templates = tmp_path / 'templates'
    templates.mkdir()
    (templates / 'check.yaml').write_text(
        'id: test-check\ninfo:\n  name: check\n  author: tests\n  severity: medium\n'
        "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/'\n")
    out = tmp_path / 'out'
    out.mkdir()
    (out / 'dns_resolution.json').write_text(json.dumps({'records': [
        {'host': 'one.example', 'a': ['192.0.2.1']}]}))
    clock = [1000.0]
    monkeypatch.setattr(ns.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(ns.shutil, 'which', lambda _: '/usr/bin/nuclei')
    def run(cmd, **kw):
        clock[0] += 55
        return subprocess.CompletedProcess(cmd, 0, '', '[INF] Templates loaded for current scan: 1')
    monkeypatch.setattr(ns, 'run_command', run)
    result = ns.run_nuclei_scan(['192.0.2.1:443/tcp'], NucleiConfig(
        templates_dir=str(templates), template_ids=['test-check'], overall_timeout_seconds=60), out)
    statuses = [r['status'] for r in result['coverage'].get('authority_results', [])]
    assert statuses == ['complete', 'skipped_deadline']
    assert result['coverage']['ran'] is False
    assert result['coverage']['templates_expected'] == 2
    assert result['checked_count'] == 0
