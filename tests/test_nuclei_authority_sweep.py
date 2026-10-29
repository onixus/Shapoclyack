import json
import subprocess
from scanner.pipeline import nuclei_scan as ns


def test_authority_is_forward_name_but_connection_remains_ip():
    targets = ns._sweep_authorities([('192.0.2.1', 443, 'https')],
        {'192.0.2.1': ['one.example', 'two.example', 'bad\r\nHost:x', '-bad.example']})
    assert [t['sni'] for t in targets] == ['one.example', 'two.example']
    assert {t['url'] for t in targets} == {'https://192.0.2.1:443/'}
    assert ns._sweep_authorities([('192.0.2.2', 80, 'http')], {})[0]['host_header'] is None


def test_invocations_isolate_authority_and_preserve_partial_failure(tmp_path, monkeypatch):
    from pathlib import Path
    calls = []
    def run(cmd, **kw):
        calls.append(cmd)
        Path(cmd[cmd.index('-jsonl-export') + 1]).write_text(json.dumps({'host':'192.0.2.1', 'port':'443'})+'\n')
        Path(cmd[cmd.index('-elog') + 1]).write_text('')
        return subprocess.CompletedProcess(cmd, 0 if len(calls) == 1 else 1, '', '')
    monkeypatch.setattr(ns, 'run_command', run)
    targets = ns._sweep_authorities([('192.0.2.1',443,'https')], {'192.0.2.1':['one.example','two.example']})
    cmd=['nuclei','-list',str(tmp_path/'targets'),'-jsonl-export',str(tmp_path/'raw'),'-elog',str(tmp_path/'errors')]
    result=ns._run_authority_sweep(cmd,targets,tmp_path,30)
    assert result.returncode == 1
    assert [c[c.index('-sni')+1] for c in calls] == ['one.example','two.example']
    assert [c[c.index('-H')+1] for c in calls] == ['Host: one.example:443','Host: two.example:443']
    rows=[json.loads(x) for x in (tmp_path/'raw').read_text().splitlines()]
    assert [r['shapoclyack_input']['authority'] for r in rows] == ['one.example:443','two.example:443']


def test_each_authority_must_load_the_expected_catalog(tmp_path, monkeypatch):
    responses = iter(['[INF] Templates loaded for current scan: 1', ''])
    monkeypatch.setattr(ns, 'run_command', lambda cmd, **kw:
        subprocess.CompletedProcess(cmd, 0, '', next(responses)))
    targets = ns._sweep_authorities([('192.0.2.1',443,'https')],
        {'192.0.2.1':['one.example','two.example']})
    cmd=['nuclei','-list',str(tmp_path/'targets'),'-jsonl-export',str(tmp_path/'raw'),'-elog',str(tmp_path/'errors')]
    result = ns._run_authority_sweep(cmd, targets, tmp_path, 30, expected_templates=1)
    assert result.returncode != 0


def test_expired_budget_never_launches_nuclei(tmp_path, monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError('Must not launch after deadline')
    monkeypatch.setattr(ns, 'run_command', unexpected)
    targets = ns._sweep_authorities([('192.0.2.1',443,'https')], {})
    cmd=['nuclei','-list',str(tmp_path/'targets'),'-jsonl-export',str(tmp_path/'raw'),'-elog',str(tmp_path/'errors')]
    assert ns._run_authority_sweep(cmd, targets, tmp_path, 0).returncode != 0


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
