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
