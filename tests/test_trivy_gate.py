"""Exercise the Jenkins shell gate against fixed/unfixed findings and mutations."""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def trivy_shell(source: str) -> str:
    stage = source.split("stage('Trivy')", 1)[1].split("stage('SBOM')", 1)[0]
    shell = re.search(r'sh """(.*?)"""', stage, re.S).group(1)
    return shell.replace('\\\\', '\\').replace('\\$', '$')


def run_gate(tmp_path, source, severity, fixed):
    stub = tmp_path / 'docker'
    stub.write_text(
        f'#!{sys.executable}\n'
        'import os, sys\n'
        'args = sys.argv[1:]\n'
        'def value(key): return args[args.index(key) + 1]\n'
        'selected = os.environ["FINDING_SEVERITY"] in value("--severity").split(",")\n'
        'ignored = "--ignore-unfixed" in args and os.environ["FINDING_FIXED"] == "0"\n'
        'sys.exit(int(value("--exit-code")) if selected and not ignored else 0)\n'
    )
    stub.chmod(0o755)
    result = subprocess.run(
        ['bash', '-c', trivy_shell(source)], capture_output=True, text=True,
        env=dict(os.environ, PATH=f'{tmp_path}:{os.environ["PATH"]}', WORKSPACE=str(tmp_path),
                 TRIVY_IMAGE='trivy:test', IMAGE_TAG='scanner:test',
                 FINDING_SEVERITY=severity, FINDING_FIXED='1' if fixed else '0'),
        check=False,
    )
    assert result.returncode in (0, 1), result.stderr
    return result.returncode


@pytest.mark.parametrize('severity,fixed,expected', [
    ('HIGH', True, 1), ('CRITICAL', True, 1), ('MEDIUM', True, 0),
    ('HIGH', False, 0), ('CRITICAL', False, 0),
])
def test_jenkins_blocks_fixable_high_and_critical(tmp_path, severity, fixed, expected):
    assert run_gate(tmp_path, (ROOT / 'Jenkinsfile').read_text(), severity, fixed) == expected


@pytest.mark.parametrize('before,after', [
    ('--severity HIGH,CRITICAL', '--severity CRITICAL'),
    ('--exit-code 1', '--exit-code 0'),
    ('--exit-code 1 ${IMAGE_TAG}', '--exit-code 1 ${IMAGE_TAG} || true'),
])
def test_weakening_the_gate_is_detected(tmp_path, before, after):
    source = (ROOT / 'Jenkinsfile').read_text()
    assert before in source
    assert run_gate(tmp_path, source.replace(before, after), 'HIGH', True) == 0
    assert run_gate(tmp_path, source, 'HIGH', True) == 1


def test_github_gate_matches_jenkins_and_report_keeps_unfixed():
    doc = yaml.safe_load((ROOT / '.github/workflows/ci.yml').read_text())
    steps = [s for job in doc['jobs'].values() for s in job.get('steps', [])
             if str(s.get('uses', '')).startswith('aquasecurity/trivy-action@')]
    gate, = [s for s in steps if s['with'].get('exit-code') == '1']
    assert set(gate['with']['severity'].split(',')) == {'HIGH', 'CRITICAL'}
    assert gate['with']['ignore-unfixed'] is True
    report, = [s for s in steps if s['with'].get('exit-code') == '0']
    assert not report['with'].get('ignore-unfixed', False)
    assert {'HIGH', 'CRITICAL', 'MEDIUM'} <= set(report['with']['severity'].split(','))
    assert yaml.safe_load((ROOT / '.trivyignore.yaml').read_text())['vulnerabilities'] == []


@pytest.mark.parametrize('name', ['Dockerfile', 'Dockerfile.api', 'Dockerfile.allinone'])
def test_runtime_removes_installers_after_the_locked_install(name):
    source = (ROOT / name).read_text()
    install = source.rindex('pip install ')
    remove = source.index('python -m pip uninstall --yes pip')
    assert install < remove < source.index('USER ', remove)
    assert "shutil.rmtree(pathlib.Path(ensurepip.__file__).parent)" in source[remove:]
    assert "assert importlib.util.find_spec('pip') is None" in source[remove:]
    assert "assert importlib.util.find_spec('ensurepip') is None" in source[remove:]
