"""Execute the Jenkins cell runner with process stubs, without Docker or root."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_new_branch_revision_supersedes_obsolete_validation_without_skipping_tests():
    pipeline = (REPO_ROOT / "Jenkinsfile").read_text()
    assert "disableConcurrentBuilds(abortPrevious: true)" in pipeline
    assert "for (PY in ['3.11', '3.12'])" in pipeline
    assert "sh 'scripts/ci-jenkins-tests.sh'" in pipeline

_STUB = r'''
import json
import os
import sys
from pathlib import Path

name = Path(sys.argv[0]).name
args = sys.argv[1:]
log = Path(os.environ['CALL_LOG'])
with log.open('a') as out:
    out.write(json.dumps([name, args, os.environ.get('HOME'),
                          os.environ.get('JUNIT_XML'), os.environ.get('COVERAGE_XML')]) + '\n')
mode = os.environ['FAIL_AT']
if name == 'stat':
    print('0' if mode == 'root' else '1001')
if name == 'setpriv':
    os.execvp(args[3], args[3:])
step = name
if name == 'python':
    step = 'compile' if args[0] == '-m' else ('postgres' if 'socket' in args[1] else ('clickhouse' if 'clickhouse_connect' in args[1] else 'jetstream'))
if mode == 'retry' and step == 'postgres':
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    attempts = sum(c[0] == 'python' and c[1][0] == '-c' and 'socket' in c[1][1] for c in calls)
    sys.exit(1 if attempts < 3 else 0)
if mode == step and step in {'postgres', 'jetstream', 'clickhouse'}:
    print(f'probe-error:{step}', file=sys.stderr)
sys.exit(7 if mode == step else 0)
'''


@pytest.mark.parametrize(
    ('failure', 'last_step', 'returncode'),
    [('none', 'ci-pytest.sh', 0), ('retry', 'ci-pytest.sh', 0),
     ('root', 'stat', 1), ('pip', 'pip', 7), ('compile', 'python', 7),
     ('postgres', 'python', 1), ('jetstream', 'python', 1),
     ('clickhouse', 'python', 1), ('alembic', 'alembic', 7), ('ci-sdk.sh', 'ci-sdk.sh', 7),
     ('ci-pytest.sh', 'ci-pytest.sh', 7)],
)
def test_cell_stops_at_failed_step_and_preserves_test_status(tmp_path, failure, last_step, returncode):
    scripts = tmp_path / 'scripts'
    scripts.mkdir()
    runner = scripts / 'ci-jenkins-tests.sh'
    shutil.copyfile(REPO_ROOT / 'scripts' / runner.name, runner)
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    for name in ['stat', 'pip', 'mkdir', 'chown', 'setpriv', 'python', 'sleep', 'alembic']:
        stub = bindir / name
        stub.write_text(f'#!{sys.executable}\n' + _STUB)
        stub.chmod(0o755)
    for name in ['ci-sdk.sh', 'ci-pytest.sh']:
        script_stub = scripts / name
        script_stub.write_text(f'#!{sys.executable}\n' + _STUB)
        script_stub.chmod(0o755)
    log = tmp_path / 'calls.jsonl'
    env = dict(os.environ, PATH=f'{bindir}:{os.environ["PATH"]}', CALL_LOG=str(log),
               FAIL_AT=failure, JUNIT_XML='junit-3.12.xml', COVERAGE_XML='coverage-3.12.xml')
    result = subprocess.run(['bash', str(runner), '-k', 'a test'], env=env,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == returncode, result.stdout + result.stderr
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert calls[-1][0] == last_step
    if failure in {'postgres', 'jetstream', 'clickhouse'}:
        assert f'{failure} did not become ready after 60 attempts' in result.stderr
        assert sum(c[0] == 'sleep' for c in calls) == 59
        assert result.stderr.count(f'probe-error:{failure}') == 1
        assert not any(c[0] in {'alembic', 'ci-sdk.sh', 'ci-pytest.sh'} for c in calls)
    if failure == 'ci-sdk.sh':
        assert not any(c[0] == 'ci-pytest.sh' for c in calls)
    if last_step == 'ci-pytest.sh':
        assert calls[-1][1:] == [['-k', 'a test'], '/tmp/ci-home',
                                'junit-3.12.xml', 'coverage-3.12.xml']
        assert [c[1] for c in calls if c[0] == 'setpriv'] == [
            ['--reuid=1001', '--regid=1001', '--clear-groups',
             'python', '-m', 'compileall', '-q', 'scanner', 'api', 'tests', 'agent'],
            ['--reuid=1001', '--regid=1001', '--clear-groups', 'scripts/ci-sdk.sh'],
            ['--reuid=1001', '--regid=1001', '--clear-groups',
             'scripts/ci-pytest.sh', '-k', 'a test'],
        ]
        assert next(c[1] for c in calls if c[0] == 'pip') == [
            'install', '--quiet', '--require-hashes', '--only-binary=:all:',
            '-r', 'requirements-dev.lock',
        ]
        assert next(c[1] for c in calls if c[0] == 'alembic') == [
            '-c', 'api/db/alembic.ini', 'upgrade', 'head',
        ]


def test_jenkins_delegates_cell_setup_and_keeps_per_version_reports():
    pipeline = (REPO_ROOT / 'Jenkinsfile').read_text()
    assert "sh 'scripts/ci-jenkins-tests.sh'" in pipeline
    assert '"JUNIT_XML=junit-${PY}.xml"' in pipeline
    assert '"COVERAGE_XML=coverage-${PY}.xml"' in pipeline
    assert 'docker.image(CLICKHOUSE_IMAGE).withRun(' in pipeline
    assert '--tmpfs /var/lib/clickhouse:size=512m' in pipeline
    assert '--tmpfs /var/log/clickhouse-server:size=64m' in pipeline
    assert 'OCTO_CLICKHOUSE_URL=http://octo:octo-ch-ci-secret@ch:8123/shapoclyack' in pipeline
