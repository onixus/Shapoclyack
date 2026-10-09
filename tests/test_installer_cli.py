"""Installer argument failures must happen before host mutations or builds."""
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('option', [
    '--server', '-s', '--key', '-k', '--tenant', '-t', '--agent-id', '-a',
    '--install-dir', '-d', '--nats-url', '--bundle-url',
])
@pytest.mark.parametrize('tail', [[], ['--docker'], ['-h'], ['']])
def test_sensor_missing_value_is_reported(option, tail):
    result = subprocess.run(['bash', str(ROOT / 'scripts/install-agent.sh'), option, *tail],
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert f'Missing value for {option}' in result.stderr
    assert 'unbound variable' not in result.stderr


def test_pulse_source_ref_failure_does_not_build_or_retry_default_branch(tmp_path):
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    calls = tmp_path / 'calls'
    for name, status in [('git', 42), ('cargo', 99)]:
        command = bindir / name
        command.write_text(f'#!/bin/sh\nprintf "%s\\n" "{name} $*" >> "$TEST_CALLS"\nexit {status}\n')
        command.chmod(0o755)
    result = subprocess.run(['bash', str(ROOT / 'scripts/install-pulse.sh')],
                            env={**os.environ, 'PATH': f'{bindir}:{os.environ["PATH"]}',
                                 'TEST_CALLS': str(calls), 'PULSE_FROM_SOURCE': '1',
                                 'PULSE_REPO': '', 'PULSE_REF': 'missing-ref',
                                 'PULSE_DEST': str(tmp_path / 'pulse')},
                            capture_output=True, text=True)
    assert result.returncode == 42
    lines = calls.read_text().splitlines()
    assert len(lines) == 1
    assert lines[0].startswith('git clone --depth 1 --branch missing-ref ')
    assert not (tmp_path / 'pulse').exists()
