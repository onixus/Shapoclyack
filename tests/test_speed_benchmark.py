"""Contracts for the isolated speed benchmark (scripts/benchmark-speed.py)."""
import importlib.util
import ipaddress
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('speed_benchmark', ROOT / 'scripts/benchmark-speed.py')
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


@pytest.mark.parametrize('scenario', sorted(BENCH.SCENARIOS))
@pytest.mark.parametrize('scale', ['small', 'full'])
def test_plans_are_deterministic_and_stay_in_the_benchmark_range(scenario, scale):
    plan = BENCH.make_plan(scenario, scale, seed=7)
    assert plan == BENCH.make_plan(scenario, scale, seed=7)
    assert ipaddress.ip_network(plan['cidr']).subnet_of(BENCH.TARGET_NET)
    assert plan['hosts']
    assert BENCH.make_plan(scenario, scale, seed=8)['hosts'] != plan['hosts']


def test_impairment_is_part_of_the_plan():
    assert BENCH.make_plan('dense', 'small', 1)['impairment'] is None
    assert BENCH.make_plan('dense', 'small', 1, impaired=True)['impairment'] == BENCH.IMPAIRMENT


@pytest.mark.parametrize('cidr', ['10.0.0.0/24', '198.18.0.0/30', '0.0.0.0/0', '198.18.0.0/15'])
def test_plans_outside_the_benchmark_range_are_refused(cidr):
    plan = BENCH.make_plan('dense', 'small', 1)
    with pytest.raises(ValueError, match='outside'):
        BENCH.validate_plan(dict(plan, cidr=cidr))


def test_hosts_and_ports_outside_the_plan_are_refused():
    plan = BENCH.make_plan('dense', 'small', 1)
    with pytest.raises(ValueError, match='outside'):
        BENCH.validate_plan(dict(plan, hosts={'198.19.200.1': [80]}))
    first = next(iter(plan['hosts']))
    with pytest.raises(ValueError, match='port outside'):
        BENCH.validate_plan(dict(plan, hosts={first: [65535]}))


def test_unknown_scenario_is_refused():
    with pytest.raises(ValueError, match='unknown scenario'):
        BENCH.make_plan('internet', 'full', 1)


def test_score_counts_misses_and_extras():
    truth = {('198.19.0.1', 22), ('198.19.0.1', 80), ('198.19.0.2', 443), ('198.19.0.3', 25)}
    found = {('198.19.0.1', 22), ('198.19.0.2', 443), ('198.19.0.9', 8080)}
    assert BENCH.score(found, truth) == {
        'expected': 4, 'found': 3, 'true_positives': 2, 'missing': 2, 'unexpected': 1,
        'recall': 0.5, 'precision': 0.666667}


def test_empty_result_has_zero_recall_not_a_silent_pass():
    truth = {('198.19.0.1', 22)}
    assert BENCH.score(set(), truth)['recall'] == 0.0


def test_naabu_parser_deduplicates_events():
    event = json.dumps({'ip': '198.19.0.1', 'port': 22, 'protocol': 'tcp'})
    assert BENCH.parse_naabu(f'{event}\n\n{event}\n') == {('198.19.0.1', 22)}


def test_masscan_parser_reads_list_output():
    text = '#masscan\nopen tcp 443 198.19.0.2 1761066000\nopen tcp 22 198.19.0.1 1761066001\n# end\n'
    assert BENCH.parse_masscan(text) == {('198.19.0.2', 443), ('198.19.0.1', 22)}


@pytest.mark.parametrize('tool', BENCH.TOOLS)
def test_every_tool_scans_only_the_plan_at_the_requested_rate(tool):
    plan = BENCH.make_plan('dense', 'small', 1)
    argv = BENCH.command(tool, plan, 5000, Path('/tmp/out'), router_mac='02:00:00:00:00:01')
    assert plan['cidr'] in argv
    assert '1-1024' in argv
    assert '5000' in argv
    assert tool in BENCH.PARSERS


def test_naabu_modes_differ_only_in_scan_technique():
    plan = BENCH.make_plan('dense', 'small', 1)
    syn = BENCH.command('naabu-syn', plan, 1000, Path('/tmp/out'))
    connect = BENCH.command('naabu-connect', plan, 1000, Path('/tmp/out'))
    assert syn[syn.index('-s') + 1] == 's'
    assert connect[connect.index('-s') + 1] == 'c'
    assert [a for a in syn if a != 's'] == [a for a in connect if a != 'c']


def test_masscan_needs_the_farm_as_router():
    with pytest.raises(ValueError, match='router'):
        BENCH.command('masscan', BENCH.make_plan('dense', 'small', 1), 1000, Path('/tmp/out'))


@pytest.mark.parametrize('count', [-1, 0, 4, 101])
def test_repetitions_must_support_reported_spread(count):
    with pytest.raises(ValueError, match='5..100'):
        BENCH.validate_repeats(count)


@pytest.mark.parametrize('rate', [0, 99, 10_000_001])
def test_rate_must_be_bounded(rate):
    with pytest.raises(ValueError):
        BENCH.validate_rate(rate)


def test_deadline_scales_with_the_sweep():
    plan = BENCH.make_plan('dense', 'small', 1)
    probes = 64 * 1024
    assert BENCH.deadline_seconds(plan, 1000) == pytest.approx(5 * probes / 1000 + 120)


def test_summary_separates_failures_from_samples():
    rows = [{'tool': 'naabu-syn', 'exit_code': 0, 'seconds': s, 'recall': r}
            for s, r in [(1.0, 1.0), (3.0, 0.5), (2.0, 0.75)]]
    rows.append({'tool': 'naabu-syn', 'exit_code': -9, 'seconds': 99.0})
    (entry,) = BENCH.summarize(rows)
    assert entry['samples'] == 3
    assert entry['failed'] == 1
    assert (entry['seconds_median'], entry['seconds_min'], entry['seconds_max']) == (2.0, 1.0, 3.0)
    assert entry['recall_min'] == 0.5


@pytest.mark.parametrize('tail, seconds', [
    (b'rate:  0.00-kpps, 100.00% done, waiting 2-secs, found=346       \r', 0),
    (b'rate:  0.00-kpps, 100.00% done, waiting 0-secs, found=346       \r', 0),
    (b'rate:  0.00-kpps, 100.00% done, waiting -1-secs, found=346       \r', 1),
    (b'waiting -127-secs, found=278       \rrate:  0.00-kpps, 100.00% done, waiting -128-secs, found=278   \r', 128),
    (b'rate:  9.97-kpps, 74.14% done, 0:00:07 remaining, found=260       \r', 0),
])
def test_masscan_overrun_is_read_from_its_status_line(tail, seconds):
    assert BENCH.masscan_overrun(tail) == seconds


def test_the_wake_up_traffic_goes_from_the_farm_to_the_scanner_end_only(monkeypatch):
    argv = []
    monkeypatch.setattr(BENCH.subprocess, 'Popen', lambda a, **kwargs: argv.extend(a))
    BENCH.wake_receiver()
    assert argv[:2] == ['nsenter', f'--net=/var/run/netns/{BENCH.NETNS["farm"]}']
    assert repr(BENCH.LINK['scan']) in argv[-1]
    # Nothing else in the code it runs names an address.
    assert ipaddress.ip_address(BENCH.LINK['scan']) not in BENCH.TARGET_NET


# A stand-in for masscan 1.3.2 on a silent link: writes its findings, then
# counts its --wait window below zero and never exits on its own.
FAKE_MASSCAN = r'''
import sys, time
with open(sys.argv[1], 'w') as handle:
    handle.write('#masscan\nopen tcp 22 198.19.0.1 1761066000\n')
for left in range(2, -600, -1):
    sys.stderr.write(f'rate:  0.00-kpps, 100.00% done, waiting {left}-secs, found=1       \r')
    sys.stderr.flush()
    time.sleep(0.05)
'''


class FakeWaker:
    started = killed = 0

    def __init__(self):
        FakeWaker.started += 1

    def kill(self):
        FakeWaker.killed += 1

    def wait(self):
        return 0


def test_masscan_stalled_past_its_window_is_a_failure_not_a_sample(monkeypatch, tmp_path):
    import sys
    FakeWaker.started = FakeWaker.killed = 0
    monkeypatch.setattr(BENCH, 'in_netns', lambda side, argv: argv)
    monkeypatch.setattr(BENCH, 'command', lambda tool, plan, rate, output, mac=None:
                        [sys.executable, '-c', FAKE_MASSCAN, str(output)])
    monkeypatch.setattr(BENCH, 'wake_receiver', FakeWaker)
    monkeypatch.setattr(BENCH, 'MASSCAN_OVERRUN_LIMIT', 3)
    plan = BENCH.make_plan('dense', 'small', 1)
    row, found = BENCH.run_tool('masscan', plan, 100000, tmp_path, 'r0', '02:00:00:00:00:01')
    assert row['error'] == ['killed 3 s past its --wait window']
    assert found == set()
    # Killed on the overrun, long before the 123 s deadline.
    assert row['seconds'] < 5
    assert (FakeWaker.started, FakeWaker.killed) == (1, 1)


def test_naabu_runs_without_wake_up_traffic(monkeypatch, tmp_path):
    import sys
    FakeWaker.started = 0
    monkeypatch.setattr(BENCH, 'in_netns', lambda side, argv: argv)
    monkeypatch.setattr(BENCH, 'command', lambda tool, plan, rate, output, mac=None:
                        [sys.executable, '-c', 'pass'])
    monkeypatch.setattr(BENCH, 'wake_receiver', FakeWaker)
    plan = BENCH.make_plan('dense', 'small', 1)
    row, _ = BENCH.run_tool('naabu-syn', plan, 100000, tmp_path, 'r0', None)
    assert row['exit_code'] == 0
    assert FakeWaker.started == 0


def test_cli_takes_no_targets():
    # The only addresses a run can touch are the ones make_plan draws from TARGET_NET.
    with pytest.raises(SystemExit):
        BENCH.main(['run', '--scenario', 'dense', '--output', '/tmp/x', '--target', '192.0.2.1'])


def test_stand_requires_explicit_root_only_in_the_isolated_wrapper(tmp_path):
    import os
    import subprocess
    import sys

    dockerfile = (ROOT / 'docs/benchmarks/speed/Stand.Dockerfile').read_text()
    users = [line.split()[1] for line in dockerfile.splitlines() if line.startswith('USER ')]
    assert users[-1] == 'scanner'
    binaries = tmp_path / 'bin'
    binaries.mkdir()
    log = tmp_path / 'docker-runs.jsonl'
    docker = binaries / 'docker'
    docker.write_text(
        f'#!{sys.executable}\n'
        'import json, os, sys\n'
        'if sys.argv[1] == "image": print("sha256:stand-fixture")\n'
        'if sys.argv[1] == "run":\n'
        '    with open(os.environ["BENCH_DOCKER_LOG"], "a") as out:\n'
        '        out.write(json.dumps(sys.argv[2:]) + "\\n")\n'
    )
    docker.chmod(0o755)
    subprocess.run(
        ['bash', str(ROOT / 'scripts/run-speed-benchmark-stand.sh'), str(tmp_path / 'results')],
        env={**os.environ, 'PATH': f'{binaries}:{os.environ["PATH"]}',
             'BENCH_DOCKER_LOG': str(log), 'RATES': '1000', 'REPEATS': '1', 'SCALE': 'small'},
        check=True, capture_output=True, text=True,
    )
    runs = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(runs) == 3
    for argv in runs:
        assert argv[argv.index('--user') + 1] == '0:0'
        assert argv[argv.index('--network') + 1] == 'none'
        assert '--privileged' in argv
        assert any('target=/bench,readonly' in arg for arg in argv)
