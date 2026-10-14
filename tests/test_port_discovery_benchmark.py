"""Evidence and parser contracts for the isolated discovery experiment."""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('port_benchmark', ROOT / 'scripts/benchmark-port-discovery.py')
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


def test_naabu_duplicate_events_do_not_duplicate_endpoints():
    event = json.dumps({'ip': '127.20.0.1', 'port': 8080, 'protocol': 'tcp'})
    assert BENCH.normalize('naabu', event + '\n' + event) == [('127.20.0.1', 8080, 'tcp')]


def test_pulse_flat_results_preserve_udp_and_normalize_syn_transport():
    rows = [{'ip': '::1', 'port': 8080, 'protocol': 'tcpsyn', 'state': 'open'},
            {'ip': '127.20.0.1', 'port': 8999, 'protocol': 'udp', 'state': 'closed'},
            {'ip': '127.20.0.1', 'port': 53, 'protocol': 'udp', 'state': 'open'}]
    assert BENCH.normalize('pulse', json.dumps({'results': rows})) == [
        ('127.20.0.1', 53, 'udp'), ('::1', 8080, 'tcp')]


@pytest.mark.parametrize('count', [-1, 0, 4, 101])
def test_repetitions_must_support_reported_spread(count):
    with pytest.raises(ValueError, match='5..100'):
        BENCH.validate_repeats(count)


def test_summary_refuses_duplicate_or_missing_repetitions():
    sample = dict(profile='unprivileged', cache='cold', variant='pulse',
                  seconds=1., cpu_seconds=.1, accepted_connections=3,
                  packets=20, wire_bytes=500, matches_truth=True)
    with pytest.raises(ValueError, match='distinct repetitions'):
        BENCH.summarize([dict(sample, repeat=i) for i in range(4)])
    with pytest.raises(ValueError, match='distinct repetitions'):
        BENCH.summarize([dict(sample, repeat=0) for _ in range(5)])


def test_enrichment_plans_preserve_actual_discovery_misses():
    observed = [('127.20.0.1', 8080, 'tcp'), ('127.20.0.3', 2222, 'tcp')]
    assert BENCH.enrichment_plan('fixed_exact', observed) == [
        ('127.20.0.1', [8080]), ('127.20.0.3', [2222])]
    assert BENCH.enrichment_plan('baseline_union', observed) == [
        ('127.20.0.1,127.20.0.3', [2222, 8080])]
    assert BENCH.enrichment_plan('fixed_exact', []) == []
    assert BENCH.enrichment_plan('baseline_union', []) == []
    with pytest.raises(ValueError, match='outside fixed fixture scope'):
        BENCH.enrichment_plan('fixed_exact', [('192.0.2.1', 80, 'tcp')])


def test_runner_checks_isolation_before_creating_fixture_or_spawning(monkeypatch):
    from types import SimpleNamespace

    def reject(_):
        raise RuntimeError('external interface active')

    monkeypatch.setattr(BENCH, 'load_engine', lambda: SimpleNamespace(verify_binary=reject))
    with pytest.raises(RuntimeError, match='external interface active'):
        BENCH.main(SimpleNamespace(repeats=5))


def test_runner_rejects_extra_interfaces_even_when_inactive(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(BENCH, 'load_engine', lambda: SimpleNamespace(verify_binary=lambda _: None))
    monkeypatch.setattr(BENCH.socket, 'if_nameindex', lambda: [(1, 'lo'), (2, 'eth0')])
    monkeypatch.setattr(BENCH.Path, 'is_file', lambda _: True)
    with pytest.raises(ValueError, match='outside allowed inactive'):
        BENCH.main(SimpleNamespace(repeats=5))


def test_recorded_samples_reproduce_summary_and_preserve_failures():
    folder = ROOT / 'docs/benchmarks/port-discovery-20261015'
    samples = json.loads((folder / 'results.json').read_text())
    pipelines = json.loads((folder / 'pipelines.json').read_text())
    assert BENCH.summarize(samples) == json.loads((folder / 'summary.json').read_text())
    assert BENCH.summarize(pipelines) == json.loads((folder / 'pipeline-summary.json').read_text())
    assert len(pipelines) == 30
    assert all(s['matches_truth'] for s in pipelines)
    # Empty SYN results are retained as a failed fixture coverage outcome.
    assert any(s['profile'] == 'root_syn' and not s['matches_truth'] for s in samples)
    for row in pipelines:
        assert row['seconds'] == sum(stage['seconds'] for stage in row['stages'])
        assert row['processes'] == len(row['stages'])
        assert all(stage['returncode'] == 0 and not stage['timed_out'] for stage in row['stages'])


def test_archived_raw_evidence_hashes_and_capture_counters():
    import hashlib
    import tarfile
    from types import SimpleNamespace

    folder = ROOT / 'docs/benchmarks/port-discovery-20261015'
    for line in (folder / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split('  ', 1)
        assert hashlib.sha256((folder / name).read_bytes()).hexdigest() == digest
    expected = json.loads((folder / 'raw-sha256.json').read_text())
    engine = BENCH.load_engine()
    with tarfile.open(folder / 'raw-outputs.tar.gz') as archive:
        files = {member.name: archive.extractfile(member).read()
                 for member in archive.getmembers() if member.isfile()}
    assert set(files) == set(expected)
    for name, data in files.items():
        assert hashlib.sha256(data).hexdigest() == expected[name]
        if name.endswith('/metrics.json'):
            metrics = json.loads(data)
            pcap = files[name.removesuffix('metrics.json') + 'traffic.pcap']
            assert metrics['traffic'] == engine.pcap_stats(SimpleNamespace(read_bytes=lambda: pcap))
            assert metrics['capture_complete'] == (metrics['capture_dropped'] == 0)
            assert metrics['peak_rss_kib'] > 0
    metadata = json.loads((folder / 'metadata.json').read_text())
    assert hashlib.sha256(files['sources/benchmark-port-discovery.py']).hexdigest() == metadata['runner_sha256']
