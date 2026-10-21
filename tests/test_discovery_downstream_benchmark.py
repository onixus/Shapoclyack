"""Independent audit of pinned discovery/TLS/Nuclei experiment evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import statistics
import tarfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'docs/benchmarks/port-discovery-20261020'
SPEC = importlib.util.spec_from_file_location('downstream_bench', ROOT / 'scripts/benchmark-discovery-downstream.py')
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


def archive_files():
    with tarfile.open(FOLDER / 'raw-outputs.tar.gz') as archive:
        return {m.name: archive.extractfile(m).read() for m in archive.getmembers() if m.isfile()}


def test_flattened_tls_certificate_is_not_lost_in_canonicalization():
    row = {'ip': '127.20.0.2', 'port': 8443, 'subject_cn': 'fixture', 'issuer_cn': 'issuer',
           'negotiated_protocol': 'TLSv1_3', 'self_signed': True}
    observations = BENCH.canonical_observations([{'results': [], 'tls': [row]}])
    certificate = json.loads(observations['tls'][0][2])
    assert certificate['subject_cn'] == 'fixture'
    assert certificate['issuer_cn'] == 'issuer'
    assert certificate['negotiated_protocol'] == 'TLSv1_3'


def test_downstream_raw_evidence_integrity_sources_and_capture():
    files = archive_files()
    expected = json.loads((FOLDER / 'raw-sha256.json').read_text())
    assert set(files) == set(expected)
    for name, data in files.items():
        assert hashlib.sha256(data).hexdigest() == expected[name], name
        if name.endswith('/metrics.json'):
            metrics = json.loads(data)
            pcap = files[name.removesuffix('metrics.json') + 'traffic.pcap']
            assert metrics['traffic'] == BENCH.B.load_engine().pcap_stats(SimpleNamespace(read_bytes=lambda: pcap))
    provenance = json.loads((FOLDER / 'provenance.json').read_text())
    for key, name in [('source_sha256', 'benchmark-discovery-downstream.py'),
                      ('helper_sha256', 'benchmark-port-discovery-downstream-helper.py'),
                      ('engine_sha256', 'benchmark-pulse-engine.py')]:
        assert hashlib.sha256(files['sources/' + name]).hexdigest() == provenance[key]
    metadata = json.loads((FOLDER / 'discovery-metadata.json').read_text())
    assert hashlib.sha256(files['sources/benchmark-port-discovery.py']).hexdigest() == metadata['runner_sha256']
    assert hashlib.sha256((FOLDER / 'nginx-status.yaml').read_bytes()).hexdigest() == BENCH.TEMPLATE_SHA256
    assert not any(name.endswith('/key.pem') for name in files)
    for line in (FOLDER / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split('  ', 1)
        assert hashlib.sha256((FOLDER / name).read_bytes()).hexdigest() == digest


def test_all_thirty_actual_chains_preserve_expected_endpoints_services_tls_findings():
    files = archive_files()
    rows = json.loads((FOLDER / 'chains.json').read_text())
    provenance = json.loads((FOLDER / 'provenance.json').read_text())
    assert len(rows) == 30
    for row in rows:
        prefix = 'downstream/' + f"{row['cache']}-{row['repeat']}-{row['variant']}"
        outputs = [json.loads(data) for name, data in files.items()
                   if name.startswith(prefix + '-enrichment-') and name.endswith('/stdout')]
        observed = BENCH.canonical_observations(outputs)
        assert json.loads(json.dumps(observed['services'])) == provenance['truth_services']
        assert len(observed['tls']) == 1
        host, port, certificate = observed['tls'][0]
        assert (host, port) == ('127.20.0.2', 8443)
        certificate = json.loads(certificate)
        assert certificate['subject_cn'] == certificate['issuer_cn'] == 'discovery-loopback-fixture'
        assert certificate['self_signed'] is True
        assert certificate['negotiated_protocol'] == 'TLSv1_3'
        assert len(observed['pulse_findings']) == 2
        assert {f[4] for f in observed['pulse_findings']} == {
            'TLS certificate expiring soon', 'TLS certificate self-signed (heuristic)'}
        findings = [json.loads(line) for line in files[prefix + '-verification/stdout'].splitlines() if line.strip()]
        actual = sorted({(r['template-id'], r['url'], r['matched-at']) for r in findings})
        assert json.loads(json.dumps(actual)) == provenance['truth_nuclei_findings']
        assert row['execution_complete'] and row['endpoints_match_truth']
        assert row['services_match_truth'] and row['findings_match_truth'] and row['tls_matches_truth']
        assert all(m['returncode'] == 0 and not m['timed_out'] and m['capture_complete'] for m in row['stages'])
        assert row['seconds'] == sum(m['seconds'] for m in row['stages'])
        assert row['os_status'] == 'disabled_after_scope_budget_preflight_failure'
        baseline = next(r for r in rows if r['cache'] == row['cache'] and r['repeat'] == row['repeat'] and r['variant'] == 'baseline_union')
        for key in ['services', 'tls', 'findings', 'pulse_findings']:
            assert row[key] == baseline[key]
    for group in json.loads((FOLDER / 'chains-summary.json').read_text()):
        sample = [r for r in rows if (r['cache'], r['variant']) == (group['cache'], group['variant'])]
        assert len(sample) == 5
        assert {r['repeat'] for r in sample} == set(range(5))
        assert group['semantic_parity_samples'] == 5
        assert group['seconds'] == {'median': statistics.median(r['seconds'] for r in sample),
                                    'min': min(r['seconds'] for r in sample),
                                    'max': max(r['seconds'] for r in sample)}


def test_os_preflight_exposes_implicit_probes_outside_declared_ports():
    files = archive_files()
    metrics = json.loads(files['os-preflight/cold-0-baseline_union-enrichment-0/metrics.json'])
    assert metrics['timed_out'] and metrics['returncode'] != 0
    declared = {2222, 8080, 8443}
    observed = {int(endpoint.rsplit(':', 1)[1]) for endpoint in metrics['traffic']['tcp_syn']}
    assert {21, 22, 25, 80, 135, 139, 443, 445, 3306, 3389, 5900} <= observed - declared


def test_native_resume_requires_reconciling_the_cancelled_stream():
    files = archive_files()
    partial = BENCH.B.normalize('naabu', files['discovery/naabu_cancel/stdout'].decode())
    resumed = BENCH.B.normalize('naabu', files['discovery/naabu_resume/stdout'].decode())
    expected = [('127.20.0.1', 8080, 'tcp'), ('127.20.0.2', 8443, 'tcp'), ('127.20.0.3', 2222, 'tcp')]
    assert sorted(set(partial) | set(resumed)) == expected
    assert resumed != expected
    assert BENCH.B.normalize('pulse', files['discovery/pulse_resume/stdout'].decode()) == expected
    argv = json.loads(files['discovery/naabu_resume/metrics.json'])['argv']
    assert '-resume' in argv and '-host' in argv and '-p' in argv
