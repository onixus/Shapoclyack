"""Fixed loopback comparison including real TLS, OS attempts and pinned Nuclei.

Run only through run-discovery-downstream-benchmark.sh. Not a product backend.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import ssl
import subprocess

SPEC = importlib.util.spec_from_file_location('ports', Path(__file__).with_name('benchmark-port-discovery.py'))
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)
NUCLEI_SHA256 = '7a2fb8a51e4aa0e0aefc57bf8865ea32c4e307de8f44e125e532884d6129156d'
TEMPLATE_SHA256 = 'e6de6a8870f3c329ba43e63443bb76f4412711903394b95c392242fa2f5e996d'


def canonical_observations(outputs):
    """Retain semantic OS/TLS fields but remove observation timestamps/latency."""
    services = B.service_observations(outputs)
    tls = sorted({(r.get('ip', r.get('host')), r['port'],
                   json.dumps({k: r.get(k) for k in ('subject_cn', 'issuer_cn', 'not_before', 'not_after',
                       'negotiated_protocol', 'self_signed', 'http_product', 'http_version')}, sort_keys=True))
                  for o in outputs for r in o.get('tls', [])})
    pulse_findings = sorted({(r.get('ip'), r.get('port'), r.get('finding_class'), r.get('source'),
                              r.get('title'), r.get('severity'))
                             for o in outputs for r in o.get('findings', [])})
    os_rows = [r for o in outputs for r in o.get('os', [])]
    return {'services': services, 'tls': tls, 'os': os_rows, 'pulse_findings': pulse_findings}


def main(args):
    B.validate_repeats(args.repeats)
    engine = B.load_engine()
    engine.verify_binary(B.PINS['pulse'])
    for path, expected in [('/usr/local/bin/naabu', B.PINS['naabu']),
                           ('/usr/local/bin/nuclei', NUCLEI_SHA256),
                           ('/template/nginx-status.yaml', TEMPLATE_SHA256)]:
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected:
            raise ValueError('immutable input mismatch: ' + path)
    # Includes the strict interface and Docker checks in the existing runner.
    kernel_defaults = {'tunl0', 'gre0', 'gretap0', 'erspan0', 'ip_vti0', 'ip6_vti0', 'sit0', 'ip6tnl0', 'ip6gre0'}
    if not Path('/.dockerenv').exists() or {n for _, n in B.socket.if_nameindex()} - ({'lo'} | kernel_defaults):
        raise ValueError('network none with only loopback required')
    out = Path(args.output)
    out.mkdir()
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=discovery-loopback-fixture', '-keyout', str(out / 'key.pem'),
                    '-out', str(out / 'cert.pem')], check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(out / 'cert.pem', out / 'key.pem')

    class Fixture(engine.Server):
        def handle(self, conn):
            try:
                conn.settimeout(.5)
                if self.kind == 'tls':
                    conn = self.ctx.wrap_socket(conn, server_side=True)
                if self.kind == 'ssh':
                    conn.sendall(b'SSH-2.0-OpenSSH_9.2\r\n')
                else:
                    conn.recv(8192)
                    body = b'Active connections: 1\nserver accepts handled requests\n 1 1 1\nReading: 0 Writing: 1 Waiting: 0\n'
                    conn.sendall(b'HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nConnection: close\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
            except (OSError, ssl.SSLError):
                pass
            finally:
                conn.close()

    servers = [Fixture(h, p, k, ctx) for h, p, k in zip(B.HOSTS, [8080, 8443, 2222], ['http', 'tls', 'ssh'])]
    truth = sorted((s.host, s.port, 'tcp') for s in servers)
    service_truth = sorted([(B.HOSTS[0], 8080, 'http', 'nginx', '1.24.0'),
                            (B.HOSTS[1], 8443, 'https-alt', 'nginx', '1.24.0'),
                            (B.HOSTS[2], 2222, 'ssh', 'OpenSSH', '9.2')])
    expected_findings = sorted(('nginx-status', url, url + path)
        for url in ['http://127.20.0.1:8080', 'https://127.20.0.2:8443']
        for path in ['/nginx_status', '/nginx-status'])
    rows = []
    try:
        for cache in ['cold', 'warm']:
            for repeat in range(args.repeats):
                for variant in ['baseline_union', 'fixed_exact', 'pulse_reuse']:
                    name = f'{cache}-{repeat}-{variant}'
                    home = out / (f'home-{cache}-{variant}' + (f'-{repeat}' if cache == 'cold' else ''))
                    home.mkdir(exist_ok=True)
                    home.chmod(0o777)
                    stages, outputs = [], []
                    discovered = []
                    if variant != 'pulse_reuse':
                        argv = ['naabu', '-host', ','.join(B.HOSTS), '-p', ','.join(map(str, B.PORTS)),
                                '-s', 'c', '-json', '-silent', '-duc', '-no-stdin', '-Pn', '-rate', '100',
                                '-c', '16', '-retries', '1', '-timeout', '300', '-warm-up-time', '1']
                        m, stdout = B.run_command(out / (name + '-discovery'), argv, 'unprivileged', servers, engine, home)
                        stages.append(dict(stage='discovery', **m))
                        discovered = B.normalize('naabu', stdout) if m['returncode'] == 0 else []
                    for i, (hosts, ports) in enumerate(B.enrichment_plan(variant, discovered)):
                        argv = ['pulse', hosts, '-p', ','.join(map(str, ports)), '-b',
                                '-q', '-f', 'json', '--all', '--no-nmap-data', '--rate', '100', '-c', '16',
                                '-t', '300', '--max-retries', '0']
                        m, stdout = B.run_command(out / f'{name}-enrichment-{i}', argv, 'unprivileged', servers, engine, home, deadline_seconds=60)
                        stages.append(dict(stage='combined_discovery_enrichment' if variant == 'pulse_reuse' else 'enrichment', **m))
                        outputs.append(json.loads(stdout) if m['returncode'] == 0 else {'results': []})
                    endpoints = sorted({e for o in outputs for e in B.normalize('pulse', json.dumps(o))})
                    observations = canonical_observations(outputs)
                    tls_endpoints = {(r[0], r[1]) for r in observations['tls']}
                    urls = sorted({f'{"https" if (h,p) in tls_endpoints else "http"}://{h}:{p}'
                                   for h, p, _ in endpoints if p in [8080, 8443]})
                    targets = out / (name + '-urls.txt')
                    targets.write_text('\n'.join(urls) + '\n')
                    argv = ['nuclei', '-l', str(targets), '-t', '/template/nginx-status.yaml', '-jsonl', '-silent',
                            '-duc', '-ni', '-no-stdin', '-rl', '100', '-c', '4', '-timeout', '1', '-retries', '0']
                    m, stdout = B.run_command(out / (name + '-verification'), argv, 'unprivileged', servers, engine, home, deadline_seconds=60)
                    stages.append(dict(stage='verification', **m))
                    findings = sorted({(r['template-id'], r['url'], r['matched-at']) for line in stdout.splitlines() if line.strip() for r in [json.loads(line)]})
                    row = {'cache': cache, 'repeat': repeat, 'variant': variant, 'endpoints': endpoints,
                           'endpoints_match_truth': endpoints == truth, **observations, 'findings': findings,
                           'tls_matches_truth': tls_endpoints == {(B.HOSTS[1], 8443)},
                           'services_match_truth': observations['services'] == service_truth,
                           'findings_match_truth': findings == expected_findings,
                           'os_status': 'disabled_after_scope_budget_preflight_failure',
                           'stages': stages, 'seconds': sum(m['seconds'] for m in stages),
                           'execution_complete': all(B.outcome(m) == 'executed_coverage_unverified' for m in stages)}
                    rows.append(row)
                    (out / 'chains.json').write_text(json.dumps(rows, indent=2))
                    print(json.dumps({k: row[k] for k in ['cache', 'repeat', 'variant', 'endpoints_match_truth', 'tls_matches_truth', 'services_match_truth', 'findings_match_truth', 'execution_complete']}), flush=True)
    finally:
        for server in servers:
            server.close()
        (out / 'key.pem').unlink()
    (out / 'provenance.json').write_text(json.dumps({'pulse': B.PINS['pulse'], 'naabu': B.PINS['naabu'],
        'nuclei': NUCLEI_SHA256, 'template': TEMPLATE_SHA256,
        'template_source': 'projectdiscovery/nuclei-templates v9.9.4 f4251b06c100067f230c4f54a1679de59802c7a4 http/misconfiguration/nginx/nginx-status.yaml',
        'truth_services': service_truth, 'truth_nuclei_findings': expected_findings,
        'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'helper_sha256': hashlib.sha256(Path(B.__file__).read_bytes()).hexdigest(),
        'engine_sha256': hashlib.sha256(Path(engine.__file__).read_bytes()).hexdigest(),
        'privilege_profile': 'all scanner stages UID/GID 65534; no-new-privs; no raw capabilities',
        'limitations': ['CLI stage sums, not scheduler pipeline', 'controlled banners are not real nginx/sshd',
                        'OS fingerprints require classified evidence, equal empty OS arrays are not parity',
                        'no routed topology or installed sensor acceptance']}, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', required=True)
    p.add_argument('--repeats', type=int, default=5)
    main(p.parse_args())
