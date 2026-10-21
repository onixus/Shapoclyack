"""Pinned upstream detector acceptance on isolated loopback only.

Run with --network none, /catalog=v9.9.4, /fixture-bin/nuclei=v3.11.1,
/work=this checkout and /evidence writable. No vulnerable appliance is claimed:
responses implement upstream matcher contracts for regression acceptance.
"""
import hashlib
import json
import os
import platform
import signal
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import scanner.pipeline.nuclei_scan as adapter
from scanner.pipeline.config_schema import NucleiConfig
from scanner.pipeline.nuclei_plan import catalog, snapshot_catalog

ROOT = Path('/evidence')
ROOT.mkdir(exist_ok=True)
active = {p.name for p in Path('/sys/class/net').iterdir()
          if (p / 'flags').is_file() and int((p / 'flags').read_text(), 16) & 1}
assert active == {'lo'}, active
os.environ['PATH'] = '/fixture-bin:' + os.environ['PATH']
CATALOG = Path('/catalog')
digest, rows, error = catalog([CATALOG], 20000)
assert error is None, error
expected = {'apache-server-status', 'nginx-status', 'public-tomcat-manager', 'CVE-2000-0114'}
full = os.environ.get('FULL_CATALOG') == '1'
selected = [r for r in rows if r['http'] and r['scope_safe'] and
            not set(r['tags']) & {'intrusive', 'fuzz', 'dos'} and
            (full or r['id'] in expected)]
assert expected <= {r['id'] for r in selected}
templates = ROOT / 'templates'
templates.mkdir(exist_ok=True)
snapshot_catalog([CATALOG], selected, templates)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests += 1
        self.server.authorities.add(self.headers.get('Host'))
        content = {
            '/server-info': 'Apache Server Information\nServer Version: Apache/2.4.62',
            '/server-status': 'Apache Server Status\nServer Version: Apache/2.4.62',
            '/nginx_status': 'Active connections: 1',
            '/nginx-status': 'Active connections: 1',
            '/manager/html': 'Tomcat Manager',
            '/host-manager/html': 'Tomcat Manager',
            '/_vti_inf.html': '_vti_bin/shtml.dll',
        }.get(self.path)
        self.send_response(200 if content else 404)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        try:
            self.wfile.write((content or 'not found').encode())
        except (BrokenPipeError, ConnectionResetError):
            pass
    do_POST = do_GET
    def log_message(self, *args):
        pass

class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 256
    def get_request(self):
        sock, addr = super().get_request()
        self.connections += 1
        if hasattr(self, 'tls'):
            try:
                sock = self.tls.wrap_socket(sock, server_side=True)
            except (ssl.SSLError, ConnectionResetError):
                sock.close()
                raise OSError('fixture TLS handshake rejected')
        return sock, addr

class IPv6Server(Server):
    address_family = socket.AF_INET6

servers = []
for cls, addr, tls in ((Server, '127.0.0.1', False), (IPv6Server, '::1', True)):
    server = cls((addr, 0), Handler)
    server.requests = server.connections = 0
    server.authorities = set()
    server.snis = set()
    if tls:
        cert, key = ROOT / 'cert.pem', ROOT / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=fixture.example'], check=True, capture_output=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        context.set_servername_callback(lambda sock, name, ctx: server.snis.add(name))
        server.tls = context
    threading.Thread(target=server.serve_forever, daemon=True).start()
    servers.append(server)

measurements = []
def command(argv, **kwargs):
    started = time.monotonic()
    out, err = ROOT / f'process-{len(measurements)}.stdout', ROOT / f'process-{len(measurements)}.stderr'
    with out.open('w') as stdout, err.open('w') as stderr:
        process = subprocess.Popen(argv, stdout=stdout, stderr=stderr, start_new_session=True)
        while True:
            pid, status, usage = os.wait4(process.pid, os.WNOHANG)
            if pid:
                break
            if time.monotonic() - started >= kwargs['timeout']:
                os.killpg(process.pid, signal.SIGKILL)
                _, status, usage = os.wait4(process.pid, 0)
                break
            time.sleep(.01)
        process.returncode = os.waitstatus_to_exitcode(status)
    measurements.append({'cpu_seconds': usage.ru_utime + usage.ru_stime,
                         'peak_rss_kib': usage.ru_maxrss,
                         'wall_seconds': time.monotonic() - started})
    return subprocess.CompletedProcess(argv, process.returncode, out.read_text(), err.read_text())
adapter.run_command = command
report = {'network': 'none; loopback only', 'active_interfaces': sorted(active),
          'architecture': platform.machine(), 'catalog_ref': 'v9.9.4',
          'catalog_commit': 'f4251b06c100067f230c4f54a1679de59802c7a4',
          'catalog_sha256': digest, 'catalog_rows': len(rows),
          'selection': 'full scope-proven policy-eligible catalog' if full else 'four upstream matcher contracts',
          'selected_templates': len(selected), 'expected_ids': sorted(expected),
          'engine': subprocess.run(['nuclei', '-version'], capture_output=True, text=True).stderr.strip(),
          'engine_sha256': hashlib.sha256(Path('/fixture-bin/nuclei').read_bytes()).hexdigest(),
          'instrumentation_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          'source_sha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in
                            [Path('scanner/pipeline') / n for n in ('nuclei_plan.py', 'nuclei_scan.py', 'config_schema.py')]},
          'template_sha256': {r['id']: r['sha256'] for r in selected}, 'runs': []}
# Full eligible catalog is measured on one HTTP endpoint; mixed-scheme and
# wrong/unknown technology runs use the representative pinned detectors.
scenarios = ('known',) if full else ('known', 'unknown', 'wrong_technology')
for scenario in scenarios:
    for mode in ('legacy', 'directed'):
        directory = ROOT / f'{scenario}-{mode}'
        directory.mkdir(exist_ok=True)
        active_servers = servers[:1] if full else servers
        services = []
        for index, server in enumerate(active_servers):
            services.append({'ip': server.server_address[0], 'port': server.server_port,
                             'service': 'unknown' if scenario == 'unknown' else ('http' if index == 0 else 'https'),
                             'confidence': 0 if scenario == 'unknown' else 100,
                             'product': {'known': 'nginx', 'unknown': '', 'wrong_technology': 'wordpress'}[scenario]})
        (directory / 'services.json').write_text(json.dumps(services))
        before = [(s.connections, s.requests) for s in active_servers]
        start, count = time.monotonic(), len(measurements)
        ports = [s.server_port for s in active_servers]
        cfg = NucleiConfig(templates_dir=str(templates), planner_mode=mode,
                           network_templates=False, severities=[], http_ports=ports, https_ports=ports,
                           retries=0, concurrency=10, rate_limit=1000, max_host_error=10000,
                           timeout_seconds=5, overall_timeout_seconds=120)
        result = adapter.run_nuclei_scan([
            f"{'[' + r['ip'] + ']' if ':' in r['ip'] else r['ip']}:{r['port']}/tcp" for r in services
        ], cfg, directory)
        metrics = measurements[count:]
        found = {r['template_id'] for r in result['findings']}
        endpoint_findings = {
            r['ip']: sorted({f['template_id'] for f in result['findings']
                             if urlsplit(f['matched_at']).hostname == r['ip']
                             and urlsplit(f['matched_at']).port == r['port']
                             and urlsplit(f['matched_at']).scheme == ('http' if i == 0 else 'https')})
            for i, r in enumerate(services)
        }
        row = {'scenario': scenario, 'mode': mode, 'wall_seconds': time.monotonic() - start,
               'cpu_seconds': sum(m['cpu_seconds'] for m in metrics),
               'peak_rss_kib': max((m['peak_rss_kib'] for m in metrics), default=0),
               'processes': len(metrics), 'selected_templates': len(selected),
               'connections': sum(s.connections - n[0] for s,n in zip(active_servers,before)),
               'requests': sum(s.requests - n[1] for s,n in zip(active_servers,before)),
               'found_ids': sorted(found), 'expected_found': sorted(expected & found),
               'expected_preserved': all(expected <= set(v) for v in endpoint_findings.values()),
               'endpoint_findings': endpoint_findings, 'checked_count': result['checked_count'],
               'coverage_ran': result['coverage']['ran'], 'skipped_reason': result.get('skipped_reason')}
        report['runs'].append(row)
        print(json.dumps(row), flush=True)
        (ROOT / 'benchmark.json').write_text(json.dumps(report, indent=2) + '\n')
        assert row['expected_preserved'], row
# Actual Host + SNI capture uses the same adapter and the real upstream detector.
if not full:
    server = servers[1]
    directory = ROOT / 'vhosts'
    directory.mkdir(exist_ok=True)
    (directory / 'services.json').write_text(json.dumps([{'ip': '::1', 'port': server.server_port, 'service': 'https', 'confidence': 100}]))
    (directory / 'dns_resolution.json').write_text(json.dumps({'records': [
        {'host': name, 'aaaa': ['::1']} for name in ('a.fixture.example', 'b.fixture.example')]}))
    result = adapter.run_nuclei_scan([f'[::1]:{server.server_port}/tcp'],
        NucleiConfig(templates_dir=str(templates), planner_mode='directed', network_templates=False,
                     severities=[], retries=0, timeout_seconds=1, overall_timeout_seconds=60), directory)
    raw = [json.loads(line) for line in (directory / 'nuclei_raw.jsonl').read_text().splitlines()]
    vhost_findings = {
        name: sorted({f['template-id'] for f in raw
                      if f['shapoclyack_input']['authority'] == f'{name}:{server.server_port}'
                      and f['shapoclyack_input']['sni'] == name
                      and urlsplit(f['matched-at']).hostname == '::1'
                      and urlsplit(f['matched-at']).port == server.server_port
                      and urlsplit(f['matched-at']).scheme == 'https'})
        for name in ('a.fixture.example', 'b.fixture.example')
    }
    assert all(expected <= set(ids) for ids in vhost_findings.values())
    report['vhosts'] = {'authorities': sorted(server.authorities),
                        'expected_findings_by_authority': vhost_findings,
                        'snis': sorted(x for x in server.snis if x),
                        'complete': result['coverage']['plan']['complete'],
                        'raw_rows': len((directory / 'nuclei_raw.jsonl').read_text().splitlines())}
    assert {'a.fixture.example', 'b.fixture.example'} <= server.snis
    assert all(f'{name}:{server.server_port}' in server.authorities for name in ('a.fixture.example', 'b.fixture.example'))
(ROOT / 'benchmark.json').write_text(json.dumps(report, indent=2) + '\n')
for server in servers:
    server.shutdown()
