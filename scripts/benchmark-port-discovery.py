"""Issue 452: fixed-scope, network-none, real-binary discovery experiment.

This is an experiment, not a selectable product backend. No arbitrary targets.
"""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import socket
import statistics
import struct
import subprocess
import threading
import time

HOSTS = ['127.20.0.1', '127.20.0.2', '127.20.0.3']
PORTS = [2222, 8080, 8443, 8999]
PINS = {'pulse': '9e825d76783e5bc35ae66d8c485eb083c0725a53ac2e0d05e94c89bbdc9af529',
        'naabu': '231b3b89a3695ae874e6f7007c3da37c93cf7bfbf689579eaf0d5d6062b4abb3'}

def load_engine():
    spec = importlib.util.spec_from_file_location('engine', Path(__file__).with_name('benchmark-pulse-engine.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_repeats(value):
    if not 5 <= value <= 100:
        raise ValueError('repeats must be 5..100')


def normalize(tool, stdout):
    if tool == 'naabu':
        return sorted({(r['ip'], int(r['port']), r.get('protocol', 'tcp'))
                      for line in stdout.splitlines() if line.strip()
                      for r in [json.loads(line)]})
    data = json.loads(stdout)
    rows = data if isinstance(data, list) else data.get('results', data.get('hosts', []))
    found = []
    for row in rows:
        if row.get('state') == 'open':
            found.append((row.get('ip', row.get('host')), int(row['port']), 'tcp' if row.get('protocol', 'tcp') == 'tcpsyn' else row.get('protocol', 'tcp')))
    return sorted(found)


def enrichment_plan(variant, discovered):
    """Build plans from observed endpoints; truth must never repair a miss."""
    allowed = {(h, p, 'tcp') for h in HOSTS for p in PORTS}
    if not set(discovered) <= allowed:
        raise ValueError('discovery produced an endpoint outside fixed fixture scope')
    if variant == 'fixed_exact':
        return [(h, sorted({p for host, p, _ in discovered if host == h}))
                for h in sorted({host for host, _, _ in discovered})]
    if variant == 'baseline_union':
        return [(','.join(sorted({h for h, _, _ in discovered})),
                 sorted({p for _, p, _ in discovered}))] if discovered else []
    if variant == 'pulse_reuse':
        return [(','.join(HOSTS), PORTS)]
    raise ValueError('unknown pipeline variant')


def demote():
    # Prevent file capabilities from restoring raw privileges at exec.
    if ctypes.CDLL(None).prctl(38, 1, 0, 0, 0):
        raise OSError('PR_SET_NO_NEW_PRIVS failed')
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)


class Capture:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, 33, 4 * 1024 * 1024)  # SO_RCVBUFFORCE, Linux
        except OSError:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        self.sock.bind(('lo', 0))
        self.sock.settimeout(.1)
        self.file = path.open('wb')
        self.file.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        self.stop = False
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
    def run(self):
        while not self.stop:
            try:
                frame = self.sock.recv(65535)
            except socket.timeout:
                continue
            now = time.time()
            self.file.write(struct.pack('<IIII', int(now), int(now % 1 * 1e6), len(frame), len(frame)))
            self.file.write(frame)
    def close(self):
        time.sleep(.1)
        self.stop = True
        self.thread.join(1)
        # PACKET_STATISTICS includes kernel socket drops since last read.
        received, dropped = struct.unpack('II', self.sock.getsockopt(263, 6, 8))
        self.sock.close()
        self.file.close()
        return received, dropped


def run_command(out, argv, profile, servers, engine, home, cancel_after=None):
    out.mkdir()
    before = [s.count for s in servers]
    cap = Capture(out / 'traffic.pcap')
    start = time.monotonic()
    expired = threading.Event()
    kill_timer = None
    with (out / 'stdout').open('w') as stdout_file, (out / 'stderr').open('w') as stderr_file:
        proc = subprocess.Popen(argv, stdout=stdout_file, stderr=stderr_file,
                                preexec_fn=demote if profile == 'unprivileged' else None,
                                env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(home)})
        def expire():
            nonlocal kill_timer
            expired.set()
            try:
                os.kill(proc.pid, signal.SIGINT)
            except ProcessLookupError:
                return
            def kill():
                try:
                    os.kill(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            kill_timer = threading.Timer(5, kill)
            kill_timer.start()
        timer = threading.Timer(cancel_after or 10, expire)
        timer.start()
        try:
            _, status, usage = os.wait4(proc.pid, 0)
            proc.returncode = os.waitstatus_to_exitcode(status)
            elapsed = time.monotonic() - start
        finally:
            timer.cancel()
            if kill_timer is not None:
                kill_timer.cancel()
            received, dropped = cap.close()
    stdout = (out / 'stdout').read_text()
    metrics = {'argv': argv, 'returncode': proc.returncode, 'seconds': elapsed, 'cancellation_requested': cancel_after is not None and expired.is_set(),
               'timed_out': cancel_after is None and expired.is_set(), 'deadline_seconds': cancel_after or 10,
               'cpu_seconds': usage.ru_utime + usage.ru_stime,
               'peak_rss_kib': usage.ru_maxrss, 'processes': 1,
               'accepted_connections': sum(s.count - c for s, c in zip(servers, before)),
               'traffic': engine.pcap_stats(out / 'traffic.pcap'), 'capture_dropped': dropped,
               'packet_socket_received': received, 'capture_complete': dropped == 0}
    (out / 'metrics.json').write_text(json.dumps(metrics, indent=2))
    return metrics, stdout


def summarize(rows):
    groups = {}
    for row in rows:
        groups.setdefault((row['profile'], row['cache'], row['variant']), []).append(row)
    result = []
    for key, samples in sorted(groups.items()):
        if len(samples) < 5 or len({s['repeat'] for s in samples}) != len(samples):
            raise ValueError('need at least five distinct repetitions per group')
        result.append(dict(zip(['profile', 'cache', 'variant'], key), samples=len(samples),
                           **{f'{name}_{stat}': round(fn([r[name] for r in samples]), 6)
                              for name in ['seconds', 'cpu_seconds', 'accepted_connections', 'packets', 'wire_bytes', 'peak_rss_kib', 'processes']
                              for stat, fn in [('median', statistics.median), ('min', min), ('max', max)]},
                           endpoint_matches=sum(s['matches_truth'] for s in samples),
                           capture_complete_samples=sum(s.get('capture_complete', False) for s in samples)))
    return result


def main(args):
    validate_repeats(args.repeats)
    engine = load_engine()
    engine.verify_binary(PINS['pulse'])
    if not Path('/.dockerenv').is_file():
        raise ValueError('Docker container required; refusing host network changes')
    # Linux may instantiate these inactive default tunnel devices in every
    # new netns after their modules load. engine.verify_binary already rejects
    # ANY active non-loopback interface, including these defaults.
    kernel_defaults = {'tunl0', 'gre0', 'gretap0', 'erspan0', 'ip_vti0', 'ip6_vti0', 'sit0', 'ip6tnl0', 'ip6gre0'}
    if {name for _, name in socket.if_nameindex()} - ({'lo'} | kernel_defaults):
        raise ValueError('interfaces outside allowed inactive kernel defaults; network none required')
    for name, digest in PINS.items():
        if hashlib.sha256(Path('/usr/local/bin/' + name).read_bytes()).hexdigest() != digest:
            raise ValueError(f'{name} binary hash mismatch')
    out = Path(args.output)
    out.mkdir()
    help_text = {}
    for tool in PINS:
        r = subprocess.run([tool, '--help' if tool == 'pulse' else '-h'], capture_output=True, text=True)
        help_text[tool] = r.stdout + r.stderr
        (out / f'{tool}-help.txt').write_text(help_text[tool])
    ctx = None
    servers = [engine.Server(h, p, kind, ctx) for h, p, kind in
               zip(HOSTS, [8080, 8443, 2222], ['http', 'http', 'ssh'])]
    truth = sorted((s.host, s.port, 'tcp') for s in servers)
    metadata = {'pins': PINS, 'platform': platform.platform(), 'network': 'none; loopback only',
                'truth_open': truth, 'truth_closed': [(h, p, 'tcp') for h in HOSTS for p in PORTS if (h, p, 'tcp') not in truth],
                'udp_truth': {'8997': 'echo responder', '8998': 'bound socket silently discards requests', '8999': 'unbound closed port'},
                'cache_definition': 'cold=fresh per-command HOME; warm=shared HOME; no page-cache flush',
                'capture_definition': 'AF_PACKET lo includes outgoing/incoming copies; packets are captured frames, bytes sum captured Ethernet wire lengths; no physical-wire claim',
                'profile': 'TCP discovery invocation including engine implicit service probes; pipeline stages use identical banner flags; OS/TLS/CVE options disabled',
                'rss_definition': 'Linux per-child peak RSS in KiB from wait4, including pre-exec fork memory; not binary-only or total concurrent memory',
                'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (out / 'metadata.json').write_text(json.dumps(metadata, indent=2))
    rows = []
    discoveries = {}
    try:
        for profile in ['unprivileged', 'root_syn']:
            for cache in ['cold', 'warm']:
                for repeat in range(args.repeats):
                    for variant in (['naabu', 'pulse'] if repeat % 2 == 0 else ['pulse', 'naabu']):
                        common = ['-p', ','.join(map(str, PORTS))]
                        if variant == 'naabu':
                            argv = ['naabu', '-host', ','.join(HOSTS), *common, '-s', 's' if profile == 'root_syn' else 'c',
                                    '-json', '-silent', '-duc', '-no-stdin', '-Pn', '-rate', '100', '-c', '16',
                                    '-retries', '1', '-timeout', '150', '-warm-up-time', '1']
                        else:
                            argv = ['pulse', ','.join(HOSTS), *common, '-f', 'json', '-q', '--all', '--no-nmap-data',
                                    '--rate', '100', '-c', '16', '-t', '150', '--max-retries', '0']
                            if profile == 'root_syn':
                                argv += ['--syn', '--syn-retries', '0']
                        home = out / ('home-' + profile + ('-warm-' + variant if cache == 'warm' else f'-cold-{repeat}-{variant}'))
                        home.mkdir(exist_ok=True)
                        home.chmod(0o777)
                        metrics, stdout = run_command(out / f'{profile}-{cache}-{repeat}-{variant}', argv, profile, servers, engine, home)
                        found = normalize(variant, stdout) if metrics['returncode'] == 0 else []
                        row = dict(profile=profile, cache=cache, repeat=repeat, variant=variant,
                                   endpoints=found, matches_truth=metrics['returncode'] == 0 and not metrics['timed_out'] and metrics['capture_complete'] and found == truth,
                                   seconds=metrics['seconds'], cpu_seconds=metrics['cpu_seconds'],
                                   peak_rss_kib=metrics['peak_rss_kib'], processes=1, capture_complete=metrics['capture_complete'],
                                   accepted_connections=metrics['accepted_connections'], packets=metrics['traffic']['packets'],
                                   wire_bytes=metrics['traffic']['wire_bytes'], returncode=metrics['returncode'])
                        discoveries[(profile, cache, repeat, variant)] = (metrics, stdout)
                        rows.append(row)
                        (out / 'results.json').write_text(json.dumps(rows, indent=2))
                        print(json.dumps(row), flush=True)
        # Same flags and targets in CLI-stage comparisons. Discovery is shared
        # from above; aggregate values are sums of recorded stages, not a timed
        # invocation of the product pipeline or its scheduler.
        pipelines = []
        for cache in ['cold', 'warm']:
            for repeat in range(args.repeats):
                discovery, discovery_stdout = discoveries[('unprivileged', cache, repeat, 'naabu')]
                discovered = normalize('naabu', discovery_stdout) if discovery['returncode'] == 0 else []
                for variant in ['baseline_union', 'fixed_exact', 'pulse_reuse']:
                    stages, outputs = [], []
                    home = out / f'pipeline-home-{cache}-{variant}'
                    if cache == 'cold':
                        home = out / f'pipeline-home-{cache}-{variant}-{repeat}'
                    home.mkdir(exist_ok=True)
                    home.chmod(0o777)
                    plans = enrichment_plan(variant, discovered)
                    for index, (hosts, ports) in enumerate(plans):
                        argv = ['pulse', hosts, '-p', ','.join(map(str, ports)), '-b', '-f', 'json', '-q',
                                '--all', '--no-nmap-data', '--rate', '100', '-c', '16', '-t', '150', '--max-retries', '0']
                        metrics, stdout = run_command(out / f'pipeline-{cache}-{repeat}-{variant}-{index}', argv,
                                                       'unprivileged', servers, engine, home)
                        stages.append(metrics)
                        outputs.append(json.loads(stdout) if metrics['returncode'] == 0 else {'results': []})
                    combined = stages if variant == 'pulse_reuse' else [discovery, *stages]
                    found = sorted({endpoint for output in outputs for endpoint in normalize('pulse', json.dumps(output))})
                    services = sorted((r['ip'], r['port'], r.get('service'), r.get('product'), r.get('version'))
                                      for output in outputs for r in output['results'] if r['state'] == 'open')
                    sample = {'profile': 'unprivileged', 'cache': cache, 'repeat': repeat, 'variant': variant,
                              'seconds': sum(m['seconds'] for m in combined), 'cpu_seconds': sum(m['cpu_seconds'] for m in combined),
                              'accepted_connections': sum(m['accepted_connections'] for m in combined),
                              'packets': sum(m['traffic']['packets'] for m in combined),
                              'wire_bytes': sum(m['traffic']['wire_bytes'] for m in combined),
                              'processes': len(combined), 'peak_rss_kib': max(m['peak_rss_kib'] for m in combined), 'matches_truth': all(m['returncode'] == 0 and not m['timed_out'] and m['capture_complete'] for m in combined) and found == truth, 'endpoints': found,
                              'services': services, 'stages': combined, 'capture_complete': all(m['capture_complete'] for m in combined)}
                    pipelines.append(sample)
                    (out / 'pipelines.json').write_text(json.dumps(pipelines, indent=2))
        (out / 'pipeline-summary.json').write_text(json.dumps(summarize(pipelines), indent=2))
        # Explicit capability outcomes; root SYN loopback does not establish
        # routed-Ethernet SYN support. No external interface is activated.
        checks = []
        home = out / 'capability-home'
        home.mkdir()
        home.chmod(0o777)
        ipv6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        ipv6.bind(('::1', 8080))
        ipv6.listen(128)
        ipv6.settimeout(.1)
        stop_ipv6 = threading.Event()
        def accept6():
            while not stop_ipv6.is_set():
                try:
                    connection, _ = ipv6.accept()
                    connection.close()
                except socket.timeout:
                    pass
        ipv6_thread = threading.Thread(target=accept6, daemon=True)
        ipv6_thread.start()
        cases = [
            ('pulse_ipv6_connect', 'unprivileged', ['pulse', '::1', '-p', '8080,8999', '-q', '-f', 'json', '--all', '-t', '150', '--no-nmap-data']),
            ('naabu_ipv6_connect', 'unprivileged', ['naabu', '-host', '::1', '-p', '8080,8999', '-s', 'c', '-iv', '6', '-json', '-silent', '-duc', '-no-stdin', '-Pn', '-retries', '1', '-timeout', '150', '-warm-up-time', '1']),
            ('pulse_no_raw_syn', 'unprivileged', ['pulse', HOSTS[0], '-p', '8080', '--syn', '-q', '-f', 'json', '-t', '150', '--no-nmap-data']),
            ('naabu_no_raw_syn', 'unprivileged', ['naabu', '-host', HOSTS[0], '-p', '8080', '-s', 's', '-json', '-silent', '-duc', '-no-stdin', '-Pn', '-retries', '1', '-timeout', '150', '-warm-up-time', '1']),
            ('pulse_udp_closed', 'root_syn', ['pulse', HOSTS[0], '-p', '8999', '--protocol', 'udp', '--icmp-states', '-q', '-f', 'json', '--all', '-t', '150', '--no-nmap-data']),
            ('naabu_udp_closed', 'root_syn', ['naabu', '-host', HOSTS[0], '-p', 'u:8999', '-json', '-silent', '-duc', '-no-stdin', '-Pn', '-retries', '1', '-timeout', '150', '-warm-up-time', '1']),
            ('pulse_max_hosts', 'unprivileged', ['pulse', ','.join(HOSTS), '-p', '8080', '--max-hosts', '2', '-q', '-f', 'json', '--no-nmap-data']),
            ('pulse_exclusion', 'unprivileged', ['pulse', ','.join(HOSTS), '-p', '2222,8080,8443', '--exclude', HOSTS[1], '-q', '-f', 'json', '--all', '-t', '150', '--no-nmap-data']),
            ('naabu_exclusion', 'unprivileged', ['naabu', '-host', ','.join(HOSTS), '-p', '2222,8080,8443', '-eh', HOSTS[1], '-s', 'c', '-json', '-silent', '-duc', '-no-stdin', '-Pn', '-retries', '1', '-timeout', '150', '-warm-up-time', '1']),
        ]
        udp_sockets = []
        udp_stop = threading.Event()
        udp_threads = []
        for family, address in [(socket.AF_INET, '127.20.0.1'), (socket.AF_INET6, '::1')]:
            for port in [8997, 8998]:
                udp = socket.socket(family, socket.SOCK_DGRAM)
                udp.bind((address, port))
                udp.settimeout(.1)
                udp_sockets.append(udp)
                def serve_udp(sock=udp, reply=port == 8997):
                    while not udp_stop.is_set():
                        try:
                            payload, peer = sock.recvfrom(65535)
                            if reply:
                                sock.sendto(payload or b'owned-fixture', peer)
                        except socket.timeout:
                            pass
                thread = threading.Thread(target=serve_udp, daemon=True)
                thread.start()
                udp_threads.append(thread)
        for address, label in [('127.20.0.1', 'v4'), ('::1', 'v6')]:
            for profile in ['root_syn', 'unprivileged']:
                cases.append((f'pulse_udp_{label}_{profile}', profile,
                              ['pulse', address, '-p', '8997,8998,8999', '--protocol', 'udp', '--all',
                               '-q', '-f', 'json', '-t', '150', '--no-nmap-data'] + (['--icmp-states'] if profile == 'root_syn' else [])))
                cases.append((f'naabu_udp_{label}_{profile}', profile,
                              ['naabu', '-host', address, '-p', 'u:8997,u:8998,u:8999', '-json', '-silent',
                               '-duc', '-no-stdin', '-Pn', '-retries', '1', '-timeout', '150', '-warm-up-time', '1']))
        cases += [
            ('pulse_ipv6_syn', 'root_syn', ['pulse', '::1', '-p', '8080,8999', '--syn', '-q', '-f', 'json', '--all', '-t', '150', '--no-nmap-data']),
            ('naabu_ipv6_syn', 'root_syn', ['naabu', '-host', '::1', '-p', '8080,8999', '-s', 's', '-iv', '6', '-json', '-silent', '-duc', '-no-stdin', '-Pn', '-retries', '1', '-timeout', '150', '-warm-up-time', '1']),
        ]
        try:
            for case, profile, argv in cases:
                case_home = home / case
                case_home.mkdir()
                case_home.chmod(0o777)
                metrics, stdout = run_command(out / case, argv, profile, servers, engine, case_home)
                checks.append({'case': case, 'metrics': metrics})
        finally:
            stop_ipv6.set()
            ipv6_thread.join(1)
            ipv6.close()
            udp_stop.set()
            for thread in udp_threads:
                thread.join(1)
            for udp in udp_sockets:
                udp.close()
        checkpoint = home / 'checkpoint.json'
        cancel_argv = ['pulse', ','.join(HOSTS), '-p', '1-100,2222,8080,8443', '--rate', '100', '--checkpoint', str(checkpoint),
                       '-q', '-f', 'json', '-t', '150', '--no-nmap-data']
        metrics, stdout = run_command(out / 'pulse_cancel', cancel_argv, 'unprivileged', servers, engine, home, cancel_after=.3)
        checks.append({'case': 'pulse_cancel', 'metrics': metrics, 'checkpoint_exists': checkpoint.exists()})
        # Complete the identical bounded scope from its saved checkpoint.
        if checkpoint.exists():
            metrics, stdout = run_command(out / 'pulse_resume', cancel_argv, 'unprivileged', servers, engine, home)
            checks.append({'case': 'pulse_resume', 'metrics': metrics, 'checkpoint_exists': checkpoint.exists()})
        # Configuration changes are confined to this verified network-none
        # namespace. The fixed lo interface is never obtained from user input.
        shaping = []
        def tc(*arguments):
            r = subprocess.run(['/sbin/tc', *arguments], capture_output=True, text=True)
            shaping.append({'argv': ['/sbin/tc', *arguments], 'returncode': r.returncode,
                            'stdout': r.stdout, 'stderr': r.stderr})
            return r.returncode == 0
        def measured_scenario(name, hosts, ports, expected):
            for repeat in range(args.repeats):
                for variant in (['naabu', 'pulse'] if repeat % 2 == 0 else ['pulse', 'naabu']):
                    if variant == 'naabu':
                        argv = ['naabu', '-host', ','.join(hosts), '-p', ports, '-s', 'c', '-json', '-silent',
                                '-duc', '-no-stdin', '-Pn', '-rate', '100', '-c', '16', '-retries', '1', '-timeout', '150', '-warm-up-time', '1']
                    else:
                        argv = ['pulse', ','.join(hosts), '-p', ports, '-q', '-f', 'json', '--all', '--no-nmap-data',
                                '--rate', '100', '-c', '16', '-t', '150', '--max-retries', '0']
                    metrics, stdout = run_command(out / f'{name}-{repeat}-{variant}', argv, 'unprivileged', servers, engine, home)
                    found = normalize(variant, stdout) if metrics['returncode'] == 0 else []
                    rows.append({'profile': name, 'cache': 'warm', 'repeat': repeat, 'variant': variant,
                                 'seconds': metrics['seconds'], 'cpu_seconds': metrics['cpu_seconds'],
                                 'peak_rss_kib': metrics['peak_rss_kib'], 'processes': 1, 'capture_complete': metrics['capture_complete'],
                                 'accepted_connections': metrics['accepted_connections'], 'packets': metrics['traffic']['packets'],
                                 'wire_bytes': metrics['traffic']['wire_bytes'], 'matches_truth': metrics['returncode'] == 0 and not metrics['timed_out'] and metrics['capture_complete'] and found == expected,
                                 'endpoints': found, 'returncode': metrics['returncode']})
                    (out / 'results.json').write_text(json.dumps(rows, indent=2))
        measured_scenario('approved_64_closed', [f'127.20.1.{i}' for i in range(1, 65)], '8999', [])
        if tc('qdisc', 'add', 'dev', 'lo', 'clsact'):
            try:
                if tc('filter', 'add', 'dev', 'lo', 'egress', 'protocol', 'ip', 'flower',
                      'dst_ip', HOSTS[0], 'ip_proto', 'tcp', 'dst_port', '8998', 'action', 'drop'):
                    for variant in ['naabu', 'pulse']:
                        argv = (['naabu', '-host', HOSTS[0], '-p', '8998,8999', '-s', 'c', '-json', '-silent', '-duc', '-no-stdin', '-Pn', '-retries', '1', '-timeout', '150', '-warm-up-time', '1']
                                if variant == 'naabu' else ['pulse', HOSTS[0], '-p', '8998,8999', '-q', '-f', 'json', '--all', '--no-nmap-data', '-t', '150'])
                        metrics, stdout = run_command(out / f'{variant}_filtered', argv, 'unprivileged', servers, engine, home)
                        checks.append({'case': f'{variant}_filtered', 'metrics': metrics,
                                       'truth': {'127.20.0.1:8998/tcp': 'filtered by lo egress drop rule', '127.20.0.1:8999/tcp': 'closed'}})
                    tc('-s', 'filter', 'show', 'dev', 'lo', 'egress')
            finally:
                tc('qdisc', 'del', 'dev', 'lo', 'clsact')
        if tc('qdisc', 'add', 'dev', 'lo', 'root', 'netem', 'delay', '10ms', 'loss', '5%', 'seed', '452'):
            try:
                measured_scenario('delay10ms_loss5pct', HOSTS, ','.join(map(str, PORTS)), truth)
                tc('-s', 'qdisc', 'show', 'dev', 'lo')
            finally:
                tc('qdisc', 'del', 'dev', 'lo', 'root')
        naabu_home = home / 'native-naabu-cancel'
        naabu_home.mkdir()
        naabu_home.chmod(0o777)
        naabu_cancel = ['naabu', '-host', ','.join(HOSTS), '-p', '1-100,2222,8080,8443', '-s', 'c', '-rate', '100',
                        '-json', '-silent', '-duc', '-no-stdin', '-Pn', '-retries', '1', '-timeout', '150', '-warm-up-time', '1']
        metrics, stdout = run_command(out / 'naabu_cancel', naabu_cancel, 'unprivileged', servers, engine, naabu_home, cancel_after=.3)
        resume_files = list(naabu_home.rglob('resume.cfg'))
        checks.append({'case': 'naabu_cancel', 'metrics': metrics,
                       'resume_files': [str(p.relative_to(naabu_home)) for p in resume_files]})
        if resume_files:
            metrics, stdout = run_command(out / 'naabu_resume', ['naabu', '-resume', '-duc', '-no-stdin'],
                                           'unprivileged', servers, engine, naabu_home)
            checks.append({'case': 'naabu_resume', 'metrics': metrics})
        (out / 'network-shaping.json').write_text(json.dumps(shaping, indent=2))
        (out / 'capabilities.json').write_text(json.dumps(checks, indent=2))
    finally:
        for server in servers:
            server.close()
    (out / 'summary.json').write_text(json.dumps(summarize(rows), indent=2))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--repeats', type=int, default=5)
    main(parser.parse_args())
