"""Speed benchmark: port discovery throughput and recall on a generated farm.

Method and scenarios: docs/benchmark-speed.md. This is a measurement harness,
not a product backend, and it has no target arguments. Every address comes
from a plan generated from a seed inside 198.19.0.0/16 (RFC 2544 benchmarking
space). The farm and the scanners each run in a fresh network namespace joined
by one veth pair; the scanner namespace has no other interface and its only
route leads to the farm, which has none either, so nothing it sends can leave
the machine.
"""
import argparse
import ctypes.util
import hashlib
import ipaddress
import json
import os
import platform
import random
import re
import resource
import selectors
import shutil
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path

TARGET_NET = ipaddress.ip_network('198.19.0.0/16')
LINK = {'farm': '198.18.0.1', 'scan': '198.18.0.2', 'prefixlen': 30}
NETNS = {'farm': 'shapo-speed-farm', 'scan': 'shapo-speed-scan'}
VETH = {'farm': 'spdfarm0', 'scan': 'spdscan0'}
# naabu runs twice: SYN is what the product asks for first, CONNECT is the
# fallback it switches to when SYN sees nothing (scanner/pipeline/ports.py).
# Nmap stays out: no code path here runs it (#97, docs/nmap-migration.md).
TOOLS = ('naabu-syn', 'naabu-connect', 'masscan')
# Ports a live host most often exposes; the rest of a host's ports are drawn
# uniformly from the scanned range so a scanner cannot win by guessing these.
COMMON_PORTS = (22, 80, 443, 25, 53, 110, 143, 445, 993, 995, 3389, 3306, 5432, 8080, 8443)
BANNERS = {22: b'SSH-2.0-OpenSSH_9.6\r\n'}
HTTP_BANNER = b'HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n'

# cidr: the swept range; live: share of its addresses that answer; ports: the
# scanned range; open_per_host: how many ports a live host listens on.
SCENARIOS = {
    'sparse': {
        'full': {'cidr': '198.19.0.0/16', 'live': 0.01, 'ports': (1, 1024), 'open_per_host': (1, 4)},
        'small': {'cidr': '198.19.0.0/22', 'live': 0.05, 'ports': (1, 1024), 'open_per_host': (1, 4)},
    },
    'dense': {
        'full': {'cidr': '198.19.0.0/22', 'live': 1.0, 'ports': (1, 1024), 'open_per_host': (1, 4)},
        'small': {'cidr': '198.19.0.0/26', 'live': 1.0, 'ports': (1, 1024), 'open_per_host': (1, 4)},
    },
    'allports': {
        'full': {'cidr': '198.19.0.0/26', 'live': 1.0, 'ports': (1, 65535), 'open_per_host': (2, 8)},
        'small': {'cidr': '198.19.0.0/30', 'live': 1.0, 'ports': (1, 65535), 'open_per_host': (2, 8)},
    },
}
# Applied on both veth ends, so the round trip gets twice the delay and about
# twice the loss: 50 ms RTT and ~1 % loss.
IMPAIRMENT = {'delay_ms': 25, 'loss_pct': 0.5}


def validate_repeats(value):
    if not 5 <= value <= 100:
        raise ValueError('repeats must be 5..100')


def validate_rate(value):
    if not 100 <= value <= 10_000_000:
        raise ValueError('rate must be 100..10000000 packets per second')


def make_plan(scenario, scale, seed, impaired=False):
    try:
        params = SCENARIOS[scenario][scale]
    except KeyError:
        raise ValueError(f'unknown scenario/scale {scenario}/{scale}') from None
    network = ipaddress.ip_network(params['cidr'])
    rng = random.Random(f'{scenario}:{scale}:{seed}')
    addresses = list(network.hosts()) if network.prefixlen < 31 else list(network)
    count = max(1, round(len(addresses) * params['live']))
    live = sorted(rng.sample(addresses, count))
    low, high = params['ports']
    common = [port for port in COMMON_PORTS if low <= port <= high]
    hosts = {}
    for address in live:
        wanted = rng.randint(*params['open_per_host'])
        ports = set()
        while len(ports) < wanted:
            if common and rng.random() < 0.6:
                ports.add(rng.choice(common))
            else:
                ports.add(rng.randint(low, high))
        hosts[str(address)] = sorted(ports)
    plan = {'scenario': scenario, 'scale': scale, 'seed': seed, 'cidr': str(network),
            'ports': [low, high], 'impairment': IMPAIRMENT if impaired else None, 'hosts': hosts}
    validate_plan(plan)
    return plan


def validate_plan(plan):
    network = ipaddress.ip_network(plan['cidr'])
    if not network.subnet_of(TARGET_NET):
        raise ValueError(f'{network} is outside {TARGET_NET}')
    low, high = plan['ports']
    if not 1 <= low <= high <= 65535:
        raise ValueError('invalid port range')
    for host, ports in plan['hosts'].items():
        if ipaddress.ip_address(host) not in network:
            raise ValueError(f'{host} is outside {network}')
        if any(not low <= port <= high for port in ports):
            raise ValueError(f'{host} has a port outside {low}-{high}')


def ground_truth(plan):
    return {(host, port) for host, ports in plan['hosts'].items() for port in ports}


def score(found, truth):
    found = set(found)
    hits = found & truth
    return {
        'expected': len(truth),
        'found': len(found),
        'true_positives': len(hits),
        'missing': len(truth - found),
        'unexpected': len(found - truth),
        'recall': round(len(hits) / len(truth), 6) if truth else 1.0,
        'precision': round(len(hits) / len(found), 6) if found else 1.0,
    }


def parse_naabu(stdout):
    found = set()
    for line in stdout.splitlines():
        line = line.strip()
        if line:
            row = json.loads(line)
            found.add((row['ip'], int(row['port'])))
    return found


MASSCAN_LINE = re.compile(r'^open tcp (\d+) (\S+) \d+$')


def parse_masscan(stdout):
    found = set()
    for line in stdout.splitlines():
        match = MASSCAN_LINE.match(line.strip())
        if match:
            found.add((match.group(2), int(match.group(1))))
    return found


PARSERS = {'naabu-syn': parse_naabu, 'naabu-connect': parse_naabu, 'masscan': parse_masscan}
# masscan's receive thread sleeps in libpcap until a packet arrives (TPACKET_V3
# has no timeout on an empty block), and it only notices its --wait window is
# over when it wakes. A real network always has some traffic; the stand's veth
# pair has none, so masscan sat there for up to two minutes after the window
# ("waiting -128-secs") and was timed for it. While masscan runs, the farm
# sends its side of the link a stray UDP datagram ten times a second.
WAKE_INTERVAL = 0.1
WAKE_PORT = 9
# Should it hang past the window anyway, this many seconds is a failure, not a
# sample: kill it instead of waiting for the deadline.
MASSCAN_OVERRUN = re.compile(rb'waiting -([0-9]+)-secs')
MASSCAN_OVERRUN_LIMIT = 15


def command(tool, plan, rate, output, router_mac=None):
    """Equivalent workloads: SYN, no host discovery, one retry, the same pps."""
    low, high = plan['ports']
    ports = f'{low}-{high}'
    cidr = plan['cidr']
    if tool in ('naabu-syn', 'naabu-connect'):
        technique = 's' if tool == 'naabu-syn' else 'c'
        return ['naabu', '-host', cidr, '-p', ports, '-s', technique, '-Pn', '-rate', str(rate),
                '-retries', '1', '-json', '-silent', '-disable-update-check', '-o', str(output)]
    if tool == 'masscan':
        if not router_mac:
            raise ValueError('masscan needs the farm MAC as its router')
        return ['masscan', cidr, '-p', ports, '--rate', str(rate), '--retries', '1', '--wait', '2',
                '--adapter', VETH['scan'], '--adapter-ip', LINK['scan'],
                '--router-mac', router_mac, '-oL', str(output)]
    raise ValueError(f'unknown tool {tool}')


def binary_record(tool):
    name = tool.split('-')[0]
    path = shutil.which(name)
    if not path:
        return None
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    flag = '-version' if name == 'naabu' else '--version'
    proc = subprocess.run([path, flag], capture_output=True, text=True, timeout=30, check=False)
    text = (proc.stdout + proc.stderr).strip().splitlines()
    return {'path': path, 'sha256': digest, 'version': text[:3]}


def host_metadata():
    cpu = ''
    try:
        for line in Path('/proc/cpuinfo').read_text().splitlines():
            if line.startswith('model name'):
                cpu = line.split(':', 1)[1].strip()
                break
    except OSError:
        pass
    mem_kib = None
    try:
        mem_kib = int(Path('/proc/meminfo').read_text().split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return {'kernel': platform.release(), 'machine': platform.machine(), 'cpu': cpu,
            'cpus': os.cpu_count(), 'mem_kib': mem_kib, 'python': platform.python_version(),
            'libpcap': libpcap_record()}


def libpcap_record():
    """naabu 2.6 dlopens libpcap for its SYN listener; without it SYN finds nothing."""
    return ctypes.util.find_library('pcap')


class Namespaces:
    """Two fresh namespaces joined by one veth pair; removed on exit."""

    def __init__(self, plan):
        self.plan = plan
        self.farm_mac = None

    def __enter__(self):
        from pyroute2 import netns
        for name in NETNS.values():
            if name in netns.listnetns():
                raise RuntimeError(f'namespace {name} already exists; remove it first')
        try:
            for name in NETNS.values():
                netns.create(name)
            self._build()
        except BaseException:
            self.__exit__()
            raise
        return self

    def _build(self):
        from pyroute2 import IPRoute, NetNS
        from pyroute2.netlink.exceptions import NetlinkError
        with IPRoute() as ipr:
            ipr.link('add', ifname=VETH['scan'], kind='veth',
                     peer={'ifname': VETH['farm'], 'net_ns_fd': NETNS['farm']})
            ipr.link('set', index=ipr.link_lookup(ifname=VETH['scan'])[0], net_ns_fd=NETNS['scan'])
        impairment = self.plan.get('impairment')
        for side in ('farm', 'scan'):
            with NetNS(NETNS[side]) as ns:
                lo = ns.link_lookup(ifname='lo')[0]
                ns.link('set', index=lo, state='up')
                index = ns.link_lookup(ifname=VETH[side])[0]
                ns.addr('add', index=index, address=LINK[side], prefixlen=LINK['prefixlen'])
                ns.link('set', index=index, state='up')
                if side == 'farm':
                    self.farm_mac = ns.get_links(index)[0].get_attr('IFLA_ADDRESS')
                    # Live hosts are addresses on lo; the rest of the range is a
                    # blackhole, so a dead host is silent rather than unreachable.
                    for host in self.plan['hosts']:
                        ns.addr('add', index=lo, address=host, prefixlen=32)
                    ns.route('add', dst=str(TARGET_NET), type='blackhole')
                else:
                    # A default route as well: naabu picks its SYN source from
                    # the default route. It still leads only to the farm, which
                    # has no other interface.
                    ns.route('add', dst='0.0.0.0/0', gateway=LINK['farm'])
                if impairment:
                    try:
                        ns.tc('add', 'netem', index=index, handle='1:', delay=impairment['delay_ms'] * 1000,
                              loss=impairment['loss_pct'])
                    except NetlinkError as error:
                        raise SystemExit(f'--impaired needs netem (CONFIG_NET_SCH_NETEM): {error}') from None

    def __exit__(self, *exc):
        from pyroute2 import netns
        for name in NETNS.values():
            if name in netns.listnetns():
                netns.remove(name)


def in_netns(side, argv):
    return ['nsenter', f'--net=/var/run/netns/{NETNS[side]}', *argv]


def serve(plan_path, ready_path):
    """The farm: accept on every planned (host, port), answer, close."""
    plan = json.loads(Path(plan_path).read_text())
    validate_plan(plan)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    needed = len(ground_truth(plan)) + 256
    if soft < needed:
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(needed, hard), hard))
    selector = selectors.DefaultSelector()
    for host, port in sorted(ground_truth(plan)):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(64)
        listener.setblocking(False)
        selector.register(listener, selectors.EVENT_READ, port)
    Path(ready_path).write_text('ready\n')
    while True:
        for key, _ in selector.select():
            try:
                conn, _ = key.fileobj.accept()
            except BlockingIOError:
                continue
            try:
                conn.setblocking(False)
                conn.send(BANNERS.get(key.data, HTTP_BANNER))
            except OSError:
                pass
            finally:
                conn.close()


def deadline_seconds(plan, rate):
    """Five times the sweep at the configured rate, plus two minutes of slack."""
    low, high = plan['ports']
    probes = ipaddress.ip_network(plan['cidr']).num_addresses * (high - low + 1)
    return 5 * probes / rate + 120


def masscan_overrun(stderr_tail):
    """Seconds masscan's status line shows past its --wait window, else 0."""
    counts = [int(value) for value in MASSCAN_OVERRUN.findall(stderr_tail)]
    return max(counts, default=0)


def stderr_tail(path, size=512):
    with open(path, 'rb') as handle:
        handle.seek(max(0, os.path.getsize(path) - size))
        return handle.read()


def wake_receiver():
    """Stray datagrams from the farm to the scanner's end of the link."""
    code = ('import socket, time\n'
            's = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n'
            'while True:\n'
            f'    s.sendto(b"wake", ({LINK["scan"]!r}, {WAKE_PORT}))\n'
            f'    time.sleep({WAKE_INTERVAL})\n')
    return subprocess.Popen(in_netns('farm', [sys.executable, '-c', code]),
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_tool(tool, plan, rate, out_dir, label, router_mac):
    raw = out_dir / f'{label}.{tool}.out'
    stderr_path = out_dir / f'{label}.{tool}.stderr'
    argv = in_netns('scan', command(tool, plan, rate, raw, router_mac))
    deadline = deadline_seconds(plan, rate)
    waker = wake_receiver() if tool == 'masscan' else None
    started = time.monotonic()
    stalled = False
    # nsenter execs the tool in place, so wait4 reports the tool's own usage.
    with open(stderr_path, 'wb') as stderr:
        # naabu reads targets from stdin whenever stdin is not a terminal, and
        # fails with "Timeout" when nothing arrives; give it an empty one.
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stderr)
        timed_out = False
        next_check = started
        try:
            while True:
                pid, status, usage = os.wait4(proc.pid, os.WNOHANG)
                if pid:
                    break
                now = time.monotonic()
                if tool == 'masscan' and now >= next_check:
                    next_check = now + 0.5
                    stalled = masscan_overrun(stderr_tail(stderr_path)) >= MASSCAN_OVERRUN_LIMIT
                if stalled or now - started > deadline:
                    timed_out = True
                    proc.kill()
                    _, status, usage = os.wait4(proc.pid, 0)
                    break
                time.sleep(0.02)
        finally:
            if waker:
                waker.kill()
                waker.wait()
    seconds = time.monotonic() - started
    proc.returncode = os.waitstatus_to_exitcode(status)
    row = {'tool': tool, 'label': label, 'argv': argv, 'exit_code': proc.returncode,
           'seconds': round(seconds, 6), 'cpu_seconds': round(usage.ru_utime + usage.ru_stime, 6),
           'peak_rss_kib': usage.ru_maxrss}
    if timed_out:
        row['error'] = [f'killed {MASSCAN_OVERRUN_LIMIT} s past its --wait window' if stalled
                        else f'killed after the {round(deadline)} s deadline']
        return row, set()
    if proc.returncode != 0:
        row['error'] = stderr_path.read_text(errors='replace').strip().splitlines()[-5:]
        return row, set()
    text = raw.read_text() if raw.exists() else ''
    return row, PARSERS[tool](text)


def summarize(rows):
    summary = []
    for tool in sorted({row['tool'] for row in rows}):
        ok = [row for row in rows if row['tool'] == tool and row.get('exit_code') == 0]
        entry = {'tool': tool, 'samples': len(ok),
                 'failed': sum(1 for row in rows if row['tool'] == tool and row.get('exit_code') != 0)}
        for field in ('seconds', 'cpu_seconds', 'recall', 'precision', 'addresses_per_second', 'probes_per_second'):
            values = [row[field] for row in ok if field in row]
            if values:
                entry[f'{field}_median'] = round(statistics.median(values), 6)
                entry[f'{field}_min'] = round(min(values), 6)
                entry[f'{field}_max'] = round(max(values), 6)
        summary.append(entry)
    return summary


def run(args):
    validate_repeats(args.repeats)
    validate_rate(args.rate)
    if os.geteuid() != 0:
        raise SystemExit('run as root: the harness creates network namespaces')
    out_dir = Path(args.output)
    if out_dir.exists():
        raise SystemExit(f'{out_dir} already exists; choose a fresh directory')
    out_dir.mkdir(parents=True)
    tools = [tool for tool in args.tools.split(',') if tool]
    unknown = set(tools) - set(TOOLS)
    if unknown:
        raise SystemExit(f'unknown tools: {sorted(unknown)}')
    plan = make_plan(args.scenario, args.scale, args.seed, impaired=args.impaired)
    plan_path = out_dir / 'ground-truth.json'
    plan_path.write_text(json.dumps(plan, indent=1, sort_keys=True) + '\n')
    truth = ground_truth(plan)
    network = ipaddress.ip_network(plan['cidr'])
    low, high = plan['ports']
    probes = network.num_addresses * (high - low + 1)
    binaries = {tool: binary_record(tool) for tool in tools}
    available = [tool for tool in tools if binaries[tool]]
    metadata = {'scenario': plan['scenario'], 'scale': plan['scale'], 'seed': plan['seed'],
                'cidr': plan['cidr'], 'ports': plan['ports'], 'live_hosts': len(plan['hosts']),
                'open_endpoints': len(truth), 'probes_per_sweep': probes, 'rate_pps': args.rate,
                'repeats': args.repeats, 'impairment': plan['impairment'], 'host': host_metadata(),
                'binaries': binaries,
                'skipped': {tool: 'not installed' for tool in tools if tool not in available}}
    if 'naabu-syn' in available and not metadata['host']['libpcap']:
        metadata['warnings'] = ['no libpcap on this host: naabu SYN cannot see replies and reports nothing']
        print(metadata['warnings'][0], file=sys.stderr)
    rows = []
    with Namespaces(plan) as spaces:
        ready = out_dir / 'farm.ready'
        farm = subprocess.Popen(in_netns('farm', [sys.executable, os.path.abspath(__file__), 'serve',
                                                  '--plan', str(plan_path), '--ready', str(ready)]))
        try:
            deadline = time.monotonic() + 60
            while not ready.exists():
                if farm.poll() is not None or time.monotonic() > deadline:
                    raise SystemExit('farm did not start')
                time.sleep(0.1)
            for repeat in range(args.repeats):
                # Rotate the order so no tool always runs first on a cold cache.
                order = available[repeat % len(available):] + available[:repeat % len(available)] if available else []
                for tool in order:
                    row, found = run_tool(tool, plan, args.rate, out_dir, f'r{repeat}', spaces.farm_mac)
                    row['repeat'] = repeat
                    if row['exit_code'] == 0:
                        row.update(score(found, truth))
                        row['addresses_per_second'] = round(network.num_addresses / row['seconds'], 3)
                        row['probes_per_second'] = round(probes / row['seconds'], 3)
                    rows.append(row)
        finally:
            farm.terminate()
            farm.wait(timeout=30)
            ready.unlink(missing_ok=True)
    (out_dir / 'metadata.json').write_text(json.dumps(metadata, indent=1, sort_keys=True) + '\n')
    (out_dir / 'results.json').write_text(json.dumps(rows, indent=1, sort_keys=True) + '\n')
    summary = summarize(rows)
    (out_dir / 'summary.json').write_text(json.dumps(summary, indent=1, sort_keys=True) + '\n')
    sums = [f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}'
            for path in sorted(out_dir.iterdir()) if path.is_file() and path.name != 'SHA256SUMS']
    (out_dir / 'SHA256SUMS').write_text('\n'.join(sums) + '\n')
    print(json.dumps(summary, indent=1))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='command', required=True)
    run_parser = sub.add_parser('run', help='build the farm, run the scanners, score them')
    run_parser.add_argument('--scenario', choices=sorted(SCENARIOS), required=True)
    run_parser.add_argument('--scale', choices=('small', 'full'), default='small')
    run_parser.add_argument('--impaired', action='store_true', help='50 ms RTT and ~1 %% loss (scenario F)')
    run_parser.add_argument('--seed', type=int, default=1)
    run_parser.add_argument('--rate', type=int, default=10000, help='packets per second, the same for every tool')
    run_parser.add_argument('--repeats', type=int, default=5)
    run_parser.add_argument('--tools', default=','.join(TOOLS))
    run_parser.add_argument('--output', required=True)
    plan_parser = sub.add_parser('plan', help='print the generated ground truth')
    plan_parser.add_argument('--scenario', choices=sorted(SCENARIOS), required=True)
    plan_parser.add_argument('--scale', choices=('small', 'full'), default='small')
    plan_parser.add_argument('--seed', type=int, default=1)
    serve_parser = sub.add_parser('serve', help=argparse.SUPPRESS)
    serve_parser.add_argument('--plan', required=True)
    serve_parser.add_argument('--ready', required=True)
    args = parser.parse_args(argv)
    if args.command == 'run':
        run(args)
    elif args.command == 'plan':
        print(json.dumps(make_plan(args.scenario, args.scale, args.seed), indent=1, sort_keys=True))
    else:
        serve(args.plan, args.ready)


if __name__ == '__main__':
    main()
