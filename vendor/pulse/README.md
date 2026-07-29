# Pulse

**Modern async network & open-port scanner** on Rust — CLI, TUI, HTML reports, and a native **macOS app**.

TCP/UDP · SYN · SinFP / nmap OS · CVE/CVSS · glass-neon GUI

```
  P U L S E
  NETWORK  ·  SIGNAL  ·  TRUTH
```

## Features

| Area | Capabilities |
|------|----------------|
| **Scan** | Async TCP connect, UDP probe, TCP SYN half-open |
| **Large nets** | Discover (ARP/ICMP/TCP), exclude, rate, adaptive `-c`, host-first/`--host-parallel`, checkpoint/resume, NDJSON stream |
| **Targets** | IP, host, CIDR, **netmask**, ranges, **lists**, **file** (`-T`) |
| **OS** | SinFP (fast), nmap-os-db (deep), auto |
| **Vuln** | Offline CVE rules + optional NVD online |
| **UX** | Pretty CLI (per-host blocks), TUI, JSON/CSV, HTML, macOS GUI |
| **Services** | Name hints, banner grab, top-N ports |

## Documentation

**Полная документация:** [`docs/README.md`](docs/README.md)

| | |
|--|--|
| [Установка](docs/install.md) | CLI + macOS `.app` / DMG |
| [Быстрый старт](docs/quickstart.md) | Первые команды и GUI |
| [CLI](docs/cli.md) | Справочник флагов |
| [macOS App](docs/macos-app.md) | Кнопки, elevation, OS detect |
| [Сканирование](docs/scanning.md) | TCP / SYN / UDP |
| [OS detection](docs/os-detection.md) | SinFP, nmap-os-db |
| [CVE / CVSS](docs/cve.md) | Offline + NVD |
| [Отчёты](docs/reports.md) | Pretty, JSON, HTML, TUI |
| [Troubleshooting](docs/troubleshooting.md) | Висяки, raw sockets, DMG |
| [Архитектура](docs/architecture.md) | Модули |
| [Legal](docs/legal.md) | Разрешения, NPSL, MIT |

## Install (short)

### CLI

```bash
cargo build --release
./target/release/pulse --help
```

### macOS app

```bash
./scripts/package-macos.sh
cp -R dist/Pulse.app /Applications/
xattr -dr com.apple.quarantine /Applications/Pulse.app
open /Applications/Pulse.app
```

> Копируйте app в **Applications**. Не используйте постоянно app с `/Volumes/…` (DMG).

Also: `dist/Pulse-macos-*.dmg`, `dist/Pulse-macos-*.zip`.

## Quick examples

```bash
# Ports
pulse 127.0.0.1 --top 50
pulse 10.0.0.5 -p 22,80,443 -b --html report.html

# Subnet by mask / CIDR
pulse 192.168.1.0/24 -p 22,80,443
pulse 192.168.1.0/255.255.255.0 -p 22,80,443

# Domain list or file
pulse "a.example,b.example,c.example" --top 50
pulse -T domains.txt --top 100

# SYN (root)
sudo pulse 10.0.0.5 --top 200 --syn --syn-retries 1

# Large LAN / subnet
pulse 192.168.1.0/24 -D --discover-method auto --top 100 \
  --host-parallel 16 --adaptive -c 800 --rate 3000 \
  --checkpoint ~/job.ckpt --stream ~/open.ndjson

# OS + CVE (root for OS)
sudo pulse example.com --top 100 --os --os-mode sinfp --cve

# Deep OS via nmap-os-db
sudo pulse example.com --os --os-mode nmap --os-db-fetch

# JSON
pulse 10.0.0.5 --top 50 --cve -f json -q
```

## CLI options (summary)

| Flag | Default | Description |
|------|---------|-------------|
| `TARGET` | —* | IP / host / CIDR / mask / list (*or `-T`) |
| `-T, --targets-file` | — | File with targets (domains, CIDR, …) |
| `--max-hosts` | `4096` | Cap after expansion |
| `-p, --ports` | `1-1024` | Ports / ranges / lists |
| `--top N` | — | Top N common ports |
| `-c, --concurrency` | `500` | Parallel probes |
| `-t, --timeout` | `800` | Timeout (ms) |
| `-b, --banner` | off | TCP banners |
| `--protocol` | `tcp` | `tcp` \| `udp` \| `both` |
| `--syn` | off | SYN scan (root, IPv4) |
| `--os` | off | OS fingerprint (root, IPv4) |
| `--os-mode` | `sinfp` | `sinfp` \| `nmap` \| `auto` |
| `--os-db` / `--os-db-fetch` | — | nmap-os-db path / download |
| `--cve` / `--cve-online` | off | CVE+CVSS local / +NVD |
| `--tui` | off | Full-screen UI |
| `--html FILE` | — | HTML report |
| `-f` | `pretty` | `pretty` \| `json` \| `csv` |
| `-q` | off | Quiet |

Full table: [docs/cli.md](docs/cli.md).

## macOS GUI (short)

Buttons: **SCAN**, **STOP**, **SCAN + HTML**, **OS DETECT NOW**.  
Toggles: SYN, OS (SinFP/nmap/auto), Banner, CVE, CVE online, Admin.

OS/SYN → macOS password (raw sockets).  
Live OUTPUT streams elevated log from `/tmp`.

Details: [docs/macos-app.md](docs/macos-app.md).

## How it works (short)

- **TCP connect** — no root  
- **SYN** — raw SYN/SYN-ACK/RST (`pnet`), root, IPv4  
- **SinFP** — one SYN fingerprint  
- **nmap mode** — multi-probe + external `nmap-os-db` (NPSL, not bundled)  
- **CVE** — curated offline rules + optional NVD  

## Legal

Only scan systems you own or have **explicit permission** to test.

- Pulse code: **MIT**  
- `nmap-os-db`: **NPSL** (Nmap Software LLC) — fetched at runtime only  

See [docs/legal.md](docs/legal.md).

## Project layout

```
pulse/
├── src/           # CLI engine
├── macos/         # SwiftUI app
├── scripts/       # package-macos.sh
├── docs/          # this documentation
├── dist/          # build artifacts (.app, dmg, zip)
└── README.md
```
