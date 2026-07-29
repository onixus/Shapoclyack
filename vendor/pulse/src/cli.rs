use clap::{Parser, ValueEnum};
use std::path::PathBuf;

/// Pulse — sleek async network & open-port scanner
#[derive(Debug, Parser)]
#[command(
    name = "pulse",
    version,
    about = "⚡ Pulse — modern network & open-port scanner",
    long_about = "Fast async TCP/UDP port scanner with live TUI, service hints, banners, and HTML reports.",
    styles = clap::builder::styling::Styles::styled()
        .header(clap::builder::styling::AnsiColor::Magenta.on_default().bold())
        .usage(clap::builder::styling::AnsiColor::Cyan.on_default().bold())
        .literal(clap::builder::styling::AnsiColor::Green.on_default().bold())
        .placeholder(clap::builder::styling::AnsiColor::Yellow.on_default())
)]
pub struct Cli {
    /// Target(s): IP, host, CIDR, netmask, range, or comma/list
    /// Examples: 10.0.0.0/24 · 10.0.0.0/255.255.255.0 · a.com,b.com · 10.0.0.1-50
    #[arg(value_name = "TARGET")]
    pub target: Option<String>,

    /// File with targets (one per line): domains, IPs, CIDR, masks, ranges)
    /// Lines starting with # are comments
    #[arg(long = "targets-file", short = 'T', value_name = "FILE")]
    pub targets_file: Option<PathBuf>,

    /// Max hosts after expansion (CIDR / lists / ranges)
    #[arg(long, default_value_t = 4096)]
    pub max_hosts: usize,

    /// Exclude hosts/CIDR/ranges (comma-separated or repeat flag)
    #[arg(long = "exclude", short = 'x', value_name = "SPEC", action = clap::ArgAction::Append)]
    pub exclude: Vec<String>,

    /// File of hosts/CIDR to exclude (one per line)
    #[arg(long = "exclude-file", value_name = "FILE")]
    pub exclude_file: Option<PathBuf>,

    /// Host discovery before port scan (skip dark hosts)
    #[arg(long = "discover", short = 'D')]
    pub discover: bool,

    /// Discovery method: tcp, icmp, arp, both, auto (arp LAN + icmp/tcp)
    #[arg(long = "discover-method", value_enum, default_value_t = DiscoverMethodCli::Auto)]
    pub discover_method: DiscoverMethodCli,

    /// TCP ports for discovery probes
    #[arg(long = "discover-ports", default_value = "80,443,22,445,3389")]
    pub discover_ports: String,

    /// Discovery probe timeout (ms)
    #[arg(long = "discover-timeout", default_value_t = 500)]
    pub discover_timeout: u64,

    /// Fail if discovery finds zero live hosts
    #[arg(long = "discover-strict")]
    pub discover_strict: bool,

    /// Max probes per second (connect + SYN). 0 = unlimited
    #[arg(long = "rate", value_name = "PPS")]
    pub rate: Option<u64>,

    /// Append open-port events as NDJSON while scanning
    #[arg(long = "stream", value_name = "FILE")]
    pub stream: Option<PathBuf>,

    /// Hosts per scheduling chunk (large nets)
    #[arg(long = "host-batch", default_value_t = 256)]
    pub host_batch: usize,

    /// Checkpoint file for resume (auto-loads if file exists)
    #[arg(long = "checkpoint", value_name = "FILE")]
    pub checkpoint: Option<PathBuf>,

    /// Resume from checkpoint file (alias of --checkpoint when file exists)
    #[arg(long = "resume", value_name = "FILE")]
    pub resume: Option<PathBuf>,

    /// Ports: single, range, or list (e.g. 80, 1-1024, 22,80,443)
    #[arg(short, long, default_value = "1-1024", value_name = "PORTS")]
    pub ports: String,

    /// Max concurrent connections (ceiling when --adaptive)
    #[arg(short = 'c', long, default_value_t = 500)]
    pub concurrency: usize,

    /// Adapt concurrency up to -c based on timeout ratio (large nets)
    #[arg(long = "adaptive")]
    pub adaptive: bool,

    /// Scan host-by-host (finish all ports before next host)
    #[arg(long = "host-first")]
    pub host_first: bool,

    /// Concurrent hosts in host-ordered mode (implies host-first; default 1 with --host-first)
    #[arg(long = "host-parallel", value_name = "N")]
    pub host_parallel: Option<usize>,

    /// SYN retransmits on silence (0–3 recommended)
    #[arg(long = "syn-retries", default_value_t = 0)]
    pub syn_retries: u8,

    /// Connect timeout in milliseconds
    #[arg(short = 't', long, default_value_t = 800)]
    pub timeout: u64,

    /// Grab service banners from open ports
    #[arg(short, long)]
    pub banner: bool,

    /// Output format (ignored when --tui is set)
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Pretty)]
    pub format: OutputFormat,

    /// Quiet mode — results only, no banner/progress
    #[arg(short, long)]
    pub quiet: bool,

    /// Top N most common ports (overrides --ports)
    #[arg(long, value_name = "N")]
    pub top: Option<usize>,

    /// Include closed ports in JSON/CSV output
    #[arg(long)]
    pub all: bool,

    /// Interactive live TUI dashboard
    #[arg(long)]
    pub tui: bool,

    /// Write a cyberpunk HTML report to this path
    #[arg(long, value_name = "FILE")]
    pub html: Option<PathBuf>,

    /// Also probe UDP (or use --protocol udp)
    #[arg(long)]
    pub udp: bool,

    /// Protocol(s) to scan
    #[arg(long, value_enum, default_value_t = ProtocolChoice::Tcp)]
    pub protocol: ProtocolChoice,

    /// Half-open TCP SYN scan (IPv4, requires root / CAP_NET_RAW)
    #[arg(long)]
    pub syn: bool,

    /// TCP/IP OS fingerprinting (IPv4, requires root / CAP_NET_RAW)
    #[arg(long)]
    pub os: bool,

    /// OS engine: sinfp (fast, 1 probe), nmap (deep), auto (sinfp→nmap)
    #[arg(long, value_enum, default_value_t = OsEngine::SinFp)]
    pub os_mode: OsEngine,

    /// Path to nmap-os-db (NPSL; not bundled — see --os-db-fetch)
    #[arg(long, value_name = "PATH")]
    pub os_db: Option<PathBuf>,

    /// Download nmap-os-db into ~/.pulse/nmap-os-db
    #[arg(long)]
    pub os_db_fetch: bool,

    /// Max OS DB matches to keep per host
    #[arg(long, default_value_t = 3)]
    pub os_limit: usize,

    /// Min accuracy (0.0–1.0) to treat as solid match (nmap uses ~0.85)
    #[arg(long, default_value_t = 0.85)]
    pub os_min_accuracy: f64,

    /// Correlate open ports/banners with CVE + CVSS (offline rules)
    #[arg(long)]
    pub cve: bool,

    /// Also query NVD online for banner keywords (rate-limited; optional NVD_API_KEY)
    #[arg(long)]
    pub cve_online: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum OutputFormat {
    #[default]
    Pretty,
    Json,
    Csv,
}

#[derive(Debug, Clone, Copy, ValueEnum, Default, PartialEq, Eq)]
pub enum ProtocolChoice {
    #[default]
    Tcp,
    Udp,
    Both,
}

#[derive(Debug, Clone, Copy, ValueEnum, Default, PartialEq, Eq)]
pub enum OsEngine {
    /// Single-probe SinFP (fast)
    #[default]
    #[value(name = "sinfp")]
    SinFp,
    /// Full nmap-os-db suite (slow, precise)
    Nmap,
    /// SinFP first, nmap if confidence low
    Auto,
}

#[derive(Debug, Clone, Copy, ValueEnum, Default, PartialEq, Eq)]
pub enum DiscoverMethodCli {
    #[value(name = "tcp")]
    Tcp,
    #[value(name = "icmp")]
    Icmp,
    /// On-link IPv4 via ARP / neighbor table (LAN)
    #[value(name = "arp")]
    Arp,
    /// ICMP then TCP
    #[value(name = "both")]
    Both,
    /// ARP for LAN, then ICMP+TCP for dark / remote (recommended)
    #[default]
    #[value(name = "auto")]
    Auto,
}
