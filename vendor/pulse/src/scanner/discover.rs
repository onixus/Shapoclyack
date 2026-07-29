//! Host discovery (live hosts before full port scan).
//!
//! Methods:
//! - **TCP** — connect / connection-refused on common ports
//! - **ICMP** — system `ping` (no raw sockets required)
//! - **ARP** — on-link IPv4 only: trigger neighbor resolution + parse ARP/neigh table
//! - **Both** — ICMP then TCP for dark hosts
//! - **Auto** — ARP for LAN (on-link), then ICMP+TCP for still-dark / remote hosts

use super::rate::RateLimiter;
use super::Target;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use ipnet::Ipv4Net;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiscoverMethod {
    /// TCP connect probes only (no root required)
    Tcp,
    /// ICMP echo via system ping
    Icmp,
    /// ARP/neighbor table for on-link IPv4 (LAN)
    Arp,
    /// ICMP then TCP for dark hosts
    #[default]
    Both,
    /// ARP (LAN) + ICMP/TCP for remaining / remote
    Auto,
}

#[derive(Debug, Clone)]
pub struct DiscoverConfig {
    pub method: DiscoverMethod,
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub concurrency: usize,
    pub rate: Arc<RateLimiter>,
}

impl Default for DiscoverConfig {
    fn default() -> Self {
        Self {
            method: DiscoverMethod::Both,
            ports: vec![80, 443, 22, 445, 3389],
            timeout: Duration::from_millis(500),
            concurrency: 500,
            rate: Arc::new(RateLimiter::unlimited()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoverStats {
    #[allow(dead_code)]
    pub candidates: usize,
    pub live: usize,
    pub method_used: String,
}

/// Probe which hosts appear alive.
pub async fn discover_hosts(
    targets: Vec<Target>,
    config: DiscoverConfig,
) -> Result<(Vec<Target>, DiscoverStats)> {
    let candidates = targets.len();
    if candidates == 0 {
        return Ok((
            Vec::new(),
            DiscoverStats {
                candidates: 0,
                live: 0,
                method_used: "none".into(),
            },
        ));
    }

    let mut method_used = String::new();
    let mut live_flags = vec![false; targets.len()];

    let want_arp = matches!(
        config.method,
        DiscoverMethod::Arp | DiscoverMethod::Auto
    );
    let want_icmp = matches!(
        config.method,
        DiscoverMethod::Icmp | DiscoverMethod::Both | DiscoverMethod::Auto
    );
    let want_tcp = matches!(
        config.method,
        DiscoverMethod::Tcp | DiscoverMethod::Both | DiscoverMethod::Auto
    );

    // ── ARP (on-link IPv4 only) ──
    if want_arp {
        let arp_hits = probe_arp_batch(&targets, &config).await;
        let hits = arp_hits.iter().filter(|&&h| h).count();
        if hits > 0 {
            method_used = "arp".into();
            for (i, h) in arp_hits.into_iter().enumerate() {
                live_flags[i] |= h;
            }
        } else if matches!(config.method, DiscoverMethod::Arp) {
            method_used = "arp".into();
        } else {
            method_used = "arp→".into();
        }
    }

    // ARP-only: stop here (don't fall through to ICMP/TCP)
    if matches!(config.method, DiscoverMethod::Arp) {
        return finish(targets, live_flags, candidates, method_used);
    }

    // ── ICMP ──
    if want_icmp {
        // Only probe still-dark hosts
        let icmp_hits = probe_icmp_batch_dark(&targets, &live_flags, &config).await;
        let hits = icmp_hits.iter().filter(|&&h| h).count();
        if hits > 0 {
            for (i, h) in icmp_hits.into_iter().enumerate() {
                live_flags[i] |= h;
            }
            if method_used.is_empty() || method_used == "arp→" {
                method_used = if method_used.starts_with("arp") {
                    "arp+icmp".into()
                } else {
                    "icmp".into()
                };
            } else if !method_used.contains("icmp") {
                method_used.push_str("+icmp");
            }
        } else if matches!(config.method, DiscoverMethod::Icmp) {
            method_used = "icmp".into();
        } else if method_used == "arp→" {
            method_used = "arp→icmp→tcp".into();
        }
    }

    // ── TCP ──
    if want_tcp {
        let need_tcp = live_flags.iter().any(|&l| !l)
            || matches!(config.method, DiscoverMethod::Tcp);
        if need_tcp {
            if method_used.is_empty() {
                method_used = "tcp".into();
            } else if method_used == "icmp" {
                method_used = "icmp+tcp".into();
            } else if method_used == "arp" {
                method_used = "arp+tcp".into();
            } else if method_used == "arp+icmp" {
                method_used = "arp+icmp+tcp".into();
            } else if method_used.ends_with('→') || method_used.contains('→') {
                if !method_used.contains("tcp") {
                    method_used.push_str("tcp");
                }
            } else if !method_used.contains("tcp") {
                method_used.push_str("+tcp");
            }

            let tcp_hits = probe_tcp_batch(&targets, &live_flags, &config).await;
            for (i, h) in tcp_hits.into_iter().enumerate() {
                live_flags[i] |= h;
            }
        }
    }

    if method_used.is_empty() {
        method_used = "none".into();
    }

    finish(targets, live_flags, candidates, method_used)
}

fn finish(
    targets: Vec<Target>,
    live_flags: Vec<bool>,
    candidates: usize,
    method_used: String,
) -> Result<(Vec<Target>, DiscoverStats)> {
    let live: Vec<Target> = targets
        .into_iter()
        .zip(live_flags)
        .filter_map(|(t, live)| if live { Some(t) } else { None })
        .collect();
    let n = live.len();
    Ok((
        live,
        DiscoverStats {
            candidates,
            live: n,
            method_used,
        },
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// ARP / neighbor discovery (LAN)
// ─────────────────────────────────────────────────────────────────────────────

/// Trigger ARP for on-link IPv4 targets, then parse the system neighbor table.
async fn probe_arp_batch(targets: &[Target], config: &DiscoverConfig) -> Vec<bool> {
    let local_nets = local_ipv4_nets();
    if local_nets.is_empty() {
        return vec![false; targets.len()];
    }

    // Indices of on-link IPv4 hosts
    let mut on_link: Vec<(usize, Ipv4Addr)> = Vec::new();
    for (i, t) in targets.iter().enumerate() {
        if let IpAddr::V4(ip) = t.addr {
            if is_on_link(ip, &local_nets) {
                on_link.push((i, ip));
            }
        }
    }

    if on_link.is_empty() {
        return vec![false; targets.len()];
    }

    // 1) Blast UDP packets to force neighbor resolution (no root needed)
    let concurrency = config.concurrency.max(1).min(512);
    let rate = config.rate.clone();
    let timeout_dur = config.timeout;

    stream::iter(on_link.iter().copied())
        .map(|(_idx, ip)| {
            let rate = rate.clone();
            async move {
                rate.acquire().await;
                trigger_arp(ip).await;
            }
        })
        .buffer_unordered(concurrency)
        .collect::<Vec<()>>()
        .await;

    // 2) Give the kernel a moment to fill the table
    let wait = timeout_dur.min(Duration::from_millis(800)).max(Duration::from_millis(150));
    sleep(wait).await;

    // 3) Parse ARP / neighbor table for resolved MACs
    let live_ips = parse_neighbor_table();

    let mut flags = vec![false; targets.len()];
    for (idx, ip) in on_link {
        if live_ips.contains(&ip) {
            flags[idx] = true;
        }
    }

    // 4) Also treat our own interface IPs as live
    for (i, t) in targets.iter().enumerate() {
        if let IpAddr::V4(ip) = t.addr {
            if local_nets.iter().any(|n| n.addr() == ip) {
                flags[i] = true;
            }
        }
    }

    flags
}

/// Send a single UDP datagram to port 9 (discard) — OS resolves ARP first.
async fn trigger_arp(ip: Ipv4Addr) {
    let addr = SocketAddr::new(IpAddr::V4(ip), 9);
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await {
        let _ = sock.send_to(&[0u8], addr).await;
    }
}

fn is_on_link(ip: Ipv4Addr, nets: &[Ipv4Net]) -> bool {
    if ip.is_loopback() {
        return true;
    }
    nets.iter().any(|n| n.contains(&ip))
}

/// Local IPv4 networks from the system (best-effort, no extra crates).
fn local_ipv4_nets() -> Vec<Ipv4Net> {
    let mut nets = Vec::new();

    // Prefer `ifconfig` (macOS) / fall back to `ip -4 addr` (Linux)
    if let Ok(out) = Command::new("ifconfig").output() {
        if out.status.success() {
            nets.extend(parse_ifconfig_ipv4(&String::from_utf8_lossy(&out.stdout)));
        }
    }
    if nets.is_empty() {
        if let Ok(out) = Command::new("ip")
            .args(["-4", "-o", "addr", "show"])
            .output()
        {
            if out.status.success() {
                nets.extend(parse_ip_addr_ipv4(&String::from_utf8_lossy(&out.stdout)));
            }
        }
    }

    // Always include loopback /8 for 127.0.0.0/8 discovery edge cases
    if let Ok(n) = Ipv4Net::from_str("127.0.0.0/8") {
        nets.push(n);
    }

    nets
}

/// Parse macOS/BSD ifconfig: `inet 192.168.1.5 netmask 0xffffff00`
fn parse_ifconfig_ipv4(text: &str) -> Vec<Ipv4Net> {
    let mut nets = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("inet ") {
            continue;
        }
        // skip inet6
        let parts: Vec<&str> = line.split_whitespace().collect();
        // inet <ip> netmask <hex|dotted> ...
        if parts.len() < 4 || parts[0] != "inet" {
            continue;
        }
        let Ok(ip) = Ipv4Addr::from_str(parts[1]) else {
            continue;
        };
        if ip.is_loopback() {
            continue; // added separately as /8
        }
        // find netmask
        let mut mask: Option<Ipv4Addr> = None;
        for i in 0..parts.len().saturating_sub(1) {
            if parts[i] == "netmask" {
                mask = parse_netmask_token(parts[i + 1]);
                break;
            }
        }
        // or CIDR form inet 10.0.0.1/24
        if parts[1].contains('/') {
            if let Ok(n) = Ipv4Net::from_str(parts[1]) {
                nets.push(n.trunc());
                continue;
            }
        }
        if let Some(m) = mask {
            if let Ok(n) = Ipv4Net::with_netmask(ip, m) {
                nets.push(n.trunc());
            }
        }
    }
    nets
}

fn parse_netmask_token(s: &str) -> Option<Ipv4Addr> {
    // 0xffffff00 hex (BSD)
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if let Ok(v) = u32::from_str_radix(hex, 16) {
            return Some(Ipv4Addr::from(v));
        }
    }
    Ipv4Addr::from_str(s).ok()
}

/// Parse `ip -4 -o addr show`: `2: eth0    inet 10.0.0.5/24 ...`
fn parse_ip_addr_ipv4(text: &str) -> Vec<Ipv4Net> {
    let mut nets = Vec::new();
    for line in text.lines() {
        for token in line.split_whitespace() {
            if let Some(cidr) = token.split('/').next().and_then(|_| {
                if token.contains('/') {
                    Some(token)
                } else {
                    None
                }
            }) {
                if let Ok(n) = Ipv4Net::from_str(cidr) {
                    if !n.addr().is_loopback() {
                        nets.push(n.trunc());
                    }
                }
            }
        }
    }
    nets
}

/// IPs that have a resolved MAC (not incomplete) in the neighbor/ARP table.
fn parse_neighbor_table() -> HashSet<Ipv4Addr> {
    let mut set = HashSet::new();

    // macOS / BSD: arp -an
    if let Ok(out) = Command::new("arp").args(["-an"]).output() {
        if out.status.success() {
            set.extend(parse_arp_an(&String::from_utf8_lossy(&out.stdout)));
        }
    }

    // Linux: ip neigh show
    if let Ok(out) = Command::new("ip").args(["neigh", "show"]).output() {
        if out.status.success() {
            set.extend(parse_ip_neigh(&String::from_utf8_lossy(&out.stdout)));
        }
    }

    set
}

/// `? (192.168.1.1) at 0:1c:42:0:0:1 on en0 ifscope [ethernet]`
/// `? (192.168.1.99) at (incomplete) on en0`
fn parse_arp_an(text: &str) -> HashSet<Ipv4Addr> {
    let mut set = HashSet::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("incomplete") || lower.contains("permanent") && lower.contains("(incomplete)") {
            continue;
        }
        // extract (x.x.x.x)
        if let Some(start) = line.find('(') {
            if let Some(end) = line[start + 1..].find(')') {
                let ip_s = &line[start + 1..start + 1 + end];
                if let Ok(ip) = Ipv4Addr::from_str(ip_s) {
                    // must have " at " with a MAC-looking token
                    if let Some(at) = lower.find(" at ") {
                        let after = &lower[at + 4..];
                        let mac = after.split_whitespace().next().unwrap_or("");
                        if mac.contains(':') && !mac.contains("incomplete") {
                            set.insert(ip);
                        }
                    }
                }
            }
        }
    }
    set
}

/// `192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE`
/// `192.168.1.2 dev eth0 FAILED`
fn parse_ip_neigh(text: &str) -> HashSet<Ipv4Addr> {
    let mut set = HashSet::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("failed")
            || lower.contains("incomplete")
            || lower.contains("none")
        {
            continue;
        }
        if !lower.contains("lladdr") {
            continue;
        }
        let ip_s = line.split_whitespace().next().unwrap_or("");
        if let Ok(ip) = Ipv4Addr::from_str(ip_s) {
            set.insert(ip);
        }
    }
    set
}

// ─────────────────────────────────────────────────────────────────────────────
// TCP / ICMP (existing)
// ─────────────────────────────────────────────────────────────────────────────

async fn probe_tcp_batch(
    targets: &[Target],
    already_live: &[bool],
    config: &DiscoverConfig,
) -> Vec<bool> {
    let concurrency = config.concurrency.max(1);
    let sem = Arc::new(Semaphore::new(concurrency));
    let rate = config.rate.clone();
    let ports = config.ports.clone();
    let timeout_dur = config.timeout;
    let results = Arc::new(
        (0..targets.len())
            .map(|_| AtomicUsize::new(0))
            .collect::<Vec<_>>(),
    );

    let jobs: Vec<(usize, Target)> = targets
        .iter()
        .enumerate()
        .filter(|(i, _)| !already_live.get(*i).copied().unwrap_or(false))
        .map(|(i, t)| (i, t.clone()))
        .collect();

    stream::iter(jobs)
        .map(|(idx, target)| {
            let sem = sem.clone();
            let rate = rate.clone();
            let ports = ports.clone();
            let results = results.clone();
            async move {
                let _permit = sem.acquire().await.ok();
                rate.acquire().await;
                if tcp_ping_host(&target, &ports, timeout_dur).await {
                    results[idx].store(1, Ordering::Relaxed);
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await;

    results
        .iter()
        .map(|a| a.load(Ordering::Relaxed) > 0)
        .collect()
}

async fn tcp_ping_host(target: &Target, ports: &[u16], timeout_dur: Duration) -> bool {
    for &port in ports {
        let addr = SocketAddr::new(target.addr, port);
        match timeout(timeout_dur, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => return true,
            Ok(Err(e)) => {
                let kind = e.kind();
                if matches!(
                    kind,
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                ) {
                    return true;
                }
            }
            Err(_) => {}
        }
    }
    false
}

async fn probe_icmp_batch_dark(
    targets: &[Target],
    already_live: &[bool],
    config: &DiscoverConfig,
) -> Vec<bool> {
    let concurrency = config.concurrency.max(1).min(128);
    let timeout_ms = config.timeout.as_millis().max(100) as u64;
    let rate = config.rate.clone();

    let jobs: Vec<(usize, IpAddr)> = targets
        .iter()
        .enumerate()
        .filter(|(i, _)| !already_live.get(*i).copied().unwrap_or(false))
        .map(|(i, t)| (i, t.addr))
        .collect();

    let results = stream::iter(jobs)
        .map(|(idx, ip)| {
            let rate = rate.clone();
            async move {
                rate.acquire().await;
                let live = icmp_ping_one(ip, timeout_ms).await;
                (idx, live)
            }
        })
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await;

    let mut flags = vec![false; targets.len()];
    for (idx, live) in results {
        if idx < flags.len() {
            flags[idx] = live;
        }
    }
    flags
}

async fn icmp_ping_one(ip: IpAddr, timeout_ms: u64) -> bool {
    let ip_s = ip.to_string();
    let mut cmd = tokio::process::Command::new("ping");
    #[cfg(target_os = "macos")]
    {
        cmd.args(["-c", "1", "-W", &timeout_ms.to_string(), &ip_s]);
    }
    #[cfg(target_os = "linux")]
    {
        let secs = ((timeout_ms + 999) / 1000).max(1);
        cmd.args(["-c", "1", "-W", &secs.to_string(), &ip_s]);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        cmd.args(["-c", "1", &ip_s]);
    }
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    match timeout(Duration::from_millis(timeout_ms + 500), cmd.status()).await {
        Ok(Ok(status)) => status.success(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn localhost_tcp_discover() {
        let targets = vec![Target {
            display: "127.0.0.1".into(),
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }];
        let cfg = DiscoverConfig {
            method: DiscoverMethod::Tcp,
            ports: vec![1, 22, 80, 443, 65535],
            timeout: Duration::from_millis(300),
            concurrency: 32,
            rate: Arc::new(RateLimiter::unlimited()),
        };
        let (live, stats) = discover_hosts(targets, cfg).await.unwrap();
        assert_eq!(stats.candidates, 1);
        assert_eq!(stats.live, 1, "127.0.0.1 should be live via TCP ping");
        assert_eq!(live.len(), 1);
    }

    #[test]
    fn parse_arp_an_sample() {
        let sample = r#"
? (192.168.1.1) at 0:1c:42:0:0:1 on en0 ifscope [ethernet]
? (192.168.1.50) at (incomplete) on en0 ifscope [ethernet]
? (10.0.0.5) at aa:bb:cc:dd:ee:ff on en1 [ethernet]
"#;
        let set = parse_arp_an(sample);
        assert!(set.contains(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(set.contains(&Ipv4Addr::new(10, 0, 0, 5)));
        assert!(!set.contains(&Ipv4Addr::new(192, 168, 1, 50)));
    }

    #[test]
    fn parse_ip_neigh_sample() {
        let sample = r#"
192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
192.168.1.2 dev eth0 FAILED
10.0.0.9 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE
"#;
        let set = parse_ip_neigh(sample);
        assert!(set.contains(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(set.contains(&Ipv4Addr::new(10, 0, 0, 9)));
        assert!(!set.contains(&Ipv4Addr::new(192, 168, 1, 2)));
    }

    #[test]
    fn parse_ifconfig_netmask_hex() {
        let sample = r#"
en0: flags=8863
	inet 192.168.1.10 netmask 0xffffff00 broadcast 192.168.1.255
"#;
        let nets = parse_ifconfig_ipv4(sample);
        assert!(!nets.is_empty());
        assert!(nets[0].contains(&Ipv4Addr::new(192, 168, 1, 50)));
        assert!(!nets[0].contains(&Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[tokio::test]
    async fn arp_method_runs() {
        // Should not panic; may find 0 or more depending on LAN
        let targets = vec![Target {
            display: "127.0.0.1".into(),
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }];
        let cfg = DiscoverConfig {
            method: DiscoverMethod::Arp,
            ports: vec![],
            timeout: Duration::from_millis(200),
            concurrency: 16,
            rate: Arc::new(RateLimiter::unlimited()),
        };
        let (_live, stats) = discover_hosts(targets, cfg).await.unwrap();
        assert_eq!(stats.method_used, "arp");
        // loopback counted as on-link interface address
        assert_eq!(stats.candidates, 1);
    }
}
