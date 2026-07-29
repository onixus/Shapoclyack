use super::services::{service_name, udp_service_name};
use super::Target;
use anyhow::{bail, Result};
use futures::stream::{self, StreamExt};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    /// Half-open SYN scan result (still TCP service space)
    TcpSyn,
    Udp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::TcpSyn => "syn",
            Protocol::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanMode {
    #[default]
    Connect,
    Syn,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct PortResult {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub protocol: Protocol,
    pub open: bool,
    pub service: String,
    pub latency_ms: Option<u64>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub concurrency: usize,
    pub timeout: Duration,
    pub grab_banner: bool,
    pub protocols: Vec<Protocol>,
    pub mode: ScanMode,
    /// Max probes per second (None = unlimited).
    pub rate_pps: Option<u64>,
    /// Keep closed ports in result vector (default false for large nets).
    pub store_closed: bool,
    /// Emit Progress every N probes (plus final).
    pub progress_every: usize,
    /// Hosts per scheduling chunk (connect path).
    pub host_batch: usize,
    /// Optional checkpoint file — written after each host batch.
    pub checkpoint_path: Option<std::path::PathBuf>,
    /// Open results restored from a prior checkpoint (merged into final output).
    pub resume_open: Vec<PortResult>,
    /// Probes already completed (for progress totals when resuming).
    pub resume_probes_done: usize,
    /// Closed count already accumulated when resuming.
    pub resume_closed: usize,
    /// Full job size including already-completed probes (progress denominator).
    pub resume_total_probes: Option<usize>,
    /// Adapt concurrency up to `concurrency` ceiling based on timeout ratio.
    pub adaptive: bool,
    /// Finish all ports on a host before starting the next (pretty host-ordered output).
    pub host_first: bool,
    /// How many hosts to scan concurrently in host-ordered mode (0 = auto: 1 if host_first).
    pub host_parallel: usize,
    /// SYN retransmits on silence (0 = none).
    pub syn_retries: u8,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            concurrency: 500,
            timeout: Duration::from_millis(800),
            grab_banner: false,
            protocols: vec![Protocol::Tcp],
            mode: ScanMode::Connect,
            rate_pps: None,
            store_closed: false,
            progress_every: 64,
            host_batch: 256,
            checkpoint_path: None,
            resume_open: Vec::new(),
            resume_probes_done: 0,
            resume_closed: 0,
            resume_total_probes: None,
            adaptive: false,
            host_first: false,
            host_parallel: 0,
            syn_retries: 0,
        }
    }
}

#[derive(Debug, Default)]
pub struct ScanStats {
    pub total: usize,
    pub open: AtomicUsize,
    pub closed: AtomicUsize,
    pub started: Option<Instant>,
    pub elapsed_ms: AtomicU64,
    pub done: AtomicUsize,
}

impl ScanStats {
    pub fn new(total: usize) -> Self {
        Self {
            total,
            open: AtomicUsize::new(0),
            closed: AtomicUsize::new(0),
            started: Some(Instant::now()),
            elapsed_ms: AtomicU64::new(0),
            done: AtomicUsize::new(0),
        }
    }

    pub fn finish(&self) {
        if let Some(start) = self.started {
            self.elapsed_ms
                .store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
        }
    }

    pub fn open_count(&self) -> usize {
        self.open.load(Ordering::Relaxed)
    }

    pub fn closed_count(&self) -> usize {
        self.closed.load(Ordering::Relaxed)
    }

    pub fn done_count(&self) -> usize {
        self.done.load(Ordering::Relaxed)
    }

    pub fn elapsed(&self) -> u64 {
        if let Some(start) = self.started {
            let stored = self.elapsed_ms.load(Ordering::Relaxed);
            if stored == 0 {
                return start.elapsed().as_millis() as u64;
            }
            return stored;
        }
        self.elapsed_ms.load(Ordering::Relaxed)
    }

    pub fn rate(&self) -> f64 {
        let elapsed = self.elapsed().max(1) as f64 / 1000.0;
        self.done_count() as f64 / elapsed
    }
}

#[derive(Debug, Clone)]
pub enum ScanEvent {
    Progress { done: usize, total: usize },
    Open(PortResult),
    /// Host fully probed (host-first or after single-host batch).
    HostDone {
        host: String,
        ip: String,
        open: usize,
        ports: usize,
    },
    Finished,
}

/// Parse port specifications: "80", "1-1024", "22,80,443", "1-100,443,8080-8090"
pub fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid port: {start}"))?;
            let end: u16 = end
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid port: {end}"))?;

            if start == 0 || end == 0 {
                bail!("port 0 is not valid");
            }
            if start > end {
                bail!("invalid range {start}-{end}");
            }

            for p in start..=end {
                ports.push(p);
            }
        } else {
            let p: u16 = part
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid port: {part}"))?;
            if p == 0 {
                bail!("port 0 is not valid");
            }
            ports.push(p);
        }
    }

    if ports.is_empty() {
        bail!("no ports specified");
    }

    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// Callback-style scan with progress / open / host-done hooks.
pub async fn scan_ports_ex(
    targets: &[Target],
    ports: &[u16],
    config: &ScanConfig,
    on_progress: impl Fn(usize) + Send + Sync + 'static,
    on_open: impl Fn(&PortResult) + Send + Sync + 'static,
    on_host_done: impl Fn(HostDoneInfo) + Send + Sync + 'static,
) -> (Vec<PortResult>, Arc<ScanStats>) {
    let (tx, mut rx) = mpsc::unbounded_channel::<ScanEvent>();
    let cancel = Arc::new(AtomicBool::new(false));

    let targets = targets.to_vec();
    let ports = ports.to_vec();
    let config = config.clone();
    let handle = tokio::spawn(scan_with_events(targets, ports, config, tx, cancel));

    while let Some(ev) = rx.recv().await {
        match ev {
            ScanEvent::Progress { done, .. } => on_progress(done),
            ScanEvent::Open(r) => on_open(&r),
            ScanEvent::HostDone {
                host,
                ip,
                open,
                ports,
            } => on_host_done(HostDoneInfo {
                host,
                ip,
                open,
                ports,
            }),
            ScanEvent::Finished => break,
        }
    }

    handle.await.unwrap_or_else(|_| (Vec::new(), Arc::new(ScanStats::new(0))))
}

#[derive(Debug, Clone)]
pub struct HostDoneInfo {
    #[allow(dead_code)]
    pub host: String,
    pub ip: String,
    pub open: usize,
    pub ports: usize,
}

/// Event-driven scan used by TUI and CLI.
pub async fn scan_with_events(
    targets: Vec<Target>,
    ports: Vec<u16>,
    config: ScanConfig,
    tx: mpsc::UnboundedSender<ScanEvent>,
    cancel: Arc<AtomicBool>,
) -> (Vec<PortResult>, Arc<ScanStats>) {
    let protocols = if config.protocols.is_empty() {
        vec![Protocol::Tcp]
    } else {
        config.protocols.clone()
    };

    let want_tcp = protocols.iter().any(|p| matches!(p, Protocol::Tcp | Protocol::TcpSyn));
    let want_udp = protocols.iter().any(|p| matches!(p, Protocol::Udp));
    let syn_mode = matches!(config.mode, ScanMode::Syn) && want_tcp;

    // SYN path for TCP (IPv4); optional UDP still uses datagram probes.
    if syn_mode {
        let tcp_targets = targets.clone();
        let tcp_ports = ports.clone();
        let syn_config = config.clone();
        let syn_tx = tx.clone();
        let syn_cancel = cancel.clone();

        let (mut syn_results, syn_stats) = match super::syn::scan_syn(
            tcp_targets,
            tcp_ports,
            syn_config,
            syn_tx,
            syn_cancel,
        )
        .await
        {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("  SYN scan error: {e:#}");
                let _ = tx.send(ScanEvent::Finished);
                return (Vec::new(), Arc::new(ScanStats::new(0)));
            }
        };

        if !want_udp {
            let _ = tx.send(ScanEvent::Finished);
            return (syn_results, syn_stats);
        }

        // TCP SYN + UDP datagram probes
        let udp_config = ScanConfig {
            mode: ScanMode::Connect,
            protocols: vec![Protocol::Udp],
            ..config.clone()
        };
        let (udp_tx, mut udp_rx) = mpsc::unbounded_channel();
        let udp_cancel = cancel.clone();
        let udp_handle = tokio::spawn(scan_connect_only(
            targets,
            ports,
            udp_config,
            udp_tx,
            udp_cancel,
        ));

        while let Some(ev) = udp_rx.recv().await {
            match ev {
                ScanEvent::Progress { done, total } => {
                    let _ = tx.send(ScanEvent::Progress {
                        done: syn_stats.done_count() + done,
                        total: syn_stats.total + total,
                    });
                }
                ScanEvent::Open(r) => {
                    let _ = tx.send(ScanEvent::Open(r));
                }
                ScanEvent::HostDone {
                    host,
                    ip,
                    open,
                    ports,
                } => {
                    let _ = tx.send(ScanEvent::HostDone {
                        host,
                        ip,
                        open,
                        ports,
                    });
                }
                ScanEvent::Finished => break,
            }
        }

        let (udp_results, udp_stats) = udp_handle
            .await
            .unwrap_or_else(|_| (Vec::new(), Arc::new(ScanStats::new(0))));

        syn_results.extend(udp_results);
        let total = syn_stats.total + udp_stats.total;
        let merged = Arc::new(ScanStats::new(total));
        merged
            .open
            .store(syn_stats.open_count() + udp_stats.open_count(), Ordering::Relaxed);
        merged.closed.store(
            syn_stats.closed_count() + udp_stats.closed_count(),
            Ordering::Relaxed,
        );
        merged.done.store(
            syn_stats.done_count() + udp_stats.done_count(),
            Ordering::Relaxed,
        );
        merged.finish();
        let _ = tx.send(ScanEvent::Finished);
        return (syn_results, merged);
    }

    scan_connect_only(targets, ports, config, tx, cancel).await
}

async fn scan_connect_only(
    targets: Vec<Target>,
    ports: Vec<u16>,
    config: ScanConfig,
    tx: mpsc::UnboundedSender<ScanEvent>,
    cancel: Arc<AtomicBool>,
) -> (Vec<PortResult>, Arc<ScanStats>) {
    use super::rate::RateLimiter;

    let protocols = if config.protocols.is_empty() {
        vec![Protocol::Tcp]
    } else {
        config
            .protocols
            .iter()
            .copied()
            .filter(|p| !matches!(p, Protocol::TcpSyn))
            .map(|p| if matches!(p, Protocol::Tcp) { Protocol::Tcp } else { p })
            .collect::<Vec<_>>()
    };
    let protocols = if protocols.is_empty() {
        vec![Protocol::Tcp]
    } else {
        protocols
    };

    let remaining_probes = targets.len() * ports.len() * protocols.len();
    let total = config
        .resume_total_probes
        .unwrap_or(remaining_probes + config.resume_probes_done)
        .max(remaining_probes);
    let stats = Arc::new(ScanStats::new(total));
    // Seed stats with prior progress so rates/progress look continuous
    stats
        .done
        .store(config.resume_probes_done, Ordering::Relaxed);
    stats
        .closed
        .store(config.resume_closed, Ordering::Relaxed);
    stats
        .open
        .store(config.resume_open.len(), Ordering::Relaxed);

    let ceiling = config.concurrency.max(1);
    let mut adaptive = super::adaptive::AdaptiveController::new(config.adaptive, ceiling);
    let rate = Arc::new(match config.rate_pps {
        Some(pps) if pps > 0 => RateLimiter::per_second(pps),
        _ => RateLimiter::unlimited(),
    });
    let progress_every = config.progress_every.max(1);
    let store_closed = config.store_closed;
    let checkpoint_path = config.checkpoint_path.clone();
    let ports_per_host = ports.len() * protocols.len();
    let hosts_total = targets.len();

    // Host-ordered mode: complete each host's ports before HostDone; N hosts in parallel.
    let host_ordered = config.host_first || config.host_parallel > 0;
    let host_parallel = if config.host_parallel > 0 {
        config.host_parallel.max(1)
    } else if config.host_first {
        1
    } else {
        0
    };
    let host_batch = if host_ordered {
        host_parallel.max(1)
    } else {
        config.host_batch.max(1)
    };

    // Seed with resumed opens
    let open_results: Arc<tokio::sync::Mutex<Vec<PortResult>>> =
        Arc::new(tokio::sync::Mutex::new(config.resume_open.clone()));
    let closed_results: Arc<tokio::sync::Mutex<Vec<PortResult>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));

    if host_ordered {
        // ── Host-ordered: each host fully scanned; up to host_parallel hosts concurrent ──
        let mut hosts_finished = 0usize;
        for wave in targets.chunks(host_batch) {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            let concurrency = adaptive.concurrency();
            let semaphore = Arc::new(Semaphore::new(concurrency));
            let wave_timeouts = Arc::new(AtomicUsize::new(0));
            let wave_probes = wave.len() * ports_per_host;

            let wave_targets: Vec<Target> = wave.to_vec();
            let results_list: Vec<(Target, usize, usize)> = stream::iter(wave_targets)
                .map(|target| {
                    let sem = semaphore.clone();
                    let stats = stats.clone();
                    let tx = tx.clone();
                    let cancel = cancel.clone();
                    let rate = rate.clone();
                    let open_results = open_results.clone();
                    let closed_results = closed_results.clone();
                    let wave_timeouts = wave_timeouts.clone();
                    let ports = ports.clone();
                    let protocols = protocols.clone();
                    let timeout_dur = config.timeout;
                    let grab = config.grab_banner;
                    let total = stats.total;
                    let checkpoint_path = checkpoint_path.clone();

                    async move {
                        if cancel.load(Ordering::Relaxed) {
                            return (target, 0usize, 0usize);
                        }
                        let mut host_open: Vec<PortResult> = Vec::new();
                        let mut host_timeouts = 0usize;
                        let mut host_closed = 0usize;

                        let jobs: Vec<(u16, Protocol)> = ports
                            .iter()
                            .flat_map(|&p| protocols.iter().map(move |&proto| (p, proto)))
                            .collect();

                        let probe_outs: Vec<(PortResult, bool)> = stream::iter(jobs)
                            .map(|(port, proto)| {
                                let sem = sem.clone();
                                let cancel = cancel.clone();
                                let rate = rate.clone();
                                let target = target.clone();
                                async move {
                                    if cancel.load(Ordering::Relaxed) {
                                        return (closed_result(&target, port, proto), false);
                                    }
                                    let _permit = sem.acquire().await.expect("sem");
                                    rate.acquire().await;
                                    if cancel.load(Ordering::Relaxed) {
                                        return (closed_result(&target, port, proto), false);
                                    }
                                    match proto {
                                        Protocol::Tcp | Protocol::TcpSyn => {
                                            probe_tcp_ex(&target, port, timeout_dur, grab).await
                                        }
                                        Protocol::Udp => {
                                            let r = probe_udp(&target, port, timeout_dur).await;
                                            let to = !r.open && r.latency_ms.is_none();
                                            (r, to)
                                        }
                                    }
                                }
                            })
                            .buffer_unordered(concurrency.max(1))
                            .collect()
                            .await;

                        for (result, timed_out) in probe_outs {
                            if timed_out {
                                host_timeouts += 1;
                                wave_timeouts.fetch_add(1, Ordering::Relaxed);
                            }
                            if result.open {
                                stats.open.fetch_add(1, Ordering::Relaxed);
                                let _ = tx.send(ScanEvent::Open(result.clone()));
                                open_results.lock().await.push(result.clone());
                                host_open.push(result);
                            } else {
                                stats.closed.fetch_add(1, Ordering::Relaxed);
                                host_closed += 1;
                                if store_closed {
                                    closed_results.lock().await.push(result);
                                }
                            }
                            let n = stats.done.fetch_add(1, Ordering::Relaxed) + 1;
                            if n == total || n % progress_every == 0 {
                                let _ = tx.send(ScanEvent::Progress { done: n, total });
                            }
                        }

                        let open_n = host_open.len();
                        let _ = tx.send(ScanEvent::HostDone {
                            host: target.display.clone(),
                            ip: target.addr.to_string(),
                            open: open_n,
                            ports: ports_per_host,
                        });

                        if let Some(path) = &checkpoint_path {
                            if !cancel.load(Ordering::Relaxed) {
                                let _ = save_batch_checkpoint(
                                    path,
                                    &[target.addr.to_string()],
                                    &host_open,
                                    ports_per_host,
                                    host_closed,
                                );
                            }
                        }

                        (target, open_n, host_timeouts)
                    }
                })
                .buffer_unordered(host_batch)
                .collect()
                .await;

            hosts_finished += results_list.len();
            let to_n = wave_timeouts.load(Ordering::Relaxed);
            if let Some(new_c) = adaptive.observe_batch(wave_probes.max(1), to_n) {
                eprintln!(
                    "  adaptive  concurrency → {new_c}  (timeouts {to_n}/{wave_probes} = {:.0}%)",
                    adaptive.last_timeout_ratio * 100.0
                );
            }
            if hosts_total > 1 && hosts_finished % 25 == 0 {
                eprintln!(
                    "  host-first  {hosts_finished}/{hosts_total} hosts done  (parallel {host_batch})"
                );
            }
        }
    } else {
        // ── Mixed host×port pool (legacy high-throughput) ──
        let batch_open: Arc<tokio::sync::Mutex<Vec<PortResult>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));

        for chunk in targets.chunks(host_batch) {
            if cancel.load(Ordering::Relaxed) {
                break;
            }

            let concurrency = adaptive.concurrency();
            let semaphore = Arc::new(Semaphore::new(concurrency));

            batch_open.lock().await.clear();
            let batch_closed = Arc::new(AtomicUsize::new(0));
            let batch_timeouts = Arc::new(AtomicUsize::new(0));

            let mut jobs: Vec<(Target, u16, Protocol)> =
                Vec::with_capacity(chunk.len() * ports.len() * protocols.len());
            for t in chunk {
                for &p in &ports {
                    for &proto in &protocols {
                        jobs.push((t.clone(), p, proto));
                    }
                }
            }
            let batch_probes = jobs.len();

            stream::iter(jobs)
                .map(|(target, port, proto)| {
                    let sem = semaphore.clone();
                    let stats = stats.clone();
                    let tx = tx.clone();
                    let cancel = cancel.clone();
                    let rate = rate.clone();
                    let open_results = open_results.clone();
                    let closed_results = closed_results.clone();
                    let batch_open = batch_open.clone();
                    let batch_closed = batch_closed.clone();
                    let batch_timeouts = batch_timeouts.clone();
                    let timeout_dur = config.timeout;
                    let grab = config.grab_banner;
                    let total = stats.total;

                    async move {
                        if cancel.load(Ordering::Relaxed) {
                            return;
                        }
                        let _permit = sem.acquire().await.expect("semaphore closed");
                        rate.acquire().await;
                        if cancel.load(Ordering::Relaxed) {
                            return;
                        }

                        let (result, timed_out) = match proto {
                            Protocol::Tcp | Protocol::TcpSyn => {
                                probe_tcp_ex(&target, port, timeout_dur, grab).await
                            }
                            Protocol::Udp => {
                                let r = probe_udp(&target, port, timeout_dur).await;
                                let to = !r.open && r.latency_ms.is_none();
                                (r, to)
                            }
                        };

                        if timed_out {
                            batch_timeouts.fetch_add(1, Ordering::Relaxed);
                        }
                        if result.open {
                            stats.open.fetch_add(1, Ordering::Relaxed);
                            let _ = tx.send(ScanEvent::Open(result.clone()));
                            open_results.lock().await.push(result.clone());
                            batch_open.lock().await.push(result);
                        } else {
                            stats.closed.fetch_add(1, Ordering::Relaxed);
                            batch_closed.fetch_add(1, Ordering::Relaxed);
                            if store_closed {
                                closed_results.lock().await.push(result);
                            }
                        }
                        let n = stats.done.fetch_add(1, Ordering::Relaxed) + 1;
                        if n == total || n % progress_every == 0 {
                            let _ = tx.send(ScanEvent::Progress { done: n, total });
                        }
                    }
                })
                .buffer_unordered(concurrency)
                .collect::<Vec<()>>()
                .await;

            let to_n = batch_timeouts.load(Ordering::Relaxed);
            if let Some(new_c) = adaptive.observe_batch(batch_probes, to_n) {
                eprintln!(
                    "  adaptive  concurrency → {new_c}  (timeouts {to_n}/{batch_probes} = {:.0}%)",
                    adaptive.last_timeout_ratio * 100.0
                );
            }

            let delta_open = batch_open.lock().await.clone();
            for t in chunk {
                let open_n = delta_open
                    .iter()
                    .filter(|r| r.ip == t.addr.to_string())
                    .count();
                let _ = tx.send(ScanEvent::HostDone {
                    host: t.display.clone(),
                    ip: t.addr.to_string(),
                    open: open_n,
                    ports: ports_per_host,
                });
            }

            if let Some(path) = &checkpoint_path {
                if !cancel.load(Ordering::Relaxed) {
                    let hosts: Vec<String> = chunk.iter().map(|t| t.addr.to_string()).collect();
                    let closed_n = batch_closed.load(Ordering::Relaxed);
                    if let Err(e) = save_batch_checkpoint(
                        path,
                        &hosts,
                        &delta_open,
                        batch_probes,
                        closed_n,
                    ) {
                        eprintln!("  checkpoint warning: {e:#}");
                    }
                }
            }
        }
    }

    // Final progress tick
    let _ = tx.send(ScanEvent::Progress {
        done: stats.done_count(),
        total: stats.total,
    });

    stats.finish();
    let _ = tx.send(ScanEvent::Finished);

    let mut results = open_results.lock().await.clone();
    if store_closed {
        results.extend(closed_results.lock().await.clone());
    }
    results.sort_by(|a, b| a.ip.cmp(&b.ip).then(a.port.cmp(&b.port)));
    (results, stats)
}

fn save_batch_checkpoint(
    path: &std::path::Path,
    hosts: &[String],
    new_open: &[PortResult],
    probes: usize,
    closed: usize,
) -> anyhow::Result<()> {
    use super::checkpoint::{Checkpoint, CheckpointStatus};

    let mut ck = if path.exists() {
        Checkpoint::load(path)?
    } else {
        anyhow::bail!("checkpoint file missing during save (create via --checkpoint first)");
    };
    if ck.status == CheckpointStatus::Done {
        return Ok(());
    }
    ck.mark_hosts_done(hosts.iter().cloned(), new_open, probes, closed);
    ck.save(path)?;
    Ok(())
}

fn closed_result(target: &Target, port: u16, proto: Protocol) -> PortResult {
    PortResult {
        host: target.display.clone(),
        ip: target.addr.to_string(),
        port,
        protocol: proto,
        open: false,
        service: match proto {
            Protocol::Tcp | Protocol::TcpSyn => service_name(port),
            Protocol::Udp => udp_service_name(port),
        }
        .to_string(),
        latency_ms: None,
        banner: None,
    }
}

/// Returns `(result, timed_out)` — timed_out is true only on connect timeout
/// (not on immediate connection refused).
async fn probe_tcp_ex(
    target: &Target,
    port: u16,
    timeout_dur: Duration,
    grab_banner: bool,
) -> (PortResult, bool) {
    let addr = SocketAddr::new(target.addr, port);
    let start = Instant::now();

    match timeout(timeout_dur, TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let latency = start.elapsed().as_millis() as u64;
            let banner = if grab_banner {
                grab_service_banner(&mut stream, timeout_dur).await
            } else {
                None
            };

            (
                PortResult {
                    host: target.display.clone(),
                    ip: target.addr.to_string(),
                    port,
                    protocol: Protocol::Tcp,
                    open: true,
                    service: service_name(port).to_string(),
                    latency_ms: Some(latency),
                    banner,
                },
                false,
            )
        }
        Ok(Err(_)) => {
            // Immediate refuse/reset — host is responsive, not a timeout
            (closed_result(target, port, Protocol::Tcp), false)
        }
        Err(_) => {
            // Wall-clock timeout
            (closed_result(target, port, Protocol::Tcp), true)
        }
    }
}

/// Best-effort UDP probe: send a small payload, treat any reply as open.
/// Silence is reported as closed/filtered (no ICMP handling without raw sockets).
async fn probe_udp(target: &Target, port: u16, timeout_dur: Duration) -> PortResult {
    let addr = SocketAddr::new(target.addr, port);
    let start = Instant::now();

    let result = async {
        let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
        socket.connect(addr).await.ok()?;

        let payload: &[u8] = match port {
            53 => b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01",
            123 => &[
                0x1b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            161 => {
                b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
            }
            _ => b"\x00pulse\x00",
        };

        socket.send(payload).await.ok()?;

        let mut buf = [0u8; 512];
        match timeout(timeout_dur, socket.recv(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let latency = start.elapsed().as_millis() as u64;
                let snippet: String = String::from_utf8_lossy(&buf[..n.min(64)])
                    .chars()
                    .map(|c| if c.is_control() { '.' } else { c })
                    .take(80)
                    .collect();
                Some(PortResult {
                    host: target.display.clone(),
                    ip: target.addr.to_string(),
                    port,
                    protocol: Protocol::Udp,
                    open: true,
                    service: udp_service_name(port).to_string(),
                    latency_ms: Some(latency),
                    banner: if snippet.trim().is_empty() {
                        None
                    } else {
                        Some(snippet)
                    },
                })
            }
            _ => None,
        }
    }
    .await;

    result.unwrap_or_else(|| closed_result(target, port, Protocol::Udp))
}

async fn grab_service_banner(stream: &mut TcpStream, timeout_dur: Duration) -> Option<String> {
    let _ = timeout(Duration::from_millis(50), stream.write_all(b"\r\n")).await;

    let mut buf = [0u8; 512];
    match timeout(
        timeout_dur.min(Duration::from_millis(600)),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => {
            let raw = String::from_utf8_lossy(&buf[..n]);
            let cleaned: String = raw
                .chars()
                .map(|c| {
                    if c.is_control() && c != '\n' && c != '\r' && c != '\t' {
                        '.'
                    } else {
                        c
                    }
                })
                .collect::<String>()
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .chars()
                .take(120)
                .collect();

            if cleaned.is_empty() {
                None
            } else {
                Some(cleaned)
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single() {
        assert_eq!(parse_ports("80").unwrap(), vec![80]);
    }

    #[test]
    fn parse_list() {
        assert_eq!(parse_ports("22,80,443").unwrap(), vec![22, 80, 443]);
    }

    #[test]
    fn parse_range() {
        assert_eq!(parse_ports("1-3").unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn parse_mixed() {
        assert_eq!(
            parse_ports("22,80-82,443").unwrap(),
            vec![22, 80, 81, 82, 443]
        );
    }
}
