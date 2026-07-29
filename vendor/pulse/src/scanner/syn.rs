//! Half-open TCP SYN scanner (IPv4).
//!
//! Sends crafted SYN segments via a raw Layer-4 socket and classifies replies:
//! - SYN+ACK → open (then polite RST)
//! - RST     → closed
//! - silence → filtered / no response
//!
//! Requires elevated privileges (root / Administrator / CAP_NET_RAW).

use super::rate::RateLimiter;
use super::services::service_name;
use super::{PortResult, Protocol, ScanConfig, ScanEvent, ScanStats, Target};
use anyhow::{bail, Context, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::transport::{
    tcp_packet_iter, transport_channel, TransportChannelType, TransportProtocol, TransportReceiver,
    TransportSender,
};
use rand::RngExt;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket as StdUdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Key: (target_ip, target_port, our_source_port)
type ProbeKey = (Ipv4Addr, u16, u16);

#[derive(Clone)]
struct Pending {
    host: String,
    sent_at: Instant,
    /// 0 = first try
    attempt: u8,
    src_ip: Ipv4Addr,
}

/// Verify we can open a raw TCP transport channel (needs root/cap).
pub fn ensure_syn_capable() -> Result<()> {
    let channel_type =
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
    transport_channel(64, channel_type)
        .map(|_| ())
        .context(
            "SYN scan needs raw sockets (run as root/sudo, or setcap cap_net_raw+ep on Linux)",
        )?;
    Ok(())
}

pub async fn scan_syn(
    targets: Vec<Target>,
    ports: Vec<u16>,
    config: ScanConfig,
    tx: mpsc::UnboundedSender<ScanEvent>,
    cancel: Arc<AtomicBool>,
) -> Result<(Vec<PortResult>, Arc<ScanStats>)> {
    // Raw sockets + pnet are blocking; run engine off the async runtime.
    let handle = tokio::task::spawn_blocking(move || {
        run_syn_engine(targets, ports, config, tx, cancel)
    });
    handle
        .await
        .context("SYN scan task panicked")?
}

fn run_syn_engine(
    targets: Vec<Target>,
    ports: Vec<u16>,
    config: ScanConfig,
    event_tx: mpsc::UnboundedSender<ScanEvent>,
    cancel: Arc<AtomicBool>,
) -> Result<(Vec<PortResult>, Arc<ScanStats>)> {
    let mut ipv4_targets: Vec<(Target, Ipv4Addr)> = Vec::new();
    for t in targets {
        match t.addr {
            IpAddr::V4(ip) => ipv4_targets.push((t, ip)),
            IpAddr::V6(_) => {
                // Skip IPv6 for SYN path (connect-scan still handles v6)
            }
        }
    }

    if ipv4_targets.is_empty() {
        bail!("SYN scan supports IPv4 targets only (no IPv4 addresses to probe)");
    }

    let remaining_probes = ipv4_targets.len() * ports.len();
    let total = config
        .resume_total_probes
        .unwrap_or(remaining_probes + config.resume_probes_done)
        .max(remaining_probes);
    let stats = Arc::new(ScanStats::new(total));
    stats
        .done
        .store(config.resume_probes_done, Ordering::Relaxed);
    stats
        .closed
        .store(config.resume_closed, Ordering::Relaxed);
    stats
        .open
        .store(config.resume_open.len(), Ordering::Relaxed);
    let store_closed = config.store_closed;
    let progress_every = config.progress_every.max(1);
    let host_batch = config.host_batch.max(1);
    let checkpoint_path = config.checkpoint_path.clone();
    let rate = Arc::new(match config.rate_pps {
        Some(pps) if pps > 0 => RateLimiter::per_second(pps),
        _ => RateLimiter::unlimited(),
    });

    let channel_type =
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
    let (mut sender, receiver) = transport_channel(65535, channel_type).context(
        "failed to open raw TCP channel — need root/sudo (or CAP_NET_RAW on Linux)",
    )?;

    let pending: Arc<Mutex<HashMap<ProbeKey, Pending>>> = Arc::new(Mutex::new(HashMap::new()));
    // Seed with resumed open results
    let results: Arc<Mutex<Vec<PortResult>>> =
        Arc::new(Mutex::new(config.resume_open.clone()));
    let sport_counter = Arc::new(AtomicU16::new(rand::rng().random_range(40000..50000u16)));
    let src_cache: Arc<Mutex<HashMap<u32, Ipv4Addr>>> = Arc::new(Mutex::new(HashMap::new()));

    // Listener thread: classify SYN-ACK / RST
    let pending_rx = pending.clone();
    let results_rx = results.clone();
    let stats_rx = stats.clone();
    let event_rx = event_tx.clone();
    let cancel_rx = cancel.clone();
    let timeout = config.timeout;
    let total_rx = total;
    let store_rx = store_closed;
    let pe_rx = progress_every;

    let listener = thread::Builder::new()
        .name("pulse-syn-rx".into())
        .spawn(move || {
            listen_replies(
                receiver,
                pending_rx,
                results_rx,
                stats_rx,
                event_rx,
                cancel_rx,
                timeout,
                total_rx,
                store_rx,
                pe_rx,
            )
        })
        .context("failed to spawn SYN listener")?;

    let hosts: Vec<(String, Ipv4Addr)> = ipv4_targets
        .iter()
        .map(|(t, ip)| (t.display.clone(), *ip))
        .collect();
    let port_list = ports;
    let ceiling = config.concurrency.max(1).min(4000);
    let mut adaptive = super::adaptive::AdaptiveController::new(config.adaptive, ceiling);
    let syn_retries = config.syn_retries;
    // Host-ordered: host_parallel concurrent hosts (each fully drained)
    let host_batch = if config.host_parallel > 0 {
        config.host_parallel.max(1)
    } else if config.host_first {
        1
    } else {
        host_batch
    };
    let hosts_total = hosts.len();
    let mut hosts_finished = 0usize;

    // Process host batches so checkpoint/resume works at host granularity
    for chunk in hosts.chunks(host_batch) {
        if cancel.load(Ordering::Relaxed) {
            break;
        }

        let max_inflight = adaptive.concurrency();
        let open_before = stats.open_count();
        let closed_before = stats.closed_count();
        let done_before = stats.done_count();
        let batch_jobs: Vec<(String, Ipv4Addr, u16)> = chunk
            .iter()
            .flat_map(|(name, ip)| {
                port_list
                    .iter()
                    .map(move |&p| (name.clone(), *ip, p))
            })
            .collect();
        let batch_probes = batch_jobs.len();
        let mut next = 0usize;

        while next < batch_jobs.len() || !pending.lock().unwrap().is_empty() {
            if cancel.load(Ordering::Relaxed) {
                break;
            }

            let retries = reap_timeouts(
                &pending,
                &results,
                &stats,
                &event_tx,
                config.timeout,
                total,
                store_closed,
                progress_every,
                syn_retries,
            );
            // Retransmit silent probes
            for (dst, dport, pend) in retries {
                rate.acquire_blocking();
                let sport = next_sport(&sport_counter);
                let seq: u32 = rand::rng().random();
                if send_syn(&mut sender, pend.src_ip, dst, sport, dport, seq).is_ok() {
                    pending.lock().unwrap().insert(
                        (dst, dport, sport),
                        Pending {
                            host: pend.host,
                            sent_at: Instant::now(),
                            attempt: pend.attempt.saturating_add(1),
                            src_ip: pend.src_ip,
                        },
                    );
                } else {
                    push_result(
                        &results,
                        &stats,
                        &event_tx,
                        closed_syn_named(&pend.host, dst, dport),
                        total,
                        store_closed,
                        progress_every,
                    );
                }
            }

            while next < batch_jobs.len() {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let inflight = pending.lock().unwrap().len();
                if inflight >= max_inflight {
                    break;
                }

                rate.acquire_blocking();

                let (host_name, dst_ip, dport) = &batch_jobs[next];
                next += 1;

                let src_ip = match cached_local_ipv4(*dst_ip, &src_cache) {
                    Ok(ip) => ip,
                    Err(_) => {
                        push_result(
                            &results,
                            &stats,
                            &event_tx,
                            closed_syn_named(host_name, *dst_ip, *dport),
                            total,
                            store_closed,
                            progress_every,
                        );
                        continue;
                    }
                };

                let sport = next_sport(&sport_counter);
                let seq: u32 = rand::rng().random();

                if let Err(e) = send_syn(&mut sender, src_ip, *dst_ip, sport, *dport, seq) {
                    let _ = e;
                    push_result(
                        &results,
                        &stats,
                        &event_tx,
                        closed_syn_named(host_name, *dst_ip, *dport),
                        total,
                        store_closed,
                        progress_every,
                    );
                    continue;
                }

                pending.lock().unwrap().insert(
                    (*dst_ip, *dport, sport),
                    Pending {
                        host: host_name.clone(),
                        sent_at: Instant::now(),
                        attempt: 0,
                        src_ip,
                    },
                );

                if !rate.is_limited() && max_inflight > 1000 && next % 64 == 0 {
                    thread::sleep(Duration::from_micros(50));
                }
            }

            thread::sleep(Duration::from_millis(1));
        }

        // Drain batch — force expire, no more retries
        let _ = reap_timeouts(
            &pending,
            &results,
            &stats,
            &event_tx,
            Duration::from_millis(0),
            total,
            store_closed,
            progress_every,
            0, // no retries on final drain
        );
        {
            let mut pend = pending.lock().unwrap();
            for ((dst, dport, _), p) in pend.drain() {
                let r = PortResult {
                    host: p.host,
                    ip: dst.to_string(),
                    port: dport,
                    protocol: Protocol::TcpSyn,
                    open: false,
                    service: service_name(dport).to_string(),
                    latency_ms: None,
                    banner: None,
                };
                push_result(
                    &results,
                    &stats,
                    &event_tx,
                    r,
                    total,
                    store_closed,
                    progress_every,
                );
            }
        }

        // HostDone for each host in chunk (delta opens this batch)
        let batch_opens: Vec<_> = {
            let all = results.lock().unwrap();
            chunk
                .iter()
                .map(|(name, ip)| {
                    let ip_s = ip.to_string();
                    let open_n = all.iter().filter(|r| r.open && r.ip == ip_s).count();
                    (name.clone(), ip_s, open_n)
                })
                .collect()
        };
        // For multi-host chunks, open counts are cumulative for that IP (fine)
        let _ = open_before;
        for (name, ip_s, open_n) in batch_opens {
            let _ = event_tx.send(ScanEvent::HostDone {
                host: name,
                ip: ip_s,
                open: open_n,
                ports: port_list.len(),
            });
            hosts_finished += 1;
        }
        if config.host_first && hosts_total > 1 && hosts_finished % 25 == 0 {
            eprintln!("  host-first  {hosts_finished}/{hosts_total} hosts done");
        }

        // SYN silence ≈ timeout for adaptive (closed that gained no open in batch)
        let open_delta = stats.open_count().saturating_sub(open_before);
        let closed_delta = stats.closed_count().saturating_sub(closed_before);
        let done_delta = stats.done_count().saturating_sub(done_before);
        // Treat "no SYN-ACK and no RST within timeout" as timeout-ish: closed with no fast RST share
        // Approximate: timeouts ≈ closed_delta when open is low and batch finished slowly — use closed_delta
        // that weren't quick RSTs. Without per-probe flag, use closed / done as timeout proxy when open_delta==0.
        let timeout_proxy = if done_delta > 0 && open_delta == 0 {
            // all closed/silence — likely filtered/dark → back off
            closed_delta
        } else {
            // mix of open/RST — count only excess closed as potential silence
            closed_delta.saturating_sub(open_delta)
        };
        if let Some(new_c) = adaptive.observe_batch(batch_probes.max(done_delta), timeout_proxy) {
            eprintln!(
                "  adaptive  SYN inflight → {new_c}  (silence~ {timeout_proxy}/{batch_probes})"
            );
        }

        // Checkpoint after host batch
        if let Some(path) = &checkpoint_path {
            if !cancel.load(Ordering::Relaxed) && path.exists() {
                let host_ips: Vec<String> = chunk.iter().map(|(_, ip)| ip.to_string()).collect();
                let open_after = stats.open_count();
                let closed_after = stats.closed_count();
                let closed_n = closed_after.saturating_sub(closed_before);
                // Collect opens for these hosts from results
                let all = results.lock().unwrap().clone();
                let host_set: std::collections::HashSet<String> =
                    host_ips.iter().cloned().collect();
                let delta_open: Vec<PortResult> = all
                    .into_iter()
                    .filter(|r| r.open && host_set.contains(&r.ip))
                    .collect();
                let _ = open_after;
                if let Ok(mut ck) = super::checkpoint::Checkpoint::load(path) {
                    ck.mark_hosts_done(host_ips, &delta_open, batch_probes, closed_n);
                    let _ = ck.save(path);
                }
            }
        }
    }

    cancel.store(true, Ordering::Relaxed);
    drop(listener);

    stats.finish();

    let mut out = results.lock().unwrap().clone();
    out.sort_by(|a, b| a.ip.cmp(&b.ip).then(a.port.cmp(&b.port)));
    Ok((out, stats))
}

fn listen_replies(
    mut receiver: TransportReceiver,
    pending: Arc<Mutex<HashMap<ProbeKey, Pending>>>,
    results: Arc<Mutex<Vec<PortResult>>>,
    stats: Arc<ScanStats>,
    event_tx: mpsc::UnboundedSender<ScanEvent>,
    cancel: Arc<AtomicBool>,
    _timeout: Duration,
    total: usize,
    store_closed: bool,
    progress_every: usize,
) {
    let mut iter = tcp_packet_iter(&mut receiver);

    while !cancel.load(Ordering::Relaxed) {
        // non-blocking-ish: next() blocks; we rely on cancel + channel close after scan
        match iter.next() {
            Ok((tcp, addr)) => {
                let IpAddr::V4(src_ip) = addr else {
                    continue;
                };

                let flags = tcp.get_flags();
                let our_sport = tcp.get_destination();
                let target_port = tcp.get_source();

                let key: ProbeKey = (src_ip, target_port, our_sport);
                let pending_entry = {
                    let mut map = pending.lock().unwrap();
                    map.remove(&key)
                };

                let Some(pend) = pending_entry else {
                    continue;
                };

                let latency = pend.sent_at.elapsed().as_millis() as u64;

                if flags & TcpFlags::RST != 0 {
                    let r = PortResult {
                        host: pend.host,
                        ip: src_ip.to_string(),
                        port: target_port,
                        protocol: Protocol::TcpSyn,
                        open: false,
                        service: service_name(target_port).to_string(),
                        latency_ms: Some(latency),
                        banner: None,
                    };
                    push_result(
                        &results,
                        &stats,
                        &event_tx,
                        r,
                        total,
                        store_closed,
                        progress_every,
                    );
                } else if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                    // Open — polite RST so we don't leave half-open sockets on target
                    send_rst_for_reply(&src_ip, &tcp);

                    let r = PortResult {
                        host: pend.host,
                        ip: src_ip.to_string(),
                        port: target_port,
                        protocol: Protocol::TcpSyn,
                        open: true,
                        service: service_name(target_port).to_string(),
                        latency_ms: Some(latency),
                        banner: None,
                    };
                    push_result(
                        &results,
                        &stats,
                        &event_tx,
                        r,
                        total,
                        store_closed,
                        progress_every,
                    );
                }
            }
            Err(_) => {
                // transient read error
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

fn send_rst_for_reply(remote_ip: &Ipv4Addr, tcp: &TcpPacket) {
    // Open a short-lived channel to fire RST (listener thread can't easily share sender).
    let channel_type =
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
    let Ok((mut sender, _)) = transport_channel(128, channel_type) else {
        return;
    };
    let Ok(local) = local_ipv4_for(*remote_ip) else {
        return;
    };

    let mut buf = [0u8; 20];
    let mut pkt = match MutableTcpPacket::new(&mut buf) {
        Some(p) => p,
        None => return,
    };
    pkt.set_source(tcp.get_destination());
    pkt.set_destination(tcp.get_source());
    pkt.set_sequence(tcp.get_acknowledgement());
    pkt.set_acknowledgement(0);
    pkt.set_data_offset(5);
    pkt.set_flags(TcpFlags::RST | TcpFlags::ACK);
    pkt.set_window(0);
    pkt.set_urgent_ptr(0);
    let csum = ipv4_checksum(&pkt.to_immutable(), &local, remote_ip);
    pkt.set_checksum(csum);
    let _ = sender.send_to(pkt, IpAddr::V4(*remote_ip));
}

fn send_syn(
    sender: &mut TransportSender,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
) -> Result<()> {
    let mut buf = [0u8; 20];
    let mut pkt = MutableTcpPacket::new(&mut buf).context("tcp buffer")?;
    pkt.set_source(sport);
    pkt.set_destination(dport);
    pkt.set_sequence(seq);
    pkt.set_acknowledgement(0);
    pkt.set_data_offset(5);
    pkt.set_flags(TcpFlags::SYN);
    pkt.set_window(64240);
    pkt.set_urgent_ptr(0);
    let csum = ipv4_checksum(&pkt.to_immutable(), &src, &dst);
    pkt.set_checksum(csum);
    sender
        .send_to(pkt, IpAddr::V4(dst))
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("send SYN: {e}"))
}

/// Returns probes that should be retransmitted (attempt < max_retries).
fn reap_timeouts(
    pending: &Arc<Mutex<HashMap<ProbeKey, Pending>>>,
    results: &Arc<Mutex<Vec<PortResult>>>,
    stats: &Arc<ScanStats>,
    event_tx: &mpsc::UnboundedSender<ScanEvent>,
    timeout: Duration,
    total: usize,
    store_closed: bool,
    progress_every: usize,
    max_retries: u8,
) -> Vec<(Ipv4Addr, u16, Pending)> {
    let now = Instant::now();
    let mut expired = Vec::new();
    {
        let mut map = pending.lock().unwrap();
        map.retain(|&key, p| {
            if timeout.is_zero() || now.duration_since(p.sent_at) >= timeout {
                expired.push((key, p.clone()));
                false
            } else {
                true
            }
        });
    }

    let mut retries = Vec::new();
    for ((dst, dport, _sport), p) in expired {
        if p.attempt < max_retries {
            retries.push((dst, dport, p));
            continue;
        }
        let r = PortResult {
            host: p.host,
            ip: dst.to_string(),
            port: dport,
            protocol: Protocol::TcpSyn,
            open: false,
            service: service_name(dport).to_string(),
            latency_ms: None,
            banner: None,
        };
        push_result(
            results,
            stats,
            event_tx,
            r,
            total,
            store_closed,
            progress_every,
        );
    }
    retries
}

fn push_result(
    results: &Arc<Mutex<Vec<PortResult>>>,
    stats: &Arc<ScanStats>,
    event_tx: &mpsc::UnboundedSender<ScanEvent>,
    r: PortResult,
    total: usize,
    store_closed: bool,
    progress_every: usize,
) {
    if r.open {
        stats.open.fetch_add(1, Ordering::Relaxed);
        let _ = event_tx.send(ScanEvent::Open(r.clone()));
        results.lock().unwrap().push(r);
    } else {
        stats.closed.fetch_add(1, Ordering::Relaxed);
        if store_closed {
            results.lock().unwrap().push(r);
        }
    }
    let n = stats.done.fetch_add(1, Ordering::Relaxed) + 1;
    if n == total || n % progress_every.max(1) == 0 {
        let _ = event_tx.send(ScanEvent::Progress { done: n, total });
    }
}

fn closed_syn_named(host: &str, ip: Ipv4Addr, port: u16) -> PortResult {
    PortResult {
        host: host.to_string(),
        ip: ip.to_string(),
        port,
        protocol: Protocol::TcpSyn,
        open: false,
        service: service_name(port).to_string(),
        latency_ms: None,
        banner: None,
    }
}

fn next_sport(counter: &AtomicU16) -> u16 {
    // Stay in ephemeral-ish range 40000–60999
    let v = counter.fetch_add(1, Ordering::Relaxed);
    40000 + (v % 21000)
}

/// Cache source IP per destination /24 — avoids UDP connect per SYN.
fn cached_local_ipv4(
    dst: Ipv4Addr,
    cache: &Mutex<HashMap<u32, Ipv4Addr>>,
) -> Result<Ipv4Addr> {
    let key = u32::from(dst) & 0xffff_ff00;
    if let Some(ip) = cache.lock().unwrap().get(&key).copied() {
        return Ok(ip);
    }
    let ip = local_ipv4_for(dst)?;
    cache.lock().unwrap().insert(key, ip);
    Ok(ip)
}

fn local_ipv4_for(dst: Ipv4Addr) -> Result<Ipv4Addr> {
    let sock = StdUdpSocket::bind("0.0.0.0:0").context("bind for route discovery")?;
    sock.connect(SocketAddrV4::new(dst, 9))
        .context("connect for route discovery")?;
    match sock.local_addr().context("local_addr")? {
        std::net::SocketAddr::V4(a) => Ok(*a.ip()),
        _ => bail!("expected IPv4 local address"),
    }
}
