//! Scan checkpoint / resume for large multi-host jobs.
//!
//! Granularity: **whole hosts**. After each host batch finishes, completed
//! host IPs + open results are written atomically so a crash only re-scans
//! the incomplete batch.

use super::port::{PortResult, Protocol, ScanMode};
use super::Target;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};

pub const CHECKPOINT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub version: u32,
    pub status: CheckpointStatus,
    pub job: JobFingerprint,
    /// Full host list at job start (after discovery). Used to resume without re-discover.
    #[serde(default)]
    pub all_hosts: Vec<String>,
    /// Hosts fully scanned (IP strings).
    pub completed_hosts: Vec<String>,
    /// Open ports found so far.
    pub open: Vec<PortResult>,
    pub probes_done: usize,
    pub open_count: usize,
    pub closed_count: usize,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointStatus {
    InProgress,
    Done,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobFingerprint {
    /// Stable hash of sorted hosts + ports + protocols + mode.
    pub fingerprint: String,
    pub host_count: usize,
    pub ports: Vec<u16>,
    pub protocols: Vec<String>,
    pub mode: String,
    /// Optional human label (target CLI string).
    pub label: Option<String>,
}

impl JobFingerprint {
    pub fn compute(
        targets: &[Target],
        ports: &[u16],
        protocols: &[Protocol],
        mode: ScanMode,
        label: Option<String>,
    ) -> Self {
        let mut ips: Vec<String> = targets.iter().map(|t| t.addr.to_string()).collect();
        ips.sort();
        let mut ports = ports.to_vec();
        ports.sort_unstable();
        let protos: Vec<String> = protocols.iter().map(|p| p.as_str().to_string()).collect();
        let mode_s = match mode {
            ScanMode::Connect => "connect",
            ScanMode::Syn => "syn",
        }
        .to_string();

        // Simple stable fingerprint without extra deps (FNV-ish)
        let mut h: u64 = 0xcbf29ce484222325;
        let mut feed = |s: &str| {
            for b in s.as_bytes() {
                h ^= u64::from(*b);
                h = h.wrapping_mul(0x100000001b3);
            }
            h ^= 0xff;
            h = h.wrapping_mul(0x100000001b3);
        };
        feed("pulse-ckpt-v1");
        for ip in &ips {
            feed(ip);
        }
        for p in &ports {
            feed(&p.to_string());
        }
        for p in &protos {
            feed(p);
        }
        feed(&mode_s);
        feed(&ips.len().to_string());

        Self {
            fingerprint: format!("{h:016x}"),
            host_count: ips.len(),
            ports,
            protocols: protos,
            mode: mode_s,
            label,
        }
    }
}

impl Checkpoint {
    pub fn new(job: JobFingerprint, all_hosts: Vec<String>) -> Self {
        Self {
            version: CHECKPOINT_VERSION,
            status: CheckpointStatus::InProgress,
            job,
            all_hosts,
            completed_hosts: Vec::new(),
            open: Vec::new(),
            probes_done: 0,
            open_count: 0,
            closed_count: 0,
            updated_at: now_iso(),
        }
    }

    /// Rebuild Target list from stored IPs (display = ip).
    pub fn targets_from_all(&self) -> Vec<Target> {
        self.all_hosts
            .iter()
            .filter_map(|s| {
                let addr = s.parse().ok()?;
                Some(Target {
                    display: s.clone(),
                    addr,
                })
            })
            .collect()
    }

    pub fn load(path: &Path) -> Result<Self> {
        let f = File::open(path)
            .with_context(|| format!("failed to open checkpoint {}", path.display()))?;
        let ck: Checkpoint = serde_json::from_reader(BufReader::new(f))
            .with_context(|| format!("invalid checkpoint JSON in {}", path.display()))?;
        if ck.version != CHECKPOINT_VERSION {
            bail!(
                "checkpoint version {} unsupported (need {})",
                ck.version,
                CHECKPOINT_VERSION
            );
        }
        Ok(ck)
    }

    /// Load existing checkpoint. Caller supplies expected ports/mode for a soft check.
    pub fn load_for_resume(
        path: &Path,
        ports: &[u16],
        protocols: &[Protocol],
        mode: ScanMode,
    ) -> Result<Self> {
        let ck = Self::load(path)?;
        let mode_s = match mode {
            ScanMode::Connect => "connect",
            ScanMode::Syn => "syn",
        };
        let mut ports_sorted = ports.to_vec();
        ports_sorted.sort_unstable();
        if ck.job.ports != ports_sorted {
            bail!(
                "checkpoint ports differ from CLI (checkpoint has {} ports, CLI has {}).\n\
                 Use the same -p/--top as the original scan, or a new --checkpoint file.",
                ck.job.ports.len(),
                ports_sorted.len()
            );
        }
        if ck.job.mode != mode_s {
            bail!(
                "checkpoint mode is '{}' but CLI mode is '{}'",
                ck.job.mode,
                mode_s
            );
        }
        let protos: Vec<String> = protocols.iter().map(|p| p.as_str().to_string()).collect();
        if ck.job.protocols != protos {
            bail!("checkpoint protocols differ from CLI");
        }
        Ok(ck)
    }

    pub fn completed_set(&self) -> HashSet<String> {
        self.completed_hosts.iter().cloned().collect()
    }

    pub fn mark_hosts_done(
        &mut self,
        hosts: impl IntoIterator<Item = String>,
        new_open: &[PortResult],
        probes_in_batch: usize,
        closed_in_batch: usize,
    ) {
        let mut set = self.completed_set();
        for h in hosts {
            if set.insert(h.clone()) {
                self.completed_hosts.push(h);
            }
        }
        // Merge open (dedupe by ip:port:proto)
        let mut seen: HashSet<String> = self
            .open
            .iter()
            .map(|r| format!("{}:{}:{}", r.ip, r.port, r.protocol.as_str()))
            .collect();
        for r in new_open {
            let k = format!("{}:{}:{}", r.ip, r.port, r.protocol.as_str());
            if seen.insert(k) {
                self.open.push(r.clone());
            }
        }
        self.probes_done = self.probes_done.saturating_add(probes_in_batch);
        self.open_count = self.open.len();
        self.closed_count = self.closed_count.saturating_add(closed_in_batch);
        self.status = CheckpointStatus::InProgress;
        self.updated_at = now_iso();
    }

    pub fn mark_done(&mut self) {
        self.status = CheckpointStatus::Done;
        self.updated_at = now_iso();
    }

    /// Atomic write: temp file + rename.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("mkdir {}", parent.display()))?;
            }
        }
        let tmp = tmp_path(path);
        {
            let mut f = File::create(&tmp)
                .with_context(|| format!("create temp checkpoint {}", tmp.display()))?;
            serde_json::to_writer_pretty(&mut f, self)
                .context("serialize checkpoint")?;
            f.write_all(b"\n")?;
            f.sync_all().ok();
        }
        fs::rename(&tmp, path).with_context(|| {
            format!(
                "rename checkpoint {} → {}",
                tmp.display(),
                path.display()
            )
        })?;
        Ok(())
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

fn now_iso() -> String {
    // Prefer chrono if available (already a dep)
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Filter targets that are not yet completed.
pub fn remaining_targets(targets: &[Target], completed: &HashSet<String>) -> Vec<Target> {
    targets
        .iter()
        .filter(|t| !completed.contains(&t.addr.to_string()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn t(ip: &str) -> Target {
        Target {
            display: ip.into(),
            addr: IpAddr::V4(ip.parse::<Ipv4Addr>().unwrap()),
        }
    }

    #[test]
    fn fingerprint_stable() {
        let hosts = vec![t("10.0.0.2"), t("10.0.0.1")];
        let a = JobFingerprint::compute(&hosts, &[80, 22], &[Protocol::Tcp], ScanMode::Connect, None);
        let hosts2 = vec![t("10.0.0.1"), t("10.0.0.2")];
        let b = JobFingerprint::compute(&hosts2, &[22, 80], &[Protocol::Tcp], ScanMode::Connect, None);
        assert_eq!(a.fingerprint, b.fingerprint);
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("pulse-ckpt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("scan.ckpt");

        let job = JobFingerprint::compute(
            &[t("127.0.0.1")],
            &[80],
            &[Protocol::Tcp],
            ScanMode::Connect,
            Some("test".into()),
        );
        let mut ck = Checkpoint::new(job.clone(), vec!["127.0.0.1".into()]);
        ck.mark_hosts_done(vec!["127.0.0.1".into()], &[], 1, 1);
        ck.save(&path).unwrap();

        let loaded = Checkpoint::load(&path).unwrap();
        assert_eq!(loaded.completed_hosts, vec!["127.0.0.1".to_string()]);
        assert_eq!(loaded.job.fingerprint, job.fingerprint);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remaining_filters() {
        let hosts = vec![t("10.0.0.1"), t("10.0.0.2"), t("10.0.0.3")];
        let mut set = HashSet::new();
        set.insert("10.0.0.2".into());
        let r = remaining_targets(&hosts, &set);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].addr.to_string(), "10.0.0.1");
        assert_eq!(r[1].addr.to_string(), "10.0.0.3");
    }
}
