//! Parser and matcher for Nmap's `nmap-os-db` (2nd generation).
//!
//! The database is **not** redistributed inside Pulse (Nmap Public Source
//! License / NPSL). Load it from a local path or fetch it at runtime.
//!
//! Format: <https://nmap.org/book/osdetect-fingerprint-format.html>

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Points awarded per test attribute (from the DB header `MatchPoints`).
pub type MatchPoints = HashMap<String, HashMap<String, u32>>;

#[derive(Debug, Clone)]
pub struct NmapFingerprint {
    pub name: String,
    pub classes: Vec<OsClass>,
    pub cpes: Vec<String>,
    /// test name → (attr → expression)
    pub tests: HashMap<String, HashMap<String, String>>,
    pub line: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OsClass {
    pub vendor: String,
    pub family: String,
    pub generation: String,
    pub device_type: String,
}

#[derive(Debug, Clone)]
pub struct NmapOsDb {
    pub match_points: MatchPoints,
    pub fingerprints: Vec<NmapFingerprint>,
    pub path: PathBuf,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MatchResult {
    pub name: String,
    pub classes: Vec<OsClass>,
    pub cpes: Vec<String>,
    pub score: u32,
    pub max_score: u32,
    pub accuracy: f64,
    pub line: usize,
}

impl NmapOsDb {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read nmap-os-db at {}", path.display()))?;
        Self::parse(&text, path.to_path_buf())
    }

    pub fn parse(text: &str, path: PathBuf) -> Result<Self> {
        let mut match_points: MatchPoints = HashMap::new();
        let mut fingerprints = Vec::new();
        let mut current: Option<NmapFingerprint> = None;
        let mut in_match_points = false;
        let mut line_no = 0usize;

        for line in text.lines() {
            line_no += 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line == "MatchPoints" {
                if let Some(fp) = current.take() {
                    fingerprints.push(fp);
                }
                in_match_points = true;
                continue;
            }

            if line.starts_with("Fingerprint ") {
                in_match_points = false;
                if let Some(fp) = current.take() {
                    fingerprints.push(fp);
                }
                current = Some(NmapFingerprint {
                    name: line["Fingerprint ".len()..].to_string(),
                    classes: Vec::new(),
                    cpes: Vec::new(),
                    tests: HashMap::new(),
                    line: line_no,
                });
                continue;
            }

            if let Some(rest) = line.strip_prefix("Class ") {
                if let Some(fp) = current.as_mut() {
                    let parts: Vec<&str> = rest.split('|').map(str::trim).collect();
                    if parts.len() >= 4 {
                        fp.classes.push(OsClass {
                            vendor: parts[0].to_string(),
                            family: parts[1].to_string(),
                            generation: parts[2].to_string(),
                            device_type: parts[3].to_string(),
                        });
                    }
                }
                continue;
            }

            if let Some(rest) = line.strip_prefix("CPE ") {
                if let Some(fp) = current.as_mut() {
                    let cpe = rest.trim().trim_end_matches(" auto").to_string();
                    fp.cpes.push(cpe);
                }
                continue;
            }

            if let Some((name, body)) = parse_test_line(line) {
                let attrs = parse_attrs(body);
                if in_match_points {
                    let mut pts = HashMap::new();
                    for (k, v) in attrs {
                        if let Ok(n) = v.parse::<u32>() {
                            pts.insert(k, n);
                        }
                    }
                    match_points.insert(name, pts);
                } else if let Some(fp) = current.as_mut() {
                    fp.tests.insert(name, attrs);
                }
            }
        }

        if let Some(fp) = current.take() {
            fingerprints.push(fp);
        }

        if fingerprints.is_empty() {
            bail!("no fingerprints parsed from {}", path.display());
        }

        if match_points.is_empty() {
            match_points = default_match_points();
        }

        Ok(Self {
            match_points,
            fingerprints,
            path,
        })
    }

    /// Score a subject fingerprint against every reference print.
    pub fn match_subject(
        &self,
        subject: &HashMap<String, HashMap<String, String>>,
        limit: usize,
    ) -> Vec<MatchResult> {
        let mut scored: Vec<MatchResult> = self
            .fingerprints
            .iter()
            .filter_map(|fp| self.score_one(fp, subject))
            .collect();

        scored.sort_by(|a, b| {
            b.accuracy
                .partial_cmp(&a.accuracy)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.score.cmp(&a.score))
        });
        scored.truncate(limit.max(1));
        scored
    }

    fn score_one(
        &self,
        fp: &NmapFingerprint,
        subject: &HashMap<String, HashMap<String, String>>,
    ) -> Option<MatchResult> {
        let mut score = 0u32;
        let mut max_score = 0u32;

        for (test_name, points) in &self.match_points {
            let subj_attrs = subject.get(test_name);
            let ref_attrs = fp.tests.get(test_name);

            // Subject missing entire test
            if subj_attrs.is_none() {
                if let Some(ref_attrs) = ref_attrs {
                    // Both effectively "no response" when ref says R=N
                    if ref_attrs.get("R").map(|v| v.as_str()) == Some("N") {
                        if let Some(&p) = points.get("R") {
                            max_score += p;
                            score += p;
                        }
                    }
                }
                continue;
            }

            let subj_attrs = subj_attrs.unwrap();
            let Some(ref_attrs) = ref_attrs else {
                continue;
            };

            for (attr, pts) in points {
                let Some(expr) = ref_attrs.get(attr) else {
                    continue;
                };
                max_score += pts;

                if let Some(val) = subj_attrs.get(attr) {
                    if value_matches(expr, val) {
                        score += pts;
                    }
                } else if expr.is_empty() {
                    score += pts;
                }
            }
        }

        if max_score == 0 {
            return None;
        }

        let accuracy = score as f64 / max_score as f64;
        Some(MatchResult {
            name: fp.name.clone(),
            classes: fp.classes.clone(),
            cpes: fp.cpes.clone(),
            score,
            max_score,
            accuracy,
            line: fp.line,
        })
    }
}

fn parse_test_line(line: &str) -> Option<(String, &str)> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    if close <= open {
        return None;
    }
    let name = line[..open].to_string();
    if name.is_empty()
        || !name
            .chars()
            .next()
            .map(|c| c.is_ascii_uppercase())
            .unwrap_or(false)
        || !name.chars().all(|c| c.is_ascii_alphanumeric())
    {
        return None;
    }
    Some((name, &line[open + 1..close]))
}

fn parse_attrs(body: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for part in body.split('%') {
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    map
}

/// Match a subject value against a reference expression.
pub fn value_matches(expr: &str, value: &str) -> bool {
    if expr == value {
        return true;
    }
    for alt in expr.split('|') {
        if alt_matches(alt, value) {
            return true;
        }
    }
    false
}

fn alt_matches(alt: &str, value: &str) -> bool {
    if alt == value {
        return true;
    }
    if alt.is_empty() {
        return value.is_empty();
    }

    if let Some(rest) = alt.strip_prefix('>') {
        if let (Some(a), Some(b)) = (parse_num(rest), parse_num(value)) {
            return b > a;
        }
    }
    if let Some(rest) = alt.strip_prefix('<') {
        if let (Some(a), Some(b)) = (parse_num(rest), parse_num(value)) {
            return b < a;
        }
    }
    if let Some((lo, hi)) = alt.split_once('-') {
        if let (Some(a), Some(b), Some(v)) = (parse_num(lo), parse_num(hi), parse_num(value)) {
            let (min, max) = if a <= b { (a, b) } else { (b, a) };
            return v >= min && v <= max;
        }
    }
    false
}

fn parse_num(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    if s.chars().all(|c| c.is_ascii_hexdigit()) {
        return u64::from_str_radix(s, 16).ok();
    }
    s.parse().ok()
}

fn default_match_points() -> MatchPoints {
    let mut m = MatchPoints::new();
    let insert = |m: &mut MatchPoints, test: &str, pairs: &[(&str, u32)]| {
        m.insert(
            test.into(),
            pairs.iter().map(|(k, v)| ((*k).into(), *v)).collect(),
        );
    };
    insert(
        &mut m,
        "SEQ",
        &[
            ("SP", 25),
            ("GCD", 75),
            ("ISR", 25),
            ("TI", 100),
            ("CI", 50),
            ("II", 100),
            ("SS", 80),
            ("TS", 100),
        ],
    );
    insert(
        &mut m,
        "OPS",
        &[
            ("O1", 20),
            ("O2", 20),
            ("O3", 20),
            ("O4", 20),
            ("O5", 20),
            ("O6", 20),
        ],
    );
    insert(
        &mut m,
        "WIN",
        &[
            ("W1", 15),
            ("W2", 15),
            ("W3", 15),
            ("W4", 15),
            ("W5", 15),
            ("W6", 15),
        ],
    );
    insert(
        &mut m,
        "ECN",
        &[
            ("R", 100),
            ("DF", 20),
            ("T", 15),
            ("TG", 15),
            ("W", 15),
            ("O", 15),
            ("CC", 100),
            ("Q", 20),
        ],
    );
    for t in ["T1", "T2", "T3", "T4", "T5", "T6", "T7"] {
        let r = if matches!(t, "T2" | "T3" | "T7") {
            80
        } else {
            100
        };
        insert(
            &mut m,
            t,
            &[
                ("R", r),
                ("DF", 20),
                ("T", 15),
                ("TG", 15),
                ("W", 25),
                ("S", 20),
                ("A", 20),
                ("F", 30),
                ("O", 10),
                ("RD", 20),
                ("Q", 20),
            ],
        );
    }
    insert(
        &mut m,
        "IE",
        &[("R", 50), ("DFI", 40), ("T", 15), ("TG", 15), ("CD", 100)],
    );
    m
}

/// Locate nmap-os-db on disk.
pub fn find_os_db(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    if let Ok(p) = std::env::var("PULSE_OS_DB") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    let candidates = [
        default_fetch_path(),
        Some(PathBuf::from("/usr/share/nmap/nmap-os-db")),
        Some(PathBuf::from("/usr/local/share/nmap/nmap-os-db")),
        Some(PathBuf::from("/opt/homebrew/share/nmap/nmap-os-db")),
        Some(PathBuf::from("/opt/local/share/nmap/nmap-os-db")),
    ];
    for c in candidates.into_iter().flatten() {
        if c.is_file() {
            return Some(c);
        }
    }
    None
}

/// Default path for fetched DB: `~/.pulse/nmap-os-db`
pub fn default_fetch_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".pulse").join("nmap-os-db"))
}

/// Fetch official nmap-os-db into `dest` (creates parent dirs).
pub fn fetch_os_db(dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let url = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-os-db";
    let status = std::process::Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(dest)
        .arg(url)
        .status()
        .context("failed to run curl to fetch nmap-os-db")?;
    if !status.success() {
        bail!("curl failed fetching nmap-os-db (status {status})");
    }
    if let Some(parent) = dest.parent() {
        let notice = parent.join("NMAP-OS-DB-NOTICE.txt");
        let _ = fs::write(
            notice,
            "nmap-os-db is Copyright (C) 1996-2026 Nmap Software LLC.\n\
             Distributed under the Nmap Public Source License (NPSL):\n\
             https://nmap.org/npsl/\n\
             Fetched from: https://github.com/nmap/nmap\n\
             Pulse loads this file at runtime and does not relicense it.\n",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_range_hex() {
        assert!(value_matches("7B-85", "80"));
        assert!(value_matches("3B-45", "40"));
        assert!(!value_matches("7B-85", "10"));
    }

    #[test]
    fn value_or() {
        assert!(value_matches("I|RD", "I"));
        assert!(value_matches("I|RD", "RD"));
        assert!(!value_matches("I|RD", "Z"));
    }

    #[test]
    fn load_real_db_if_present() {
        let path = default_fetch_path().expect("home");
        if !path.is_file() {
            return;
        }
        let db = NmapOsDb::load(&path).expect("load nmap-os-db");
        assert!(db.fingerprints.len() > 1000, "expected large DB, got {}", db.fingerprints.len());
        assert!(db.match_points.contains_key("T1"));
    }

    #[test]
    fn parse_minimal_db() {
        let sample = r#"
MatchPoints
T1(R=100%DF=20%T=15)
Fingerprint Test OS
Class Linux | Linux | 5.X | general purpose
CPE cpe:/o:linux:linux_kernel:5
T1(R=Y%DF=Y%T=3B-45%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
"#;
        let db = NmapOsDb::parse(sample, PathBuf::from("mem")).unwrap();
        assert_eq!(db.fingerprints.len(), 1);
        assert_eq!(db.fingerprints[0].name, "Test OS");

        let mut subject = HashMap::new();
        let mut t1 = HashMap::new();
        t1.insert("R".into(), "Y".into());
        t1.insert("DF".into(), "Y".into());
        t1.insert("T".into(), "40".into());
        t1.insert("TG".into(), "40".into());
        t1.insert("S".into(), "O".into());
        t1.insert("A".into(), "S+".into());
        t1.insert("F".into(), "AS".into());
        t1.insert("RD".into(), "0".into());
        t1.insert("Q".into(), "".into());
        subject.insert("T1".into(), t1);

        let hits = db.match_subject(&subject, 3);
        assert!(!hits.is_empty());
        assert!(hits[0].accuracy > 0.5);
    }
}
