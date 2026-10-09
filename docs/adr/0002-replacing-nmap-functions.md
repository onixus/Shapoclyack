# ADR 0002: Where the functions Nmap provided move to

| | |
|---|---|
| **Status** | **Accepted** — onixus, 2026-10-10 |
| **Issue** | [#549](https://github.com/onixus/Shapoclyack/issues/549) (epic) |
| **Date** | 2026-10-10, against `claude/drop-bundled-nmap` at `6cf272a` ([#539](https://github.com/onixus/Shapoclyack/pull/539)) |
| **Related** | [ADR 0001](0001-pulse-distribution-model.md) (how Pulse is distributed — still Proposed), [#97](https://github.com/onixus/Shapoclyack/issues/97) (NPSL), [#447](https://github.com/onixus/Shapoclyack/issues/447) (Naabu / Pulse / Nuclei chain), [#450](https://github.com/onixus/Shapoclyack/issues/450) (Nuclei planning by Pulse services), [Using your own Nmap](../nmap-external.md) |

## Context

[#539](https://github.com/onixus/Shapoclyack/pull/539) stops building and
distributing Nmap: `0.47-1009-rc1` is the last release with `-nmap` image tags.
The scanner still calls an `nmap` it finds on `PATH`
([nmap-external.md](../nmap-external.md)). The owner's decision is to go
further: Shapoclyack stops depending on Nmap at all, and every function Nmap
provided either lands in Pulse or in Shapoclyack, or is dropped on purpose.

### What still calls Nmap

| Function | Code | Default |
|---|---|---|
| L2 discovery: ARP sweep (`-sn -PR`), then NetBIOS (`nbstat`) and mDNS (`dns-service-discovery`) names over UDP | [`l2_discovery.py`](../../scanner/pipeline/l2_discovery.py) | off (`discovery.l2.enabled: false`) |
| `-sV` / `-O` / NSE stage, profiles `baseline` (`default,safe`), `vuln_legacy` (`+vuln,vulners,ssl-enum-ciphers`), `vuln-offline` (Vulscan), `service_specific` | [`nse.py`](../../scanner/pipeline/nse.py), `nse_profiles` in [`default.yaml`](../../scanner/config/default.yaml) | only with `service_probe.backend: nmap\|hybrid` |
| Pulse-versus-Nmap coverage diff (`diff_pulse_nmap.json`) | [`pulse_shadow.py`](../../scanner/pipeline/pulse_shadow.py) | only with `service_probe.shadow: true` |
| TLS cipher-suite enumeration and grades (`ssl-enum-ciphers`); SSLv2/SSLv3 detection | `nmap-nse` source in [`tls_posture.py`](../../scanner/pipeline/tls_posture.py) | only when NSE ran; the stdlib probe [`tls_probe.py`](../../scanner/pipeline/tls_probe.py) does not enumerate suites |
| CPE names and the distribution revision in `version` (`8.2p1 Ubuntu 4ubuntu0.5`), preferred on merge | [`retro_match.py`](../../api/services/retro_match.py), [`asset_services.py`](../../api/services/asset_services.py) | only when NSE ran |

Stored data refers to Nmap too: the `nmap-nse` detector
([`0079_vuln_detectors.py`](../../api/db/migrations/versions/0079_vuln_detectors.py)),
the `nmap` prober on asset services
([`models.py`](../../api/db/models.py)), and `nmap/` XML inside past run
directories, which [`report.py`](../../scanner/pipeline/report.py),
[`evidence_artifacts.py`](../../scanner/pipeline/evidence_artifacts.py) and
[`verification_coverage.py`](../../api/services/verification_coverage.py) read.

### What Pulse already does

From the Pulse v1.3.0 CLI and GenDec `ROADMAP.md`: host discovery over ARP,
ICMP and TCP (`-D --discover-method arp|auto`); a declarative service-probe DB
(17 probes, 203 rules) replaceable with `--probe-db`; SinFP OS detection;
offline CVE rules with KEV/EPSS; a TLS handshake probe and JARM (it already
builds its own ClientHellos); Rhai audit plugins run inside the scan
(`--scripts`, `--script-dir`, 30 plugins upstream, a sandboxed network API
limited to the audited host and its open ports). The Shapoclyack adapter
([`pulse_probe.py`](../../scanner/pipeline/pulse_probe.py)) passes neither
`--scripts` nor `--probe-db` nor `--services-db`.

### Measured, 2026-10-10

Pulse v1.3.0 darwin-arm64 (installed by `scripts/install-pulse.sh`, digest
pinned), against a loopback listener that sends
`SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5` and against Jetty on `127.0.0.1:8081`;
Homebrew Nmap installed on the same host; `HOME` pointed at an empty directory.

1. **Pulse reads Nmap's data files from a system Nmap install.** With
   `PULSE_SERVICES_DB=/dev/null` port 2222 was named `EtherNetIP-1`. That string
   is not in the Pulse binary; it is in
   `/opt/homebrew/share/nmap/nmap-services`. The binary carries the fallback
   paths `/usr/share/nmap/nmap-services`, `/usr/local/share/nmap/…`,
   `/opt/homebrew/share/nmap/…` and the same set for `nmap-os-db` (used by
   `--os-mode nmap` and `auto`). A sensor host with a distribution `nmap`
   package therefore runs Pulse on NPSL data without anyone choosing it.
   The global `pulse.os_mode` default and the `balanced` profile set `auto`
   ([`default.yaml`](../../scanner/config/default.yaml),
   [`k8s.yaml`](../../k8s/shapoclyack/base/config/k8s.yaml)).
2. **The service name comes from the port table, not from the probe match.**
   The same endpoint had `product: "OpenSSH"`, `detection_method: "probe-db"`,
   `service: "EtherNetIP-1"`. With a services file mapping 2222 to `ssh` the
   name became `ssh`.
3. **No CPE, and the distribution revision is not in `version`.** `open[]`
   carries `banner, product, version, service, detection_method, …`;
   `version` is `8.2p1`. The revision survives only in `banner`. Pulse's own
   CVE row for that banner says `requires_confirmation: true` with
   "Ubuntu package — upstream version…", i.e. it knows it cannot judge
   backports.

Not measured: whether `pulse -D --discover-method arp` reports MAC addresses
and NetBIOS/mDNS names in its JSON, and whether it honours a rate cap. That
needs a directly attached segment and is the first step of work item 2.

## Decision drivers

1. **No NPSL in what runs by default** — neither the binary nor its data files
   (`nmap-services`, `nmap-os-db`, `nmap-service-probes`).
2. **Customer auditability.** Pulse is built from a private repository
   (ADR 0001). What a scan checks for must be readable by a customer without
   access to GenDec.
3. **Each component does what it is built for.** Rust with raw sockets for wire
   work; the Python control plane for data, policy and state; Nuclei for
   template-shaped checks.
4. **No silent loss.** Every Nmap function is replaced, measured as replaced,
   or dropped with a recorded reason before the code that calls Nmap goes.

## Options

For the *content* — service-probe rules and audit plugins:

- **A. Upstream in GenDec**, embedded in the Pulse binary. One owner of the
  schema; Pulse users outside Shapoclyack benefit. But the rules a customer's
  scan applies live in a private repository, and a rule change needs a Pulse
  release.
- **B. In Shapoclyack**, passed to Pulse with `--probe-db` and `--script-dir`.
  Public and reviewable, versioned with the product, changeable without a
  Pulse release. Shapoclyack takes over maintaining the rule set (the upstream
  `probes.json` and plugins are MIT and can be the starting point, with
  attribution).

For each *function* the split follows driver 3; the table in the Decision is
the result.

## Decision

**Option B for content. Engine work goes to Pulse; rules, plugins, policy,
data and measurement live in Shapoclyack.**

| Function | Pulse (engine) | Shapoclyack | Nuclei |
|---|---|---|---|
| Service and version detection | probe engine; derive `service` from the matched probe, not the port table (measurement 2) | owns the probe DB (`scanner/data/pulse/probes.json`, passed with `--probe-db`); rules written clean-room — nothing copied or paraphrased from `nmap-service-probes` | — |
| Distribution revision, backports | report the distribution suffix separately from the upstream version (measurement 3) | backport judgement in `retro_match` | — |
| CPE | — | product→CPE mapping next to the `retro_match` alias table | — |
| OS detection | SinFP | always pass `--os-mode sinfp`; `auto` and `nmap` are not used | — |
| Port frequencies | — | ship a non-NPSL services table and always pass `--services-db` (measurement 1) | — |
| L2: ARP, NetBIOS and mDNS names | discovery (ARP exists; names if missing) | scope, `max_hosts`, rate cap, the artifact shape `l2_discovery` writes today | — |
| TLS suites, versions, SSLv2/SSLv3 | enumeration with its own ClientHellos | grading and thresholds in `tls_posture` | — |
| NSE `default,safe` identification (SSH algorithms, SMB signing, RDP NTLM info, FTP anonymous, SNMP…) | the Rhai sandbox | the plugins (`scanner/data/pulse/plugins/`, passed with `--script-dir`) and the parser for their findings | — |
| NSE `vuln` checks | TLS-level ones (Heartbleed and the like) with the enumeration above | the list of checks and where each lands | network templates first; Rhai only for what has none |
| CVE by version (`vulners`, Vulscan) | `--cve` stays a secondary source | `retro_match` is authoritative | — |
| Quality reference (`pulse_shadow`) | — | a golden corpus recorded **before** Nmap goes, replayed in CI and on a kind stand | — |
| `nmap_timing` | — | mapped onto Pulse `rate` / `concurrency` in profiles | — |
| Past data | — | `nmap/` XML and `nmap-nse` rows stay readable; `backend: nmap\|hybrid` is rejected with a message naming the replacement | — |

Using Nmap as a benchmark while developing Pulse (GenDec's
`scripts/benchmark-nmap.sh` in its own CI) is not affected: it distributes
nothing.

## Consequences

- Shapoclyack maintains a service-probe rule set. Its size is the main gap:
  Nmap has thousands of `match` lines, Pulse 203. Work item 6 grows it against
  the golden corpus, not against a target number.
- Pulse is told everything explicitly (`--probe-db`, `--services-db`,
  `--script-dir`, `--os-mode sinfp`) and run with a private `HOME`, so its
  behaviour does not depend on what else is installed on the sensor host.
- Some Pulse changes are needed (service naming, distribution revision, TLS
  enumeration, possibly L2 names). They are filed in GenDec and pinned by
  version in Shapoclyack as usual.
- Until work item 8 lands, the `PATH` Nmap from #539 keeps working; after it,
  Nmap is not called at all and [nmap-external.md](../nmap-external.md) is
  replaced by a migration note.
- ADR 0001 is not decided by this record, but this one moves weight away from
  the private repository: what is checked becomes public, only the engine
  stays in GenDec.

## Work items

Tracked under [#549](https://github.com/onixus/Shapoclyack/issues/549). Order matters for 1:
the reference has to be recorded while Nmap still runs.

1. [#541](https://github.com/onixus/Shapoclyack/issues/541) — Golden corpus: record Nmap and Pulse output on a kind stand with typical
   services; commit fixtures; replay in CI.
2. [#542](https://github.com/onixus/Shapoclyack/issues/542) — L2 discovery through Pulse.
3. [#543](https://github.com/onixus/Shapoclyack/issues/543) — Pin Pulse's inputs: `--services-db`, `--os-mode sinfp`, private `HOME`;
   service name from the probe (GenDec).
4. [#544](https://github.com/onixus/Shapoclyack/issues/544) — Audit plugins in Shapoclyack, `--script-dir`, finding contract and parser.
5. [#545](https://github.com/onixus/Shapoclyack/issues/545) — TLS suite and version enumeration (GenDec) and grading (`tls_posture`).
6. [#546](https://github.com/onixus/Shapoclyack/issues/546) — Probe DB in Shapoclyack: clean-room rules, distribution revision, CPE
   mapping.
7. [#547](https://github.com/onixus/Shapoclyack/issues/547) — NSE `vuln` coverage mapped onto Nuclei network templates; gaps to Rhai.
8. [#548](https://github.com/onixus/Shapoclyack/issues/548) — Remove the Nmap code paths; keep readers for past data; config migration.

## Not decided here

- How Pulse itself is distributed — [ADR 0001](0001-pulse-distribution-model.md).
- Whether Naabu or Pulse finds ports — [#452](https://github.com/onixus/Shapoclyack/issues/452).
- How Nuclei templates are planned from Pulse services — [#450](https://github.com/onixus/Shapoclyack/issues/450).
- GOST cipher suites in TLS posture: Nmap did not cover them either; a separate
  question for the Russian compliance work.
