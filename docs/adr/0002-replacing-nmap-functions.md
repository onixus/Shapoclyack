# ADR 0002: Where the functions Nmap provided move to

| | |
|---|---|
| **Status** | **Accepted** — onixus, 2026-10-10 |
| **Issue** | [#549](https://github.com/onixus/Shapoclyack/issues/549) (epic) |
| **Date** | 2026-10-10, against `claude/drop-bundled-nmap` at `6cf272a` ([#539](https://github.com/onixus/Shapoclyack/pull/539)) |
| **Related** | [ADR 0001](0001-pulse-distribution-model.md) (how Pulse is distributed — still Proposed), [#97](https://github.com/onixus/Shapoclyack/issues/97) (NPSL), [#447](https://github.com/onixus/Shapoclyack/issues/447) (Naabu / Pulse / Nuclei chain), [#450](https://github.com/onixus/Shapoclyack/issues/450) (Nuclei planning by Pulse services), [Migrating off Nmap](../nmap-migration.md) |

## Context

[#539](https://github.com/onixus/Shapoclyack/pull/539) stops building and
distributing Nmap: `0.47-1009-rc1` is the last release with `-nmap` image tags.
At the time of writing the scanner still called an `nmap` it found on `PATH`
(the note on installing your own Nmap, since replaced by
[nmap-migration.md](../nmap-migration.md)). The owner's decision is to go
further: Shapoclyack stops depending on Nmap at all, and every function Nmap
provided either lands in Pulse or in Shapoclyack, or is dropped on purpose.

### What still called Nmap (when this was written; none of it does after #548)

L2 discovery (ARP sweep, NetBIOS and mDNS names) no longer does: it runs through Pulse since [#542](https://github.com/onixus/Shapoclyack/issues/542), see [pulse-backend.md](../pulse-backend.md#l2-discovery).

| Function | Code | Default |
|---|---|---|
| `-sV` / `-O` / NSE stage, profiles `baseline` (`default,safe`), `vuln_legacy` (`+vuln,vulners,ssl-enum-ciphers`), `vuln-offline` (Vulscan), `service_specific` | `nse.py` (removed in #548), `nse_profiles` in [`default.yaml`](../../scanner/config/default.yaml) | only with `service_probe.backend: nmap\|hybrid` |
| Pulse-versus-Nmap coverage diff (`diff_pulse_nmap.json`) | `pulse_shadow.py` (removed in #548) | only with `service_probe.shadow: true` |
| TLS cipher-suite enumeration and grades (`ssl-enum-ciphers`); SSLv2/SSLv3 detection | `nmap-nse` source in [`tls_posture.py`](../../scanner/pipeline/tls_posture.py) | only when NSE ran; the stdlib probe [`tls_probe.py`](../../scanner/pipeline/tls_probe.py) does not enumerate suites |
| CPE names and the distribution revision in `version` (`8.2p1 Ubuntu 4ubuntu0.5`), preferred on merge | [`retro_match.py`](../../api/services/retro_match.py), [`asset_services.py`](../../api/services/asset_services.py) | only when NSE ran |

Stored data refers to Nmap too: the `nmap-nse` detector
([`0079_vuln_detectors.py`](../../api/db/migrations/versions/0079_vuln_detectors.py)),
the `nmap` prober on asset services
([`models.py`](../../api/db/models.py)), and `nmap/` XML inside past run
directories, which [`report.py`](../../scanner/pipeline/report.py),
[`evidence_artifacts.py`](../../scanner/pipeline/evidence_artifacts.py) and
[`verification_coverage.py`](../../api/services/verification_coverage.py) read.

### Historical Pulse baseline (v1.3.0, 2026-10-10)

At the original measurement, from the Pulse v1.3.0 CLI and GenDec `ROADMAP.md`: host discovery over ARP,
ICMP and TCP (`-D --discover-method arp|auto`); a declarative service-probe DB
(17 probes, 203 rules) replaceable with `--probe-db`; SinFP OS detection;
offline CVE rules with KEV/EPSS; a TLS handshake probe and JARM (it already
builds its own ClientHellos); Rhai audit plugins run inside the scan
(`--scripts`, `--script-dir`, 30 plugins upstream, a sandboxed network API
limited to the audited host and its open ports). The Shapoclyack adapter
([`pulse_probe.py`](../../scanner/pipeline/pulse_probe.py)) then passed neither
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

Starting gap against the recorded corpus (work item 1, [#541](https://github.com/onixus/Shapoclyack/issues/541);
Nmap 7.93, Pulse 1.3.0, 15 stand hosts): service names agree on 18 of 19
endpoints, product on 14 of 18, version exactly on 11 of 17 (3 more lack the
distribution revision, 3 are missing); CPE on 0 of 17; OS family on 14 of 14;
TLS cipher suites 0 of 122 enumerated, TLS protocol sets equal on 2 of 3 shared
endpoints and one endpoint (MySQL) absent. Table, method and caveats:
[pulse-backend.md](../pulse-backend.md#reference-corpus-nmap-versus-pulse-541).

L2 discovery (work item 2, [#542](https://github.com/onixus/Shapoclyack/issues/542);
Pulse 1.3.0 against Nmap 7.93 on one Docker bridge: a scanner container with
`NET_RAW`, an `nmbd` responder, an `avahi-daemon` responder, an idle host and
the bridge gateway; wire rate read from the scanner's `tx_packets` counter
every 100 ms, because a capture on Docker Desktop shows every frame twice):

- **Live hosts.** `-D --discover-method arp` found the same 4 live hosts as
  `nmap -sn -PR` on a /28 and a /24, and none for an off-link network (no
  packet left for it). It works without `NET_RAW` too.
- **How.** "ARP" is the kernel's neighbour resolution, not raw frames: Pulse
  sends a 1-byte UDP datagram to port **9** of every candidate and the kernel
  ARPs for it — 3 requests per dead address (`mcast_solicit`); 253 candidates
  cost 759 packets where Nmap sends 532. Pulse reads the neighbours back with
  `ip -4 neigh`: without iproute2 it finds nothing, prints nothing and exits
  0. The interface cannot be chosen; the
  routing table picks it.
- **MAC.** Not in the JSON, CSV or XML output. The kernel neighbour table
  (`/proc/net/arp`) holds it for every live host after the run. No vendor.
- **No discovery-only mode.** Discovery always continues into a port phase;
  with `--all` every live host gets one result row per port, which is the only
  machine-readable list of live hosts. With no live host Pulse prints nothing
  and exits 0. `--top 0` falls back to the default ports, `-p 0` is rejected.
- **Rate.** `--rate N` paces candidates, not packets. Peak packets per second
  on the wire with 4 of 253 candidates alive: `--rate 5` → 18, `20` → 70,
  `25` → 90, `100` → 247 (unlimited: 261); Nmap `--max-rate 20` → 20,
  `100` → 97. With 55 of 253 alive and the UDP/137 and UDP/5353 name probes in
  the same run: `--rate 25` → 101 and 86 (two runs), `5` → 21, `20` → 74,
  `4` → 17; without name probes `--rate 25` → 86 and 103, `--rate 20` → 79,
  68 and 71. So a ceiling of `R` packets per second held, in every run, with
  `--rate ⌊R / (mcast_solicit + 2)⌋` (peaks 68–83 for `R` = 100, 20 for
  `R` = 20); `mcast_solicit + 1` overshot by up to 3%. It is an estimate for
  other `mcast_solicit` values and denser segments, not a guarantee. Below the
  divisor it cannot be held at all, and `l2_discovery` skips the stage.
- **NetBIOS.** `--protocol udp -p 137 -b` sends a wildcard NBSTAT query; the
  banner carries the name table (printable bytes, others as `.`, high-bit bytes
  as U+FFFD, cut at about 150 characters), from which the machine name can be
  read. Nmap's `nbstat` reports the same name.
- **mDNS.** UDP/5353 asks `_services._dns-sd._udp.local` and the banner lists
  service types (`_ssh._tcp`), not the host name. Nmap's
  `dns-service-discovery` gave no `.local` host name on the same responder
  either, so nothing is lost — but neither tool reports the host name.

What Pulse lacks here (MAC and names in structured output, a packet-rate
discovery cap, a discovery-only mode, an interface choice) is filed as
onixus/GenDec#35; `l2_discovery` works around it as described in
[pulse-backend.md](../pulse-backend.md#l2-discovery) until that lands.

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
| Service and version detection | probe engine; derive `service` from the matched probe, not the port table (measurement 2) | owns the probe DB (`scanner/pipeline/pulse_data/probes.json`, passed with `--probe-db`); base = GenDec's embedded set as stated by its author (see `probes.json.LICENSE`); rules added by this project are written from observed banners — nothing copied or paraphrased from `nmap-service-probes` | — |
| Distribution revision, backports | report the distribution suffix separately from the upstream version (measurement 3) | backport judgement in `retro_match` | — |
| CPE | — | product→CPE mapping next to the `retro_match` alias table | — |
| OS detection | SinFP | always pass `--os-mode sinfp`; `auto` and `nmap` are not used | — |
| Port frequencies | — | ship a non-NPSL services table and always pass `--services-db` (measurement 1) | — |
| L2: ARP, NetBIOS and mDNS names | discovery (ARP exists; MAC, names and a packet-rate cap in structured output: GenDec#35) | scope, `max_hosts`, rate cap, the artifact shape `l2_discovery` writes today | — |
| TLS suites, versions, SSLv2/SSLv3 | enumeration with its own ClientHellos | grading and thresholds in `tls_posture` | — |
| NSE `default,safe` identification (SSH algorithms, SMB signing, RDP NTLM info, FTP anonymous, SNMP…) | the Rhai sandbox | the plugins (`scanner/pipeline/pulse_data/plugins/`, passed with `--script-dir`) and the parser for their findings | — |
| NSE `vuln` checks | planned TLS-level probes; enumeration does not implement Heartbleed/CCS/Ticketbleed | the list of checks and where each lands, [script by script](../nse-vuln-coverage.md) | network templates first (a curated table run by a network pass; v9.9.4 has one for SMB signing and none for MS17-010); Rhai only for what has none and the sandbox can send (HTTP TRACE) |
| CVE by version (`vulners`, Vulscan) | `--cve` stays a secondary source | `retro_match` is authoritative (API side, offline NVD ranges; only as complete as its dataset, [measured](../nse-vuln-coverage.md#cve-by-version-vulners-vulscan)) | — |
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
  Nmap is not called at all and the note on installing your own Nmap is
  replaced by [nmap-migration.md](../nmap-migration.md) (done in #548).
- ADR 0001 is not decided by this record, but this one moves weight away from
  the private repository: what is checked becomes public, only the engine
  stays in GenDec.

## Plugins (#544)

The plugins are in `scanner/pipeline/pulse_data/plugins/` and
described in [Pulse plugins](../pulse-plugins.md). Original v1.3.0 measurements
showed that text-only UTF-8 requests could not send SMB/RDP binary negotiation,
UDP was unavailable and per-read timeouts were not total call deadlines.
[GenDec#39](https://github.com/onixus/GenDec/pull/39) supplies byte-preserving
TCP/UDP APIs and one deadline per exchange. It is not yet a released/pinned
engine dependency, so source and loopback validation do not establish shipped
sensor acceptance.

| Function | Candidate source status | Remaining boundary |
|---|---|---|
| `ssh2-enum-algos` weaknesses | `shapo_ssh_algorithms` | advertisement, not a complete algorithm inventory |
| `ssh-hostkey` | `shapo_ssh_hostkey`: curve25519-sha256 / Ed25519 exchange signature verified | possession on this connection; no known-host trust; other algorithms unknown |
| `ftp-anon` | anonymous login checked | no PASV directory listing or second-port connection |
| cleartext services / STARTTLS | capability plugin plus opt-in native TLS upgrade enumeration | plugin capability alone is not a completed TLS handshake |
| SMB inventory/signing | `shapo_smb_protocols`: SMB1 and single offers for SMB2 2.0.2/2.1/3.0/3.0.2/3.1.1; direct 445 or RFC1002 on 139 | selected dialects/signing only; no relay exploit proof |
| MS17-010 | separate `shapo_ms17_010` read-only anonymous IPC$/FID0 status hypothesis | non-indicator, denial and error stay UNKNOWN; no exploit or patch attestation |
| RDP | standard-security negotiation plus `shapo_rdp_ntlm_info` X.224/TLS/CredSSP type2 inventory | no type3, credentials, desktop session, authenticated identity or full encryption enumeration |
| SNMP | `shapo_snmp_info`: one UDP SNMPv2c GET with `public`, sysDescr/sysName | standalone/native UDP only; production adapter remains TCP-only; no guessing/SET |
| VNC | `shapo_vnc_security`: RFB3.3/3.7/3.8 security advertisements | no client security selection, ClientInit or desktop/session acceptance |

The LOW exposure plugins remain independent observations. New negotiation
plugins do not turn their reachability evidence into vulnerability proof.

Decisions taken while implementing it:

- **A plugin finding is its own detector**, `pulse-plugin`, not `pulse`: what
  re-checks it is the plugin file, not the CVE ruleset. The finding carries the
  file's sha256; a verification credits a plugin only if the re-scan loaded the same
  bytes, finished the endpoint, saw a service the plugin's gate accepts there and had
  no plugin error on it. No migration:
  `vulnerabilities.detectors` is JSON.
- **A probe that fails is an error, not an empty result**, so that "the plugin
  could not look" is not read as "the plugin looked and found nothing".
- **Plugins are off under a `per_host_rate` policy** because
  their connections bypass `--rate`; they are serial, so a concurrency ceiling needs
  nothing.
- **Pulse loads three directories**: `--script-dir`, `./scripts` and
  `$HOME/.pulse/scripts`. The process runs in an empty directory that is also its
  `HOME`, which is what makes the first the only one.

## TLS (#545)

Measured 2026-10-10 on the corpus stand (`tests/fixtures/nmap_pulse_corpus/`,
Pulse v1.3.0 linux-arm64 with the adapter's flags, run again live, plus
`openssl s_server` listeners inside the scanner container):

- **What Pulse reports.** One `tls[]` row per endpoint it probed: certificate
  fields, `self_signed`, `expired`, `jarm`, `negotiated_protocol`
  (`TLSv1_3`, `TLSv1_2`) and, when a legacy handshake succeeded,
  `accepts_weak_protocols` (`["TLSv1.0", "TLSv1.1"]` on nginx-legacy — the
  same set Nmap found). No cipher suites, no server preference, no key
  exchange, no SSLv2/SSLv3 attempt; the CLI has no enumeration switch.
- **Where it looks.** Only ports 443 and 8443. Six TLS listeners on 443,
  8443, 465, 636, 993 and 9443 gave two `tls[]` rows; the MySQL TLS that Nmap
  enumerated on 3306 gave none. Until this change `tls_posture` stopped at
  the first non-empty Pulse artifact, so a `probe_tls_ports` port Pulse
  skipped (9443, 4443, 10443, 6443) was not checked at all; now the stdlib
  probe tops those up (rows tagged `pulse-tls-probe`). 465, 636, 993 and
  STARTTLS ports stay unchecked on the Pulse path: they are not in
  `probe_tls_ports`.
- **The reference.** Nmap 7.93 `ssl-enum-ciphers` enumerated 4 endpoints,
  122 suite entries, graded A except the 4 `TLS_ECDH_anon_*` entries ×3
  versions on nginx-legacy (F, "Anonymous key exchange").

Decided:

- **Grading is ours** (`scanner/pipeline/tls_grading.py`), written from the
  public SSL Labs Server Rating Guide, not from the NSE script. On the 122
  corpus entries it gives Nmap's letter every time. The corpus only exercises A
  and F, so the C caps (RC4, 64-bit blocks, MD5) and the key-size steps are
  covered by unit tests against the guide, not by a recorded reference.
  Finding kinds and the C–F threshold are the same as on the `nmap-nse` path.
- **The enumeration format began as our proposal**
  (`tls[].enumeration`, read by `scanner/pipeline/tls_enumeration.py`; shape in
  [pulse-backend.md](../pulse-backend.md#cipher-suites-and-a-f-grades-on-the-pulse-path)).
  Signed/pinned Pulse v1.4.0 now emits it. A contract test builds that shape from the
  recorded Nmap output and checks that the Pulse path yields the same findings
  as the Nmap path on the same endpoints. Raw-selection findings always retain `requires_confirmation`; a suite missing from it is not
  read as refused. Code points without names resolve through the IANA
  registry copied into `scanner/pipeline/pulse_data/tls_cipher_suites.tsv`.
- **NSE `vuln` scripts at the TLS level** — split with #547:

  | NSE script | Where |
  |---|---|
  | `ssl-poodle` (SSLv3 with CBC) | here: `weak_protocol` SSLv3 from the enumeration |
  | `sslv2-drown` (SSLv2 offered) | here: `weak_protocol` SSLv2; the cross-protocol part is not checked |
  | `ssl-dh-params` (weak/common DH groups) | here, by key size in the grade, once GenDec#34 reports `kex_bits`; named common primes are not checked |
  | RC4, SWEET32 (64-bit blocks) | here: grade C → `weak_cipher_grade`, and `weak_cipher_name` |
  | `ssl-heartbleed`, `ssl-ccs-injection`, `tls-ticketbleed` | #547: they need malformed records, not an enumeration — a Nuclei network template where one exists, otherwise the "nice to have" in GenDec#34 |
  | `ssl-known-key` | #547 (a fingerprint list, not a TLS mechanism) |

  In the corpus only `ssl-ccs-injection` produced output, on the RDP stub
  (`No reply from server (TIMEOUT)`); no TLS-level `vuln` script reported a
  vulnerability.

Pulse 1.4.0 enumerates raw SSLv2/SSLv3…TLS1.3
selection and server preference. Opt-in STARTTLS covers SMTP, IMAP, POP3,
FTP, LDAP, PostgreSQL and MySQL. Visible Certificate/ServerKeyExchange facts
supply RSA/DHE modulus sizes and supported ECDHE curves; normal TLS1.3 x25519
shares supply curve size. HRR, static ECDH/PSK and unavailable parameters remain
unmeasured. Raw selection and unverified signatures are not authenticated/full
handshake acceptance; findings require confirmation and missing sizes keep
upper-bound grades. GOST and vulnerability-specific malformed-record probes
(Heartbleed, CCS injection, Ticketbleed) are not implemented.

Local native OpenSSL fixtures record TLS1.2 ECDHE/DHE/RSA and a PostgreSQL
SSLRequest→TLS1.3 shim. They do not establish an installed release or complete
native-service fleet acceptance. See [TLS contracts and limits](../pulse-endpoints.md#optional-tls-suite-enumeration).
The measured v1.3.0 results above remain the historical comparison baseline.

## Work items

Tracked under [#549](https://github.com/onixus/Shapoclyack/issues/549). Order matters for 1:
the reference has to be recorded while Nmap still runs.

1. [#541](https://github.com/onixus/Shapoclyack/issues/541) — Golden corpus: record Nmap and Pulse output on a kind stand with typical
   services; commit fixtures; replay in CI.
2. [#542](https://github.com/onixus/Shapoclyack/issues/542) — L2 discovery through Pulse.
3. [#543](https://github.com/onixus/Shapoclyack/issues/543) — Pin Pulse's inputs: `--services-db`, `--os-mode sinfp`, private `HOME`;
   service name from the probe (GenDec).
4. [#544](https://github.com/onixus/Shapoclyack/issues/544) — Audit plugins in Shapoclyack, `--script-dir`, finding contract and parser.
   **Content and bounded native helpers are implemented with signed/pinned Pulse v1.4.0** — see [Plugins (#544)](#plugins-544) below.
5. [#545](https://github.com/onixus/Shapoclyack/issues/545) — TLS suite and version enumeration (GenDec) and grading (`tls_posture`).
6. [#546](https://github.com/onixus/Shapoclyack/issues/546) — Probe DB in Shapoclyack: clean-room rules, distribution revision, CPE
   mapping.
7. [#547](https://github.com/onixus/Shapoclyack/issues/547) — NSE `vuln` coverage mapped onto Nuclei network templates; gaps to Rhai.
   **Implemented** — table, network pass and live checks in [NSE `vuln` coverage](../nse-vuln-coverage.md).
8. [#548](https://github.com/onixus/Shapoclyack/issues/548) — Remove the Nmap code paths; keep readers for past data; config migration.
   **Done** — see [Status after #548](#status-after-548).

## Status after #548

Nmap is no longer called by anything in the product. Work item 8 removed the NSE
stage, the `nmap` and `hybrid` backends, `nse_profiles`, the shadow run and the
`PATH` lookups, and turned `backend: nmap|hybrid`, `shadow`, `nmap_timing`,
`OCTO_SERVICE_BACKEND=nmap|hybrid` and the other removed keys into load-time
errors that name the replacement ([Migrating off
Nmap](../nmap-migration.md) lists each, and where it is checked). The `nmap/`
XML of past runs, `nmap-nse` findings and `prober: nmap` rows stay readable
(`scanner/pipeline/legacy_nmap.py`); the golden corpus of #541 stays as the
reference it was recorded to be.

**Release-backed implementation.** #548 removed runtime Nmap paths before
all replacements were complete (owner decision, 2026-10-11). Input isolation,
bounded raw TLS/STARTTLS and exchange-size facts, verified SSH host-key
observations, native SMB/RDP/VNC helpers, and standalone/native UDP SNMP
inventory are now implemented. GenDec#31/#32 and
[GenDec#39](https://github.com/onixus/GenDec/pull/39) are merged upstream.

Dockerfiles, publish workflows and all four archive pins select signed
[Pulse v1.4.0](https://github.com/onixus/GenDec/releases/tag/v1.4.0), built from
`cf5c4e82677ccb9b5edea84e775590d51068afff` (the tree matches the reviewed
`6ca248b` source). Its Sigstore bundle was verified against the exact release
workflow/tag identity and each downloaded archive matched the signed checksum.
Combined CI is required before merge; source and released CLI fixtures do not
establish installed sensor acceptance. Historical corpus evidence remains
unchanged and distinct from the current capability map.

Remaining limits: production Pulse enrichment is TCP-only, so SNMP UDP cannot
be verified by a TCP completion receipt. SSH trust/other algorithms, complete
RDP encryption/authentication, VNC session authentication, FTP PASV, SMB
print-spooler RPC and vulnerability-specific TLS checks remain unsupported.
DoS, write/exploit, brute-force and credential-guessing checks described in
[NSE coverage](../nse-vuln-coverage.md) remain deliberately excluded. Negotiation,
version matches and status hypotheses never establish exploitability or a patch.
