# NSE `vuln` coverage without Nmap

Where each of Nmap's `vuln` scripts that ever printed something on the reference
stand goes now: a Nuclei template, a Rhai plugin, the TLS work, version
matching, or a stated refusal
([ADR 0002](adr/0002-replacing-nmap-functions.md), work item
[#547](https://github.com/onixus/Shapoclyack/issues/547)). Read it as a list of
what is covered, by what, under which configuration, and what is **not**.

Status after #548: the NSE stage is gone, so this is now the whole answer to
"what replaced the `vuln` category", not a plan. The four scripts marked as gaps
below (`smb-vuln-ms17-010`, `smb-vuln-ms10-061`, `smb-protocols`,
`rdp-enum-encryption`) have no replacement, and neither does the TLS part until
Pulse enumerates suites ([Migrating off Nmap](nmap-migration.md#known-gaps)).

Sources of the table:

- The Nmap side is the recorded corpus
  (`tests/fixtures/nmap_pulse_corpus/nmap/tcp.xml`, Nmap 7.93,
  `--script default,safe,vuln,ssl-enum-ciphers`, 15 hosts). `scripts/compare-nmap-pulse-corpus.py`
  prints the same list under `nse_vuln.*`, and `tests/test_nmap_pulse_corpus.py` pins the
  numbers. The categories were read from the `.nse` files of that Nmap.
- The Nuclei side is `nuclei-templates` **v9.9.4** (`NUCLEI_TEMPLATES_REF` in
  `Dockerfile.allinone`) and nuclei **v3.11.1**: every id below was looked up in a
  checkout of that tag and its severity and tags read from the file.
- "Today's default sweep" is `nuclei.severities: [critical, high, medium]`,
  `exclude_tags: [intrusive, fuzz, dos]`, over the `http(s)://` URLs of the configured web ports.

## What the issue assumed, and what was true

| Assumption | Finding |
|---|---|
| `smb-vuln-ms17-010` has a Nuclei network template | **No.** v9.9.4 has none (no template mentions MS17-010, EternalBlue or CVE-2017-0143..0148). The check is an SMB1 transaction; it needs binary payloads (GenDec#38). Gap, stated below. |
| Network templates never run because the sweep only gets web URLs | **Half true.** A host that has a web port does get them: for a `javascript:` template nuclei v3.11.1 uses the template's own port for a URL input (`http://h:80/` and `http://h/` both ran `smb-signing-not-required` against `h:445`). What never happens is a host with **no** web port, the Samba of the stand, being looked at. The network pass fills that, and a finding the sweep already made on the same host, port and template is not repeated. |
| `ssl-*` has Nuclei templates to map | The `ssl/` directory of v9.9.4 has protocol-version, weak-cipher, expiry and issuer templates, not CCS injection, Heartbleed or POODLE checks. Those are #545 and are not touched here. |
| The slowloris and byterange hits were on the legacy nginx / IIS stub | Slowloris and TRACE were on the **Apache** (`.22`); byterange on both **nginx** (`.20`, `.21`) and not on Apache; the litespeed and phpMyAdmin hits were the IIS stub's catch-all page. |

## Mapping, script by script

`n` is how many host:port rows printed something; "Nmap says" is what the script
printed.

### `vuln` category

| NSE script | n | Nmap says (stand) | Destination | Covered by, under which config | Not covered / why |
|---|---|---|---|---|---|
| `vulners` | 10 | CVE ids by version: 428 (host, port, CVE) triples over 10 endpoints | version matching | `retro_match` (API) first, `pulse --cve` second; see [CVE by version](#cve-by-version-vulners-vulscan) | Probe-free by construction. The shipped NVD dataset is a 23-CVE seed: until the real one is harvested the coverage is a handful (below). |
| `http-vuln-cve2011-3192` | 4 | VULNERABLE (Apache byterange DoS) on **nginx** 1.27/1.18 :80/:443; Apache not flagged | refused | none | The reply to a many-range `Range` request is the whole test, and it flagged four nginx endpoints. No Nuclei template for CVE-2011-3192 in v9.9.4. A version question (Apache < 2.2.21) belongs to version matching. |
| `http-slowloris-check` | 1 | LIKELY VULNERABLE (CVE-2007-6750) on Apache :80 | refused | none | Holds connections open to starve the server: a DoS check, against the non-destructive posture (`dos` is in the default `exclude_tags` for the same reason). |
| `http-trace` | 2 | `TRACE is enabled` on Apache :80, :443 | Rhai plugin | **`shapo_http_trace`** (new, default on with the Pulse backend, `service_probe.pulse.plugins`) | Plain HTTP only: the sandbox has no TLS, so :443 is not reported (corpus: 1 of 2 endpoints agree). A hang-up on TRACE reads as refused (clean, and not evidence of a fix), a non-HTTP reply is a plugin error, and an echo server that answers every request with 200 is reported although it has no TRACE method. Nuclei `http-trace` exists (`http/miscellaneous`, **info**, tags `miscellaneous,misc,generic`) but the default floor drops info; it runs only with `nuclei.severities` widened or pinned. Live: reports :80 and :443 of the Apache, nothing on nginx. |
| `http-litespeed-sourcecode-download` | 1 | VULNERABLE (CVE-2010-2333), evidence: the IIS stub's index | refused | none | Exploit-category probe (`intrusive,exploit`); a false positive of a catch-all server on the stand. |
| `http-phpmyadmin-dir-traversal` | 1 | VULNERABLE, state `UNKNOWN (unable to test)`, evidence: the stub's page | refused | none | CVE-2005-3299 (phpMyAdmin 2.6.4) traversal exploit; Nuclei has phpMyAdmin panel/misconfig templates but none for this CVE. |
| `http-majordomo2-dir-traversal` | 1 | `ERROR: Script execution failed` (stub) | Nuclei web | **`CVE-2011-0049`** (`http/cves/2011`, medium, tags `cve,cve2011,majordomo2,lfi,edb,mj2`): inside the default floor and not excluded | Live: no match on the IIS stub or the Apache. |
| `http-vuln-cve2017-1001000` | 1 | `ERROR` (stub) | refused | none | WordPress 4.7.0/4.7.1 REST *write* probe; no template in v9.9.4, and sending a write request is not ours to do. |
| `http-csrf` | 7 | `Couldn't find any CSRF vulnerabilities.` | refused | none | Crawler/DAST: out of scope. Nuclei's `dast/` templates carry `fuzz` and are excluded. |
| `http-dombased-xss` | 7 | `Couldn't find any DOM based XSS.` | refused | none | Crawler/DAST: out of scope. |
| `http-stored-xss` | 7 | `Couldn't find any stored XSS vulnerabilities.` | refused | none | Crawler that submits forms: out of scope. |
| `ssl-ccs-injection` | 1 | `No reply from server (TIMEOUT)` on the RDP stub :3389 | TLS | **#545** | TLS-handshake level. No Nuclei template either. Not implemented here. |
| `smb-vuln-ms10-054` | 1 | `false` | refused | none | `dos` category: a malformed SMB request. |
| `smb-vuln-ms10-061` | 1 | `Could not negotiate a connection` | gap | none | Print-spooler RPC over SMB: binary protocol, no Nuclei template. GenDec#38. |
| `samba-vuln-cve-2012-1182` | 1 | `Could not negotiate a connection` | version matching | `retro_match` / `pulse --cve` | The probe is a malformed RPC call (`intrusive`); the affected range (Samba < 3.6.4) is a version question. |
| `smb-vuln-ms17-010` | 0 | (printed nothing; Samba is not affected) | gap | none | No Nuclei template in v9.9.4; SMB1 transaction, GenDec#38. Pulse raises an `exposure` hypothesis for SMB, which is a hypothesis and not a check. |

### Named by the issue, not in the `vuln` category

| NSE script | n | Destination | Covered by | Not covered |
|---|---|---|---|---|
| `smb2-security-mode` | 1 | Nuclei network | **`smb-signing-not-required`** (`javascript/misconfiguration/smb`, **medium**, tags `js,network,smb,enum`), run by the network pass | Reports "signing enabled but not required", as Nmap's `311: Message signing enabled but not required` did. Not the dialect-specific form; SMB1's `smb-security-mode` is not mirrored. |
| `smb-protocols` | 1 | gap | none | Dialect list. Nuclei's `smb-version-detect`, `samba-detect` and `smb2-capabilities` are **info**, report less and are not wired in. |
| `rdp-enum-encryption` | 1 | gap | none | NLA/CredSSP/security layer needs the X.224 handshake (a `0xE0` byte): GenDec#38. Nuclei `rdp-detect` (`network/detection`, info, `port: 3389`) only detects RDP. |
| `http-methods` | 2 | Rhai plugin | `shapo_http_trace` | TRACE only; PUT/DELETE/CONNECT are not probed. |
| `http-malware-host` | 1 | refused | none | Heuristics for an infected page; printed `false`. |

### The `ssl-*` / TLS family

All of `ssl-enum-ciphers`, `ssl-cert`, `ssl-date`, `ssl-ccs-injection` and the
protocol-version checks are **#545** (TLS enumeration in Pulse, grading in
`tls_posture`). This work neither touches that code nor adds a TLS check. The
Nuclei `ssl/` templates (`deprecated-tls`, `weak-cipher-suites`, `tls-version`,
`self-signed-ssl`, ...) are in the default sweep only for web ports and are not a
substitute for it.

### Considered and not mapped

| Template | Why not |
|---|---|
| `smb-anonymous-access` (high), `smb-shares` (low), `smb-enum` | Authenticated listing attempts with empty or test credentials. The default sweep already loads `smb-anonymous-access` (high); it did not match the guest-enabled Samba of the stand in the direct run. Not added to the network pass. |
| `smb-default-creds` (high) | **A brute-force template** (up to nine logons). On the stand it returned nine matches because the Samba maps unknown users to guest. It is not tagged `intrusive`, so `exclude_tags` would not stop it, and it must never be put in the table. |
| `CVE-2011-2523` (vsftpd backdoor), `proftpd-backdoor` | When the backdoor answers, the template runs `id` / `cat /etc/passwd` through it. Not tagged `intrusive`. Refused: a check that executes commands on a compromised service. |
| `CVE-2012-2122` (MySQL auth bypass) | Tagged `fuzz`, so the default `exclude_tags` already excludes it; it repeats logons. |
| `CVE-2015-3306` (ProFTPD mod_copy) | Writes a file on the target. |

## The Nuclei network pass

`scanner/pipeline/nuclei_network.py` holds a table; `nuclei_scan.run_nuclei_scan`
runs it after the web sweep.

```python
NetworkRule(name="smb", services={"smb", "microsoft-ds"}, ports={445},
            template_ids=("smb-signing-not-required",), nse=("smb2-security-mode",))
```

- **Targets.** `open_ports` (TCP) joined with `services.json`, the Pulse
  output in the same run directory. The service *name* decides, on any port; the
  default port counts only for an endpoint whose service is unnamed, the rule the
  plugins' gates use. SMB on `14450` is checked; an HTTP server on `445` is not.
  Without `services.json` (a failed or missing Pulse stage) only default ports match.
- **One nuclei process per rule**, `-list host:port`, `-id <the rule's ids>`: an id
  never meets an endpoint of another service. IPv6 targets are bracketed.
- **Port.** Nuclei v3.11.1 takes the port from the input `host:port` for these
  templates even though they hardcode one (`Port: "445"`, `port: 3389`). Checked
  live: with the input port `1445` or `13389` (a relay to the real service) the
  template ran against that port, against a closed `1445` it found nothing.
- **Safety floor.** `nuclei.exclude_tags` is passed as `-exclude-tags` and also checked
  against each template's own tags, so an id whose file carries an excluded tag is
  not run and is recorded under `template_ids_excluded`. The table lists nothing
  that needs excluding today; the floor is for the template that changes in a
  later release, or the operator who adds tags.
- **Severity floor.** The pass obeys `nuclei.severities`, but checked by us
  against the template files instead of passed as `-severity`: `-id` together with
  `-severity` makes nuclei drop an id with no word, and a dropped id would read as
  "looked, clean". An id under the floor is recorded under `template_ids_below_floor`
  and the process is not started. `intent: vuln` (critical and high only) therefore
  does not run the medium SMB check, as it does not run medium web templates.
  An empty `severities` list is no floor. The `tags` option (an include filter for
  the sweep) does not apply: the table is the selection.
- **Never OAST.** `-no-interactsh`: nothing in the table needs a callback, so
  `nuclei.interactsh_server` is not contacted by this pass.
- **Not counted as assessed.** `assets._assessed_vulnerabilities` still reads a run whose nuclei
  result says `no_web_ports` as not assessed, even if the network pass ran: that tile is a property of
  the whole run, and an SMB check on some hosts does not assess the estate.
- **Not in a pinned run.** A verification re-scan with `nuclei.template_ids` loads
  exactly those ids and nothing more; its `coverage` block is byte-for-byte what it
  was, with no `network` key. A finding from the network pass therefore cannot be closed
  as machine-verified yet: the pinned run only targets URLs, and
  `verification_coverage` answers `endpoint_not_targeted`. That stays manual
  until a pinned run learns network targets.
- **Where a finding goes.** A match of a table template, whether the network pass or the web sweep made it, is a row in `vulnerabilities.json`:
  `source: nuclei`, `script_id: nuclei:<template id>`, `cve: ""` when the template names
  none (a CVE-tagged one is a CVE row as for any nuclei finding), keyed by host, port and
  script id like a plugin finding. The scanner merges them into the report
  (`nuclei.json` → `network_vulnerabilities`, `scanner/main.py`), the API tracker reads the
  detector and the template id from that `script_id` (`vulnerabilities._detector_of`), and the
  evidence projection reads `nuclei_network_<rule>_raw.jsonl` next to `nuclei_raw.jsonl`.
  The web sweep's CVE-less matches (panels, misconfiguration, tech detection) still stay in
  `nuclei.json` only, as before. A host with a web port and SMB gets the template from both
  the sweep and the pass; one finding and one row are kept (key: template, host, port; nuclei
  writes `host` and `port` the same way for a URL and a `host:port` input). Raw files of an earlier
  attempt (`nuclei_network_*`) are deleted at the start of every nuclei stage, so a `--resume` with the
  pass off cannot leave evidence nuclei.json denies.
- **Time.** The stage is bounded as a whole: the pass may run until
  `overall_timeout_seconds` + 120 s (`NETWORK_GRACE_SECONDS`) after the stage began, each process
  gets what is left, and a rule reached later is recorded `stage_deadline_exhausted`. A sweep that
  used its whole budget therefore leaves the pass about two minutes. A process that times out or
  crashes is `nuclei_run_failed`, never a look (`ran: false`), but findings it had already written
  to its JSONL are kept.
- **Which file runs.** The table names an id; an id that matches more than one file (a copy in
  `custom_templates_dir` shadowing the baked one) is not run and is listed under
  `template_ids_ambiguous`. The sha256 of the one file that ran is recorded per id
  (`template_sha256`) but **not enforced**: a hash pin would switch the pass off with every
  nuclei-templates bump. A newer revision of the same id under the same directory therefore does
  run; the record is how a reviewer sees which one.
- **Off switch.** `nuclei.network_templates: false` (default `true`; also off with
  `nuclei.enabled: false` and in `intent: inventory`). Per speed profile it is not
  separately switchable; profiles cut `severities`, which the pass honours.
- **What SMB signing costs the target.** The template opens a connection (a port
  probe), negotiates SMB2 and sends the first NTLMSSP message (type 1); it stops at the
  server's challenge (type 2). Measured through a relay that logged NTLMSSP message
  types: no type 3, so no logon is attempted and no failed-logon event is raised. Its
  `User: test` / `Pass: test` arguments are never put on the wire.
- **Same plan as #450.** The pass reads the same `services.json` map the planner of
  [#450](https://github.com/onixus/Shapoclyack/issues/450) will use for the web
  sweep (`nuclei_network.load_service_names`). The web sweep, its command and its
  `coverage` fields are unchanged.

### Evidence: `nuclei.json` → `coverage.network`

```json
"network": {
  "enabled": true, "ran": true, "skipped_reason": null,
  "targets_considered": 1, "truncated": false,
  "severities": ["critical", "high", "medium"], "duplicates_of_sweep": 0,
  "passes": [{
    "rule": "smb", "nse": ["smb2-security-mode"], "ran": true, "returncode": 0,
    "skipped_reason": null, "targets": ["172.29.41.40:445"], "truncated": false,
    "template_ids_requested": ["smb-signing-not-required"],
    "template_ids_missing": [], "template_ids_excluded": [], "template_ids_below_floor": [],
    "template_ids_ambiguous": [], "template_sha256": {"smb-signing-not-required": "<sha256 of the file>"},
    "templates_loaded": 1, "templates_expected": 1,
    "skipped_targets": [], "errors_log_truncated": false
  }]
}
```

- A pass `ran` only when nuclei exited 0; `templates_loaded` is nuclei's own
  "Templates loaded for current scan" count against `templates_expected`.
- `skipped_reason` of the block: `network_templates_disabled`, `no_network_targets`,
  `not_all_passes_ran` (some pass has its own reason), or the sweep's own
  (`nuclei.disabled`, `nuclei_binary_missing`, `templates_dir_missing`). Per pass:
  `no_template_available` (all ids missing, excluded, below the floor or ambiguous),
  `nuclei_run_failed`, `stage_deadline_exhausted`.
- The key is **absent** from `nuclei.json` written before this pass and from a pinned
  run; present, saying why nothing ran, in every sweep. "Not observed" and "not
  looked for" are told apart by `ran`, `targets` and the three id lists, as for the web sweep.
- Findings carry `"pass": "network"` and `"rule"`; a CVE-tagged one is merged into
  `cve_findings` as any Nuclei finding is.
- Past `nuclei.max_targets` endpoints of a rule, the rest are skipped and `truncated` is set.
- `coverage.ran` and `coverage.targets` still describe the **web** sweep only. A host with
  SMB and no web port gives `skipped_reason: no_web_ports` (web) next to
  `coverage.network.ran: true`.

### Live check

Stand: the corpus compose stand (`tests/fixtures/nmap_pulse_corpus/stand`, on a
second subnet so it could run beside another session's), nuclei **v3.11.1**
(official linux-arm64 release, sha256 checked against the release's checksums
file), nuclei-templates **v9.9.4**, Pulse **v1.3.0**, Docker Desktop VM linux/arm64.

| Check | Command / harness | Observed |
|---|---|---|
| The real function | `run_nuclei_scan()` in a `python:3.12-alpine` container on the stand network, `open_ports` and `services.json` from a real Pulse run (18 open ports; Pulse named 445 `smb`, 139 `netbios-ssn`, 3389 `rdp`, 21 `ftp`), default `NucleiConfig` | Web sweep: 7 URLs (`.20/.21/.22/.23` :80, `.20/.21/.22` :443), 347 s, **0 findings** at medium+. Network pass: one process, `-id smb-signing-not-required -exclude-tags intrusive,fuzz,dos`, target `<samba>:445`, templates loaded 1/1, exit 0, **1 finding**: `smb-signing-not-required`, medium, `javascript`, at `<samba>:445`. Nmap's `smb2-security-mode` on the same host: `Message signing enabled but not required`. They agree. |
| Only SMB ports open | same, `ONLY_PORTS` restricted | `no_web_ports` for the web sweep in 0.0 s, network pass still ran: 1 finding (9.4 s in all). |
| `severities: [critical, high]` | same | Warning `below nuclei.severities: smb-signing-not-required`, nuclei not started, `template_ids_below_floor` set, no finding. |
| `exclude_tags` + `smb` | same | `template_ids_excluded: [smb-signing-not-required]`, not started. |
| `network_templates: false` | same | `skipped_reason: network_templates_disabled`, no nuclei. |
| Port override | relay containers `:1445 -> smb:445`, `:13389 -> rdp-stub:3389`; `nuclei -u relay:1445 -id smb-signing-not-required`, `-u relay:13389 -id rdp-detect` | Both matched with the **input** port (`matched-at relay:1445`, relay saw the connection); the same ids against a closed `:1445` / `:1234`: no match. |
| URL input | `nuclei -u http://relay:80/ -id smb-signing-not-required` (relay listens on 445 only) | Matched at `relay:445`: the sweep reaches the SMB port of any host with a web port. |
| No logon | relay logging NTLMSSP message types | type 1 sent, type 2 received, **no type 3**. |
| Web template | `nuclei -id http-trace` on Apache :80 and :443 | `info`, matched `trace-request` and `options-request` on both; no match on nginx `.20`, `.21`. Nmap's `http-trace`: Apache :80, :443 only. Agree. |
| Web template | `nuclei -id CVE-2011-0049` on the IIS stub and Apache :80 | no match. |
| Floor | `nuclei -tl -severity critical,high,medium -exclude-tags intrusive,fuzz,dos` | 4281 templates; includes `CVE-2011-0049`, `smb-signing-not-required`, `smb-anonymous-access`; not `http-trace`, `rdp-detect`. |
| `shapo_http_trace` | `pulse plugin run` in the stand's scanner container | Apache :80: `FINDING [LOW] HTTP TRACE method enabled`, evidence `HTTP/1.1 200 OK (request echoed)`. Apache :443, nginx `.20`/`.21` :80, IIS stub, vsFTPd: no finding. Full Pulse run with `--script-dir`: one new finding (`SCRIPT-SHAPO_HTTP_TRACE`), nothing else changed against the previous recording. |

What this does not show: nuclei against a Windows host (every SMB number is Samba
4.17), the network pass under load, or a host that has both SMB and a web port.

## CVE by version (`vulners`, Vulscan)

[ADR 0002](adr/0002-replacing-nmap-functions.md) says `retro_match` is the
authoritative source and `pulse --cve` the secondary one. Checked against the code:

- **`retro_match` is an API-side matcher**, not a scanner stage
  (`api/services/retro_match.py`, `retro_match_worker.py`). Every succeeded run
  leaves the fingerprint of each open listener (product, version, banner, CPE,
  distribution revision) in `asset_services`; a background worker matches those against
  an offline copy of NVD's CPE version ranges, asks the Debian/Ubuntu advisories whether a
  fix was backported, and writes tracked findings (`source: retro_match`). It runs again whenever the
  dataset changes, so a CVE published after the scan is found without rescanning. See
  [Retro CVE matching](retro-cve-matching.md).
- **`pulse --cve`** runs in the scanner during the scan, against Pulse's compiled-in rules and
  with keyword matches labelled `keyword_cve` (`service_probe.pulse.cve`), and writes
  `pulse_cves.json` (`source: pulse`). It sees only what its binary knew on the day of the scan.
- So the order is by design: `retro_match` first (current, backport-aware, no probe), `pulse --cve`
  second (at scan time). **But the first is only as good as its dataset.** The shipped
  `scanner/data/nvd-cpe/nvd-cpe-ranges.json` is a *seed*: 8 products, 23 CVEs; the real
  dataset is opt-in (`OCTO_NVD_CPE_FETCH_ENABLED=true scripts/fetch-nvd-cpe.py --full`) and
  `GET /api/system` reads `nvd_cpe.usable: false` until it is loaded.
- Measured on the corpus (`tests/test_nmap_pulse_corpus.py`): Nmap's scripts named 428
  (host, port, CVE) triples; `pulse --cve` named 3 of them (`cve_both 3`, `cve_only_nmap 425`,
  `cve_only_pulse 0`); `retro_match` with the
  shipped seed and no advisory provider gives 6 of 18 listeners a match and 5 range hits on 3
  endpoints (nginx 1.18.0 :80/:443: CVE-2021-23017, CVE-2022-41741; vsftpd 3.0.3: CVE-2021-30047).
  The gap to 428 is the dataset, not the matcher, and it is not claimed to be closed: the two
  numbers count different things (a range hit on a banner version against Vulners' list for a CPE),
  so only the order of magnitude is comparable.

## Re-recording the Pulse side

The plugin set changed (`shapo_http_trace`), so `pulse/tcp-plugins.json` and
`pulse/plugins.sha256` were re-recorded with `RECORD_PARTS=pulse` against the Pulse binary
named above; the Nmap fixtures and `pulse/tcp.json`, `udp.json` are untouched. Compared with
the previous recording, the only difference in findings is the new plugin's one.
