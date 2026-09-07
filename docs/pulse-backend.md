# Pulse service probe backend

Shapoclyack can enrich open ports with **[Pulse](https://github.com/onixus/GenDec)**
instead of (or in addition to) Nmap NSE.

Migration plan (full): see GenDec `docs/shapoclyack-migration.md`.

## When to use which backend

| `service_probe.backend` | Behaviour |
|-------------------------|-----------|
| `pulse` (**default**, Phase 4.1) | Pulse OS / banner / CVE only; no nmap NSE |
| `nmap` | Classic NSE stage only (`vuln_legacy` / `baseline`) |
| `hybrid` | Pulse first, then nmap NSE |

Precedence: `OCTO_SERVICE_BACKEND` → `profiles.<mode>.service_backend` →
`service_probe.backend`.

### Speed profiles (Pulse knobs)

| Mode | Profile `pulse.*` overrides | NSE if backend nmap/hybrid |
|------|-----------------------------|----------------------------|
| `safe` | c=300 rate=500 host-parallel=4 os=sinfp | `baseline` |
| `balanced` | c=800 rate=2000 host-parallel=16 os=auto | `vuln_legacy` |
| `fast` | c=1200 rate=5000 host-parallel=32 os=sinfp | `vuln_legacy` |

### Escape hatch: full NSE

```yaml
service_probe:
  backend: nmap   # or hybrid
```

```bash
export OCTO_SERVICE_BACKEND=nmap
```

### Ports-only L1

`--skip-nse` skips **both** Pulse and nmap. Default path already uses Pulse
without nmap — you do not need `--skip-nse` for that.

### Shadow mode (Phase 3)

Run **both** Pulse and Nmap and write coverage diff. With `backend: nmap`,
the report still prefers nmap XML; Pulse CVEs can still attach.

```bash
export OCTO_PULSE_SHADOW=1
export OCTO_SERVICE_BACKEND=nmap   # report stays on nmap
# export OCTO_SERVICE_BACKEND=hybrid  # report prefers services.json
```

YAML: `service_probe.shadow: true`

Artifact: **`diff_pulse_nmap.json`**

Fair live compare (avoid multi-A inflation):

```bash
scripts/compare-pulse-nmap.py --one-ip-per-host \
  scanme.nmap.org example.com 1.1.1.1
```
 — endpoint Jaccard, only_pulse / only_nmap
samples, OS family agree/disagree.

Override without editing YAML:

```bash
export OCTO_SERVICE_BACKEND=pulse
export OCTO_PULSE_BIN=/usr/local/bin/pulse
```

## Config (`scanner/config/default.yaml`)

```yaml
service_probe:
  backend: pulse   # nmap | hybrid
  shadow: false    # or OCTO_PULSE_SHADOW=1
  pulse:
    bin: ""                  # empty → OCTO_PULSE_BIN, then PATH
    concurrency: 500
    rate: 2000
    adaptive: true
    host_parallel: 8
    timeout_ms: 800          # per-connect timeout (pulse -t)
    banner: true
    os_detect: true          # needs raw sockets; dropped for the run if pulse refuses
    os_mode: auto
    cve: true
    cve_online: false
    syn: false               # half-open scan; needs raw sockets, never auto-downgraded
    max_hosts: 65536
    chunk_hosts: 64          # hosts per pulse invocation / checkpoint
    retry_settle_seconds: 15 # pause before re-probing an all-closed chunk; 0 disables

profiles:
  balanced:
    pulse:
      concurrency: 800
      rate: 2000
      host_parallel: 16
      os_mode: auto
    nse_profile: vuln_legacy   # only if backend is nmap|hybrid
```

NVD online: set `NVD_API_KEY` or mount a key file readable by the scanner
(Pulse also supports `~/.pulse/nvd_api_key`).

## Artifacts

| Path | Content |
|------|---------|
| `services.json` | `octo.service.v1` open services |
| `pulse/tls.json` | Pulse TLS cert posture (`octo.pulse_tls.v1`) |
| `tls_posture.json` | Unified TLS findings (nmap / pulse-tls / probe) |
| `os.json` | `octo.os.v1` OS guesses |
| `pulse_cves.json` | Pulse findings (`octo.cve.v1`: version_cve / keyword_cve / exposure / tls) |
| `pulse/raw.json` | Merged raw Pulse JSON |
| `pulse/REPORT_PRIMARY` | Marker: report prefers Pulse services/OS |
| `diff_pulse_nmap.json` | Shadow/hybrid comparison |
| `nmap/**` | Written when backend is `nmap`/`hybrid` or shadow |

`report.py` prefers `services.json` / `os.json` when backend is pulse/hybrid
(or `REPORT_PRIMARY` exists), and still merges nmap script findings from XML
when hybrid/nmap ran.

## Image install

`Dockerfile` / `Dockerfile.allinone` install Pulse from a **GenDec GitHub
Release** (not a vendored Rust tree). Canonical pipeline:
[GenDec `docs/release.md`](https://github.com/onixus/GenDec/blob/main/docs/release.md).

```dockerfile
# stage pulse-bin downloads:
#   pulse-v1.1.0-linux-amd64.tar.gz from onixus/GenDec releases
COPY --from=pulse-bin /out/pulse /usr/local/bin/pulse
# + setcap cap_net_raw,cap_net_admin+eip
```

| Arg / secret | Default | Meaning |
|--------------|---------|---------|
| `PULSE_VERSION` | `v1.1.0` | GenDec release tag |
| `PULSE_GITHUB_REPO` | `onixus/GenDec` | release owner/repo |
| BuildKit secret `github_token` | — | PAT for **private** GenDec releases (`GENDEC_READ_TOKEN` in CI) |
| `INSTALL_NMAP` | `1` | set `0` for lean image without nmap |

The pin is the **engine** (banner / OS / `--cve` / TLS JSON). Shapoclyack does
not invoke `pulse monitor`, `pulse --server`, `--alert-*`, `--scripts`, or
`--inventory`. Those duplicate schedules, webhooks, Nuclei, and job targets.

v1.1.0's TLS probe may write a JARM hash onto `tls[]` (no CLI flag to skip
it). The field is kept on `pulse/tls.json` and is not scored. `finding_class:
tls` still flows into extra vulnerabilities — `tls_posture` is opt-in and
writes a separate artifact, so dropping those rows would hide cert expiry on
the default path.

Both the image stage and the host installer download `checksums.txt` from
the same release and refuse to unpack a tarball whose SHA-256 does not match
it: the binary is about to receive `cap_net_raw`/`cap_net_admin`, so a TLS
connection alone is not enough provenance.

Local image build (GenDec is private, so pass a token with `contents:read`):

```bash
printf '%s' "$GITHUB_TOKEN" > /tmp/gh_token
docker build -f Dockerfile \
  --secret id=github_token,src=/tmp/gh_token \
  --build-arg PULSE_VERSION=v1.1.0 \
  -t shapoclyack-scanner:local .
```

Host install without Docker:

```bash
GITHUB_TOKEN=… scripts/install-pulse.sh          # release tarball, verified
PULSE_VERSION=v1.1.0 scripts/install-pulse.sh    # pick a tag
PULSE_DEST=$HOME/.local/bin/pulse scripts/install-pulse.sh
PULSE_FROM_SOURCE=1 scripts/install-pulse.sh     # cargo fallback (PULSE_REF picks a ref)
scripts/smoke-pulse.sh
```

`GH_TOKEN` is accepted as an alias. `PULSE_SKIP_CHECKSUM=1` exists for a
release that ships no `checksums.txt`; it prints a warning and should not be
needed for any v1.x tag.

System UI / API status probes `pulse --version` alongside nmap/naabu/nuclei.

Connect-mode Pulse works without root; SYN/OS still need caps/root like nmap.

## Checkpoint

Hosts are probed in chunks of `chunk_hosts`; each chunk is one pulse
invocation with its own `--checkpoint` under the run's `pulse/`. Files are
named after the chunk's *content* — `chunk_<sha256(hosts, ports)[:16]>.ckpt`
plus the matching `.hosts.txt` — not after its position. Pulse trusts an
existing checkpoint file over `--targets-file` (a finished one is replayed
without touching the network; an unfinished one continues its stored host
list; a different port list aborts the run), and a `--resume` re-cuts the
chunks from the hosts still pending, so a position-based name would hand a
new host set the previous run's checkpoint and let those hosts be marked done
unscanned. With content-keyed names a chunk can only ever resume itself.
A *finished* checkpoint is deleted before pulse runs: pulse replays one
without re-running OS detection, CVE correlation or the TLS probe, and a
rescan of one chunk is cheaper than a report whose services lost their
findings. Only an unfinished checkpoint is resumed.

Shapoclyack's own stage checkpoint marks hosts done under key `pulse` (and
`nse` for nmap) only for chunks that returned at least one service; the
stage itself is marked done only when no chunk was left unresolved.

## When pulse cannot run

| Situation | Behaviour |
|-----------|-----------|
| No `pulse` binary and there are TCP ports to probe | The stage fails immediately with `FileNotFoundError` naming `scripts/install-pulse.sh`, `OCTO_PULSE_BIN` and `service_probe.pulse.bin`. Pulse is the default backend and the only source of services on that path, so this is a deployment error to surface, not a stage to skip. With no TCP ports at all the stage writes empty artifacts and never looks for the binary. |
| `os_detect: true` but no raw sockets (unprivileged host install, pod without `NET_RAW`) | Pulse aborts the whole invocation, not just OS detection. The adapter recognises its "OS detection needs raw sockets" refusal, drops `--os` for the rest of the run, re-runs the chunk at once and logs a warning; services, banners, TLS and CVEs are kept. `pulse/raw.json` records it under `adapter.os_detect_degraded`. This mirrors nse.py, which drops nmap `-O` when not root. |
| `syn: true` without raw sockets | Not downgraded: SYN is an explicit opt-in. The chunk fails, is retried once after `retry_settle_seconds`, and its hosts stay unresolved. |
| A chunk reports every port closed | A contradiction, not a result: naabu proved those ports open moments ago. The chunk's pulse checkpoint is deleted (pulse would otherwise replay the zero) and the chunk is re-probed after `retry_settle_seconds`. A chunk that is still empty afterwards leaves its hosts unmarked so `--resume` asks again. |
| Pulse exits non-zero without JSON for any other reason | Logged as a crash with its stderr (not as "0 services") and given the same single retry. |

`pulse/raw.json` also carries `adapter.pulse_bin`, `adapter.chunk_hosts`, a
per-chunk list with each chunk's key and exit code, and `stats` summed over
all chunks (`rate_pps` recomputed from the totals).

## TLS posture without nmap (Phase 4)

When `tls_posture.enabled: true` and nmap produced no `ssl-cert` /
`ssl-enum-ciphers` output (Pulse backend, `--skip-nse`, empty `nmap/`),
Shapoclyack can **probe open TLS ports directly** via stdlib `ssl`
(`scanner/pipeline/tls_probe.py`).

```yaml
tls_posture:
  enabled: true
  probe_fallback: true          # default true
  probe_timeout_seconds: 5.0
  probe_concurrency: 20
  probe_tls_ports: [443, 8443, 9443, 4443, 10443, 6443]
```

| Source | When | Covers |
|--------|------|--------|
| `nmap-nse` | SSL scripts present in nmap XML | cert + full cipher grades |
| `pulse-tls-probe` | fallback handshake | cert expiry / self-signed / weak negotiated protocol+cipher name |

Artifacts: `tls_posture.json` (same shape; `source` field), plus
`tls_probe.json` when the fallback ran.

### Certificate name mismatch (P4.1)

Whichever source produced the certificate, one more check runs over the
result: `cert_name_mismatch` (medium) when the certificate's DNS identities
(subject CN plus every `DNS:` SAN) cover none of the names the scan used to
reach the endpoint. Matching follows RFC 6125 — a leftmost `*` covers exactly
one label, so `*.example.com` matches `www.example.com` but not
`example.com` or `a.b.example.com`.

The expected names come from the **forward** half of `hostnames.json` (the
FQDNs that resolved to this IP) plus, on the Pulse/probe paths, the hostname
the scan actually dialled. PTR names are deliberately excluded: a reverse name
belongs to whoever owns the address block, not the service, so a certificate
that fails to mention `ec2-1-2-3-4.compute.amazonaws.com` is normal, not a finding.
An endpoint reached only by IP has nothing to compare against and produces no
finding at all.

**SNI is part of the evidence.** A server behind virtual hosting answers a
connection made to an *address* with its default certificate, which says
nothing about the name you scanned. The stdlib probe therefore sends the
resolved FQDN in SNI and records it in the finding's `sni` field, and its
certificate is judged against that name only. Sources that did not record an
SNI — nmap's `ssl-cert` against an IP target, and Pulse — still report the
mismatch, but tagged `requires_confirmation: true`: without re-probing with the
name, a genuine misconfiguration and a default-vhost answer look identical.

```yaml
tls_posture:
  enabled: true
  hostname_mismatch: true       # default true
```

Full cipher-suite enumeration (nmap grade A–F) still needs nmap NSE or a
future dedicated enumerator. Cert DER field extraction is richer when the
optional `cryptography` package is installed (API image).

## CVE stack without nmap-vulners (Phase 4.2)

Default path (no nmap required):

| Layer | Config | Output |
|-------|--------|--------|
| Pulse `--cve` | `service_probe.pulse.cve: true` | `pulse_cves.json` → vulns `source: pulse` |
| Nuclei (web) | `nuclei.enabled: true` (default) | `nuclei.json` + vulns `source: nuclei` |
| CVSS4 enrich | `enrichment.cvss4.enabled` | scores on `vulnerabilities.json` |

nmap-**vulners** / **vulscan** only run when `service_probe.backend` is
`nmap` or `hybrid` and the profile uses `vuln_legacy` / `vuln-offline`.

### Finding taxonomy and prioritisation

Pulse separates observations from hypotheses (GenDec `docs/findings.md`) and
labels every finding. Shapoclyack carries those labels through to scoring:

| `finding_class` | Meaning | `cve` | Scored as |
|-----------------|---------|-------|-----------|
| `version_cve` | Banner/version matched a curated CVE rule | CVE-… | confirmed |
| `keyword_cve` | NVD keyword search, unverified | CVE-… | unconfirmed |
| `exposure` | Service reachable; no CVE claimed | empty | unconfirmed |
| `tls` | Certificate / TLS posture | empty | confirmed |

`exposure` and `tls` carry no CVE and are identified by a synthetic
`script_id` (`pulse:<class>:<port>:<slug>`) so each stays a distinct row in
the report dedupe and in ClickHouse.

An **unconfirmed** finding is discounted by the scanner's own confidence
(`contextual_score × (0.4 + 0.6 × confidence)`) and capped below `Act`, the
SSVC decision that means "work this now". A high-CVSS keyword hit therefore
ranks below a confirmed, KEV-listed one instead of above it.

`epss` and `in_kev` supplied by Pulse win over the API's local
`OCTO_EPSS_DATABASE` / `OCTO_KEV_DATABASE` overlays, which stay in play for
nuclei/NSE findings that arrive without them.

Every finding returned by `GET /api/runs/{id}/vulnerabilities` carries
`contextual_score`, `cisa_decision`, and a one-line `risk_explanation` naming
the factors behind them; the run's Findings tab renders all three.

`summary.json` counts unconfirmed findings separately in
`unconfirmed_findings` — they are still part of `potential_vulnerabilities`,
which grew when exposures stopped being discarded.

Nuclei skips cleanly if the binary or `templates_dir` is missing
(host installs without the Docker bake). Disable with
`nuclei.enabled: false`.

## Optional nmap (Phase 5)

nmap remains in the default image for `backend: nmap|hybrid` and
`vuln_legacy`, but is **not required** for the default Pulse path.

| Build | Command |
|-------|---------|
| Full (default) | `docker build -f Dockerfile …` (`INSTALL_NMAP=1`) |
| Pulse-only lean | `docker build --build-arg INSTALL_NMAP=0 …` |

When nmap is absent, `run_nse` writes `nmap/SKIPPED_NMAP_MISSING` and
continues (Pulse + Nuclei + TLS probe still run).

System UI marks **nmap** as optional and shows `service_probe.backend`.

K8s caps (`NET_RAW` / `NET_ADMIN` + `allowPrivilegeEscalation: true`) remain
required for **naabu** and Pulse SYN/OS — see `k8s/README.md`.

## Limitations (current)

- Does not run NSE scripts (`ssl-enum-ciphers`, vulners, …) on the default path.
- TLS probe fallback ≠ full `ssl-enum-ciphers` grade table.
- UDP enrichment still relies on naabu (and optional nmap) paths.
- Banner ≠ full nmap `-sV` product/version.
