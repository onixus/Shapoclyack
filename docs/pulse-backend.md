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
    bin: ""                  # OCTO_PULSE_BIN overrides this; else this path; else PATH
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
# /out/bin/pulse + /out/share/shapoclyack/pulse-install.txt, one COPY per
# directory; with INSTALL_PULSE=0 both are empty and nothing is copied:
COPY --from=pulse-bin /out/bin/ /usr/local/bin/
COPY --from=pulse-bin /out/share/ /usr/local/share/
# + setcap cap_net_raw,cap_net_admin+eip when the binary is there
```

| Arg / secret | Default | Meaning |
|--------------|---------|---------|
| `PULSE_VERSION` | `v1.1.0` | GenDec release tag |
| `PULSE_GITHUB_REPO` | `onixus/GenDec` | release owner/repo |
| BuildKit secret `github_token` | — | PAT for **private** GenDec releases (`GENDEC_READ_TOKEN` in CI) |
| `INSTALL_NMAP` | `1` | set `0` for lean image without nmap |
| `INSTALL_PULSE` | `1` | set `0` to build without Pulse — and without a token for the private GenDec repo |
| `PULSE_PINS` (script only) | `scripts/pulse-pinned.sha256` | file of reviewed per-platform digests |
| `PULSE_RECORD` (script only) | empty — no record | where to write the install record; the images set `/usr/local/share/shapoclyack/pulse-install.txt` (#340) |
| `PULSE_SKIP_CHECKSUM` | `0` | `1` accepts a tarball unchecked — **only for a version with no pin**; ignored for a pinned one |

The pin is the **engine** (banner / OS / `--cve` / TLS JSON). Shapoclyack does
not invoke `pulse monitor`, `pulse --server`, `--alert-*`, `--scripts`, or
`--inventory`. Those duplicate schedules, webhooks, Nuclei, and job targets.

v1.1.0's TLS probe may write a JARM hash onto `tls[]` (no CLI flag to skip
it). The field is kept on `pulse/tls.json` and is not scored. `finding_class:
tls` still flows into extra vulnerabilities — `tls_posture` is opt-in and
writes a separate artifact, so dropping those rows would hide cert expiry on
the default path.

The image stage runs `scripts/install-pulse.sh`, so images and host installs
share one implementation.

**How the download is verified.** `scripts/pulse-pinned.sha256` holds the
SHA-256 of each platform's tarball for the version this repository builds
against. The installer looks the version up there and refuses to unpack a
tarball that does not match. That value is committed here and reviewed in a
pull request, so it is not something whoever serves the release can change —
which matters because the binary is granted `cap_net_raw`/`cap_net_admin`
(`Dockerfile`), making a swapped Pulse root-equivalent on a sensor host.
`PULSE_SKIP_CHECKSUM=1` does **not** apply to a pinned version; the installer
says so and keeps checking. Bumping `PULSE_VERSION` without bumping the pins
fails `tests/test_pulse_supply_chain.py`.

A version with no pin (a one-off tag someone is trying out) falls back to the
release's own `checksums.txt` with a warning. That is the weaker check it
always was: the checksum file travels over the same connection from the same
release, so it catches a truncated or corrupted download, not a rewritten one.
`PULSE_SKIP_CHECKSUM=1` opts out of *that* check for a release with no
`checksums.txt`, which GenDec's release job treats as an optional asset. A
download that fails for any other reason (5xx, timeout) is reported as such and
does not suggest the override.

**Provenance is checked when a pin is taken, not when it is used.** A pin proves
the bytes are the bytes that were reviewed; it does not say where they came
from, and a fresh pin taken from a compromised release would be a compromised
pin. That is what GenDec's release signature is for, and why it is checked in
`scripts/pulse-pin.sh` rather than at install time:

```bash
GITHUB_TOKEN=… scripts/pulse-pin.sh v1.2.0
```

The helper fetches the release's `checksums.txt` and its
`checksums.txt.cosign.bundle`, runs `cosign verify-blob` against GenDec's
release workflow **on that tag** as the certificate identity, and only then
prints the lines to paste into `scripts/pulse-pinned.sha256`. A release with no
signature is refused unless `PULSE_PIN_ALLOW_UNSIGNED=1` — which the `v1.1.0`
pins currently in the repo were taken with, because signing was added to GenDec
after that release. Adding cosign to the install path instead would not help:
on the pinned path the committed digest already beats anything fetched from the
release being installed, and the images carry no cosign.

This proves the release was produced by GenDec's release workflow. It does not
prove the code that went into it was reviewed — it closes "the assets were
swapped", not "a bad commit was merged". Whether GenDec's releases become
public or its sources get built here is the proposed
[ADR 0001](adr/0001-pulse-distribution-model.md), awaiting the owner's decision.

**Checking the binary in a published image.** The image keeps the binary, not
the tarball the pin is for, so the build also writes an install record —
tarball, the check it passed, and the binary's digest — to
`/usr/local/share/shapoclyack/pulse-install.txt`, and
`scripts/verify-pulse-image.py` checks an image against the pin file of its
release tag, or independently against the pinned tarball. The record is
unsigned and lives in the image it describes, so against deliberate tampering
it is only as good as the image digest that was checked. What each check
proves, the commands, and the Pulse support and update policy are in the
[release contract](release-contract.md).

Neither the script nor the image stage uses `set -x`: the token would land in
the build log.

**Building without Pulse.** `--build-arg INSTALL_PULSE=0` skips the fetch
entirely, so the image builds with no GenDec token at all. That image has no
service-probe backend of its own: with the default `service_probe.backend:
pulse` the scanner aborts the run with an error naming both fixes, rather than
silently falling back to nmap and producing a different finding set under the
same profile. Run such an image with `OCTO_SERVICE_BACKEND=nmap` on an
`INSTALL_NMAP=1` build.

Local image build (GenDec is private, so pass a token with `contents:read`):

```bash
printf '%s' "$GITHUB_TOKEN" > /tmp/gh_token
docker build -f Dockerfile \
  --secret id=github_token,src=/tmp/gh_token \
  --build-arg PULSE_VERSION=v1.1.0 \
  -t shapoclyack-scanner:local .
```

No token, no Pulse (needs `OCTO_SERVICE_BACKEND=nmap` at runtime):

```bash
docker build -f Dockerfile --build-arg INSTALL_PULSE=0 -t shapoclyack-scanner:nopulse .
```

Host install without Docker:

```bash
GITHUB_TOKEN=… scripts/install-pulse.sh          # release tarball, verified
PULSE_VERSION=v1.1.0 scripts/install-pulse.sh    # pick a tag
PULSE_DEST=$HOME/.local/bin/pulse scripts/install-pulse.sh
PULSE_FROM_SOURCE=1 scripts/install-pulse.sh     # cargo fallback (PULSE_REF picks a ref)
scripts/smoke-pulse.sh
```

`GH_TOKEN` is accepted as an alias.

System UI / API status probes `pulse --version` alongside nmap/naabu/nuclei.

Connect-mode Pulse works without root; SYN/OS still need caps/root like nmap.

## Checkpoint

Shapoclyack's own stage checkpoint (`CheckpointStore`) marks hosts done under
key `pulse` (and `nse` for nmap) for chunks that returned at least one
service; the stage itself is marked done only when no chunk was left
unresolved, so `--resume` re-probes exactly the hosts that never got an
answer.

Pulse's `--checkpoint` is **not** used. Pulse trusts an existing checkpoint
file over `--targets-file` and *replays* a finished one — or an unfinished
one whose hosts are all completed, which a kill during OS/CVE/TLS enrichment
leaves behind — without re-running OS detection, CVE correlation or the TLS
probe. Both `run_command`'s timeout retry and the adapter's own re-probe
re-run the same command, so no naming or cleanup scheme could make a
surviving checkpoint safe. A chunk (`chunk_hosts`, default 64) that dies is
simply rescanned; that costs seconds. Each chunk's hosts file is still named
after its content, `chunk_<sha256(hosts, ports, mode)[:16]>.hosts.txt`, so
the `chunks[]` records in `pulse/raw.json` stay attributable across runs.

## When pulse cannot run

| Situation | Behaviour |
|-----------|-----------|
| No `pulse` binary and there are TCP ports to probe | The stage fails immediately with `FileNotFoundError` naming `scripts/install-pulse.sh`, `OCTO_PULSE_BIN` and `service_probe.pulse.bin`. Pulse is the default backend and the only source of services on that path, so this is a deployment error to surface, not a stage to skip. With no TCP ports at all the stage writes empty artifacts and never looks for the binary. |
| `os_detect: true` but no raw sockets (unprivileged host install, pod without `NET_RAW`) | Pulse aborts the whole invocation, not just OS detection. The adapter recognises its "OS detection needs raw sockets" refusal, drops `--os` for the rest of the run, re-runs the chunk at once and logs a warning; services, banners, TLS and CVEs are kept. `pulse/raw.json` records it under `adapter.os_detect_degraded`. This mirrors nse.py, which drops nmap `-O` when not root. |
| `syn: true` without raw sockets | Not downgraded: SYN is an explicit opt-in. The chunk fails, is re-run once at once, its hosts stay unresolved, and the crash-loop breaker above ends the stage after three such chunks. |
| A chunk reports every port closed | A contradiction, not a result: naabu proved those ports open moments ago. The chunk is re-probed after `retry_settle_seconds`. A chunk that is still empty afterwards leaves its hosts unmarked so `--resume` asks again. |
| Pulse exits non-zero without JSON for any other reason | Logged as a crash with its stderr (not as "0 services") and re-run **at once** — the settle pause is for a saturated network path, not for exit 2. After three consecutive chunks that still end in a crash the stage raises `PulseCrashLoopError` naming the exit code and stderr: a crash that repeats across chunks is a broken binary or a bad flag, and sleeping through the rest of a large run would only delay the same empty result. |

`pulse/raw.json` also carries `adapter.pulse_bin`, `adapter.chunk_hosts`, a
`chunks` list with every chunk's key, hosts, last exit code and `resolved`
flag (failed chunks included), and `stats` summed over the chunks that
answered (`rate_pps` recomputed from the totals).

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
  probe_legacy_protocols: true  # default true: TLS 1.0 / 1.1 handshakes
  chain_trust: public_only      # public_only | always | off
  ca_bundle: null               # PEM of your own CAs
```

`probe_legacy_protocols`, `chain_trust` and `ca_bundle` are settings of the
scanner config on the sensor (`scanner/config/default.yaml` or the file the
sensor runs with). The platform's config overlay does not carry them yet, so
they cannot be changed from the console; a `ca_bundle` path must exist on the
sensor, for a container sensor as a mounted file.

| Source | When | Covers |
|--------|------|--------|
| `nmap-nse` | SSL scripts present in nmap XML | cert validity / self-signed heuristic / key size and signature digest + full cipher grades and every offered version |
| `pulse-tls` | `pulse/tls.json` has rows | cert validity / self-signed / Pulse's own legacy-protocol probe (`requires_confirmation`) |
| `pulse-tls-probe` | fallback handshake | cert and chain validity / self-signed / chain trust / key size and signature digest / TLS 1.0 and 1.1 acceptance |

Artifacts: `tls_posture.json` (same shape; `source` field), plus
`tls_probe.json` when the fallback ran.

### What the probe checks, and what it can establish

Per endpoint the probe makes at most four connections, one after another
inside the `probe_concurrency` pool, each handshake bounded by
`probe_timeout_seconds`. An endpoint that answers nothing costs one timeout and
yields no row; one that answered in TLS yields a row even when no handshake
completed — `accepted_protocols: []` and checks that say why — instead of
disappearing from `tls_posture.json`.

1. **Main handshake.** It offers every version the local OpenSSL can speak, so
   a server whose highest version is TLS 1.0 is found even with the legacy
   checks off. When chain trust is due (below) it verifies the presented chain
   against the system trust store plus `ca_bundle` — the chain only: names are
   `cert_name_mismatch`'s job, and the validity window is checked separately,
   over the leaf and over every CA certificate of the verified chain.
2. **Collect handshake** without verification, only when the chain did not
   verify, so protocol and cipher come from a completed handshake. If it
   fails, what the first connection showed (its ServerHello, the certificate,
   the verdict on the chain) is kept.
3. **TLS 1.0 and TLS 1.1 handshakes**, each pinned to one version
   (`probe_legacy_protocols`). A server that also speaks TLS 1.3 picks 1.3 for
   a client offering everything; only a ClientHello offering nothing newer
   shows it still accepts 1.0.

Every handshake runs over memory BIOs, so the probe reads the server's
plaintext records as they arrive — the version its ServerHello chose, a
CertificateRequest, an alert — and classifies on what the server said rather
than on OpenSSL's error string, which says how the client failed.

**Chain trust (`chain_trust`).** `public_only` (the default) judges the chain
only when the address the probe connected to is publicly routable — the
scanner's one rule for that (`safe_http.is_public_address`), so a NAT64
address is judged by the IPv4 address it delivers to — or when `ca_bundle` is
configured. An intranet's own CA is not a finding until the operator has said
which CAs are theirs: without that, every internal endpoint would read as
untrusted, the org-profile TLS control would go `weak`, and nothing in the
console could silence it. `always` judges every endpoint; `off` none. With
`ca_bundle` loaded on a host that has no system anchors, chains are judged
against the bundle alone (`store: ca_bundle`).

Findings, in the same shapes as the nmap path:

| Finding | Severity | When |
|---------|----------|------|
| `weak_protocol` | high | a TLS 1.0 / 1.1 handshake completed (`version` says which) |
| `cert_chain_expired` | high | a CA certificate of the verified chain is past its not-after (or before its not-before: `cert_not_yet_valid`); a client that checks time rejects the chain. `depth` and `subject` say which |
| `cert_not_yet_valid` | medium | the leaf's not-before is in the future (also from nmap's `ssl-cert` and Pulse) |
| `cert_untrusted` | medium | the chain does not verify to the system store or `ca_bundle`; `detail` is OpenSSL's reason (`unable to get local issuer certificate`, `self-signed certificate in certificate chain`) |
| `self_signed` | medium | the leaf is its own issuer: certain (`heuristic: false`) when verification said so, then **instead of** `cert_untrusted`; otherwise the subject/issuer heuristic, dropped when the chain verifies |
| `weak_key` | medium; high under 1024 bits | RSA/DSA under 2048 bits, EC under 224 bits (also from nmap's `ssl-cert`) |
| `weak_signature` | medium | leaf signed with MD2/MD4/MD5 or SHA-1 (also from nmap's `ssl-cert`). Not on a self-issued leaf: no client verifies a self-signature, the finding there is `self_signed` |

Each probe row also says what was actually established, so a check that did
not run never reads as a clean result:

* `accepted_protocols` — versions a completed handshake proved. Not an
  enumeration: TLS 1.2 is not tried on its own when the server prefers 1.3.
* `checks.protocols` — per legacy version:
  * `accepted` — a handshake at that version completed;
  * `rejected` — only on a version-specific answer: a `protocol_version`
    alert, or a ServerHello that chose another version (`server_hello_version`);
  * `inconclusive` — everything else that did not complete: a
    `handshake_failure` alert before any ServerHello (a refused version and a
    refused cipher list look the same), a reset or hang-up (a refusal, a
    connection limiter and a middlebox look the same), a timeout, a handshake
    the local stack aborted, and a server that chose the version and then
    asked for a client certificate (`client_cert_requested: true`, also on the
    row);
  * `not_performed` — the local OpenSSL cannot offer that version (checked by
    building the ClientHello in memory first, so a crypto policy on the
    scanner host is never reported as "server refuses TLS 1.0"), or
    `probe_legacy_protocols` is off;
  * `not_testable` — SSLv2 and SSLv3, always: modern OpenSSL cannot send them;
    nmap `ssl-enum-ciphers` can.
* `checks.chain_trust` — `trusted` (with `store` and `validity_checked`),
  `untrusted` (with `verify_code`), `inconclusive` (no handshake completed),
  `not_evaluated` (by `chain_trust`: `reason: internal_address` or
  `disabled`), or `not_performed`: no system trust anchors and no bundle, or
  a `ca_bundle` that could not be loaded. Judging an internal PKI against the
  system store alone would flag all of it, so a bad bundle path turns the
  trust check off for the run and logs a warning.
* `checks.cert_fields` — whether the leaf's dates and names were read.
* `checks.cert_strength` — whether key size and signature algorithm were read.

The org-profile TLS control reads these: an endpoint with a check that is
`not_performed` or `inconclusive` (or a trusted chain whose validity could
not be read) is not counted as checked, and with no finding the control says
`not_checked` with the gaps listed, instead of "all endpoints passed".
`not_evaluated` and `not_testable` are by design and do not count against it.

Limits worth knowing:

* `rejected` is what the server said, and an OpenSSL server says
  `protocol_version` also when none of *its* suites for that version is in the
  probe's offer — so a TLS 1.0 server with only RC4 or export suites reads as
  rejected. The probe offers OpenSSL's `DEFAULT` list at security level 0,
  which on OpenSSL 3 holds no RC4/DES/NULL/EXPORT/anon suite: it cannot see
  weak ciphers at all, and `weak_cipher_name` comes from nmap
  `ssl-enum-ciphers` only.
* Names and dates of the presented certificates are read with the stdlib.
  Key size and signature algorithm need the `cryptography` package, which
  both images install; without it `checks.cert_strength` is `not_performed`.
* The trust check uses the scanner host's store, which is not a browser's:
  a public CA missing from an old `ca-certificates` reads as untrusted, and
  so does a server that omits its intermediate certificate (`unable to get
  local issuer certificate`) — browsers often fetch the missing intermediate
  and hide that misconfiguration; OpenSSL and most API clients do not.
* An endpoint behind a middlebox that swallows TLS 1.0/1.1 ClientHellos costs
  two more timeouts (both checks `inconclusive`); the stage has no overall
  deadline. `probe_legacy_protocols: false` removes them.

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
future dedicated enumerator. Key size and signature algorithm on the probe
path need the `cryptography` package (both images; see the limits above).

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
