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
#   pulse-v1.3.0-linux-amd64.tar.gz from onixus/GenDec releases
# /out/bin/pulse + /out/share/shapoclyack/pulse-install.txt, one COPY per
# directory; with INSTALL_PULSE=0 both are empty and nothing is copied:
COPY --from=pulse-bin /out/bin/ /usr/local/bin/
COPY --from=pulse-bin /out/share/ /usr/local/share/
# + setcap cap_net_raw,cap_net_admin+eip when the binary is there
```

| Arg / secret | Default | Meaning |
|--------------|---------|---------|
| `PULSE_VERSION` | `v1.3.0` | GenDec release tag |
| `PULSE_GITHUB_REPO` | `onixus/GenDec` | release owner/repo |
| BuildKit secret `github_token` | — | PAT for **private** GenDec releases (`GENDEC_READ_TOKEN` in CI) |
| `INSTALL_PULSE` | `1` | set `0` to build without Pulse — and without a token for the private GenDec repo |
| `PULSE_PINS` (script only) | `scripts/pulse-pinned.sha256` | file of reviewed per-platform digests |
| `PULSE_RECORD` (script only) | empty — no record | where to write the install record; the images set `/usr/local/share/shapoclyack/pulse-install.txt` (#340) |
| `PULSE_SKIP_CHECKSUM` | `0` | `1` accepts a tarball unchecked — **only for a version with no pin**; ignored for a pinned one |

The pin is the **engine** (banner / OS / `--cve` / TLS JSON). Shapoclyack does
not invoke `pulse monitor`, `pulse --server`, `--alert-*`, `--scripts`, or
`--inventory`. Those duplicate schedules, webhooks, Nuclei, and job targets.

Pulse's TLS probe (since v1.1.0) may write a JARM hash onto `tls[]` (no CLI flag to skip
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
GITHUB_TOKEN=… scripts/pulse-pin.sh v1.3.0
```

The helper fetches the release's `checksums.txt` and its
`checksums.txt.cosign.bundle`, runs `cosign verify-blob` against GenDec's
release workflow **on that tag** as the certificate identity, and only then
prints the lines to paste into `scripts/pulse-pinned.sha256`. A release with no
signature is refused unless `PULSE_PIN_ALLOW_UNSIGNED=1` — which the former `v1.1.0`
pins were taken with, because signing was added to GenDec
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
same profile. Run such an image with `OCTO_SERVICE_BACKEND=nmap` with a
self-installed Nmap ([Using your own Nmap](nmap-external.md)).

Local image build (GenDec is private, so pass a token with `contents:read`):

```bash
printf '%s' "$GITHUB_TOKEN" > /tmp/gh_token
docker build -f Dockerfile \
  --secret id=github_token,src=/tmp/gh_token \
  --build-arg PULSE_VERSION=v1.3.0 \
  -t shapoclyack-scanner:local .
```

No token, no Pulse (needs `OCTO_SERVICE_BACKEND=nmap` at runtime):

```bash
docker build -f Dockerfile --build-arg INSTALL_PULSE=0 -t shapoclyack-scanner:nopulse .
```

Host install without Docker:

```bash
GITHUB_TOKEN=… scripts/install-pulse.sh          # release tarball, verified
PULSE_VERSION=v1.3.0 scripts/install-pulse.sh    # pick a tag
PULSE_DEST=$HOME/.local/bin/pulse scripts/install-pulse.sh
PULSE_FROM_SOURCE=1 scripts/install-pulse.sh     # cargo fallback (PULSE_REF picks a ref)
scripts/smoke-pulse.sh
```

`GH_TOKEN` is accepted as an alias.

System UI / API status probes `pulse --version` alongside nmap/naabu/nuclei.

Connect-mode Pulse works without root; SYN/OS still need caps/root like nmap.

**A release ships the latest Pulse.** `scripts/check-pulse-latest.sh <version>`
compares a version with GenDec's latest non-prerelease release (token from
`GH_TOKEN` / `GITHUB_TOKEN`; the repository is private). Exit 0 up to date,
1 outdated (the message prints the `scripts/pulse-pin.sh` command to bump),
3 GitHub could not be asked. `Jenkinsfile.publish` runs it as the *Pulse is
latest* stage before the build — a failure for a real publish, a warning for
`DRY_RUN`; see [release-contract.md](release-contract.md#how-the-pulse-version-changes).

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
   against the system trust store plus `ca_bundle`, with OpenSSL's time check
   on, as an ordinary client does. Names are `cert_name_mismatch`'s job. Only
   when that verification fails *on time* is the chain verified again with the
   time check off: if it then verifies, it is trusted and the CA certificate
   outside its window is the finding (`cert_chain_expired`), not
   `cert_untrusted`. Checking time first matters: a server that still sends an
   expired intermediate next to its re-issued twin is accepted by clients,
   which pick the valid one, and is not flagged. If the re-verification cannot
   connect (a per-source connection limiter), the finding still stands, without
   a `depth`: OpenSSL checks time only on a chain it has built to a trust
   anchor — an unanchored chain fails with "unable to get local issuer
   certificate" first — so a time failure with the leaf in its window names a
   CA certificate. Chain trust is then `inconclusive`, and the protocol is the
   one the main handshake's ServerHello chose.
2. **Collect handshake** without verification, only when the chain did not
   verify for a reason other than time, so protocol and cipher come from a
   completed handshake. On the time path the untimed re-verification takes its
   place, so an endpoint never costs more than four connections. If it fails,
   what the first connection showed (its ServerHello, the certificate, the
   verdict on the chain) is kept.
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
| `cert_chain_expired` | high | the chain failed the time check on a CA certificate, and verifies without it: a client that checks time rejects it. `depth` and `subject` say which (a CA certificate before its not-before is `cert_not_yet_valid` with a `depth`). When the leaf itself is outside its window, the chain counts as checked if every CA certificate of the re-verified chain is within its window; if one is not, which one a client trips on cannot be told: `validity_checked: false` |
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
    row; visible up to TLS 1.2 only — in TLS 1.3 the CertificateRequest is
    encrypted);
  * `not_performed` — the local OpenSSL cannot offer that version (checked by
    building the ClientHello in memory first, so a crypto policy on the
    scanner host is never reported as "server refuses TLS 1.0");
  * `not_evaluated` with `reason: disabled` — `probe_legacy_protocols` is off;
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
not be read) is not counted in `coverage.checked`, and the control's `why`
lists the gaps. With no finding it stays `ok` as long as at least one endpoint
was fully checked, as the credential leaks control does, but the partial
share is explicit: `coverage.partial: true`, a `why` that starts with
"partial coverage (N of M)", and an overall org-profile verdict of `partial`
instead of `ok`. It is `not_checked` only when no endpoint was fully checked. `not_evaluated`
(chain trust skipped by policy, legacy checks switched off) and
`not_testable` are by design and do not count against it.

Limits worth knowing:

* A TLS 1.0 server whose suites are all outside the probe's offer (RC4,
  export, anonymous) answers `handshake_failure`, which reads as
  `inconclusive`: the probe cannot tell that from a refused version. The probe
  offers OpenSSL's `DEFAULT` list at security level 0, which on OpenSSL 3 holds
  no RC4/DES/NULL/EXPORT/anon suite: it cannot see weak ciphers at all, and
  `weak_cipher_name` comes from nmap `ssl-enum-ciphers` only.
* Where chain trust is `not_evaluated` (an internal address under
  `public_only`), the chain's validity is not judged either: an expired
  intermediate on an internal endpoint is visible only with `ca_bundle` or
  `chain_trust: always`.
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

## Optional nmap

Nmap is not bundled in the images (NPSL, [#97](https://github.com/onixus/Shapoclyack/issues/97));
`0.47-1009-rc1` is the last release that published `-nmap` tags. It is not
required for the default Pulse path. For `backend: nmap|hybrid`, `vuln_legacy`
and the L2 ARP sweep, install your own and let it be found on `PATH`:
[Using your own Nmap](nmap-external.md).

When nmap is absent, `run_nse` logs a warning, writes `nmap/SKIPPED_NMAP_MISSING`
and continues (Pulse + Nuclei + TLS probe still run).

System UI marks **nmap** as optional and shows `service_probe.backend`.

K8s caps (`NET_RAW` / `NET_ADMIN` + `allowPrivilegeEscalation: true`) remain
required for **naabu** and Pulse SYN/OS — see `k8s/README.md`.

## Reference corpus: Nmap versus Pulse (#541)

`pulse_shadow` compares endpoints and OS family on a live run. The golden corpus
is the same comparison frozen: Nmap and Pulse run once against a fixed stand,
the outputs are committed, and the gap is measured offline in CI. It exists
because Nmap is going away ([ADR 0002](adr/0002-replacing-nmap-functions.md)) and
what Pulse is measured against has to be recorded while Nmap still runs.

| Part | Where |
|---|---|
| Stand (docker compose, pinned images) | `tests/fixtures/nmap_pulse_corpus/stand/` |
| Recorder | `tests/fixtures/nmap_pulse_corpus/record.sh` |
| Nmap XML | `tests/fixtures/nmap_pulse_corpus/nmap/{tcp,udp}.xml` |
| Pulse JSON (banners, TLS rows and findings included) | `tests/fixtures/nmap_pulse_corpus/pulse/{tcp,udp,tcp-scripts}.json` |
| Comparison | `scripts/pulse_corpus.py`, CLI `scripts/compare-nmap-pulse-corpus.py [--json]` |
| Pinned numbers | `tests/test_nmap_pulse_corpus.py` |

**Stand.** One bridge, `172.29.41.0/24`, fixed addresses, nothing published to
the host, no named volumes; the scanner container sits on the same bridge so
`-O` and banner grabs see real TCP/IP stacks. OpenSSH from Ubuntu 20.04, Ubuntu
22.04, Debian 12 and Rocky 9 packages (the banner carries the distribution
revision on the first three, none on Rocky); nginx 1.27 (TLS 1.2/1.3), nginx 1.18
(TLS 1.0/1.1/1.2, `SECLEVEL=0` suites), Apache httpd 2.4 (TLS 1.2); PostgreSQL
16, MySQL 8.0, Redis 7.2; Samba, snmpd and vsftpd (anonymous) from Debian 12.
**Stubs, not the real product:** `iis-stub` (a socket server sending IIS 10
headers) and `rdp-stub` (answers the X.224 request with `RDP_NEG_RSP`). They test
what each tool does with that wire format, not IIS or Windows. Images are pinned
by tag and digest; the distribution-package services (OpenSSH, Samba, snmpd,
vsftpd) install the then-current package of the pinned base, so their exact
versions are in the fixtures (banners), not in the compose file.

**Commands.** Nmap: `-n -Pn -T4 -sV -O --osscan-guess --script default,safe,vuln,ssl-enum-ciphers`
(plus `-sU -sV -p 161` for SNMP). Pulse 1.3.0: the adapter's flags
(`-b --os --os-mode sinfp --cve -f json`, connect scan) with an empty `HOME`,
plus a second run with `--scripts`. Both got the same targets and ports
(21, 22, 80, 139, 443, 445, 3306, 3389, 5432, 6379, and UDP 161). The scanner
image has the distribution `nmap` installed, so Pulse could read
`/usr/share/nmap/nmap-services` (ADR 0002, measurement 1): service names that
come from the port table in the Pulse column are NPSL-derived. That is the
as-is state of a sensor with Nmap installed, and #543 changes it.

**Starting gap** (Nmap 7.93 and Pulse 1.3.0, before any Pulse or adapter
change; the same numbers are pinned in the test):

| Dimension | Nmap | Pulse 1.3.0 | Gap |
|---|---|---|---|
| Open endpoints (TCP + UDP) | 19 | 19 | none (19 of 19 shared) |
| Service name | 19 | 18 agree | 1: port 445, Nmap `netbios-ssn`, Pulse `smb` |
| Product (of 18 Nmap names) | 18 | 14 agree | 3 missing (Samba x2, PostgreSQL), 1 differs (SNMP) |
| Version | 17 given | 11 exact, 3 upstream-only | 3 missing; the 3 upstream-only lack the distribution revision (`8.2p1 Ubuntu 4ubuntu0.13` against `8.2p1`) |
| CPE | 17 endpoints | 0 | Pulse's `open[]` rows carry a `cpe` field, but it is `[]` on every row (70 of 70 in the fixture); nothing fills it |
| OS family (14 hosts) | 14 | 14 agree (Linux) | family only; Nmap `Linux 4.15 - 5.6`, Pulse `Linux (modern, TS+SACK+WS)`, real kernel 6.12 |
| TLS endpoints | 4 | 3 | MySQL (3306, in-protocol TLS) missing |
| TLS protocol sets (3 shared) | enumerated | 2 equal | nginx 1.27: Nmap `TLSv1.2, TLSv1.3`, Pulse only the negotiated `TLSv1.3` |
| TLS cipher suites enumerated | 122 | 0 | `tls[]` holds the negotiated protocol and the weak protocols accepted, not suites or grades |
| Weak-protocol verdict (3 shared) | 1 endpoint | 1 endpoint, 3 of 3 agree | none on this stand; the unfavourable cases (SSLv3, weak suites on TLS 1.2) are not in it |
| Script outputs | 157 on ports, 40 distinct scripts | 13 findings (6 exposure, 4 tls, 3 version_cve) | `--scripts` added nothing (13 = 13) |
| CVE ids named | 428 (`vulners`) | 3 | the 3 are all among Nmap's; 425 are Nmap-only. Not a quality score: `vulners` names every CVE ever filed against a version |

Reading it:

- Pulse's service/product/version detection is close on what its probe DB
  covers (SSH, HTTP servers, MySQL, Redis, FTP) and absent where it has no rule
  (Samba, PostgreSQL). That is #546's job.
- The distribution revision and the CPE are the two fields that disappear when
  Nmap does (`retro_match` and `asset_services` prefer them): #546, with the
  Pulse change in #543.
- Nmap is the reference, not the truth. It reports Samba `4.6.2` (Debian 12
  ships 4.17), PostgreSQL `9.6.0 or later` for 16, and a kernel range that does
  not contain 6.12. Agreement with it is scored; being right is not. The IIS
  and RDP rows measure the stubs only.
- Cipher-suite enumeration is the largest single gap and the one with no
  workaround short of #545.

Re-recording: `PULSE_BIN=<linux pulse> tests/fixtures/nmap_pulse_corpus/record.sh`
(the header explains how to get a digest-checked Linux binary, and `MIRROR=` for
an unreachable Docker Hub). It needs Docker with NET_RAW and takes a few
minutes; the stand is removed when the script ends. Re-record only when the
stand or a tool version changes, then update `EXPECTED_SUMMARY` in the test and
the table above in the same commit; do not edit fixtures by hand.

Limits of the numbers:

- Counters are per **endpoint** (`host:port/proto`), not per distinct service:
  nginx on 80 and 443 and Samba on 139 and 445 count twice, so "11 exact
  versions" is about six distinct product/version pairs.
- A re-recording will not reproduce them exactly. Base images are pinned, but
  the packages installed on them (`nmap`, `openssh-server`, `samba`, `snmpd`,
  `vsftpd`) are not, so versions move with the distribution's repositories. The
  425 Nmap-only CVE ids come from `vulners`, which queried an external database
  during the recording (product versions leave the stand for it): a snapshot of
  that database on 2026-10-09, not a property of the stand.
- OS fingerprints were taken on an arm64 Docker VM (kernel 6.12 `linuxkit`).
  On amd64 the TCP/IP stack signatures, and so the `-O` and SinFP answers,
  change; expect to re-pin every OS and timing-dependent number.

Fixture size is 620 KB, 438 KB of it the Nmap XML (the `vuln` scripts and
`vulners` output). It is stored as recorded so that `_parse_nmap_xml` reads it
exactly as it reads a run directory.

## Limitations (current)

- Does not run NSE scripts (`ssl-enum-ciphers`, vulners, …) on the default path.
- TLS probe fallback ≠ full `ssl-enum-ciphers` grade table.
- UDP enrichment still relies on naabu (and optional nmap) paths.
- Banner ≠ full nmap `-sV` product/version.
