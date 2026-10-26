# Pulse service probe backend

Shapoclyack enriches open ports with **[Pulse](https://github.com/onixus/GenDec)**.
It is the only service-probe backend: the Nmap NSE stage, the `hybrid` backend
and the shadow comparison were removed in #548 (see
[Migrating off Nmap](nmap-migration.md) for what replaces which setting, how old
runs are still read, and the gaps listed at the end of this page).

Migration plan (full): see GenDec `docs/shapoclyack-migration.md`.

## Backend

`service_probe.backend` takes `pulse` and nothing else. `nmap`, `hybrid`,
`service_probe.shadow`, `profiles.<mode>.service_backend: nmap|hybrid`,
`OCTO_SERVICE_BACKEND=nmap|hybrid` and `OCTO_PULSE_SHADOW=1` stop the scanner
with exit code 2 and a message naming the replacement; they are not ignored.

### Speed profiles (Pulse knobs)

| Mode | Profile `pulse.*` overrides |
|------|-----------------------------|
| `safe` | c=300 rate=500 host-parallel=4 os=sinfp |
| `balanced` | c=800 rate=2000 host-parallel=16 os=sinfp |
| `fast` | c=1200 rate=5000 host-parallel=32 os=sinfp |

These replace what `nmap_timing` and `nse_max_rate` / `nse_concurrency` set per
profile ([the mapping](nmap-migration.md#nmap_timing)).

### Ports-only L1

`--skip-nse` (or `runtime.skip_nse: true`) skips the Pulse probe: discover,
ports, reports. The flag's name predates Pulse and is kept. Re-run with
`--resume` to enrich.

Override without editing YAML:

```bash
export OCTO_SERVICE_BACKEND=pulse
export OCTO_PULSE_BIN=/usr/local/bin/pulse
```

## Config (`scanner/config/default.yaml`)

```yaml
service_probe:
  backend: pulse   # the only value
  pulse:
    bin: ""                  # OCTO_PULSE_BIN overrides this; else this path; else PATH
    concurrency: 500
    rate: 2000
    adaptive: true
    host_parallel: 8
    timeout_ms: 800          # per-connect timeout (pulse -t)
    banner: true
    os_detect: true          # needs raw sockets; dropped for the run if pulse refuses
    os_mode: sinfp
    cve: true
    cve_online: false
    syn: false               # half-open scan; needs raw sockets, never auto-downgraded
    max_hosts: 65536
    chunk_hosts: 64          # hosts per pulse invocation / checkpoint
    retry_settle_seconds: 15 # pause before re-probing an all-closed chunk; 0 disables
    plugins: true            # Rhai plugins via --script-dir (docs/pulse-plugins.md)

profiles:
  balanced:
    pulse:
      concurrency: 800
      rate: 2000
      host_parallel: 16
      os_mode: sinfp
```

NVD online: set `NVD_API_KEY` in the sensor's environment. Pulse's own
`~/.pulse/nvd_api_key` is not read (see below).

### Rhai plugins

`plugins: true` (the default; also settable per speed profile) hands the plugins in
`scanner/pipeline/pulse_data/plugins/` to Pulse with `--script-dir`: weak SSH
algorithms, anonymous FTP, services that cannot start TLS, SMB/RDP/VNC reachability,
HTTP TRACE over plain HTTP.
They replace the part of NSE `default,safe` that Pulse's sandbox can express.
Pulse then runs in an empty working directory (the same one as its `HOME`), the
plugin files and their sha256 are recorded in `adapter.plugins` of `pulse/raw.json`,
and a policy with a `per_host_rate` ceiling turns them off. Details, limits and the
gap to NSE: [Pulse plugins](pulse-plugins.md).

### Pinned inputs

Left alone, Pulse reads `~/.pulse/` and the NPSL-licensed `nmap-services` and
`nmap-os-db` of any Nmap installed on the host, so two sensors with the same
config could name services differently. The adapter therefore pins the inputs
([ADR 0002](adr/0002-replacing-nmap-functions.md), #543):

- `--no-nmap-data` on every invocation disables ambient Nmap databases, including
  standard system paths, even if the explicit table is empty. This requires
  the Pulse release containing GenDec#32.
- `--services-db scanner/pipeline/pulse_data/services.tsv` on every invocation: a
  port-to-name table built from the IANA registry (source and terms in
  [third-party.md](third-party.md)). If the file is missing the adapter passes
  `/dev/null` and Pulse uses its embedded table; it never falls back to the
  host's Nmap files.
- `--probe-db scanner/pipeline/pulse_data/probes.json` on every invocation, once
  the file passes the adapter's own checks (see [Probe database](#probe-database)).
- `--os-mode sinfp` whenever `--os` is on. `os_mode: nmap` is
  rejected at config load with a message to switch to `sinfp`. `os_mode: auto`
  (the old default) still loads, runs as `sinfp` and logs a deprecation warning.
  Which port table a run used is recorded as `adapter.services_db` in
  `pulse/raw.json` (`/dev/null` means Pulse's embedded table).
- A private, empty `HOME` per Pulse process, and an allow-listed environment:
  `PATH`, `LANG`/`LC_*`, `TZ`, `TMPDIR`, `NVD_API_KEY`, the proxy variables
  (`HTTP(S)_PROXY`, `ALL_PROXY`, `NO_PROXY`, both cases) and `SSL_CERT_FILE/DIR`.
  Everything else is dropped: Pulse reads `SHODAN_API_KEY` and `CENSYS_API_KEY`
  on its own and would send every scanned address to those services, and
  `PULSE_*` variables switch on alerting, a server token and alternative data
  files.

Pulse gets only the standard proxy and trust variables (`HTTPS_PROXY`/`https_proxy`,
`NO_PROXY`, `SSL_CERT_FILE`/`SSL_CERT_DIR`). `OCTO_HTTP(S)_PROXY`, `OCTO_NO_PROXY` and
`OCTO_CA_BUNDLE` are the sensor-to-API contract and do not reach it; for `cve_online`
behind a proxy set the standard names. `SSL_CERT_FILE` replaces Pulse's trust store
(rustls) rather than adding to it, so the bundle must contain the public CAs too.

What the sensor user's `~/.pulse/` used to contribute and no longer does:
`kev.txt` and `epss.csv` (Pulse's `--cve` now uses its embedded KEV subset and
fallback scores; Shapoclyack's own KEV/EPSS overlays under `scanner/data` are
JSON and are not in the text/CSV format `--kev-file`/`--epss-file` expect, so
they are not passed), `nvd_api_key` and `config` (use `NVD_API_KEY`), and any
`nmap-services`/`nmap-os-db`. The port table lives in
`scanner/pipeline/pulse_data/`, next to the code, because `scanner/data` is
replaced by the enrichment volume in deployments that mount one.

The table has no frequency column (every entry reads as 0.0), so `--top` on it
is numeric order; the adapter always passes explicit `-p` lists. In Pulse
v1.3.0 about 80 well-known ports (135, 445, 3389, 5900, 8080, ...) have names
hard-coded in the engine that `--services-db` does not override, so the table
only decides the names of the remaining ports (3389 is `rdp` from the engine,
5985 is `wsman` from the table). Both limits go away when the engine derives
the name from the matched probe (onixus/GenDec#31).

GenDec#31 makes a matched probe's service name authoritative: an OpenSSH
banner on port 2222 becomes `ssh`, while unmatched endpoints retain the port
name as a fallback. GenDec#32 makes explicitly empty tables authoritative and
adds the ambient-data restriction above. The sensor release pin must contain
both changes before #543 can be accepted.

### Probe database

`scanner/pipeline/pulse_data/probes.json` is the rule set Pulse identifies
products with (`--probe-db`, #546). `--probe-db` **replaces** Pulse's embedded
set wholesale, so the file begins with GenDec's `src/scanner/probes.json` at the
pinned tag (`v1.3.0`, version `2026.08.21`, MIT, copied byte for byte in the
first commit that added it) and everything of ours comes after it: new probes at
the end of `probes`, new `matches` at the end of an existing probe's list. The
file's `version` is the upstream one plus `+shapo.N`. Licence, source tag and
sha256 of the base are in `probes.json.LICENSE` (and `NOTICE`,
[third-party.md](third-party.md)); `tests/fixtures/pulse_probe_db/probes.v1.3.0.json`
is the pinned upstream copy, and `tests/test_pulse_probe_db.py` fails if an
upstream probe, its ports, payload or the order of its matches change. Bumping
Pulse means re-importing the new embedded set as the base, re-appending ours
and updating the pin and the fixture in the same change.

**The adapter validates the file before passing it.** Pulse answers a file it
cannot read, parse or compile with one stderr line (`probe-db <path>: ... --
using the embedded set`) and carries on with the stock rules. So
`scanner/pipeline/pulse_probe_db.py` checks, before passing the file:

- the JSON itself as serde_json reads it (no `NaN`/`Infinity`, no lone
  surrogate escape), the shape of probes and matches, port and rarity ranges,
  and `payload_hex` (whitespace allowed, as Pulse's `decode_hex` strips it);
- that every pattern compiles in Python **and** stays inside the *common subset*
  of Python's `re` and Rust's `regex`. The rule is "patterns must be in the
  common subset", not "everything Rust accepts": no look-around, no
  back-references or octal escapes, no `(?#...)`, no flags except `i`, `m`, `s`
  (bare ones only at the start; scoped `(?i:...)` is fine), no possessive
  quantifiers, only `\d \D \s \S \w \W \b \B \A \n \r \t \f \v \a`, `\xHH` and
  escaped punctuation, no nested, POSIX or `&&`/`--`/`~~` classes, `{` only as a
  counted repetition. This rejects some Rust-only syntax too (`(?<n>`, `\pL`,
  `\x{41}`, `\z`), on purpose, so the verdict does not depend on the Python
  version;
- an estimated compiled size of at most 1000 per pattern (a literal is 1,
  `\w \d \s` and negated classes are 10, counted repetitions multiply and
  nest). Rust refuses programs over its size limit, which Python does not
  notice (`\w{500}`, `(\w{1,1000}){1,1000}`). `\w{200}` compiles and `\w{300}`
  does not under regex 1.13.1; the budget is half the former, and the largest
  shipped pattern is a fraction of it.

The subset was checked against a real `regex` 1.13.1 compile of every shipped
pattern, a battery of edge cases and a few thousand generated patterns: none the
validator accepted was refused by Rust. A file that fails is **not** passed: the
run logs a warning once and records `adapter.probe_db: null` with the reason
in `adapter.probe_db_skipped`. A file that passes is recorded as
`adapter.probe_db` (path), `probe_db_version` and `probe_db_sha256`; if Pulse
still printed its fallback line, it is kept in `adapter.probe_db_fallback` and
logged, so a run that did not use our rules does not look like one that did.

**Adding a rule.** Write it from a banner you observed (the stand in
`tests/fixtures/nmap_pulse_corpus/stand/`, a container, a protocol
specification or vendor documentation), never from another scanner's rule
file; `nmap-service-probes` is NPSL and is neither copied nor paraphrased
here. Then:

1. Append the probe (or the match) to `probes.json`. The product string must be
   the vendor's own name and must be either a `retro_match.PRODUCT_TABLE` row
   (with NVD keys checked against NVD's CPE dictionary) or an
   `UNMAPPED_PROBE_PRODUCTS` entry with the reason; `tests/test_pulse_probe_db_cpe.py`
   enforces it, because Pulse emits no CPE of its own.
2. Payload bytes go in `payload_hex`. Pulse 1.3.0 does not decode `\xNN` in
   `payload` (it sends the four characters literally), which is why seven stock
   probes (`postgres-startup`, `mongodb-isMaster`, `rabbitmq-amqp`,
   `mqtt-connect`, `kafka-api-versions`, `rdp-negotiate`, `telnet-do`) cannot
   provoke the replies their rules wait for. Patterns see the reply decoded as
   lossy UTF-8, so a byte >= 0x80 is U+FFFD and `\xd0` in a pattern never
   matches it.
3. Add the reply to `tests/fixtures/pulse_probe_db/observed_banners.json` with
   what a live run reported. The test replays it through a small Python
   re-implementation of `probe_db.rs` matching (first hard match wins, then the
   first soft one; `$N` expands to capture N). That emulates the engine, it
   does not run it: check new rules with `pulse --probe-db` against the stand
   too.

The stock `postgres-startup` probe is still sent first on 5432 (probes are
tried cheapest first and ours is appended), and a PostgreSQL server logs
`invalid length of startup packet` for its literal-text payload (and
`incomplete startup packet` for the listen-only `null` probe). On the stand the
chain went on regardless: the run reported `PostgreSQL database`, banner `N`,
`detection_method: probe-db` from `postgres-sslrequest` (Pulse 1.3.0,
2026-10-10).

Rules added so far: `postgres-sslrequest` (5432/5433/6432). A PostgreSQL server
answers the SSLRequest with the single byte `N` or `S`; the stock rule wants
`^[NER]\x00` and its probe never sends the request, so Pulse reported
`postgresql` from the port table only. Now it reports the product; the version
is not on the wire before authentication. A pooler that speaks the PostgreSQL
protocol answers the same way and is reported as PostgreSQL too.

What the database cannot do: Samba/SMB. The stand's Samba answers an SMB2
negotiate with a dialect, a GUID and the generic SPNEGO hint, and no product or
version; reading more takes a second round trip (session setup), and a probe is
one payload and one reply. Anything that needs authentication is out of reach
for the same reason.

## Artifacts

| Path | Content |
|------|---------|
| `services.json` | `octo.service.v1` open services |
| `pulse/tls.json` | Pulse TLS cert posture (`octo.pulse_tls.v1`) |
| `tls_posture.json` | Unified TLS findings (pulse-tls / probe; `nmap-nse` only from a run recorded before #548) |
| `os.json` | `octo.os.v1` OS guesses |
| `pulse_cves.json` | Pulse findings (`octo.cve.v1`: version_cve / keyword_cve / exposure / tls) |
| `pulse/raw.json` | Merged raw Pulse JSON; `adapter.report_schemas` lists the `meta.schema` values seen (`pulse.scan.v2` and `pulse.scan.v3` are read, another one is parsed but logged) |
| `pulse/REPORT_PRIMARY` | Marker: report prefers Pulse services/OS |

`diff_pulse_nmap.json` and `nmap/**` are no longer written. A run directory
recorded before #548 keeps them, and `report.py` still reads its Nmap XML
([Migrating off Nmap](nmap-migration.md#old-data-is-still-read)).

`report.py` prefers `services.json` / `os.json` (the `REPORT_PRIMARY` marker is
written on every run), and merges the script findings of an old run's Nmap XML
when it is given one.

## Image install

`Dockerfile` / `Dockerfile.allinone` install Pulse from a **GenDec GitHub
Release** (not a vendored Rust tree). Canonical pipeline:
[GenDec `docs/release.md`](https://github.com/onixus/GenDec/blob/main/docs/release.md).

```dockerfile
# stage pulse-bin downloads:
#   pulse-v1.4.0-linux-amd64.tar.gz from onixus/GenDec releases
# /out/bin/pulse + /out/share/shapoclyack/pulse-install.txt, one COPY per
# directory; with INSTALL_PULSE=0 both are empty and nothing is copied:
COPY --from=pulse-bin /out/bin/ /usr/local/bin/
COPY --from=pulse-bin /out/share/ /usr/local/share/
# + setcap cap_net_raw,cap_net_admin+eip when the binary is there
```

| Arg / secret | Default | Meaning |
|--------------|---------|---------|
| `PULSE_VERSION` | `v1.4.0` | GenDec release tag |
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
GITHUB_TOKEN=… scripts/pulse-pin.sh v1.4.0
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
service-probe backend of its own: the scanner aborts the run with an error
naming the fixes, rather than
silently skipping the stage and producing a different finding set under the
same profile. Run such an image ports-only (`--skip-nse`), or give it a Pulse
binary of your own (`OCTO_PULSE_BIN`).

Local image build (GenDec is private, so pass a token with `contents:read`):

```bash
printf '%s' "$GITHUB_TOKEN" > /tmp/gh_token
docker build -f Dockerfile \
  --secret id=github_token,src=/tmp/gh_token \
  --build-arg PULSE_VERSION=v1.4.0 \
  -t shapoclyack-scanner:local .
```

No token, no Pulse (runs ports-only, or with your own Pulse binary):

```bash
docker build -f Dockerfile --build-arg INSTALL_PULSE=0 -t shapoclyack-scanner:nopulse .
```

Host install without Docker:

```bash
GITHUB_TOKEN=… scripts/install-pulse.sh          # release tarball, verified
PULSE_VERSION=v1.4.0 scripts/install-pulse.sh    # pick a tag
PULSE_DEST=$HOME/.local/bin/pulse scripts/install-pulse.sh
PULSE_FROM_SOURCE=1 scripts/install-pulse.sh     # cargo fallback (PULSE_REF picks a ref)
scripts/smoke-pulse.sh
```

`GH_TOKEN` is accepted as an alias.

System UI / API status probes `pulse --version` alongside naabu/nuclei/dnsx.

Connect-mode Pulse works without root; SYN/OS still need caps/root.

**A release ships the latest Pulse.** `scripts/check-pulse-latest.sh <version>`
compares a version with GenDec's latest non-prerelease release (token from
`GH_TOKEN` / `GITHUB_TOKEN`; the repository is private). Exit 0 up to date,
1 outdated (the message prints the `scripts/pulse-pin.sh` command to bump),
3 GitHub could not be asked. `Jenkinsfile.publish` runs it as the *Pulse is
latest* stage before the build — a failure for a real publish, a warning for
`DRY_RUN`; see [release-contract.md](release-contract.md#how-the-pulse-version-changes).

## Checkpoint

Shapoclyack's own stage checkpoint (`CheckpointStore`) marks hosts done under
key `pulse` (a pre-#548 checkpoint may also hold `nse`, which nothing reads) for chunks that returned at least one
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
| `os_detect: true` but no raw sockets (unprivileged host install, pod without `NET_RAW`) | Pulse aborts the whole invocation, not just OS detection. The adapter recognises its "OS detection needs raw sockets" refusal, drops `--os` for the rest of the run, re-runs the chunk at once and logs a warning; services, banners, TLS and CVEs are kept. `pulse/raw.json` records it under `adapter.os_detect_degraded`. |
| `syn: true` without raw sockets | Not downgraded: SYN is an explicit opt-in. The chunk fails, is re-run once at once, its hosts stay unresolved, and the crash-loop breaker above ends the stage after three such chunks. |
| A chunk reports every port closed | A contradiction, not a result: naabu proved those ports open moments ago. The chunk is re-probed after `retry_settle_seconds`. A chunk that is still empty afterwards leaves its hosts unmarked so `--resume` asks again. |
| Pulse exits non-zero without JSON for any other reason | Logged as a crash with its stderr (not as "0 services") and re-run **at once** — the settle pause is for a saturated network path, not for exit 2. After three consecutive chunks that still end in a crash the stage raises `PulseCrashLoopError` naming the exit code and stderr: a crash that repeats across chunks is a broken binary or a bad flag, and sleeping through the rest of a large run would only delay the same empty result. |

`pulse/raw.json` also carries `adapter.pulse_bin`, `adapter.chunk_hosts`, a
`chunks` list with every chunk's key, hosts, last exit code and `resolved`
flag (failed chunks included), and `stats` summed over the chunks that
answered (`rate_pps` recomputed from the totals).

## TLS posture without nmap (Phase 4)

When `tls_posture.enabled: true` and there is no `ssl-cert` /
`ssl-enum-ciphers` output from an old run's `nmap/` XML (every new run),
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
| `nmap-nse` | SSL scripts present in the Nmap XML of a run recorded before #548 (read-only) | cert validity / self-signed heuristic / key size and signature digest + full cipher grades and every offered version |
| `pulse-tls` | `pulse/tls.json` has rows | cert validity / self-signed / Pulse's own legacy-protocol probe (`requires_confirmation`); with a suite enumeration (see below, Pulse v1.4.0, GenDec#34/39) also observed selections/suites with A-F grades |
| `pulse-tls-probe` | fallback handshake | cert and chain validity / self-signed / chain trust / key size and signature digest / TLS 1.0 and 1.1 acceptance |

Artifacts: `tls_posture.json` (same shape; `source` field), plus
`tls_probe.json` when the fallback ran.

**Ports Pulse did not probe.** Pulse v1.3.0 runs its TLS probe on 443 and 8443
only, so a listener on 9443, 4443, ... has no `tls[]` row. With `probe_fallback`
on, the stdlib probe now also runs on every open port of `probe_tls_ports` that
has no Pulse row, and those rows join `tls_posture.json` with their own
`source: pulse-tls-probe` (the run-level `source` stays `pulse-tls`). They count
toward `max_targets` together with the Pulse rows (`truncated` is set when either
side is cut); `tls_probe.json` holds just the probed rows. The stdlib fallback does not look outside
`probe_tls_ports` (465, 636, 993, 3306, ...); the opt-in native enumerator has separate direct/STARTTLS selection, and the
budget is spent on open `probe_tls_ports` endpoints whether or not they speak TLS.
The "443 and 8443 only" figure was measured live on the corpus stand with extra
`openssl s_server` listeners (443, 8443, 465, 636, 993, 9443); the measurement is
in ADR 0002, section "TLS (#545)", not in the recorded fixtures.

### Cipher suites and A-F grades on the Pulse path

Signed/pinned Pulse v1.4.0 provides `--tls-enum`, requested only when both
`tls_posture.enabled` and `tls_posture.enumerate_ciphers` are true (the latter
is off by default). Dockerfiles/workflows/checksum pins select v1.4.0 after
workflow identity and all four archive digests were verified. Released CLI
fixtures do not establish installed sensor acceptance.

The engine uses raw ClientHellos for SSLv2/SSLv3…TLS1.3 and native STARTTLS
for SMTP/IMAP/POP3/FTP/LDAP/PostgreSQL/MySQL. Each endpoint has a 30-second,
256-connection budget; per-connection deadlines are at most 3 seconds and
first-flight collection is limited to eight records/16 KiB. Shared `--rate`
paces connection starts, not packets within an upgrade. A per-host packet
ceiling disables enumeration. Missing or inconclusive results never mean
rejection; a raw ServerHello selection is not a completed/authenticated session.

`tls_grading.py` and `tls_enumeration.py` grade observed IANA names from the
bundled registry, excluding GOST/signaling suites. Letter thresholds stay the
established SSL Labs-derived contract; the historical Nmap corpus only tests
A/F parity, not complete letter or coverage parity. Unknown sizes retain
`grade_upper_bound`, and raw-selection findings always require confirmation,
even when the advertised catalog coverage is complete.

Normal TLS1.3 x25519 shares and TLS≤1.2 Certificate/SKE fields can supply
`kex_group`, `kex_bits` and `kex_evidence`. RSA/DHE sizes are modulus bits;
EC sizes are curve bits, not RSA-equivalent bits. Signatures/chain trust are
not authenticated here; HRR, static ECDH/PSK and missing/conflicting parameters
remain unknown. Finite-field exchange sizes below 2048 (EC below 224) produce
`weak_key_exchange`; this includes a 1024-bit DH suite rated B, without
inventing a C-F grade. Existing `weak_protocol`, `weak_cipher_grade` and
`weak_cipher_name` forms remain.

`enumeration_complete`, `enumeration_evidence` and `enumeration_transport`
retain the measurement boundary. Resume receipts/chunk keys carry requested
`raw-starttls-v2`; older candidate contracts re-probe rather than reuse unknown
exchange coverage. The marker records the request, not binary capability.
See [configuration/limits](pulse-endpoints.md#optional-tls-suite-enumeration)
and [native fixture provenance](../tests/fixtures/pulse_tls/README.md).

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
    the raw Pulse enumerator covers these separately. This restriction applies to the stdlib fallback.
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
  `weak_cipher_name` needs the native enumeration or historical nmap output, not this stdlib fallback.
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

Cipher enumeration/grading is available with signed/pinned Pulse v1.4.0,
with the opt-in settings and evidence limits above. The default/pinned 1.3.0
binary does not acquire it from a config change. Key size and signature
algorithm on the stdlib probe path still need `cryptography` (both images).

## CVE stack without nmap-vulners (Phase 4.2)

Default path (no nmap required):

| Layer | Where | Config | Output |
|-------|-------|--------|--------|
| `retro_match` (**primary** for CVE-by-version) | API, after the run, from the stored fingerprints; offline NVD ranges + Debian/Ubuntu backports; re-runs when the dataset changes | `OCTO_RETRO_MATCH_ENABLED` (on); the NVD dataset is opt-in, see below | tracked findings `source: retro_match` |
| Pulse `--cve` (secondary) | scanner, during the scan, its compiled-in rules | `service_probe.pulse.cve: true` | `pulse_cves.json` → vulns `source: pulse` |
| Nuclei (web) | scanner | `nuclei.enabled: true` (default) | `nuclei.json` + vulns `source: nuclei` |
| Nuclei (network, SMB) | scanner, after the web sweep | `nuclei.network_templates: true` (default) | `nuclei.json` `coverage.network` + findings with `"pass": "network"` |
| CVSS4 enrich | scanner/API | `enrichment.cvss4.enabled` | scores on `vulnerabilities.json` |

`retro_match` is primary by design, not by size: the shipped
`scanner/data/nvd-cpe/nvd-cpe-ranges.json` is a seed of 8 products and 23 CVEs, and the real
dataset is opt-in (`scripts/fetch-nvd-cpe.py --full`,
[Retro CVE matching](retro-cve-matching.md#the-dataset--apiservicescpe_rangespy)). On the
reference corpus the seed yields 5 range hits on 3 endpoints where Nmap's `vulners` named 428
(host, port, CVE) triples and `pulse --cve` 3. Where each Nmap `vuln` script goes, and the
Nuclei network pass: [NSE vuln coverage](nse-vuln-coverage.md).

nmap-**vulners** / **vulscan** are gone with the NSE stage; their rows in old
runs are still shown as `nmap-nse`.

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

## L2 discovery

`discovery.l2.enabled: true` (off by default) finds silent hosts on a directly
attached IPv4 segment and records their MAC and link-local names. It runs
Pulse, not Nmap (#542); the artifact is `l2_discovery.json` with
`engine: "pulse"`, and `discover/l2-pulse.json` keeps the raw output.

One run does it all:
`pulse --targets-file <selected networks> -D --discover-method arp --rate R --max-hosts <max_hosts> -f json -q --all --protocol udp -p 137,5353 -b`.

- **What goes on the wire.** "ARP" is the kernel's neighbour resolution: Pulse
  sends a 1-byte UDP datagram to port 9 of every candidate address and the
  kernel ARPs for it (three requests per dead address). Live hosts then get UDP
  probes on 137 (NetBIOS wildcard NBSTAT query, `netbios: true`) and 5353
  (mDNS service query, `mdns: true`); a port in `ports.exclude_ports` is
  dropped. With neither name probe left, the pass touches only port 9. Port 9
  itself in `exclude_ports` switches the stage off
  (`arp.trigger_port_excluded:9`): the trigger cannot be moved.
- **iproute2.** Pulse's ARP method reads the neighbours through
  `ip -4 neigh`. Without `ip` on its `PATH` it reports 0 live hosts, prints
  nothing and exits 0, indistinguishable from an empty segment. The scanner
  images install `iproute2` for this; on a host install, put it on `PATH`. The
  adapter checks for `ip` first and otherwise skips the stage with
  `pulse.arp_needs_iproute2`.
- **Targets.** CIDR networks are accepted in the targets file, and `--max-hosts`
  counts a /24 as 254, like `max_hosts` here.
- **Rate.** `--rate` paces candidate addresses, not packets, so a candidate
  costs `mcast_solicit + 1` packets (the sysctl of the configured interface; without one the largest value over
  `/proc/sys/net/ipv4/neigh/*` except `lo`; 3 if unreadable). The adapter passes
  `--rate ⌊max_rate / divisor⌋` and records it as `pulse_rate` with
  `rate_divisor` in the artifact, where `divisor = mcast_solicit + 2`: the
  trigger datagram, the ARP retries, and one more for what the measurements
  show on top of that, with or without name probes. Measured on a Docker
  bridge with `mcast_solicit` 3, on 4 and on 55 live hosts of 253 candidates
  (peak tx packets per second): without name probes `--rate 25` gave 86 and
  103 against a ceiling of 100, `--rate 20` gave 79, 68 and 71; with name
  probes `--rate 25` gave 101 and 86, `--rate 20` gave 74, 69, 70 and 83. Runs
  differ a lot from each other, so this is an estimate for other
  `mcast_solicit` values and longer replies, not a proof. When the quotient is
  0 the rate cannot be approached (`--rate 0` would mean unlimited) and the
  stage is skipped with `rate_cap_unenforceable:<max_rate>`.
- **Time budget.** Before the run the adapter estimates
  `candidates / pulse_rate + mcast_solicit` seconds (the last dead candidate
  still waits out its ARP retries). Over `timeout_seconds` the stage is skipped
  with `timeout_unreachable:<estimate>s` rather than killed half-way with no
  result.
- **Interface.** Pulse cannot be told which interface to use; the routing
  table decides. With `discovery.l2.interface` set, the adapter reads
  `/proc/net/route` and scans only the parts of the networks the kernel really
  sends out of that interface without a gateway. The kernel takes the longest
  prefix and, at an equal prefix, the lowest metric, so a network (or part of
  one) is dropped when a more specific route of any interface covers it, or an
  equal route has a metric that is not strictly worse than this interface's.
  The dropped parts go to `skipped_networks` as `not_on_interface:<iface>`. An unreadable route table skips the stage
  (`interface.unverifiable`). Without `interface` no route check is made, as
  before.
- **MAC.** Not in a `pulse.scan.v2` report. After the run the adapter reads the kernel
  neighbour table (`/proc/net/arp`), complete entries only, of the configured
  interface when one is set, for alive in-scope hosts. A host whose entry
  vanished has `mac: null`. `vendor` is always `null`: there is no OUI
  database (Nmap's came from `nmap-mac-prefixes`).
- **Names.** NetBIOS: the unique names of the NBSTAT table in the banner;
  group names (workgroup) are dropped by their group bit, and the table is
  cut at about 150 characters. The statistics block after the table starts
  with the adapter's MAC and would read as a name, so only names of letters,
  digits, `-` and `_` (up to 15) are kept: a NetBIOS name with a space, a `.`
  or a `$` is dropped, and that is the price of the filter. `__MSBROWSE__`
  falls out the same way (it carries non-printable bytes, shown as dots). A logged-in user name (suffix `0x03`) is
  indistinguishable from the machine name in that text and may appear. mDNS:
  only `*.local` host names, never service types. Pulse asks
  `_services._dns-sd._udp.local` and usually gets `_ssh._tcp`-style service
  types back, so mDNS names are rare (Nmap's `dns-service-discovery` gave none
  either). Evidence rows carry `script_id` `pulse:netbios-ns` / `pulse:mdns`.
- **Failure.** No live host is empty output with exit code 0 and is not an
  error. A non-zero exit code is `arp.failed:<code>`, a timeout or start error
  `arp.failed:<ExceptionName>`, unparsable output `arp.failed:invalid_json`; a
  missing binary is `pulse.unavailable` with a warning pointing here, a missing `ip`
  `pulse.arp_needs_iproute2`. The scan
  continues in every case.

Pulse is missing MAC and names in structured output, a packet-rate cap in
discovery, a discovery-only mode and an interface choice
([GenDec#35](https://github.com/onixus/GenDec/issues/35)); the workarounds above
go away when it lands.

**`pulse.scan.v3` reports** (GenDec#33/#35, APEX event
`apex.pulse.scan_report.v3`) are already read when a newer binary prints
them: every in-scope `hosts[]` entry is an alive host (except `method: local`,
the sensor's own address, which the ARP sweep never reported either); its
`mac` wins over the kernel read; names from `hostnames[]` (`netbios`, `mdns`,
`llmnr`) and `netbios.name` pass the same shape checks as the banner names and
add evidence rows (`pulse:netbios-ns`, `pulse:mdns`, `pulse:llmnr`). The
banner rows are still parsed, so a v2 report gives exactly the result it gave
before. The command line has not changed yet: `--discover-only`,
`--discover-names`, `--discover-rate` and `-e` replace the workarounds only
once the pinned Pulse release has them. **Not yet seen from a real binary:**
the pinned release prints `pulse.scan.v2`, so the `hosts[]` handling is
verified on synthetic reports only. `hosts[]` is untrusted input: a MAC must be
a unicast station address (not zero, broadcast or multicast, as for
`/proc/net/arp`), an mDNS name must be `*.local` without `_` labels, an LLMNR
name a single label, and at most 8192 entries, 16 `hostnames[]` per host and
8 names per source are read. Measurements: [ADR 0002](adr/0002-replacing-nmap-functions.md).

### Neighbour table limits

The kernel keeps neighbour (ARP) entries in a table bounded by
`net.ipv4.neigh.default.gc_thresh1/2/3` (defaults 128/512/1024; IPv6 has the
same keys under `net.ipv6.neigh.default`). Above `gc_thresh3` the kernel evicts
entries. A segment with more on-link candidates than that (a /20 has 4094)
loses live hosts silently: Pulse reads the neighbours through `ip -4 neigh`
after resolution, and an evicted host is simply not there.

- **Symptom.** `neighbour table overflow` in `dmesg`, fewer live hosts than
  expected on large segments, and the Pulse warning
  `ARP candidates exceed ... gc_thresh3`, which appears in `discovery.warnings`
  only once [GenDec#53](https://github.com/onixus/GenDec/issues/53) lands; the
  pinned GenDec v1.1.0 may not emit it, so rely on `dmesg` and `--check`.
- **Check.** `scripts/neigh-table-limits.sh --check --hosts 5000 [--ipv6]`
  prints the current values and exits 1 when the candidates do not fit. The
  verdict uses the numbers `--apply` would set: it fails when the current
  `gc_thresh3` is below the sized target (next power of two at or above twice
  the hosts, at least 4096) or `gc_thresh2` is below half of it, because above
  the soft `gc_thresh2` the garbage collector already evicts entries. Other exit
  codes: 2 usage error or not root, 3 not Linux, 4 `gc_thresh` keys not visible
  (container, or IPv6 disabled with `--ipv6`).
- **Apply.** `sudo scripts/neigh-table-limits.sh --apply --hosts 5000 --persist`
  sets `gc_thresh3` to the next power of two at or above twice the hosts
  (at least 4096), `gc_thresh2` to half of it, `gc_thresh1` to an eighth, and
  writes `/etc/sysctl.d/90-shapoclyack-neigh.conf` (idempotent). `--thresh3 N`
  sets the value explicitly (1024 to 1048576; `--force` lowers the minimum to 8);
  existing higher values are kept unless `--force`. All keys, IPv6 included,
  are verified before the first write, so a missing IPv6 key leaves everything
  untouched. Without `--persist` the values are lost on reboot (the script
  warns).
- **Containers.** The neighbour table is shared by every network namespace on
  a host, and the kernel exposes `gc_thresh1/2/3` only in the initial
  namespace: `docker run --sysctl net.ipv4.neigh.default.gc_thresh3=...` fails
  (no such file) and pod `securityContext.sysctls` cannot set them, allowlist
  or not. Set them on the host, i.e. the scanner nodes for `overlays/prod`
  (`hostNetwork: true`), for instance with a node bootstrap or a privileged
  DaemonSet that writes the sysctl.d file. Neighbour entries of all containers
  on the node count towards the same limit.

Follow-up (pre-flight check, sizing policy, chunking):
[Shapoclyack#612](https://github.com/onixus/Shapoclyack/issues/612).

## Nmap

Nmap is not bundled in the images (NPSL, [#97](https://github.com/onixus/Shapoclyack/issues/97))
and, since #548, not used: see [Migrating off Nmap](nmap-migration.md) for the
refused settings, the old data that is still read, and the known gaps. The
system page no longer probes for it.

K8s caps (`NET_RAW` / `NET_ADMIN` + `allowPrivilegeEscalation: true`) remain
required for **naabu** and Pulse SYN/OS — see `k8s/README.md`.

## Reference corpus: Nmap versus Pulse (#541)

This immutable v1.3.0 corpus remains the historical baseline. Its recorded
plugin map and counts do not describe current 1.4.0 capabilities.
Candidate unit/native fixtures add separate evidence; the historical recordings
are not silently rewritten or counted as final deployed acceptance.

The former `pulse_shadow` module compared endpoints and OS family on a live run;
its comparison now lives in `scripts/pulse_corpus.py`. The golden corpus
is that comparison frozen: Nmap and Pulse run once against a fixed stand,
the outputs are committed, and the gap is measured offline in CI. It exists
because Nmap is going away ([ADR 0002](adr/0002-replacing-nmap-functions.md)) and
what Pulse is measured against has to be recorded while Nmap still runs.

| Part | Where |
|---|---|
| Stand (docker compose, pinned images) | `tests/fixtures/nmap_pulse_corpus/stand/` |
| Recorder | `tests/fixtures/nmap_pulse_corpus/record.sh` |
| Nmap XML | `tests/fixtures/nmap_pulse_corpus/nmap/{tcp,udp}.xml` |
| Pulse JSON (banners, TLS rows and findings included) | `tests/fixtures/nmap_pulse_corpus/pulse/{tcp,udp}.json` |
| Pulse with Shapoclyack's plugins (`--script-dir`, #544): findings, stderr, plugin sha256 | `tests/fixtures/nmap_pulse_corpus/pulse/tcp-plugins.{json,stderr}`, `plugins.sha256` |
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
plus a second run with `--script-dir` pointing at the Shapoclyack plugins, in the
empty `HOME` (the adapter's run after #544). The earlier run with bare `--scripts`
is gone: it loaded nothing (no `./scripts` in its working directory), so its "added
nothing" measured an empty plugin set. Both got the same targets and ports
(21, 22, 80, 139, 443, 445, 3306, 3389, 5432, 6379, and UDP 161). The scanner
image has the distribution `nmap` installed, but Pulse is given `--services-db`
(IANA table) and `--probe-db` explicitly, as the adapter does (#543, #546), so
nothing NPSL-derived reaches the Pulse column. (The first recording, from before
#543, let Pulse read `/usr/share/nmap/nmap-services`; the service names did not
change when re-recorded with the IANA table, 18 of 19 still agree.)

**Gap** (Nmap 7.93 and Pulse 1.3.0 re-recorded on 2026-10-10 with the adapter's
pinned `--services-db` and `--probe-db`; the same numbers are pinned in the test.
The first recording, before `probes.json` (#546), differed in one row: Product
was 14 agree / 3 missing / 1 differs):

| Dimension | Nmap | Pulse 1.3.0 | Gap |
|---|---|---|---|
| Open endpoints (TCP + UDP) | 19 | 19 | none (19 of 19 shared) |
| Service name | 19 | 18 agree | 1: port 445, Nmap `netbios-ssn`, Pulse `smb` |
| Product (of 18 Nmap names) | 18 | 14 agree | 2 missing (Samba x2), 2 differ (SNMP; PostgreSQL: Pulse `PostgreSQL database`, Nmap `PostgreSQL DB`) |
| Version | 17 given | 11 exact, 3 upstream-only | 3 missing; the 3 upstream-only lack the distribution revision (`8.2p1 Ubuntu 4ubuntu0.13` against `8.2p1`) |
| CPE | 17 endpoints | 0 | Pulse's `open[]` rows carry a `cpe` field, but it is `[]` on every row (70 of 70 in the fixture); nothing fills it |
| OS family (14 hosts) | 14 | 14 agree (Linux) | family only; Nmap `Linux 4.15 - 5.6`, Pulse `Linux (modern, TS+SACK+WS)`, real kernel 6.12 |
| TLS endpoints | 4 | 3 | MySQL (3306, in-protocol TLS) missing |
| TLS protocol sets (3 shared) | enumerated | 2 equal | nginx 1.27: Nmap `TLSv1.2, TLSv1.3`, Pulse only the negotiated `TLSv1.3` |
| TLS cipher suites enumerated | 122 | 0 | `tls[]` holds the negotiated protocol and the weak protocols accepted, not suites or grades |
| Weak-protocol verdict (3 shared) | 1 endpoint | 1 endpoint, 3 of 3 agree | none on this stand; the unfavourable cases (SSLv3, weak suites on TLS 1.2) are not in it |
| Script outputs | 157 on ports, 40 distinct scripts | 13 findings (6 exposure, 4 tls, 3 version_cve) | plugins add 6 more in the `--script-dir` run (below) |
| CVE ids named | 428 (`vulners`) | 3 | the 3 are all among Nmap's; 425 are Nmap-only. Not a quality score: `vulners` names every CVE ever filed against a version |

**Plugins against NSE** (#544; `plugins` section of the report, run
`pulse/tcp-plugins.json`). Per NSE script that printed on the stand: how many
endpoints, which plugin answers it, and, where both give a verdict, whether they
agree per endpoint.

| NSE script | Endpoints | Plugin | Result |
|---|---|---|---|
| `ssh2-enum-algos` | 4 | `shapo_ssh_algorithms` | verdict (a weak algorithm is offered) agrees on 4 of 4: none offers one. Weakness only, not the lists |
| `ftp-anon` | 1 | `shapo_ftp_anonymous` | agrees 1 of 1: login accepted. No directory listing (needs a data connection) |
| `ssh-hostkey` | 4 | none | key exchange needed (binary packets) |
| `smb2-security-mode`, `smb-protocols` | 1 host | none (`shapo_smb_exposure` reports exposure only) | SMB negotiate starts with 0xFE/0xFF; the sandbox cannot send a byte above 0x7F. `smb2-security-mode` is answered by the Nuclei network pass (`smb-signing-not-required`, [NSE vuln coverage](nse-vuln-coverage.md)) |
| `rdp-enum-encryption` | 1 | none (`shapo_remote_admin_exposure` reports exposure only) | X.224 request carries 0xE0 |
| `ftp-syst` | 1 | none | informational, not a finding |
| `http-trace` | 2 | `shapo_http_trace` (#547) | agrees on 1 of 2: Apache `:80`; the plugin has no TLS, so `:443` is not reported |

Plugin findings on the stand: 6 (SMB 2, RDP 1, anonymous FTP 1, FTP without TLS 1, HTTP TRACE 1);
no plugin errors. `shapo_cleartext_services` has no NSE counterpart in
`default,safe`. Not in the table because the stand has no such server: SNMP (UDP),
Telnet, POP3, IMAP, SMTP; those plugins are exercised against stub servers in
`tests/test_pulse_plugins_files.py`. The four SSH servers are modern, so
"agrees" is agreement on a clean result; the weak-algorithm path is proven on stub
servers, not on this stand.

Reading it:

- Pulse's service/product/version detection is close on what its probe DB
  covers (SSH, HTTP servers, MySQL, Redis, FTP) and absent where it has no rule
  (Samba). PostgreSQL gained a product through `probes.json` (#546) but still
  no version: the server does not state it before authentication.
- The distribution revision and the CPE are the two fields that disappear when
  Nmap does (`retro_match` and `asset_services` prefer them): #546, with the
  Pulse change in #543.
- Nmap is the reference, not the truth. It reports Samba `4.6.2` (Debian 12
  ships 4.17), PostgreSQL `9.6.0 or later` for 16, and a kernel range that does
  not contain 6.12. Agreement with it is scored; being right is not. The IIS
  and RDP rows measure the stubs only.
- Cipher-suite enumeration is the largest single gap and the one with no
  workaround short of #545.

**NSE `vuln` scripts against their destinations** (#547; `nse_vuln` section of the report,
[NSE vuln coverage](nse-vuln-coverage.md)): 16 `vuln`-category scripts are mapped, 15 of them
printed 46 outputs on the stand (Nmap itself marked 16 VULNERABLE). By destination: 9 refused with
a reason (DoS, DAST, exploit probes, a header-only test that flagged nginx), 2 gaps behind GenDec#38
(`smb-vuln-ms10-061`, `smb-vuln-ms17-010`), 2 version matching (`vulners`, `samba-vuln-cve-2012-1182`),
1 Nuclei template in the default sweep (`http-majordomo2-dir-traversal` is `CVE-2011-0049`), 1 Rhai
plugin (`http-trace`), 1 TLS (#545, `ssl-ccs-injection`).

Re-recording only the Pulse side (after a plugin change; the Nmap fixtures stay as
they are): `RECORD_PARTS=pulse PULSE_BIN=<linux pulse> tests/fixtures/nmap_pulse_corpus/record.sh`.
`pulse/tcp.json` and `udp.json` were not re-recorded for #544, so the starting gap
above stays a baseline; `tcp-plugins.json` is a separate run, and
`tests/test_nmap_pulse_corpus.py` fails when its recorded plugin sha256 and the
shipped files differ.

Re-recording everything: `PULSE_BIN=<linux pulse> tests/fixtures/nmap_pulse_corpus/record.sh`
(`stand/scan.sh` passes Pulse the same `--services-db` and `--probe-db` as the
adapter, bind-mounted from `scanner/pipeline/pulse_data/`, so a probe-database
change shows up in the next recording)
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
`vulners` output). It is stored as recorded so that `legacy_nmap.parse_nmap_xml` reads it
exactly as it reads an old run directory.

## Limitations (current)

- Does not run NSE scripts (there are none to run since #548).
  The plugins ([Pulse plugins](pulse-plugins.md)) cover weak SSH algorithms,
  anonymous FTP, cleartext services and HTTP TRACE; SMB signing is answered by a Nuclei
  network template ([NSE vuln coverage](nse-vuln-coverage.md)); RDP NTLM information, SSH host
  keys and SNMP are not reachable from Pulse's sandbox.
- TLS probe fallback ≠ a full cipher-suite grade table (no A–F on the Pulse path
  until GenDec#34).
- UDP enrichment still relies on naabu paths.
- Banner ≠ full nmap `-sV` product/version.
- Not covered, and tracked ([Migrating off Nmap](nmap-migration.md#known-gaps)):
  `smb-vuln-ms17-010`, `smb-vuln-ms10-061`, `smb-protocols` and
  `rdp-enum-encryption` (GenDec#38); the pinned-inputs work (#543) waits for
  GenDec#31 / GenDec#32 (service names still come from the port table, not from
  the matched probe).
