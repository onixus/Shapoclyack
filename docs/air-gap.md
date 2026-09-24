# Air-gapped installation

How to run Shapoclyack on a network with no route to the internet
([#339](https://github.com/onixus/Shapoclyack/issues/339)), and on the far
more common network whose only way out is an internal mirror or an
inspecting proxy. It covers the images, the pull secret, every enrichment feed,
the offline bundle that carries the feeds across the gap, and — at the end —
what does not work offline and cannot be made to.

Two sides throughout:

- **The connected side** — a host (a build agent, a jump box) that can reach
  the public registries and feeds. It mirrors images and builds bundles. Nothing
  here needs to run there permanently.
- **The installation** — the cluster (or host) with no egress, or egress only
  to internal mirrors.

## Contents

1. [Mirror the images](#1-mirror-the-images)
2. [Feeds: a mirror, or a bundle](#2-feeds-a-mirror-or-a-bundle)
3. [Pointing every feed at a mirror](#3-pointing-every-feed-at-a-mirror)
4. [The offline bundle](#4-the-offline-bundle) — build, transfer, load, verify
5. [nuclei templates and vulscan](#5-nuclei-templates-and-vulscan)
6. [Update cadence](#6-update-cadence)
7. [What stays unavailable offline](#7-what-stays-unavailable-offline)

## 1. Mirror the images

Every image the manifests run, by the digest the release pinned. List them from
the overlay you will apply, so nothing is missed:

```bash
kubectl kustomize k8s/shapoclyack/overlays/airgap | grep -E '^\s+image:' | sort -u
```

For a release that is the all-in-one image (pinned by digest in every
manifest) and the upstream datastore images `postgres`, `nats`,
`clickhouse/clickhouse-server` and `amazon/aws-cli` (backup upload), which the
base pins by tag. Copy each with its digest intact — `skopeo` shown, `crane
copy` or `oras copy` are equivalent:

```bash
REG=registry.internal.example
TAG=shapoclyack-0.46-0922
skopeo copy --all --preserve-digests \
  docker://ghcr.io/onixus/shapoclyack-aio:$TAG@sha256:<digest from the manifests> \
  docker://$REG/shapoclyack/shapoclyack-aio:$TAG
skopeo inspect --format '{{.Digest}}' docker://$REG/shapoclyack/shapoclyack-aio:$TAG   # must match
skopeo copy --all --preserve-digests docker://postgres:16-alpine docker://$REG/library/postgres:16-alpine
skopeo inspect --format '{{.Digest}}' docker://$REG/library/postgres:16-alpine   # pin this
```

Then rewrite the image names in an overlay. `k8s/shapoclyack/overlays/airgap/`
is that overlay with `registry.internal.example` as a placeholder: kustomize's
`images:` transformer replaces the registry and keeps the aio image's digest,
and for the datastore images add a `digest:` line with the value `skopeo
inspect` printed, so they are pinned too.

### The pull secret

The ServiceAccounts in `k8s/shapoclyack/base/serviceaccount.yaml` (`scanner`,
`api`) and the bundle loader's (`enrichment-bundle`) carry
`imagePullSecrets: [shapoclyack-registry]`, so no workload manifest names a
secret. The name is a placeholder: nothing creates it, and a cluster that
pulls from public registries does not need it (the kubelet records a
`FailedToRetrieveImagePullSecret` event and pulls anonymously). For a private
registry, create it:

```bash
kubectl -n network-scan create secret docker-registry shapoclyack-registry \
  --docker-server=registry.internal.example \
  --docker-username=<robot-account> --docker-password=<token>
```

The datastores, the backup CronJob and the online enrichment CronJob run as
the namespace's `default` ServiceAccount, which belongs to the namespace, not to
these manifests — declaring it would make `kubectl delete -k` delete it and, on
platforms that inject their own pull secrets into it, replace theirs.
`overlays/airgap` therefore puts the secret on those pods' own specs, with two
patches that cover every workload kind, so the overlay needs no manual step and
a test renders it and checks that every pod can pull. To use an existing secret
under another name, change the name in those two patches and uncomment the
ServiceAccount patch below them.

An overlay without those patches (the sensors in `base/agents`, for example)
gets the same result from one command:

```bash
kubectl -n network-scan patch serviceaccount default \
  -p '{"imagePullSecrets":[{"name":"shapoclyack-registry"}]}'
```

A workload in another namespace needs the secret created in that namespace
too — a pull secret is namespaced (with the scanner-executor of
[#338](https://github.com/onixus/Shapoclyack/issues/338), that is
`network-scan-executor`; the overlay's patches already put the secret on its
pod). A cluster whose nodes already authenticate
to the registry (a kubelet credential provider, or containerd's own registry
config) needs none of this.

## 2. Feeds: a mirror, or a bundle

Every dataset the risk model and the matchers read comes from a public feed by
default. There are two ways to get them inside, and they combine:

| | Internal mirror (§3) | Offline bundle (§4) |
|---|---|---|
| The installation reaches | an internal HTTP(S) server, a mounted directory, a git server | nothing |
| Who fetches | the in-cluster refresh CronJob, as online | the connected side, `make enrichment-bundle` |
| Configure | one `*_URL` variable per feed | `overlays/airgap` |
| Moves across the gap | whatever your mirroring tool syncs | one tarball with a checksummed manifest |

A mirror suits a network with a sanctioned artifact repository (Nexus,
Artifactory, a plain web server fed by a sync job). A bundle suits a network
with no repository at all, or one where every inbound file goes through the
same review — it is one file, deterministic, and it says what is in it.

## 3. Pointing every feed at a mirror

Every fetcher reads one variable naming where its feed is instead of the public
URL. `https`, `http` and `file` URLs are accepted (a directory mounted into the
pod is a mirror too); anything else is refused by name. The same variable is
read by the script and by the in-process fetcher that shares the feed.

| Feed | Variable | Default upstream | What the mirror serves |
|---|---|---|---|
| EPSS | `EPSS_URL` | `https://epss.cyentia.com/epss_scores-current.csv.gz` | The same `.csv.gz` |
| CISA KEV | `KEV_URL` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | The same JSON |
| GeoIP City | `GEOIP_URL` | DB-IP City Lite (monthly file name) or MaxMind GeoLite2-City (with `MAXMIND_LICENSE_KEY`) | The `.mmdb`, a DB-IP `.mmdb.gz` or a MaxMind `.tar.gz` — any of the three. No licence key is sent to a mirror |
| ASN | `ASN_URL` | DB-IP ASN Lite or MaxMind GeoLite2-ASN | As for GeoIP |
| NVD CVE API 2.0 (CVSS v4 overlay *and* the CPE ranges behind retro matching) | `NVD_API_URL` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | An endpoint that answers the CVE API's query parameters — a caching proxy of NVD, not a static file |
| Debian security tracker | `DEBIAN_TRACKER_URL` | `https://security-tracker.debian.org/tracker/data/json` | The same JSON |
| Ubuntu USN | `UBUNTU_USN_URL` | `https://usn.ubuntu.com/usn-db/database.json` | The same JSON |
| Microsoft Update Guide (CVRF) | `MSRC_CVRF_BASE_URL` | `https://api.msrc.microsoft.com/cvrf/v3.0` | `<base>/updates` and `<base>/cvrf/<month>`, the API's own paths |
| Exploit-DB index | `EXPLOITDB_CSV_URL` | `https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv` | The same CSV |
| Metasploit module metadata | `METASPLOIT_MODULES_URL` | `https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json` | The same JSON |
| vulscan CSVs (nmap `vuln-offline`) | `VULSCAN_BASE_URLS` | GitHub, then computec.ch | `<base>/<db>.csv`; a space-separated list, tried in order |
| nuclei templates | `NUCLEI_TEMPLATES_REPO`, `NUCLEI_TEMPLATES_REF`, `NUCLEI_TEMPLATES_COMMIT` | nuclei's own `-update-templates` | A git mirror of `projectdiscovery/nuclei-templates` — see §5 |

Notes that matter:

- **The MSRC index names every month by an absolute Microsoft URL.** With
  `MSRC_CVRF_BASE_URL` set, a month under `api.msrc.microsoft.com/cvrf/v3.0` is
  read from the same path under the mirror, and a month listed on any other
  host is skipped rather than fetched — a mirror of the index alone must not
  quietly send twelve requests to Microsoft.
- **Proxy and trust store.** The scripts download through
  `scripts/feed_fetch.py` and the in-process fetchers (Debian, Ubuntu, MSRC,
  NVD CPE) through `api/services/advisories/fetch.py`; both use the API's
  egress module: `OCTO_HTTPS_PROXY` / `OCTO_HTTP_PROXY` / `OCTO_NO_PROXY`, and
  `OCTO_CA_BUNDLE` **added to** the system trust store
  ([network requirements](network-requirements.md#proxy-and-ca-variables)).
  The nuclei-templates git fetch gets the same three proxy variables and the
  same trust store. TLS verification is never turned off, and both paths
  refuse a redirect from `https` to anything weaker.
- **A deadline is a deadline.** Each download has a wall-clock limit that also
  holds while a read is waiting: a mirror that trickles one byte at a time is
  cut off when the time is up, not when it finishes.
- **`NVD_API_KEY` goes to `https` only.** Pointed at a plain-`http` mirror, the
  NVD fetchers withhold the key (with a warning) and run anonymously.
- **Plain `http` works and is noted.** An internal mirror on `http://` prints a
  warning on every fetch: nothing vouches for those bytes in transit. Prefer
  `https` with the mirror's CA in `OCTO_CA_BUNDLE`.
- **No credentials in logs or data.** Where a URL is printed, and where it is
  recorded as a dataset's `origin_url`, userinfo is dropped and credential-like
  query parameters (`license_key`, `apiKey`, `token`, `cred…`, `pass…`, `pwd`,
  `session…`, `…signature`) read `REDACTED`.
- **Opt-ins are unchanged.** The vendor advisories and NVD CPE ranges are still
  fetched only with `OCTO_ADVISORY_FETCH_ENABLED` / `OCTO_NVD_CPE_FETCH_ENABLED`
  ([configuration](configuration.md#vendor-advisory-datasets)); the variables
  above only say *where*.

In Kubernetes, set the variables on the `enrichment-refresh` CronJob (and on
the API's `fetch-enrichment` initContainer, which runs the same script at
start) with a patch in your overlay, next to `MAXMIND_LICENSE_KEY` and
`NVD_API_KEY`.

## 4. The offline bundle

One tarball holding every enrichment dataset, built on the connected side and
installed inside by a job that trusts none of it until it has checked all of
it.

### Build (connected side)

```bash
# What to include follows the refresh's own switches.
export OCTO_ADVISORY_FETCH_ENABLED=true     # Debian / Ubuntu / MSRC advisories
export OCTO_NVD_CPE_FETCH_ENABLED=true      # retro CVE matching
export NVD_API_KEY=...                      # optional: 50 instead of 5 requests / 30 s
export MAXMIND_LICENSE_KEY=...              # optional: MaxMind instead of DB-IP

make enrichment-bundle                      # → dist/enrichment-bundle.tar.gz
```

`make enrichment-bundle` runs `scripts/build-enrichment-bundle.sh`: the usual
refresh (`scripts/fetch-enrichment.sh`) into `build/enrichment/`, the
exploit-maturity overlay on top, then `scripts/enrichment_bundle.py build`.
`ENRICHMENT_BUILD_DIR` and `ENRICHMENT_BUNDLE` move the two paths.

Keep `build/enrichment/` between runs. The CVSS v4 and NVD CPE refreshes are
incremental and continue from what is there; the NVD CPE dataset needs one full
harvest into it first:

```bash
OCTO_NVD_CPE_FETCH_ENABLED=true python3 scripts/fetch-nvd-cpe.py --full \
  -o build/enrichment/nvd-cpe/nvd-cpe-ranges.json
```

The build's exit code is the refresh's: `0` everything refreshed; `1` a source
was unreachable — the bundle is written and records that dataset as `stale`
(make still succeeds unless `ENRICHMENT_STRICT=1`); `2` a required dataset
(`cvss4`, `epss`, `kev`, `exploit`) has no usable data, and no bundle is
written.

### What is in it

`bundle-manifest.json` first, then every dataset file at its path under the
enrichment directory:

```json
{
  "schema": "shapoclyack.enrichment-bundle",
  "schema_version": 1,
  "built_at": "2026-09-22T03:00:00+00:00",
  "files": [
    {
      "path": "kev/kev-overlay.json",
      "dataset": "kev",
      "sha256": "…",
      "size": 29558,
      "source": "cisa-kev",
      "source_urls": ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"],
      "updated": "2026-09-20",
      "fetched_at": "2026-09-22T02:58:11+00:00",
      "origin": "fetch",
      "entries": 1676,
      "usable": true
    }
  ]
}
```

`updated` is the date the feed itself stamped on the data (for a `.mmdb`, the
database's build date); `fetched_at` is when the file was written; `origin` and
`usable` are the connected side's own verdict (see
[provenance](configuration.md#provenance-what-the-image-actually-shipped)).

The archive is **deterministic**: the same directory produces the same bytes —
members sorted, owner and mode fixed, timestamps from the data (or
`SOURCE_DATE_EPOCH`), a gzip header with no name or time. Two people packing
one refresh get one checksum.

### Transfer

Whatever your process for bringing a file inside. Record the checksum on the
connected side and compare it on arrival; then check the bundle itself, which
reads and hashes every member without installing anything:

```bash
sha256sum dist/enrichment-bundle.tar.gz          # connected side, and again inside
python3 scripts/enrichment_bundle.py verify dist/enrichment-bundle.tar.gz
```

### Load: Kubernetes

`overlays/airgap` = base + `base/enrichment` + `base/enrichment-bundle`. The
last one adds:

- **`enrichment-bundle-inbox`**, an RWO volume the bundle is copied into;
- **`enrichment-bundle-load`**, a CronJob (every 15 minutes) running
  `scripts/enrichment_bundle.py install /inbox/enrichment-bundle.tar.gz --dir
  /app/scanner/data --missing-ok`. A run with no bundle changes nothing, and a
  run whose bundle is already installed reads only the bundle's first member —
  its manifest — and stops: nothing is unpacked or written. Hardened like
  every workload: non-root,
  `RuntimeDefault` seccomp, read-only root filesystem, all capabilities dropped,
  no ServiceAccount token, the inbox mounted read-only;
- **`enrichment-refresh` suspended** and the API's `fetch-enrichment`
  initContainer set to `OCTO_ENRICHMENT_OFFLINE=true` — both would otherwise
  try every feed, wait out a timeout each, and then record every
  bundle-installed dataset as `stale`.

Copying the file in, with the helper pod from
`k8s/shapoclyack/examples/enrichment-bundle-inbox.example.yaml`:

```bash
kubectl apply -f k8s/shapoclyack/examples/enrichment-bundle-inbox.example.yaml
kubectl -n network-scan wait --for=condition=Ready pod/enrichment-bundle-inbox
kubectl -n network-scan cp enrichment-bundle.tar.gz \
  enrichment-bundle-inbox:/inbox/enrichment-bundle.tar.gz.part
kubectl -n network-scan exec enrichment-bundle-inbox -- \
  mv /inbox/enrichment-bundle.tar.gz.part /inbox/enrichment-bundle.tar.gz
kubectl -n network-scan delete pod enrichment-bundle-inbox
kubectl -n network-scan create job --from=cronjob/enrichment-bundle-load load-now
kubectl -n network-scan logs -f job/load-now
```

(Or write the file into the inbox volume from the storage side, if your storage
allows it — the loader only cares that it is there.)

**Why a Job reading a volume, and not an upload endpoint on the API.** The API
keeps its read-only mount of the enrichment data and grows no
multi-hundred-megabyte upload surface, with the authentication, step-up and
streaming that would need; the loader holds no Kubernetes token and needs no
network; the same command works on a host with no Kubernetes at all; and who
put which file into the inbox is in the cluster's own audit log, next to who
created the Job that loaded it.

### Trust: who decides what is installed

Without a pin, **write access to the inbox volume is the trust boundary**:
whoever can put a file there chooses the data, within everything the installer
checks below — which is about the file being well formed and no worse than
what it replaces, not about who made it. That is the right boundary only if
the inbox is as tightly held as the enrichment volume itself.

A pin moves the decision to a second, audited channel. Record the bundle's
sha256 on the connected side when it is built (`make enrichment-bundle` prints
it), carry it over *separately* from the file — a change ticket, the build log —
and hand it to the loader as a ConfigMap, which the loader CronJob reads as
`OCTO_ENRICHMENT_BUNDLE_SHA256`:

```bash
kubectl -n network-scan create configmap shapoclyack-enrichment-bundle \
  --from-literal=sha256=<the sha256 recorded on the connected side> \
  --dry-run=client -o yaml | kubectl apply -f -
```

With it set, only the bundle file with exactly that checksum is installed; any
other file in the inbox is refused (`the bundle's sha256 is …, not the pinned
…`). The checksum is computed over the very bytes the installer parses, not a
second read of the path. Computing the pin from the file after it has crossed
the gap would defeat the point. On a single host the same pin is
`--expect-sha256` (or the same variable).

A pin is one bundle at a time — the ConfigMap changes with each one — and it
proves the file is the one that was built, not that the build machine was
sound. Signing bundles would need key management on both sides of the gap;
this release does not do it.

### Load: a single host

The same command, pointed at the enrichment directory the API and scanner read
(`scanner/data` in a source checkout; `OCTO_ENRICHMENT_DIR` wherever you moved
it):

```bash
python3 scripts/enrichment_bundle.py install enrichment-bundle.tar.gz --dir scanner/data
OCTO_ENRICHMENT_OFFLINE=true scripts/fetch-enrichment.sh   # if something runs the refresh
```

### What the installer refuses

Whatever the trust setting, the archive itself is parsed as untrusted input,
so the extractor is not `tarfile.extractall`:

- a bundle path that is not a regular file (a FIFO, a device) — decided on the
  opened descriptor, not by a separate check first;
- anything but a plain regular-file member — symlinks, hard links, devices,
  FIFOs, directories, sparse files, pax and GNU long-name headers — and a
  member whose size field is negative;
- a path that is absolute, contains `..` or an empty component, or is not one of
  the enrichment dataset paths — whatever the manifest says;
- a manifest that is not the first member, lists a path twice, is of a newer
  `schema_version` than this release reads, says it was built more than a day
  in the future of this host's clock (installed, it would make every genuine
  bundle "older than the installed one"), or declares more than 4 GiB
  (`--max-bytes`) or a compression ratio over 100 (`--max-ratio`);
- a member the manifest does not list, a member listed but missing, a size or
  sha256 that disagrees with the manifest, a truncated archive, a bad gzip CRC,
  data after the end-of-archive marker, and any stream that decompresses past
  what the manifest declared;
- a JSON dataset that does not parse (including one that is not UTF-8 or is
  nested past the parser's limit) or has no `entries`, a `.mmdb` the MaxMind
  reader cannot open, and a dataset below its usability floor that would
  replace one above it — a truncated feed on the connected side must not be
  carried across and published over a corpus;
- a bundle built before the one installed (a replayed old bundle is how last
  month's KEV would come back) — unless `--allow-older`, for a deliberate
  rollback.

A refused bundle changes nothing: every file is staged beside the data first and
only swapped in once all of it has passed. The swap itself is a transaction —
the old files are hard-linked aside, a journal is written, each file is
renamed into place (a reader sees the old file or the new one, never neither),
and any failure puts the old set back. A loader killed mid-swap leaves the
journal, and the next run rolls back before it does anything else.

What that guarantee rests on, precisely: every staged file, the journal and the
two records are fsynced before they are renamed, and each directory a rename
lands in is fsynced after it, so after a power loss the directory holds either
the journal (and the next run rolls back) or the finished commit. It assumes a
filesystem that honours fsync and rename(2) atomicity; for a network filesystem
that is the storage's promise, not this tool's. A journal that cannot be read,
or that names anything but this tool's own backup directory and dataset paths,
is not guessed at: the install stops with exit `2`, and the journal and the
backups it names stay exactly where they are for someone to look at.

Installed files keep **their age**: each is stamped with the time it was
fetched on the connected side (never later than now), so `age_days` and
`stale` in `GET /api/system`, and the risk model's own staleness warning, see
the data's age rather than the moment it was unpacked. And what the connected
side called each dataset crosses the gap too, as `source_origin` beside
`origin: bundle` — a feed that was down when the bundle was built reads
`source_origin: stale` here, and makes the offline refresh report "degraded".

The installer and every manifest rewrite (the API's offline initContainer
among them) take the same lock on the enrichment directory, so a rollout
during an install cannot write the pre-install origins back.

Exit codes: `0` installed, already installed, or (`--missing-ok`) no bundle;
`1` refused — the reason is on stderr and as a JSON line on stdout; `2` the
install could not run (the lock is held past `--lock-timeout`, an unusable
journal, the directory is unusable).

### Verify

```bash
curl -sH "Authorization: Bearer $TOKEN" https://shapoclyack.internal/api/system \
  | jq '{bundle: .enrichment_bundle, data: [.enrichment[] | {name, origin, source_origin, updated, usable, age_days, stale}]}'
```

`enrichment_bundle` is the installed bundle — `bundle_id` (the sha256 of its
manifest), `built_at`, `installed_at`, `datasets` — and `null` on an
installation that has never loaded one. Each dataset the bundle installed
reports `origin: bundle` with the feed's own `updated` date. On the volume,
`python3 scripts/enrichment_bundle.py status --dir /app/scanner/data` prints the
full record, and `enrichment-bundle-history.jsonl` beside it has one line per
install (bundle, built/installed times, host, user).

## 5. nuclei templates and vulscan

Both are tool data baked into the image at build time, not enrichment
datasets, so they are not in the bundle. **In Kubernetes the scanner uses the
copies in the image it runs** — nothing in the manifests mounts templates from
elsewhere — so there they are refreshed by mirroring a newer release image, or
by building one inside the perimeter with the script below pointed at a mirror.
The script is for that image build and for single-host installs.

**nuclei templates** come from a git mirror of
`projectdiscovery/nuclei-templates`:

```bash
NUCLEI_TEMPLATES_REPO=https://git.internal.example/mirrors/nuclei-templates.git \
NUCLEI_TEMPLATES_REF=v10.2.8 \
NUCLEI_TEMPLATES_COMMIT=<the 40-character commit that tag names> \
  scripts/fetch-nuclei-templates.sh /usr/share/nuclei-templates
```

`NUCLEI_TEMPLATES_REF` is required with a mirror — a tag or a full commit id,
never "the default branch today". `NUCLEI_TEMPLATES_COMMIT` pins it: a tag on a
mirror can be moved, a commit cannot, and a mismatch is refused. The checkout
is staged beside the destination and swapped in by rename; when the
destination is itself a mount point (which cannot be renamed) the checkout is
staged inside it and the contents are swapped, with the old ones put back on
any failure — not atomic, so a scan starting mid-swap can see a partial pack.
The resolved commit is written to `.shapoclyack-templates.json`, and nuclei is
never asked to update anything. On a single host, point `nuclei.templates_dir`
(scan config) and `OCTO_NUCLEI_TEMPLATES_DIR` (API) at the directory if it is
not the default. `OCTO_HTTPS_PROXY`, `OCTO_HTTP_PROXY`, `OCTO_NO_PROXY` and
`OCTO_CA_BUNDLE` apply to the git fetch as to everything else.

**At scan time nothing phones home.** The scanner runs nuclei, naabu and dnsx
with `-disable-update-check` on every invocation (a test holds every call site
to it). Measured with the release binaries in a network namespace with no
route, fresh `$HOME`, `strace -e connect`: without the flag, one naabu or dnsx
invocation made 12 DNS connection attempts for its update check, and one nuclei
invocation 105 plus an attempt to install templates into `$HOME`; with it, none.

**vulscan** (only for the legacy nmap `vuln-offline` NSE profile):
`VULSCAN_BASE_URLS=https://mirror.internal.example/vulscan
scripts/fetch-vulscan-db.sh`.

## 6. Update cadence

What the upstreams publish, and so how stale a bundle becomes:

| Feed | Upstream cadence |
|---|---|
| EPSS | daily |
| CISA KEV | whenever CISA adds entries |
| NVD (CVSS v4, CPE ranges) | continuously |
| Debian tracker, Ubuntu USN | continuously / several notices a week |
| Microsoft Update Guide | monthly (Patch Tuesday), plus out-of-band releases |
| GeoIP / ASN | DB-IP Lite monthly; MaxMind GeoLite2 twice a week |
| Exploit-DB, Metasploit | continuously |

A **weekly** bundle keeps KEV and EPSS — the two that move a finding's priority
most — within a week of the world. `GET /api/system` marks a dataset `stale`
once its file is more than 30 days old, which is the outside limit. Build on a
schedule on the connected side (a CI job running `make enrichment-bundle`) so
the transfer is the only manual step.

## 7. What stays unavailable offline

Nothing here fails a scan; each is either off by default or degrades to
"not checked". Leave these off on an air-gapped installation:

| Feature | Reaches | Default |
|---|---|---|
| Passive subdomain discovery (`discovery.ct`) | crt.sh, CertSpotter, AlienVault OTX | off |
| ASN expansion (`discovery.asn`) | stat.ripe.net | off |
| Cloud bucket discovery (`discovery.cloud`) | S3, GCS, Azure Blob | off |
| Cloudflare zone import (`discovery.cloudflare`) | api.cloudflare.com | off |
| Domain ownership (`org_profile.ownership`) | IANA RDAP bootstrap, registry RDAP servers | off |
| Related domains (`org_profile.related_domains`) | crt.sh and the RDAP/DNS sources | off |
| Credential leaks (`org_profile.credential_leaks`) | Have I Been Pwned | off |
| Pulse online CVE lookup (`service_probe.pulse.cve_online`) | NVD | off |
| nmap `vulners` NSE (`nse_profiles.vuln_legacy`) | vulners.com | only with the nmap backend; use `vuln-offline` (vulscan) instead |
| Run notifications to Slack/Telegram, DoH checks (`alerts`) | those services | off |
| OIDC, webhooks, ticket trackers, SMTP | whatever you configure | unset |

The public-internet surface of your *own* assets (the EASM view) is by
definition not visible from inside an air gap: scan targets are whatever the
installation can reach.

What the bundle reaches, precisely. **The API** — risk scoring (CVSS v4,
EPSS, KEV, exploit maturity), software→CVE matching (the vendor advisories),
retro matching (the CPE ranges), GeoIP on the API side and the System page —
reads the enrichment volume the bundle is installed into. **A scan** reads
GeoIP, ASN and the CVSS v4 overlay at scan time from wherever *its* pod finds
them: the scheduled scan CronJob and scans the API runs itself mount the same
volume and use the bundle's copies; the one-off scan Job (`job.yaml`) and remote
sensors use the copies baked into their image. Where scans run in a separate
executor namespace (the Kubernetes hardening of
[#338](https://github.com/onixus/Shapoclyack/issues/338)), no scan pod can mount
the volume — a PVC is namespaced — and every scan uses the image's copies; the
API side is unchanged. Refresh scan-time GeoIP/CVSS4 there by mirroring a newer
image.

## See also

- [Network requirements](network-requirements.md) — ports, proxies, CA bundles
- [Configuration — enrichment sources](configuration.md#enrichment-sources) and
  [provenance](configuration.md#provenance-what-the-image-actually-shipped)
- [Operations — enrichment data in a release build](operations.md#enrichment-data-in-a-release-build)
- [Retro CVE matching](retro-cve-matching.md) and [software → CVE matching](software-cve-matching.md) — the datasets' consumers
