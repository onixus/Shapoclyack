# Pulse service probe backend

Shapoclyack can enrich open ports with **[Pulse](https://github.com/onixus/GenDec)**
instead of (or in addition to) Nmap NSE.

Migration plan (full): see GenDec `docs/shapoclyack-migration.md`.

## When to use which backend

| `service_probe.backend` | Behaviour |
|-------------------------|-----------|
| `nmap` (default) | Classic NSE stage only |
| `pulse` | Pulse OS / banner / CVE only (no NSE scripts, no nmap XML for TLS) |
| `hybrid` | Pulse first, then nmap NSE |

### Shadow mode (Phase 3)

Run **both** Pulse and Nmap and write coverage diff. With `backend: nmap`,
the report still prefers nmap XML; Pulse CVEs can still attach.

```bash
export OCTO_PULSE_SHADOW=1
export OCTO_SERVICE_BACKEND=nmap   # report stays on nmap
# export OCTO_SERVICE_BACKEND=hybrid  # report prefers services.json
```

YAML: `service_probe.shadow: true`

Artifact: **`diff_pulse_nmap.json`** — endpoint Jaccard, only_pulse / only_nmap
samples, OS family agree/disagree.

Override without editing YAML:

```bash
export OCTO_SERVICE_BACKEND=pulse
export OCTO_PULSE_BIN=/usr/local/bin/pulse
```

## Config (`scanner/config/default.yaml`)

```yaml
service_probe:
  backend: nmap   # pulse | hybrid
  shadow: false   # or OCTO_PULSE_SHADOW=1
  pulse:
    concurrency: 500
    rate: 2000
    adaptive: true
    host_parallel: 8
    banner: true
    os_detect: true
    os_mode: auto
    cve: true
    cve_online: false
```

NVD online: set `NVD_API_KEY` or mount a key file readable by the scanner
(Pulse also supports `~/.pulse/nvd_api_key`).

## Artifacts

| Path | Content |
|------|---------|
| `services.json` | `octo.service.v1` open services |
| `os.json` | `octo.os.v1` OS guesses |
| `pulse_cves.json` | Pulse CVE hits |
| `pulse/raw.json` | Merged raw Pulse JSON |
| `diff_pulse_nmap.json` | Shadow/hybrid comparison |
| `nmap/**` | Written when backend is `nmap`/`hybrid` or shadow |

`report.py` prefers `services.json` / `os.json` when present, and still merges
nmap script findings from XML when hybrid/nmap ran.

## Image install

`Dockerfile` and `Dockerfile.allinone` multi-stage-build Pulse from
[onixus/GenDec](https://github.com/onixus/GenDec) and install to
`/usr/local/bin/pulse` with `cap_net_raw,cap_net_admin+eip` (same pattern as
nmap/naabu).

Build args:

| Arg | Default | Meaning |
|-----|---------|---------|
| `PULSE_GIT_URL` | `https://github.com/onixus/GenDec.git` | source repo |
| `PULSE_REF` | `main` | branch/tag/commit |

```bash
docker build -f Dockerfile \
  --build-arg PULSE_REF=main \
  -t shapoclyack-scanner:local .
```

Host install without image rebuild:

```bash
scripts/install-pulse.sh
scripts/smoke-pulse.sh
```

System UI / API status probes `pulse --version` alongside nmap/naabu/nuclei.

Connect-mode Pulse works without root; SYN/OS still need caps/root like nmap.

## Checkpoint

Pulse chunk checkpoints live under the run’s `pulse/*.ckpt`. Shapoclyack
stage checkpoint marks hosts done under key `pulse` (and `nse` for nmap).

## Limitations (current)

- Does not run NSE scripts (`ssl-enum-ciphers`, vulners, …).
- `tls_posture` still needs nmap XML script output unless disabled.
- UDP enrichment still relies on naabu/nmap paths.
- Banner ≠ full nmap `-sV` product/version.
