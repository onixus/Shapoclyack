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

Override without editing YAML:

```bash
export OCTO_SERVICE_BACKEND=pulse
export OCTO_PULSE_BIN=/usr/local/bin/pulse
```

## Config (`scanner/config/default.yaml`)

```yaml
service_probe:
  backend: nmap   # pulse | hybrid
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
| `nmap/**` | Still written when backend is `nmap` or `hybrid` |

`report.py` prefers `services.json` / `os.json` when present, and still merges
nmap script findings from XML when hybrid/nmap ran.

## Image install (operator)

Until the Dockerfile bakes Pulse:

```dockerfile
# example — pin a release
COPY --from=ghcr.io/.../pulse:0.2 /usr/local/bin/pulse /usr/local/bin/pulse
# or: multi-stage cargo build from https://github.com/onixus/GenDec
```

Capabilities for SYN/OS (same story as nmap):

```text
cap_net_raw (+ root for some OS paths)
```

Connect-mode Pulse (default) works without root.

## Checkpoint

Pulse chunk checkpoints live under the run’s `pulse/*.ckpt`. Shapoclyack
stage checkpoint marks hosts done under key `pulse` (and `nse` for nmap).

## Limitations (current)

- Does not run NSE scripts (`ssl-enum-ciphers`, vulners, …).
- `tls_posture` still needs nmap XML script output unless disabled.
- UDP enrichment still relies on naabu/nmap paths.
- Banner ≠ full nmap `-sV` product/version.
