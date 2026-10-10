# Using your own Nmap

Shapoclyack does not build or distribute Nmap. `shapoclyack-0.47-1009-rc1` is
the last release whose `-nmap` image tags carry it. From the next release on,
the published `shapoclyack-scanner` and `shapoclyack-aio` images contain no
Nmap binary, no NSE data and no `nmap-vulners` / Vulscan scripts, and the
`-nmap` tags are no longer published.

If you need Nmap, install it yourself next to the sensor. The scanner uses it
whenever `nmap` is on the sensor process's `PATH` and degrades visibly when it
is not.

## Why it is not bundled

Nmap is licensed under the Nmap Public Source License (NPSL), which restricts
redistributing Nmap inside a commercial product. Shapoclyack images are
distributed artifacts, so shipping Nmap in them is a licence risk for everyone
who pulls or re-hosts the image
([issue #97](https://github.com/onixus/Shapoclyack/issues/97)). The same goes
for `nmap-vulners` and Vulscan (GPL-3.0). Installing Nmap on your own hosts or
in your own derived image puts the licence decision with you. Check the NPSL
for your use before you redistribute such an image; see
[Third-party components](third-party.md).

Pulse (`service_probe.backend: pulse`, the default) and Nuclei do not need
Nmap. See [Pulse backend](pulse-backend.md).

## What needs Nmap

The scanner looks for the binary with `shutil.which("nmap")` and calls it by
name. Two features depend on it:

| Feature | Enabled by | Where in the code |
|---|---|---|
| NSE / `-sV` / `-O` stage | `service_probe.backend: nmap` or `hybrid` (default is `pulse`); profile from `nse_profiles` | `scanner/pipeline/nse.py` |
| Pulse-versus-Nmap shadow comparison | `service_probe.shadow: true` or `OCTO_PULSE_SHADOW=1` | `scanner/pipeline/pulse_shadow.py`, `scanner/main.py` |

Nothing else changes. A default scan (Pulse, Nuclei, TLS probe) does not touch
Nmap.

### Without Nmap

The scan does not fail, and the skip is not silent:

- The NSE stage logs `nmap binary not found on PATH; skipping NSE stage` at
  `WARNING`, creates the marker file `nmap/SKIPPED_NMAP_MISSING` and returns an
  empty `nmap/` directory. Both messages point to this page.

Pulse, Nuclei and the TLS probe keep running. A run whose configuration asks for
`backend: nmap` therefore reports no NSE services rather than failing. Treat
that warning as a deployment error, not as a result.

The `vuln_legacy` NSE profile also names the `vulners` script. That script and
Vulscan came from separate Git repositories, not from the Nmap package; see
[NSE vulnerability scripts](#nse-vulnerability-scripts-optional).

## Capabilities Nmap needs

SYN scans and OS detection
(`-O`) send raw packets. The old images granted this to the non-root runtime
user with file capabilities:

```bash
setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap
```

Both capabilities are required. A file capability that is not in the process's
bounding set makes `execve()` fail with `EPERM`, so wherever you run the
sensor it must also hold `NET_RAW` and `NET_ADMIN` (the Docker and Kubernetes
manifests in this repository already add both). In Kubernetes the pod also needs
`allowPrivilegeEscalation: true`; see [k8s/README.md](../k8s/README.md).

## Bare metal or VM sensor (`install-agent.sh`)

`scripts/install-agent.sh` installs the sensor as the systemd unit
`shapoclyack-agent.service`. The unit runs `/opt/shapoclyack-agent/venv/bin/python -m agent` as the system user `shapoclyack`
and sets no ambient capabilities, so Nmap needs file capabilities. The unit also
sets no `PATH`, so systemd's default applies (it includes `/usr/bin` and
`/usr/local/bin`).

1. Install the distribution package:

   ```bash
   # Debian / Ubuntu
   sudo apt-get install -y --no-install-recommends nmap libcap2-bin
   # RHEL / Fedora
   sudo dnf install -y nmap libcap
   ```

2. Grant the capabilities. Use the real path, since a package may install
   `/usr/bin/nmap` or `/usr/local/bin/nmap`:

   ```bash
   sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)"
   getcap "$(command -v nmap)"
   ```

   `getcap` should print `cap_net_admin,cap_net_raw=eip`. Package upgrades
   replace the binary and drop file capabilities, so repeat this step after
   every `nmap` upgrade.

3. Check that the service user sees it. The shell of `shapoclyack` is
   `nologin`, so name the shell explicitly:

   ```bash
   sudo -u shapoclyack sh -c 'command -v nmap && nmap --version | head -n 1'
   ```

4. Restart the sensor so that a long-running process starts with the new
   state: `sudo systemctl restart shapoclyack-agent`.

If `nmap` lives outside systemd's default `PATH`, add a drop-in
(`systemctl edit shapoclyack-agent`) with `Environment=PATH=...` that includes
its directory.

For `install-agent.sh --docker` the sensor runs in a container; follow the
container section below and pass your image through the `AGENT_IMAGE`
environment variable:

```bash
sudo AGENT_IMAGE=registry.example.com/shapoclyack-scanner-nmap:<tag> \
  ./install-agent.sh --docker --server <URL> --key-stdin
```

## Containers and Kubernetes

Build a small derived image from the released one. It installs the Debian
package, sets the file capabilities exactly as the old `Dockerfile` did, and
switches back to the image's runtime user. The scanner image runs as `scanner`:

```dockerfile
FROM ghcr.io/onixus/shapoclyack-scanner:<tag>
USER root
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends nmap libcap2-bin; \
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap; \
    rm -rf /var/lib/apt/lists/*
USER scanner
```

Replace `<tag>` with the release tag, and prefer `tag@sha256:...` as the
manifests in `k8s/` do. Do not purge `libcap2-bin` afterwards: `fping`, which
the image also uses, depends on it. Build and push to your own registry:

```bash
docker build -t registry.example.com/shapoclyack-scanner-nmap:<tag> .
docker push registry.example.com/shapoclyack-scanner-nmap:<tag>
```

Then point the sensor at the new image.

- **`install-agent.sh --docker`**: set `AGENT_IMAGE`, as above.
- **Console deployment snippets**: the snippets print the released sensor image
  (`SENSOR_IMAGE` in `api/services/agents.py`). Replace the `image:` value in
  the snippet with yours before applying it.
- **In-cluster scanner-executor**: the StatefulSet in
  `k8s/shapoclyack/base/scanner-executor/` runs the `shapoclyack-aio` image, so
  derive from the aio image (next section) and override it in your overlay:

  ```yaml
  # kustomization.yaml of your overlay
  images:
    - name: ghcr.io/onixus/shapoclyack-aio
      newName: registry.example.com/shapoclyack-aio-nmap
      newTag: <tag>
  ```

  Note that this also changes the image of every workload that references the
  aio image, API included. To change the executor only, patch the StatefulSet's
  `image:` field instead. If your registry is private, add an
  `imagePullSecret`.

### All-in-one image

Same recipe, different base and runtime user (`octo`):

```dockerfile
FROM ghcr.io/onixus/shapoclyack-aio:<tag>
USER root
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends nmap libcap2-bin; \
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap; \
    rm -rf /var/lib/apt/lists/*
USER octo
```

A derived image is a new artifact you built and signed (or did not) yourself.
The cosign signature and SLSA provenance of the release do not cover it; see
[Supply chain](supply-chain.md).

## NSE vulnerability scripts (optional)

`nse_profiles.vuln_legacy` asks for `vulners`, and Vulscan matches CVEs from
local databases. Both were cloned into `/usr/share/nmap/scripts/` in the old
images at pinned commits. Install them the same way only if you use that
profile (add it to the derived image after the `nmap` install, or run it once on
the host):

```bash
git clone https://github.com/vulnersCom/nmap-vulners.git /usr/share/nmap/scripts/nmap-vulners
git -C /usr/share/nmap/scripts/nmap-vulners checkout 0555294abe71857c581afc2ef62ea3ca5c7b7145
git clone https://github.com/scipag/vulscan.git /usr/share/nmap/scripts/vulscan
git -C /usr/share/nmap/scripts/vulscan checkout bd642ed1bc9d96795a91cdf1acd8c93ceef2d07e
nmap --script-updatedb
```

`scripts/fetch-vulscan-db.sh -o /usr/share/nmap/scripts/vulscan` refreshes the
Vulscan databases (see [Air-gapped operation](air-gap.md)). Both repositories
are GPL-3.0.

## Check that the stages ran

1. Binary and capabilities, where the sensor runs:

   ```bash
   # host
   sudo -u shapoclyack sh -c 'nmap --version | head -n 1'
   # container
   docker run --rm --entrypoint sh <your image> -c 'nmap --version | head -n 1; getcap /usr/bin/nmap'
   ```

2. Start a scan that uses the feature: set `service_probe.backend: hybrid` (or `nmap`).

3. Look at the run output directory:

   | Stage | Ran | Skipped |
   |---|---|---|
   | NSE | `nmap/` holds `*.xml`; no `nmap/SKIPPED_NMAP_MISSING` | `nmap/SKIPPED_NMAP_MISSING` exists |

   `stage_timings.json` lists `nse`. A stage that found no
   Nmap still returns normally, so its timing record does not show the skip;
   use the artifacts above.

4. In the sensor log (`journalctl -u shapoclyack-agent`, `docker logs` or
   `kubectl logs`), the absence of `nmap binary not found on PATH` is the
   positive sign. If it appears, step 1 failed for the sensor's user or `PATH`.

An `EPERM` from the scanner when it starts Nmap means the file capability is
set but the process lacks `NET_RAW`/`NET_ADMIN` in its bounding set (container
runtime flags, Kubernetes `capabilities.add`).
