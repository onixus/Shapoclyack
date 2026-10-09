#!/usr/bin/env bash
# Re-record the Nmap/Pulse golden corpus (#541, ADR 0002).
#
#   PULSE_BIN=/path/to/linux/pulse tests/fixtures/nmap_pulse_corpus/record.sh
#
# PULSE_BIN must be a LINUX Pulse binary matching the Docker VM's architecture,
# e.g. built by scripts/install-pulse.sh inside a container of the same platform
# (the script checks it against scripts/pulse-pinned.sha256):
#
#   docker run --rm -v "$PWD/scripts:/src:ro" -v /tmp/pulse-bin:/out \
#     -e GITHUB_TOKEN -e PULSE_VERSION=v1.3.0 -e PULSE_DEST=/out/pulse \
#     debian:12-slim bash -c 'apt-get update -qq && apt-get install -y -qq \
#       curl ca-certificates python3 && /src/install-pulse.sh'
#
# MIRROR=mirror.gcr.io/library  fetches the pinned images from another registry
# when Docker Hub is unreachable; the digests in docker-compose.yml still apply.
#
# The stand is torn down (containers, network, anonymous volumes) when this
# script ends, whether it succeeded or not. Recorded files overwrite the
# fixtures next to this script; review `git diff --stat` before committing.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAND="$HERE/stand"
: "${PULSE_BIN:?set PULSE_BIN to a linux Pulse binary}"
export PULSE_BIN

compose() { docker compose -f "$STAND/docker-compose.yml" "$@"; }
trap 'compose down -v --remove-orphans >/dev/null 2>&1 || true' EXIT

# --- throwaway certificates (not committed: the fixtures carry what was seen) ---
mkdir -p "$STAND/certs"
mkcert() {  # mkcert <name> <rsa-bits>
  openssl req -x509 -newkey "rsa:$2" -nodes -days 3650 \
    -keyout "$STAND/certs/$1.key" -out "$STAND/certs/$1.crt" \
    -subj "/CN=$1.stand.test" >/dev/null 2>&1
}
mkcert nginx-modern 2048
mkcert nginx-legacy 2048   # a 1024-bit key is refused at load time even with SECLEVEL=0 in ssl_ciphers
mkcert apache 2048
chmod 644 "$STAND"/certs/*.key   # the stand's nginx/apache workers are not root

compose up -d --build

# --- wait until the services answer, from inside the stand ---
compose exec -T scanner bash -c '
  deadline=$((SECONDS + 180))
  for hp in 172.29.41.10:22 172.29.41.11:22 172.29.41.12:22 172.29.41.13:22 \
            172.29.41.20:443 172.29.41.21:443 172.29.41.22:443 172.29.41.23:80 \
            172.29.41.24:3389 172.29.41.30:5432 172.29.41.31:3306 \
            172.29.41.32:6379 172.29.41.40:445 172.29.41.42:21; do
    until (echo > /dev/tcp/${hp%:*}/${hp#*:}) 2>/dev/null; do
      [ $SECONDS -lt $deadline ] || { echo "timeout waiting for $hp" >&2; exit 1; }
      sleep 1
    done
  done'
sleep 10   # mysql and postgres open the port before they are ready to answer

compose exec -T scanner bash /corpus/stand/scan.sh

# --- what the stand was made of ---
compose config --format json | python3 -c '
import json, os, sys
# The recorded refs name the canonical registry, whatever MIRROR fetched them.
raw = sys.stdin.read().replace(os.environ.get("MIRROR") or "docker.io/library", "docker.io/library")
cfg = json.loads(raw)
meta = {
    "issue": "onixus/Shapoclyack#541",
    "stub_services": ["iis-stub (172.29.41.23)", "rdp-stub (172.29.41.24)"],
    "services": {
        n: {"image": s.get("image"), "build_base": (s.get("build") or {}).get("args", {}).get("BASE")}
        for n, s in sorted(cfg["services"].items())
    },
}
json.dump(meta, sys.stdout, indent=2, sort_keys=True)
print()' > "$HERE/stand-meta.json"

echo "recorded into $HERE"
du -sh "$HERE/nmap" "$HERE/pulse"
