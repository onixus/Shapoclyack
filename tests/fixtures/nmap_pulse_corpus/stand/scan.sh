#!/usr/bin/env bash
# Runs INSIDE the scanner container (see ../record.sh). Both tools get the same
# targets and ports; Pulse gets the flags the Shapoclyack adapter would pass
# (pulse_probe.build_pulse_command: banners, --os --os-mode sinfp, --cve) with an
# empty HOME, so nothing under ~/.pulse leaks in, and the same pinned --services-db /
# --probe-db files (#543, #546), bind-mounted from scanner/pipeline/pulse_data.
set -euo pipefail

CORPUS=/corpus
TARGETS=$CORPUS/stand/targets.txt
TCP_PORTS=21,22,80,139,443,445,3306,3389,5432,6379
UDP_PORTS=161
UDP_TARGET=172.29.41.41

mkdir -p "$CORPUS/nmap" "$CORPUS/pulse"
# The pipeline's pinned inputs (pulse_probe.build_pulse_command, #543/#546): the
# IANA port table and our probe database, mounted read-only by docker-compose.yml.
PULSE_INPUTS=(--services-db /pulse_data/services.tsv --probe-db /pulse_data/probes.json)

export HOME
HOME="$(mktemp -d)"   # empty, as the adapter's private HOME will be (#543)

echo "==> nmap tcp"
nmap -n -Pn -T4 -sV -O --osscan-guess \
  --script default,safe,vuln,ssl-enum-ciphers \
  -p "$TCP_PORTS" -iL "$TARGETS" -oX "$CORPUS/nmap/tcp.xml" >/dev/null

echo "==> nmap udp"
nmap -n -Pn -sU -sV -p "$UDP_PORTS" "$UDP_TARGET" -oX "$CORPUS/nmap/udp.xml" >/dev/null

echo "==> pulse tcp (adapter flags)"
pulse --targets-file "$TARGETS" -p "$TCP_PORTS" -c 100 -t 3000 \
  -b --os --os-mode sinfp --cve -f json -q "${PULSE_INPUTS[@]}" > "$CORPUS/pulse/tcp.json"

echo "==> pulse udp"
pulse --targets-file <(echo "$UDP_TARGET") -p "$UDP_PORTS" --protocol udp -t 3000 \
  -b --cve -f json -q "${PULSE_INPUTS[@]}" > "$CORPUS/pulse/udp.json"

echo "==> pulse tcp with bundled audit plugins (--scripts)"
pulse --targets-file "$TARGETS" -p "$TCP_PORTS" -c 100 -t 3000 \
  -b --scripts --cve -f json -q "${PULSE_INPUTS[@]}" > "$CORPUS/pulse/tcp-scripts.json"

{
  echo "nmap: $(nmap --version | head -1)"
  echo "pulse: $(pulse --version)"
  echo "scanner_kernel: $(uname -sr)"
} > "$CORPUS/tools.txt"
