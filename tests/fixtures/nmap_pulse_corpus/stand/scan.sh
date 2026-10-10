#!/usr/bin/env bash
# Runs INSIDE the scanner container (see ../record.sh). Both tools get the same
# targets and ports; Pulse gets the flags the Shapoclyack adapter would pass
# (pulse_probe.build_pulse_command: banners, --os --os-mode sinfp, --cve) with an
# empty HOME, so nothing under ~/.pulse leaks in.
#
# RECORD_PARTS (default "nmap,pulse") picks what to record: "pulse" leaves the
# Nmap fixtures alone, which is how the plugin run was added after Nmap was
# pinned as the reference.
set -euo pipefail
PARTS=",${RECORD_PARTS:-nmap,pulse},"
want() { [[ "$PARTS" == *",$1,"* ]]; }

CORPUS=/corpus
TARGETS=$CORPUS/stand/targets.txt
TCP_PORTS=21,22,80,139,443,445,3306,3389,5432,6379
UDP_PORTS=161
UDP_TARGET=172.29.41.41

mkdir -p "$CORPUS/nmap" "$CORPUS/pulse"
export HOME
HOME="$(mktemp -d)"   # empty, as the adapter's private HOME will be (#543)

if want nmap; then
  echo "==> nmap tcp"
  nmap -n -Pn -T4 -sV -O --osscan-guess \
    --script default,safe,vuln,ssl-enum-ciphers \
    -p "$TCP_PORTS" -iL "$TARGETS" -oX "$CORPUS/nmap/tcp.xml" >/dev/null

  echo "==> nmap udp"
  nmap -n -Pn -sU -sV -p "$UDP_PORTS" "$UDP_TARGET" -oX "$CORPUS/nmap/udp.xml" >/dev/null
fi

if want pulse; then
  echo "==> pulse tcp (adapter flags)"
  pulse --targets-file "$TARGETS" -p "$TCP_PORTS" -c 100 -t 3000 \
    -b --os --os-mode sinfp --cve -f json -q > "$CORPUS/pulse/tcp.json"

  echo "==> pulse udp"
  pulse --targets-file <(echo "$UDP_TARGET") -p "$UDP_PORTS" --protocol udp -t 3000 \
    -b --cve -f json -q > "$CORPUS/pulse/udp.json"

  # The adapter's run with plugins (#544): --script-dir /plugins, in the empty
  # directory that is also HOME, stderr kept (plugin errors are printed there).
  echo "==> pulse tcp with the Shapoclyack plugins (--script-dir)"
  (cd "$HOME" && pulse --targets-file "$TARGETS" -p "$TCP_PORTS" -c 100 -t 3000 \
    -b --os --os-mode sinfp --cve --script-dir /plugins -f json -q \
    > "$CORPUS/pulse/tcp-plugins.json" 2> "$CORPUS/pulse/tcp-plugins.stderr")
  # Pulse colours its warnings even when stderr is a file.
  sed -i 's/\x1b\[[0-9;]*m//g' "$CORPUS/pulse/tcp-plugins.stderr"
  # What the plugins were: name and sha256, the same receipt the adapter writes.
  (cd /plugins && sha256sum *.rhai) > "$CORPUS/pulse/plugins.sha256"
fi

{
  echo "nmap: $(nmap --version | head -1)"
  echo "pulse: $(pulse --version)"
  echo "scanner_kernel: $(uname -sr)"
} > "$CORPUS/tools.txt"
