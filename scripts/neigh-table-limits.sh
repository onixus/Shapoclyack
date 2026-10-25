#!/usr/bin/env bash
# Check and raise the kernel neighbour (ARP/NDP) table limits for L2 discovery.
#
# Linux keeps neighbour entries in a table bounded by
# net.ipv4.neigh.default.gc_thresh1/2/3 (defaults 128/512/1024; IPv6 has its
# own net.ipv6.neigh.default.gc_thresh*). L2 discovery
# (`pulse -D --discover-method arp`) makes the kernel resolve every candidate
# address; with more on-link candidates than gc_thresh3 the kernel evicts
# entries ("neighbour table overflow" in dmesg) and live hosts are silently
# missed. See docs/pulse-backend.md, "Neighbour table limits".
#
# Usage:
#   scripts/neigh-table-limits.sh --check [--hosts N] [--ipv6]
#   sudo scripts/neigh-table-limits.sh --apply (--hosts N | --thresh3 N) [--ipv6] [--force] [--persist]
#   sudo scripts/neigh-table-limits.sh --persist (--hosts N | --thresh3 N) [--ipv6] [--force]
#
# Sizing from --hosts N: thresh3 = next power of two >= 2*N, at least 4096;
# thresh2 = thresh3/2; thresh1 = thresh3/8. Existing values are never lowered
# unless --force is given.
#
# Containers: the neighbour table (and its gc_thresh limits) is shared by all
# network namespaces of a host, and the kernel exposes gc_thresh1/2/3 only in
# the initial namespace. `docker run --sysctl net.ipv4.neigh.default.gc_thresh3=...`
# fails and pod securityContext.sysctls cannot set them; run this script on the
# host (scanner node). Entries of every container on the host count towards
# the same limit. Inside a container with host networking --check can read
# the values; elsewhere they are reported as unavailable.
set -euo pipefail

PERSIST_FILE="${NEIGH_PERSIST_FILE:-/etc/sysctl.d/90-shapoclyack-neigh.conf}"
MIN_THRESH3=4096

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }
die() { echo "neigh-table-limits: $*" >&2; exit 2; }

is_uint() { [[ "$1" =~ ^[0-9]+$ ]] && [ "${#1}" -le 9 ]; }

mode_check=0 mode_apply=0 mode_persist=0 ipv6=0 force=0 hosts="" thresh3=""
[ $# -eq 0 ] && { usage; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --check) mode_check=1 ;;
    --apply) mode_apply=1 ;;
    --persist) mode_persist=1 ;;
    --ipv6) ipv6=1 ;;
    --force) force=1 ;;
    --hosts) [ $# -ge 2 ] || die "--hosts needs a value"; hosts="$2"; shift ;;
    --thresh3) [ $# -ge 2 ] || die "--thresh3 needs a value"; thresh3="$2"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

if [ -n "$hosts" ] && ! { is_uint "$hosts" && [ "$hosts" -gt 0 ]; }; then
  die "--hosts must be a positive integer"
fi
if [ -n "$thresh3" ] && ! { is_uint "$thresh3" && [ "$thresh3" -ge 8 ]; }; then
  die "--thresh3 must be an integer >= 8"
fi
[ $((mode_check + mode_apply + mode_persist)) -gt 0 ] || die "choose --check, --apply or --persist"

if [ "$(uname -s)" != "Linux" ]; then
  echo "neigh-table-limits: Linux only (this is $(uname -s)); nothing to do." >&2
  exit 1
fi

families=(ipv4)
[ "$ipv6" -eq 1 ] && families+=(ipv6)

read_val() { cat "/proc/sys/net/$1/neigh/default/gc_thresh$2" 2>/dev/null || echo "?"; }

if [ ! -r /proc/sys/net/ipv4/neigh/default/gc_thresh3 ]; then
  echo "neigh-table-limits: gc_thresh is not visible here (not the host's initial network namespace?)." >&2
  echo "  The limit is host-wide: check and set it on the host / scanner node." >&2
  exit 1
fi

# Target thresh3: explicit, else sized from --hosts.
target3=""
if [ -n "$thresh3" ]; then
  target3="$thresh3"
elif [ -n "$hosts" ]; then
  target3=1
  while [ "$target3" -lt $((hosts * 2)) ]; do target3=$((target3 * 2)); done
  [ "$target3" -lt "$MIN_THRESH3" ] && target3="$MIN_THRESH3"
fi

if [ "$mode_check" -eq 1 ]; then
  rc=0
  for fam in "${families[@]}"; do
    t1=$(read_val "$fam" 1); t2=$(read_val "$fam" 2); t3=$(read_val "$fam" 3)
    echo "$fam: gc_thresh1=$t1 gc_thresh2=$t2 gc_thresh3=$t3"
    if [ -n "$hosts" ] && is_uint "$t3"; then
      if [ "$hosts" -le "$t3" ]; then
        echo "  $hosts candidates fit under gc_thresh3=$t3"
      else
        echo "  $hosts candidates EXCEED gc_thresh3=$t3: entries will be evicted, raise it (suggested gc_thresh3=$target3)"
        rc=1
      fi
    fi
  done
  [ "$mode_apply" -eq 0 ] && [ "$mode_persist" -eq 0 ] && exit "$rc"
fi

[ -n "$target3" ] || die "--apply/--persist need --hosts N or --thresh3 N"
[ "$(id -u)" -eq 0 ] || die "--apply/--persist need root"

# Final values per family/key: never lower an existing value without --force.
declare -A final=()
for fam in "${families[@]}"; do
  for i in 1 2 3; do
    case $i in 1) want=$((target3 / 8)) ;; 2) want=$((target3 / 2)) ;; 3) want=$target3 ;; esac
    cur=$(read_val "$fam" "$i")
    if [ "$force" -eq 0 ] && is_uint "$cur" && [ "$cur" -gt "$want" ]; then
      echo "keep net.$fam.neigh.default.gc_thresh$i=$cur (higher than $want; --force to lower)"
      want=$cur
    fi
    final["$fam.$i"]=$want
  done
done

if [ "$mode_apply" -eq 1 ]; then
  for fam in "${families[@]}"; do
    # Write thresh3 first when raising so thresh1 <= thresh2 <= thresh3 holds throughout.
    for i in 3 2 1; do
      key="net.$fam.neigh.default.gc_thresh$i"
      cur=$(read_val "$fam" "$i"); want=${final["$fam.$i"]}
      if [ "$cur" = "$want" ]; then
        echo "unchanged $key=$cur"
      else
        sysctl -q -w "$key=$want"
        echo "changed $key: $cur -> $want"
      fi
    done
  done
fi

if [ "$mode_persist" -eq 1 ]; then
  tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  {
    echo "# Managed by Shapoclyack scripts/neigh-table-limits.sh: neighbour table"
    echo "# limits for L2 discovery. See docs/pulse-backend.md."
    for fam in "${families[@]}"; do
      for i in 1 2 3; do echo "net.$fam.neigh.default.gc_thresh$i = ${final["$fam.$i"]}"; done
    done
  } >"$tmp"
  if [ -f "$PERSIST_FILE" ] && cmp -s "$tmp" "$PERSIST_FILE"; then
    echo "unchanged $PERSIST_FILE"
  else
    install -m 0644 "$tmp" "$PERSIST_FILE"
    echo "wrote $PERSIST_FILE"
  fi
fi
