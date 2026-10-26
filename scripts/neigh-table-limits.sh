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
# unless --force is given. --check judges --hosts by the same numbers --apply
# would set: it fails when the current gc_thresh3 or gc_thresh2 is below them.
# --thresh3 must be within 1024..1048576 (2^20); --force lifts the lower bound
# down to 8. --apply writes nothing until every key (IPv6 too) is confirmed
# present; without --persist the values are lost on reboot.
#
# Exit codes: 0 ok, 1 --check found limits too low, 2 usage error or not root,
# 3 unsupported platform (not Linux), 4 gc_thresh keys not available here.
# Test seam: NEIGH_PROC_ROOT=<dir> reads/writes <dir>/sys/net/... instead of
# /proc (plain file writes instead of sysctl, no root or Linux needed).
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
MIN_THRESH3_EXPLICIT=1024
MAX_THRESH3=1048576
PROC_ROOT="${NEIGH_PROC_ROOT:-/proc}"

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
if [ -n "$thresh3" ]; then
  min3=$MIN_THRESH3_EXPLICIT
  [ "$force" -eq 1 ] && min3=8
  is_uint "$thresh3" && [ "$thresh3" -ge "$min3" ] && [ "$thresh3" -le "$MAX_THRESH3" ] \
    || die "--thresh3 must be an integer in $min3..$MAX_THRESH3"
fi
[ $((mode_check + mode_apply + mode_persist)) -gt 0 ] || die "choose --check, --apply or --persist"

if [ -z "${NEIGH_PROC_ROOT:-}" ] && [ "$(uname -s)" != "Linux" ]; then
  echo "neigh-table-limits: Linux only (this is $(uname -s)); nothing to do." >&2
  exit 3
fi

families=(ipv4)
[ "$ipv6" -eq 1 ] && families+=(ipv6)

key_path() { echo "$PROC_ROOT/sys/net/$1/neigh/default/gc_thresh$2"; }
read_val() { cat "$(key_path "$1" "$2")" 2>/dev/null || echo "?"; }

# Every key of a family must be readable; IPv6 may be absent (ipv6.disable=1,
# no module). --check tolerates that for IPv6 only; --apply/--persist refuse
# before the first write so nothing is left half-changed.
avail=()
for fam in "${families[@]}"; do
  missing=""
  for i in 1 2 3; do [ -r "$(key_path "$fam" "$i")" ] || missing="$missing gc_thresh$i"; done
  if [ -z "$missing" ]; then
    avail+=("$fam")
  elif [ "$fam" != ipv6 ] || [ "$mode_apply" -eq 1 ] || [ "$mode_persist" -eq 1 ]; then
    echo "neigh-table-limits: $fam$missing not visible here (not the host's initial network namespace, or $fam disabled?)." >&2
    echo "  The limit is host-wide: check and set it on the host / scanner node. Nothing was changed." >&2
    exit 4
  else
    echo "$fam: unavailable (keys missing$missing)"
  fi
done
families=("${avail[@]}")

# Target thresh3: explicit, else sized from --hosts.
target3=""
if [ -n "$thresh3" ]; then
  target3="$thresh3"
elif [ -n "$hosts" ]; then
  target3=1
  while [ "$target3" -lt $((hosts * 2)) ]; do target3=$((target3 * 2)); done
  [ "$target3" -lt "$MIN_THRESH3" ] && target3="$MIN_THRESH3"
  [ "$target3" -le "$MAX_THRESH3" ] || [ "$force" -eq 1 ] \
    || die "--hosts $hosts needs gc_thresh3=$target3, above the $MAX_THRESH3 cap (--force to allow)"
fi

if [ "$mode_check" -eq 1 ]; then
  rc=0
  for fam in "${families[@]}"; do
    t1=$(read_val "$fam" 1); t2=$(read_val "$fam" 2); t3=$(read_val "$fam" 3)
    echo "$fam: gc_thresh1=$t1 gc_thresh2=$t2 gc_thresh3=$t3"
    if [ -n "$hosts" ] && is_uint "$t3" && is_uint "$t2"; then
      # Same numbers --apply would set: gc_thresh3 >= 2N-sized target, and
      # gc_thresh2 (the soft limit above which GC evicts) >= half of it.
      if [ "$t3" -ge "$target3" ] && [ "$t2" -ge $((target3 / 2)) ]; then
        echo "  $hosts candidates fit (gc_thresh3 >= $target3, gc_thresh2 >= $((target3 / 2)))"
      else
        echo "  $hosts candidates DO NOT fit: entries will be evicted, raise the limits (suggested gc_thresh3=$target3, gc_thresh2=$((target3 / 2)))"
        rc=1
      fi
    fi
  done
  [ "$mode_apply" -eq 0 ] && [ "$mode_persist" -eq 0 ] && exit "$rc"
fi

[ -n "$target3" ] || die "--apply/--persist need --hosts N or --thresh3 N"
[ -n "${NEIGH_PROC_ROOT:-}" ] || [ "$(id -u)" -eq 0 ] || die "--apply/--persist need root"

# Final values per family/key: never lower an existing value without --force.
# Plain variables final_<fam>_<i> (no associative arrays: stays bash 3.2 compatible).
for fam in "${families[@]}"; do
  for i in 1 2 3; do
    case $i in 1) want=$((target3 / 8)) ;; 2) want=$((target3 / 2)) ;; 3) want=$target3 ;; esac
    cur=$(read_val "$fam" "$i")
    if [ "$force" -eq 0 ] && is_uint "$cur" && [ "$cur" -gt "$want" ]; then
      echo "keep net.$fam.neigh.default.gc_thresh$i=$cur (higher than $want; --force to lower)"
      want=$cur
    fi
    printf -v "final_${fam}_$i" "%s" "$want"
  done
done

write_val() {
  if [ -n "${NEIGH_PROC_ROOT:-}" ]; then echo "$4" >"$(key_path "$1" "$2")"; else sysctl -q -w "$3=$4"; fi
}

if [ "$mode_apply" -eq 1 ]; then
  for fam in "${families[@]}"; do
    # Write thresh3 first when raising so thresh1 <= thresh2 <= thresh3 holds throughout.
    for i in 3 2 1; do
      key="net.$fam.neigh.default.gc_thresh$i"
      cur=$(read_val "$fam" "$i"); fv="final_${fam}_$i"; want=${!fv}
      if [ "$cur" = "$want" ]; then
        echo "unchanged $key=$cur"
      else
        write_val "$fam" "$i" "$key" "$want"
        echo "changed $key: $cur -> $want"
      fi
    done
  done
fi

if [ "$mode_apply" -eq 1 ] && [ "$mode_persist" -eq 0 ]; then
  echo "warning: values applied at runtime only and will be lost on reboot; add --persist to keep them." >&2
fi

if [ "$mode_persist" -eq 1 ]; then
  tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  {
    echo "# Managed by Shapoclyack scripts/neigh-table-limits.sh: neighbour table"
    echo "# limits for L2 discovery. See docs/pulse-backend.md."
    for fam in "${families[@]}"; do
      for i in 1 2 3; do echo "net.$fam.neigh.default.gc_thresh$i = $(fv="final_${fam}_$i"; echo "${!fv}")"; done
    done
  } >"$tmp"
  if [ -f "$PERSIST_FILE" ] && cmp -s "$tmp" "$PERSIST_FILE"; then
    echo "unchanged $PERSIST_FILE"
  else
    install -m 0644 "$tmp" "$PERSIST_FILE"
    echo "wrote $PERSIST_FILE"
  fi
fi
