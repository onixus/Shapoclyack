#!/usr/bin/env sh
set -eu

usage() {
  cat <<'EOF'
Usage: scripts/restore-clickhouse.sh --backup-url URL (--namespace NAMESPACE | --local)
                                     [--database NAME] [--dry-run]

Restores a backup written by the shapoclyack-clickhouse-backup CronJob
(k8s/shapoclyack/base/backup/clickhouse-backup.sh) and verifies it against the
manifest that job wrote next to it. See docs/disaster-recovery.md.

  --backup-url URL  the url= of the job's backup_success line, e.g.
                    https://BUCKET.s3.REGION.amazonaws.com/PREFIX/clickhouse/20260924T024500Z
  --namespace NS    run clickhouse-client in the ClickHouse pod of NS (kubectl exec);
                    refuses network-scan unless ALLOW_PRODUCTION_RESTORE=1
  --local           run a clickhouse-client on this host instead: CLICKHOUSE_CLIENT
                    (default clickhouse-client), CLICKHOUSE_HOST, CLICKHOUSE_PORT,
                    CLICKHOUSE_USER, CLICKHOUSE_PASSWORD
  --database NAME   database inside the backup (default: shapoclyack)
  --dry-run         verify the backup against its manifest and check the target;
                    restore nothing

The S3 key pair is read from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY and is
never printed. The ClickHouse server does the reading, so the server — not this
host — has to reach the bucket.

Each check stops the run with its own exit code:
  4  the manifest is unreadable or names no table
  6  the backup's part/row counts or its .backup digest differ from the manifest,
     or .backup lists parts whose count.txt is not an object of its own
  7  a table in the target database already has rows
  8  RESTORE failed, or a restored table's row count differs from the manifest
The target database — empty, by check 7 — is dropped and rebuilt from the
backup's own schema: a first boot of a newer release creates tables RESTORE
would refuse. Columns that release has and the backup lacks are reported as
schema_drift lines. The restore runs with merges stopped on the restored
tables, so the counts compared in step 8 are the ones the backup stored, not
ReplacingMergeTree's deduplicated ones; merges are started again however the
script exits, Ctrl-C and a dropped session included.
EOF
}

backup_url=""
namespace=""
local_mode=0
database="shapoclyack"
dry_run=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --backup-url)
      backup_url="${2:-}"
      shift 2
      ;;
    --namespace)
      namespace="${2:-}"
      shift 2
      ;;
    --local)
      local_mode=1
      shift
      ;;
    --database)
      database="${2:-}"
      shift 2
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[ -n "$backup_url" ] || { echo "--backup-url is required" >&2; exit 2; }
if [ "$local_mode" = 1 ] && [ -n "$namespace" ]; then
  echo "--namespace and --local are mutually exclusive" >&2
  exit 2
fi
if [ "$local_mode" = 0 ] && [ -z "$namespace" ]; then
  echo "one of --namespace or --local is required" >&2
  exit 2
fi
case "$database" in
  ''|[0-9]*|*[!A-Za-z0-9_]*)
    echo "invalid --database: use letters, digits and underscores" >&2
    exit 2
    ;;
esac
backup_url="${backup_url%/}"
[ -n "${AWS_ACCESS_KEY_ID:-}" ] || { echo "AWS_ACCESS_KEY_ID is not set" >&2; exit 2; }
[ -n "${AWS_SECRET_ACCESS_KEY:-}" ] || { echo "AWS_SECRET_ACCESS_KEY is not set" >&2; exit 2; }

if [ "$namespace" = "network-scan" ] && [ "${ALLOW_PRODUCTION_RESTORE:-0}" != "1" ]; then
  echo "refusing restore into network-scan; use an isolated namespace or set ALLOW_PRODUCTION_RESTORE=1" >&2
  exit 3
fi

CLICKHOUSE_CLIENT="${CLICKHOUSE_CLIENT:-clickhouse-client}"
CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-127.0.0.1}"
CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-9000}"
CLICKHOUSE_USER="${CLICKHOUSE_USER:-default}"
CLICKHOUSE_RESTORE_TIMEOUT_SECONDS="${CLICKHOUSE_RESTORE_TIMEOUT_SECONDS:-3600}"
CLICKHOUSE_RESTORE_POLL_SECONDS="${CLICKHOUSE_RESTORE_POLL_SECONDS:-5}"

work="$(mktemp -d)"
tables=""
merges_stopped=0
dropped=0
secret_q=""

# Same scrub as the backup job: the S3 secret travels inside the statements —
# SQL-escaped, which is the form clickhouse-client repeats after an error — and
# a parse error quotes the statement's tail without a "(query: …)" block.
scrub() {
  SCRUB_SECRET_SQL="$secret_q" awk '
    BEGIN {
      n = 0
      if (ENVIRON["SCRUB_SECRET_SQL"] != "") secret[++n] = ENVIRON["SCRUB_SECRET_SQL"]
      if (ENVIRON["AWS_SECRET_ACCESS_KEY"] != "") secret[++n] = ENVIRON["AWS_SECRET_ACCESS_KEY"]
      if (ENVIRON["CLICKHOUSE_PASSWORD"] != "") secret[++n] = ENVIRON["CLICKHOUSE_PASSWORD"]
    }
    skipping { next }
    {
      line = $0
      q = index(line, "(query: ")
      if (q > 0) {
        skipping = 1
        line = substr(line, 1, q - 1)
        if (line == "") next
      }
      for (k = 1; k <= n; k++) {
        out = ""
        while ((i = index(line, secret[k])) > 0) {
          out = out substr(line, 1, i - 1) "[HIDDEN]"
          line = substr(line, i + length(secret[k]))
        }
        line = out line
      }
      print line
    }
  '
}

# SQL on stdin, result on stdout. In a namespace the client inside the
# ClickHouse pod runs with that container's CLICKHOUSE_PASSWORD.
ch() {
  if [ -n "$namespace" ]; then
    set -- kubectl -n "$namespace" exec -i "$pod" -c clickhouse -- clickhouse-client --user default
  else
    # shellcheck disable=SC2086
    set -- $CLICKHOUSE_CLIENT --host "$CLICKHOUSE_HOST" --port "$CLICKHOUSE_PORT" --user "$CLICKHOUSE_USER"
  fi
  if "$@" >"$work/out" 2>"$work/err"; then
    scrub <"$work/err" >&2
    scrub <"$work/out"
    return 0
  fi
  scrub <"$work/err" >&2
  return 1
}

sql_quote() {
  sed -e 's/\\/\\\\/g' -e "s/'/\\\\'/g"
}

cleanup() {
  if [ "$merges_stopped" = 1 ]; then
    for table in $tables; do
      ch >/dev/null <<SQL || echo "could not restart merges on ${database}.${table}; run SYSTEM START MERGES" >&2
SYSTEM START MERGES \`${database}\`.\`${table}\`
SQL
    done
  fi
  rm -rf "$work"
}
trap cleanup EXIT
# An EXIT trap alone does not run on a fatal signal in dash or busybox ash, and
# merges left stopped fail every later OPTIMIZE with Code 236.
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Once the target has been dropped, whatever went wrong left it holding what
# RESTORE wrote, so a rerun stops at check 7. Say so, and how to start over.
restore_failed() {
  echo "$1" >&2
  if [ "$dropped" = 1 ]; then
    echo "the target now holds what RESTORE wrote and merges run again; a rerun stops at exit 7." >&2
    echo "compare the counts above, then either keep it, or DROP DATABASE \`${database}\` SYNC and run again." >&2
  fi
  exit 8
}

pod=""
if [ -n "$namespace" ]; then
  selector='app.kubernetes.io/name=shapoclyack,app.kubernetes.io/component=clickhouse'
  pod="$(kubectl -n "$namespace" get pods -l "$selector" \
    -o jsonpath='{range .items[?(@.status.phase=="Running")]}{.metadata.name}{"\n"}{end}' | head -n 1)"
  [ -n "$pod" ] || {
    echo "no running ClickHouse pod found in namespace $namespace" >&2
    exit 5
  }
  kubectl -n "$namespace" wait --for=condition=Ready "pod/$pod" --timeout=120s >/dev/null
fi

url_q="$(printf '%s' "$backup_url" | sql_quote)"
key_q="$(printf '%s' "$AWS_ACCESS_KEY_ID" | sql_quote)"
secret_q="$(printf '%s' "$AWS_SECRET_ACCESS_KEY" | sql_quote)"
creds="'${key_q}', '${secret_q}'"
source="S3('${url_q}', ${creds})"

verify_started="$(date +%s)"

# 1. The manifest, as the backup job wrote it. Its table names end up inside
# statements below, so anything that is not a plain identifier is refused
# rather than quoted: a manifest is a file in a bucket, not a trusted input.
ch >"$work/manifest" <<SQL || { echo "manifest not readable at ${backup_url}/manifest.jsonl" >&2; exit 4; }
SELECT table, parts, rows, backup_metadata_sha256
FROM s3('${url_q}/manifest.jsonl', ${creds}, 'JSONEachRow',
        'backup_id String, database String, table String, parts UInt64, rows UInt64, backup_metadata_sha256 String')
WHERE database = '${database}'
ORDER BY table
FORMAT TSVRaw
SQL
[ -s "$work/manifest" ] || {
  echo "manifest at ${backup_url}/manifest.jsonl names no table of database ${database}" >&2
  exit 4
}
# Checked per line, before any word splitting: "a b" must not pass as two names.
awk -F '\t' '$1 !~ /^[A-Za-z_][A-Za-z0-9_]*$/ { bad = 1 } END { exit bad }' "$work/manifest" || {
  echo "manifest names a table that is not a plain identifier; refusing" >&2
  exit 6
}
tables="$(awk -F '\t' '{print $1}' "$work/manifest")"

# 2. The backup as it is in the bucket now, counted the way the job counted it.
ch >"$work/observed" <<SQL || { echo "backup not readable at ${backup_url}" >&2; exit 6; }
SELECT
    t.table,
    c.parts,
    c.rows,
    (SELECT lower(hex(SHA256(raw_blob))) FROM s3('${url_q}/.backup', ${creds}, 'RawBLOB'))
FROM
(
    SELECT decodeURLComponent(left(name, length(name) - 4)) AS table
    FROM
    (
        SELECT splitByChar('/', _path)[-1] AS name
        FROM s3('${url_q}/metadata/${database}/*.sql', ${creds}, 'RawBLOB')
    )
) AS t
LEFT JOIN
(
    SELECT
        decodeURLComponent(splitByChar('/', _path)[-3]) AS table,
        count() AS parts,
        sum(toUInt64(line)) AS rows
    FROM s3('${url_q}/data/${database}/*/*/count.txt', ${creds}, 'LineAsString')
    GROUP BY table
) AS c USING (table)
ORDER BY t.table
FORMAT TSVRaw
SQL

# Column 4 is the digest of the backup's own file list, so a manifest paired
# with a different backup (or a backup rewritten after it) fails here even
# when the row counts happen to agree.
compare() {
  # $1 expected (manifest), $2 actual; both "table<TAB>parts<TAB>rows[<TAB>sha]".
  awk -F '\t' -v label="$3" '
    FNR == NR { want[$1] = $2 "\t" $3; if ($4 != "") want_sha = $4; order[++n] = $1; next }
    { have[$1] = $2 "\t" $3; if ($4 != "") have_sha = $4; if (!($1 in want)) order[++n] = $1 }
    END {
      bad = 0
      for (i = 1; i <= n; i++) {
        t = order[i]
        split((t in want) ? want[t] : "-\t-", w, "\t")
        split((t in have) ? have[t] : "-\t-", h, "\t")
        ok = (t in want) && (t in have) && w[2] == h[2]
        if (label == "backup") ok = ok && w[1] == h[1]
        printf "verify %s table=%s manifest_rows=%s %s_rows=%s %s\n", label, t, w[2], label, h[2], (ok ? "ok" : "MISMATCH")
        if (!ok) bad = 1
      }
      if (label == "backup" && want_sha != have_sha) {
        printf "verify %s backup_metadata_sha256 manifest=%s %s=%s MISMATCH\n", label, want_sha, label, have_sha
        bad = 1
      }
      exit bad
    }
  ' "$1" "$2"
}

compare "$work/manifest" "$work/observed" backup || {
  echo "backup at ${backup_url} does not match its manifest" >&2
  exit 6
}

# `.backup` lists every part's count.txt; a backup taken with deduplicate_files
# on stores one object for several identical ones, and missing objects are
# missing. Either way the counts above are not the backup's — and restoring it
# would end at step 5 with the data already in.
ch >"$work/unreadable" <<SQL || { echo "backup not readable at ${backup_url}" >&2; exit 6; }
SELECT l.table, l.listed, p.parts
FROM
(
    SELECT decodeURLComponent(arrayJoin(extractAll(raw_blob, '<name>data/${database}/([^/<]*)/[^/<]*/count[.]txt</name>'))) AS table, count() AS listed
    FROM s3('${url_q}/.backup', ${creds}, 'RawBLOB')
    GROUP BY table
) AS l
LEFT JOIN
(
    SELECT decodeURLComponent(splitByChar('/', _path)[-3]) AS table, count() AS parts
    FROM s3('${url_q}/data/${database}/*/*/count.txt', ${creds}, 'LineAsString')
    GROUP BY table
) AS p USING (table)
WHERE l.listed != p.parts
FORMAT TSVRaw
SQL
if [ -s "$work/unreadable" ]; then
  awk -F '\t' '{ printf "verify backup table=%s listed=%s readable=%s MISMATCH\n", $1, $2, $3 }' "$work/unreadable"
  echo "backup at ${backup_url} lists parts it does not store as objects (deduplicate_files, or objects lost); its counts cannot be verified" >&2
  exit 6
fi

# 3. Never merge a backup into live rows: RESTORE into a non-empty table would
# append, and ReplacingMergeTree would then keep whichever copy merged last.
# Every table counts, not only the backup's: the database is dropped below.
refuse_if_occupied() {
  ch >"$work/target" <<SQL || { echo "cannot read system.tables on the target" >&2; exit 7; }
SELECT name, ifNull(total_rows, 0) FROM system.tables WHERE database = '${database}' FORMAT TSVRaw
SQL
  occupied="$(awk -F '\t' '$2 > 0 { printf "%s(%s) ", $1, $2 }' "$work/target")"
  if [ -n "$occupied" ]; then
    echo "target database ${database} already has rows in: ${occupied}" >&2
    echo "restore into an empty ClickHouse, or drop the database first (see docs/disaster-recovery.md)" >&2
    exit 7
  fi
}
refuse_if_occupied

backup_rows="$(awk -F '\t' '{s += $3} END {print s + 0}' "$work/manifest")"
table_count="$(awk 'END {print NR}' "$work/manifest")"
if [ "$dry_run" = 1 ]; then
  printf 'restore_dry_run_ok database=%s tables=%s rows=%s verify_seconds=%s backup=%s\n' \
    "$database" "$table_count" "$backup_rows" "$(($(date +%s) - verify_started))" "$backup_url"
  exit 0
fi

restore_started="$(date +%s)"
restore_id="restore-${database}-$(date -u +%Y%m%dT%H%M%SZ)"

# 4. The target's schema is whatever release first booted it: a PVC created
# by a newer release has tables RESTORE refuses to fill (CANNOT_RESTORE_TABLE)
# when their columns differ from the backup's. Empty, by check 3, the database
# is dropped and rebuilt from the backup's own definitions; its columns are
# kept to report what the release has that the backup lacks.
columns_query="SELECT table, name, type FROM system.columns WHERE database = '${database}' ORDER BY table, position FORMAT TSVRaw"
printf '%s\n' "$columns_query" | ch >"$work/columns_before" || restore_failed "cannot read the target's columns"
# Once more, right before the DROP: an ingest worker left on writes in between.
refuse_if_occupied
ch >/dev/null <<SQL || restore_failed "DROP DATABASE refused"
DROP DATABASE IF EXISTS \`${database}\` SYNC
SQL
dropped=1

# Tables first, so merges can be stopped before the first part lands.
ch >/dev/null <<SQL || restore_failed "RESTORE (structure) refused"
RESTORE DATABASE \`${database}\` FROM ${source} SETTINGS structure_only = 1
SQL
merges_stopped=1
for table in $tables; do
  ch >/dev/null <<SQL || restore_failed "cannot stop merges on ${database}.${table}"
SYSTEM STOP MERGES \`${database}\`.\`${table}\`
SQL
done

ch >/dev/null <<SQL || restore_failed "RESTORE refused"
RESTORE DATABASE \`${database}\` FROM ${source} SETTINGS id = '${restore_id}' ASYNC
SQL
deadline=$((restore_started + CLICKHOUSE_RESTORE_TIMEOUT_SECONDS))
while :; do
  status="$(ch <<SQL
SELECT status FROM system.backups WHERE id = '${restore_id}' FORMAT TSVRaw
SQL
)" || restore_failed "cannot read the RESTORE status"
  case "$status" in
    RESTORED)
      break
      ;;
    RESTORING)
      ;;
    *)
      { ch <<SQL || true; } | head -n 1 >&2
SELECT error FROM system.backups WHERE id = '${restore_id}' FORMAT TSVRaw
SQL
      restore_failed "RESTORE ended with status '${status}'"
      ;;
  esac
  if [ "$(date +%s)" -ge "$deadline" ]; then
    restore_failed "RESTORE still running after ${CLICKHOUSE_RESTORE_TIMEOUT_SECONDS}s (id ${restore_id})"
  fi
  sleep "$CLICKHOUSE_RESTORE_POLL_SECONDS"
done

# 5. What the restored tables hold, against what the manifest says was stored.
query=""
for table in $tables; do
  [ -z "$query" ] || query="${query} UNION ALL "
  query="${query}SELECT '${table}', 0, count() FROM \`${database}\`.\`${table}\`"
done
ch >"$work/restored" <<SQL || restore_failed "cannot count the restored tables"
${query}
FORMAT TSVRaw
SQL
compare "$work/manifest" "$work/restored" restored || restore_failed "restored row counts differ from the manifest"

# 6. What the release that booted this server has and the backup does not (or
# the other way round). Not a failure: ClickHouse has no migrations here —
# init.sql runs on a first boot only — so an older backup restored into a newer
# release needs that release's upgrade step, as an in-place upgrade would.
# An empty server (no database before) has nothing to compare against.
if [ -s "$work/columns_before" ] && printf '%s\n' "$columns_query" | ch >"$work/columns_after"; then
  awk -F '\t' '
    FNR == NR { before[$0] = 1; next }
    { after[$0] = 1 }
    END {
      for (row in before) if (!(row in after)) { split(row, c, "\t"); printf "schema_drift table=%s column=%s type=%s only_in=target\n", c[1], c[2], c[3] }
      for (row in after) if (!(row in before)) { split(row, c, "\t"); printf "schema_drift table=%s column=%s type=%s only_in=backup\n", c[1], c[2], c[3] }
    }
  ' "$work/columns_before" "$work/columns_after" | sort
fi

printf 'restore_success database=%s tables=%s rows=%s restore_seconds=%s backup=%s\n' \
  "$database" "$table_count" "$backup_rows" "$(($(date +%s) - restore_started))" "$backup_url"
