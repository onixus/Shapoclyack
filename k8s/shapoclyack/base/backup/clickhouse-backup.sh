#!/bin/sh
# ClickHouse native backup to S3 (#333).
#
# Run by the shapoclyack-clickhouse-backup CronJob (mounted from the ConfigMap
# this directory's kustomization generates), and by scripts/dr-drill.py against
# a local server — one script, so the drill exercises what the cluster runs.
#
# The BACKUP itself is executed by the ClickHouse server, which uploads the
# parts straight to the bucket; this pod only issues the statement, waits for
# it, and writes a manifest (per-table part and row counts read back from the
# uploaded backup) that scripts/restore-clickhouse.sh verifies against.
#
# Every backup is a full one. An incremental (`base_backup`) cannot outlive its
# base, so a bucket lifecycle rule that expires by age would silently break the
# chain; and these tables are ReplacingMergeTree, whose merges rewrite parts, so
# the saving decays between merges anyway (measured in docs/disaster-recovery.md).
#
# Credentials: CLICKHOUSE_PASSWORD is read by clickhouse-client from the
# environment; the S3 key pair has to travel inside the statement, because
# the server is the one talking to S3. It is written to the client's stdin,
# never to argv. The server masks the secret in system.backups, query_log and
# its own log, but clickhouse-client appends the full statement to any error it
# prints, so every byte the client writes goes through scrub() first.
set -eu
umask 077

CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-shapoclyack-clickhouse-client}"
CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-9000}"
CLICKHOUSE_USER="${CLICKHOUSE_USER:-default}"
CLICKHOUSE_DATABASE="${CLICKHOUSE_DATABASE:-shapoclyack}"
CLICKHOUSE_CLIENT="${CLICKHOUSE_CLIENT:-clickhouse-client}"
CLICKHOUSE_BACKUP_TIMEOUT_SECONDS="${CLICKHOUSE_BACKUP_TIMEOUT_SECONDS:-3000}"
CLICKHOUSE_BACKUP_POLL_SECONDS="${CLICKHOUSE_BACKUP_POLL_SECONDS:-10}"

fail() {
  echo "backup_failed $*" >&2
  exit "${exit_code:-1}"
}

# Names the variable, never its value.
require() {
  eval "value=\${$1:-}"
  [ -n "$value" ] || { exit_code=2; fail "reason=missing_setting setting=$1"; }
}

require CLICKHOUSE_PASSWORD
require AWS_ACCESS_KEY_ID
require AWS_SECRET_ACCESS_KEY
require S3_BUCKET

case "$CLICKHOUSE_DATABASE" in
  ''|[0-9]*|*[!A-Za-z0-9_]*)
    exit_code=2
    fail "reason=invalid_setting setting=CLICKHOUSE_DATABASE"
    ;;
esac
case "$S3_BUCKET" in
  */*|*"'"*|*\\*)
    exit_code=2
    fail "reason=invalid_setting setting=S3_BUCKET"
    ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Masks the S3 secret and the ClickHouse password wherever they appear, and
# drops the "(query: …)" block clickhouse-client appends to an error — the
# statement it echoes there carries the S3 secret in plain text.
scrub() {
  awk '
    BEGIN {
      n = 0
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

# SQL on stdin, result on stdout. Word splitting of CLICKHOUSE_CLIENT is
# deliberate: the drill runs the single-binary `clickhouse client`.
ch() {
  # shellcheck disable=SC2086
  if $CLICKHOUSE_CLIENT --host "$CLICKHOUSE_HOST" --port "$CLICKHOUSE_PORT" \
      --user "$CLICKHOUSE_USER" >"$work/out" 2>"$work/err"; then
    scrub <"$work/err" >&2
    scrub <"$work/out"
    return 0
  fi
  scrub <"$work/err" >&2
  return 1
}

# The body of a ClickHouse string literal. The value comes in on stdin, so a
# secret never becomes an argument of sed.
sql_quote() {
  sed -e 's/\\/\\\\/g' -e "s/'/\\\\'/g"
}

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_id="${CLICKHOUSE_DATABASE}-${stamp}"
db="$CLICKHOUSE_DATABASE"

prefix="${S3_PREFIX:-}"
prefix="${prefix#/}"
prefix="${prefix%/}"
path="clickhouse/${stamp}"
if [ -n "$prefix" ]; then
  path="${prefix}/${path}"
fi
if [ -n "${S3_ENDPOINT_URL:-}" ]; then
  # MinIO, Ceph RGW and friends: path-style, same endpoint the Postgres job uses.
  backup_url="${S3_ENDPOINT_URL%/}/${S3_BUCKET}/${path}"
else
  backup_url="https://${S3_BUCKET}.s3.${AWS_DEFAULT_REGION:-us-east-1}.amazonaws.com/${path}"
fi

url_q="$(printf '%s' "$backup_url" | sql_quote)"
key_q="$(printf '%s' "$AWS_ACCESS_KEY_ID" | sql_quote)"
secret_q="$(printf '%s' "$AWS_SECRET_ACCESS_KEY" | sql_quote)"
creds="'${key_q}', '${secret_q}'"

started="$(date +%s)"
printf 'backup_started id=%s database=%s url=%s\n' "$backup_id" "$db" "$backup_url"

# ASYNC and a poll rather than one long statement: a synchronous BACKUP of a
# large database outlives the client's receive_timeout, and system.backups is
# where the server reports the outcome either way.
ch >/dev/null <<SQL || fail "reason=statement_refused id=${backup_id}"
BACKUP DATABASE \`${db}\` TO S3('${url_q}', ${creds}) SETTINGS id = '${backup_id}' ASYNC
SQL

deadline=$((started + CLICKHOUSE_BACKUP_TIMEOUT_SECONDS))
while :; do
  status="$(ch <<SQL
SELECT status FROM system.backups WHERE id = '${backup_id}' FORMAT TSVRaw
SQL
)" || fail "reason=status_unreadable id=${backup_id}"
  case "$status" in
    BACKUP_CREATED)
      break
      ;;
    CREATING_BACKUP)
      ;;
    '')
      # The row lives in server memory: gone means the server restarted.
      fail "reason=backup_vanished id=${backup_id}"
      ;;
    *)
      # The message, not the server's stack trace under it.
      { ch <<SQL || true; } | head -n 1 >&2
SELECT error FROM system.backups WHERE id = '${backup_id}' FORMAT TSVRaw
SQL
      fail "reason=backup_status status=${status} id=${backup_id}"
      ;;
  esac
  if [ "$(date +%s)" -ge "$deadline" ]; then
    fail "reason=timeout seconds=${CLICKHOUSE_BACKUP_TIMEOUT_SECONDS} id=${backup_id}"
  fi
  sleep "$CLICKHOUSE_BACKUP_POLL_SECONDS"
done

# The manifest is read back from the bucket, not from the live tables: rows
# inserted while the backup ran are in the tables and not in the backup, and a
# count taken from the backup itself is also the proof that it is readable.
# count.txt is per part, so these are row counts before ReplacingMergeTree
# deduplication — exactly what a restored table reports until it merges.
ch >/dev/null <<SQL || fail "reason=manifest_not_written id=${backup_id}"
INSERT INTO FUNCTION s3('${url_q}/manifest.jsonl', ${creds}, 'JSONEachRow')
SELECT
    '${backup_id}' AS backup_id,
    '${db}' AS database,
    t.table AS table,
    c.parts AS parts,
    c.rows AS rows,
    (SELECT lower(hex(SHA256(raw_blob))) FROM s3('${url_q}/.backup', ${creds}, 'RawBLOB')) AS backup_metadata_sha256,
    version() AS server_version,
    toString(now()) AS written_at
FROM
(
    SELECT decodeURLComponent(left(name, length(name) - 4)) AS table
    FROM
    (
        SELECT splitByChar('/', _path)[-1] AS name
        FROM s3('${url_q}/metadata/${db}/*.sql', ${creds}, 'RawBLOB')
    )
) AS t
LEFT JOIN
(
    SELECT
        decodeURLComponent(splitByChar('/', _path)[-3]) AS table,
        count() AS parts,
        sum(toUInt64(line)) AS rows
    FROM s3('${url_q}/data/${db}/*/*/count.txt', ${creds}, 'LineAsString')
    GROUP BY table
) AS c USING (table)
SQL

summary="$(ch <<SQL
SELECT count(), sum(rows)
FROM s3('${url_q}/manifest.jsonl', ${creds}, 'JSONEachRow', 'table String, rows UInt64')
FORMAT TSVRaw
SQL
)" || fail "reason=manifest_unreadable id=${backup_id}"
tables="$(printf '%s\n' "$summary" | awk -F '\t' '{print $1}')"
rows="$(printf '%s\n' "$summary" | awk -F '\t' '{print $2}')"
[ "${tables:-0}" -gt 0 ] || fail "reason=no_tables database=${db} id=${backup_id}"

sizes="$(ch <<SQL
SELECT num_files, total_size, compressed_size FROM system.backups WHERE id = '${backup_id}' FORMAT TSVRaw
SQL
)" || sizes=""
printf 'backup_success id=%s database=%s url=%s tables=%s rows=%s files=%s total_size=%s compressed_size=%s seconds=%s\n' \
  "$backup_id" "$db" "$backup_url" "$tables" "$rows" \
  "$(printf '%s\n' "$sizes" | awk -F '\t' '{print $1}')" \
  "$(printf '%s\n' "$sizes" | awk -F '\t' '{print $2}')" \
  "$(printf '%s\n' "$sizes" | awk -F '\t' '{print $3}')" \
  "$(($(date +%s) - started))"
