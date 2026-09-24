#!/usr/bin/env python3
"""Disaster-recovery drill on a local stack: seed → back up → wipe → restore → verify (#333).

Runs the artifacts the cluster runs, not look-alikes: the Postgres dump uses
the CronJob's ``pg_dump`` flags and the restore uses ``scripts/restore-postgres.sh``'s
``pg_restore`` flags followed by the API's own migrate step; ClickHouse goes
through ``k8s/shapoclyack/base/backup/clickhouse-backup.sh`` (the file the
CronJob mounts) and ``scripts/restore-clickhouse.sh --local``. What it cannot
reproduce here is the cluster around them — pod scheduling, PVC provisioning,
image pulls — so its RTO is the data path's, and docs/disaster-recovery.md
says what to add for a cluster.

    CLICKHOUSE_PASSWORD=… AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=… \\
    python3 scripts/dr-drill.py --destroy-and-restore \\
        --postgres-url postgresql://postgres@localhost:5432/shapo_drill \\
        --clickhouse-client "clickhouse client" --clickhouse-port 9000 --clickhouse-http-port 8123 \\
        --s3-endpoint http://127.0.0.1:9000 --s3-bucket drill-backups \\
        [--nats-url nats://127.0.0.1:4222] --assets 10000 --out drill.json

With ``--nats-url`` it also runs the two JetStream legs of the runbook: a run
ingested *after* the ClickHouse backup is lost with ClickHouse and recovered by
replaying the INGEST stream into the restored tables, and a JetStream whose
streams are gone is recreated by the API on connect.

**Destructive.** It drops and recreates the Postgres database named in
``--postgres-url``, the ClickHouse database ``shapoclyack`` and, with
``--nats-url``, the JOBS/INGEST/EVENTS streams; it refuses to start without
``--destroy-and-restore``. Point it at a stand, never at an installation.

Every phase records wall-clock seconds and the CPU seconds of the processes it
started (``RUSAGE_CHILDREN``); with ``--clickhouse-pid`` also the ClickHouse
server's own CPU, which is where BACKUP and RESTORE actually run. Postgres
server CPU is not captured — its backends are not children of this process —
so the ``pg_dump``/``pg_restore`` rows undercount the server side. The load
average is recorded per phase because a shared machine makes wall clock a
statement about the neighbours as much as about the drill.

Credentials come from the environment (CLICKHOUSE_PASSWORD, AWS_ACCESS_KEY_ID,
AWS_SECRET_ACCESS_KEY) and are handed to children the same way; none is ever
an argument. Exit status: 0 verified, 1 a phase failed or a check differed,
2 bad invocation.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import resource
import secrets
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parent.parent
BACKUP_SCRIPT = ROOT / "k8s/shapoclyack/base/backup/clickhouse-backup.sh"
RESTORE_CLICKHOUSE = ROOT / "scripts/restore-clickhouse.sh"
CLICKHOUSE_INIT = ROOT / "k8s/shapoclyack/base/clickhouse/init-local.sql"
CLICKHOUSE_DATABASE = "shapoclyack"
DRILL_USER = "dr-drill"
TENANT = "scale-test"
STREAMS = ("JOBS", "INGEST", "EVENTS")
CH_INGEST_CONSUMER = "octo-ch-ingest-results"

# The CronJob's flags (base/backup/postgres-cronjob.yaml) and the restore
# script's (scripts/restore-postgres.sh). Kept literal so a diff against those
# files is the review.
PG_DUMP_FLAGS = ["--format=custom", "--compress=6", "--no-owner", "--no-privileges"]
PG_RESTORE_FLAGS = ["--clean", "--if-exists", "--no-owner", "--no-privileges", "--exit-on-error"]

# One scan's worth of results, published the way the API publishes an accepted
# run (results_ingest.publish_raw_results). Hosts are outside the seed's
# 10.0.0.0/8 so the rows are countable by run_id and by nothing else.
_PUBLISH_RUN = """
import io, json, sys, tarfile
from api.services import results_ingest

run_id, hosts = sys.argv[1], int(sys.argv[2])
nats_url, tenant = sys.argv[3], sys.argv[4]
index = 0 if run_id.endswith("a") else 1
addresses = [f"172.16.{index}.{n}" for n in range(1, hosts + 1)]
files = {
    "vulnerabilities.json": json.dumps(
        [{"host": ip, "port": "443", "cve": "CVE-2024-3094", "cvss": 10.0, "severity": "critical"}
         for ip in addresses]
    ).encode(),
    "open_ports.txt": "".join(f"{ip}:443/tcp\\n{ip}:22/tcp\\n" for ip in addresses).encode(),
    "run_meta.json": json.dumps({"started_at": "2026-09-24T02:00:00Z"}).encode(),
}
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tf:
    for name, data in files.items():
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
result = results_ingest.publish_raw_results(
    nats_url=nats_url, job_id="job-" + run_id, run_id=run_id, agent_id="dr-drill",
    exit_code=0, archive_bytes=buf.getvalue(), tenant_id=tenant,
)
if not result["published"]:
    raise SystemExit("publish refused")
"""

# JetStream administration the runbook does with the `nats` CLI, done with the
# client library the API already ships.
_JETSTREAM = """
import asyncio, json, sys
import nats
from nats.js.errors import NotFoundError

async def main(url, action, names):
    nc = await nats.connect(url, connect_timeout=5)
    js = nc.jetstream()
    out = {}
    for name in names:
        try:
            if action == "delete-stream":
                await js.delete_stream(name)
            elif action == "delete-consumer":
                stream, consumer = name.split(":")
                await js.delete_consumer(stream, consumer)
            elif action == "info":
                info = await js.stream_info(name)
                cfg = info.config
                out[name] = {
                    "subjects": cfg.subjects,
                    "retention": str(cfg.retention),
                    "max_age": cfg.max_age,
                    "duplicate_window": cfg.duplicate_window,
                    "messages": info.state.messages,
                }
        except NotFoundError:
            out[name] = None
    await nc.close()
    print(json.dumps(out))

asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3:]))
"""


@dataclass
class Phase:
    name: str
    wall_seconds: float = 0.0
    child_cpu_seconds: float = 0.0
    clickhouse_server_cpu_seconds: float | None = None
    load_before: tuple[float, float, float] = (0.0, 0.0, 0.0)
    load_after: tuple[float, float, float] = (0.0, 0.0, 0.0)
    detail: dict[str, Any] = field(default_factory=dict)


class DrillError(RuntimeError):
    pass


def _children_cpu() -> float:
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def _process_cpu(pid: int | None) -> float | None:
    """utime + stime of a running process, from /proc (Linux)."""
    if pid is None:
        return None
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    except OSError:
        return None
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


class Drill:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.phases: list[Phase] = []
        self.work = Path(tempfile.mkdtemp(prefix="dr-drill-"))
        parsed = urllib.parse.urlsplit(args.postgres_url)
        self.pg_db = parsed.path.lstrip("/")
        if not self.pg_db:
            raise DrillError("--postgres-url must name a database")
        self.pg_url = args.postgres_url
        self.pg_admin_url = urllib.parse.urlunsplit(parsed._replace(path="/postgres"))
        self.sqlalchemy_url = args.postgres_url.replace("postgresql://", "postgresql+psycopg://", 1)
        self.ch_password = os.environ["CLICKHOUSE_PASSWORD"]
        self.api_password = secrets.token_urlsafe(24)
        self.api_boots = 0

    # --- plumbing -----------------------------------------------------------

    @contextlib.contextmanager
    def phase(self, name: str) -> Iterator[Phase]:
        record = Phase(name=name, load_before=os.getloadavg())
        cpu = _children_cpu()
        server = _process_cpu(self.args.clickhouse_pid)
        started = time.monotonic()
        print(f"[drill] {name} ...", flush=True)
        status = "failed"
        try:
            yield record
            status = "done"
        finally:
            record.wall_seconds = round(time.monotonic() - started, 3)
            record.child_cpu_seconds = round(_children_cpu() - cpu, 3)
            after = _process_cpu(self.args.clickhouse_pid)
            if server is not None and after is not None:
                record.clickhouse_server_cpu_seconds = round(after - server, 3)
            record.load_after = os.getloadavg()
            self.phases.append(record)
            print(
                f"[drill] {name} {status}: wall {record.wall_seconds}s, "
                f"child cpu {record.child_cpu_seconds}s, "
                f"clickhouse server cpu {record.clickhouse_server_cpu_seconds}s",
                flush=True,
            )

    def run(self, argv: list[str], *, stdin: str | None = None, **env: str) -> str:
        result = subprocess.run(
            argv,
            input=stdin,
            env={**os.environ, **env},
            capture_output=True,
            text=True,
            check=False,
            cwd=ROOT,
        )
        if result.returncode != 0:
            raise DrillError(
                f"{shlex.join(argv[:3])}… exited {result.returncode}:\n{result.stderr[-2000:]}"
            )
        return result.stdout

    def ch(self, sql: str) -> str:
        argv = [
            *shlex.split(self.args.clickhouse_client),
            "--host", self.args.clickhouse_host,
            "--port", str(self.args.clickhouse_port),
            "--user", "default",
            "--multiquery",
        ]
        return self.run(argv, stdin=sql)

    def ch_env(self, **extra: str) -> dict[str, str]:
        return {
            "CLICKHOUSE_CLIENT": self.args.clickhouse_client,
            "CLICKHOUSE_HOST": self.args.clickhouse_host,
            "CLICKHOUSE_PORT": str(self.args.clickhouse_port),
            **extra,
        }

    def pg(self, sql: str, *, admin: bool = False) -> list[tuple]:
        import psycopg

        with psycopg.connect(self.pg_admin_url if admin else self.pg_url, autocommit=True) as conn:
            cursor = conn.execute(sql)
            return cursor.fetchall() if cursor.description else []

    def jetstream(self, action: str, *names: str) -> dict[str, Any]:
        out = self.run([sys.executable, "-c", _JETSTREAM, self.args.nats_url, action, *names])
        return json.loads(out)

    def api_env(self, *, nats: bool = False) -> dict[str, str]:
        http = f"http://default:{self.ch_password}@{self.args.clickhouse_host}:{self.args.clickhouse_http_port}"
        return {
            "OCTO_ENV": "dev",
            "OCTO_POSTGRES_URL": self.sqlalchemy_url,
            "OCTO_CLICKHOUSE_URL": http,
            "OCTO_NATS_URL": self.args.nats_url if nats else "",
            "OCTO_CH_INGEST_ENABLED": "true",
            "OCTO_OUTPUT_DIR": str(self.work / "output"),
            "OCTO_STATE_DIR": str(self.work / "state"),
            "PYTHONPATH": str(ROOT),
        }

    @contextlib.contextmanager
    def api(self, *, nats: bool = False) -> Iterator[tuple[str, float]]:
        """A running API; yields its base URL and how long /readyz took."""
        self.api_boots += 1
        base = f"http://127.0.0.1:{self.args.api_port}"
        log_path = self.work / f"api-{self.api_boots}.log"
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                [sys.executable, "-m", "api"],
                cwd=ROOT,
                env={
                    **os.environ,
                    "OCTO_API_HOST": "127.0.0.1",
                    "OCTO_API_PORT": str(self.args.api_port),
                    **self.api_env(nats=nats),
                },
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            try:
                started = time.monotonic()
                while True:
                    try:
                        with urllib.request.urlopen(f"{base}/readyz", timeout=2) as response:
                            if response.status == 200:
                                break
                    except (urllib.error.URLError, OSError):
                        pass
                    if process.poll() is not None or time.monotonic() - started > 300:
                        raise DrillError(f"API did not become ready; log: {log_path}")
                    time.sleep(0.5)
                yield base, round(time.monotonic() - started, 3)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    def wait_for(self, what: str, check, timeout: float = 180.0) -> float:
        started = time.monotonic()
        while not check():
            if time.monotonic() - started > timeout:
                raise DrillError(f"timed out waiting for {what}")
            time.sleep(0.5)
        return round(time.monotonic() - started, 3)

    def run_rows(self, run_id: str) -> int:
        return int(self.ch(
            f"SELECT count() FROM shapoclyack.shapoclyack_open_ports FINAL WHERE run_id = '{run_id}' FORMAT TSVRaw"
        ).strip())

    # --- the stores ---------------------------------------------------------

    def reset(self) -> None:
        with self.phase("reset") as record:
            self.pg(f'DROP DATABASE IF EXISTS "{self.pg_db}" WITH (FORCE)', admin=True)
            self.pg(f'CREATE DATABASE "{self.pg_db}"', admin=True)
            self.run([sys.executable, "-m", "api.db.migrate"], **self.api_env())
            self.ch(f"DROP DATABASE IF EXISTS {CLICKHOUSE_DATABASE} SYNC")
            self.ch(CLICKHOUSE_INIT.read_text(encoding="utf-8"))
            if self.args.nats_url:
                self.jetstream("delete-stream", *STREAMS)
            record.detail["alembic_head"] = self.pg("SELECT version_num FROM alembic_version")[0][0]

    def seed(self) -> None:
        with self.phase("seed") as record:
            out = self.run(
                [sys.executable, "-m", "tests.fixtures.scale_seed", "--assets", str(self.args.assets),
                 "--tenant", TENANT, "--json"],
                **self.api_env(),
            )
            record.detail["seed"] = json.loads(out.strip().splitlines()[-1])
            self.run(
                [sys.executable, "-c",
                 "import os\n"
                 "from api.services import users\n"
                 "from api.settings import load_settings\n"
                 "users.configure(load_settings())\n"
                 f"users.create_user(username={DRILL_USER!r}, password=os.environ['DRILL_PASSWORD'],"
                 " role='admin', created_by='scripts/dr-drill.py')\n"],
                DRILL_PASSWORD=self.api_password,
                **self.api_env(),
            )
            # Merge now, so the drill backs up what a quiet installation at
            # 02:45 has — merged parts — rather than a fresh insert's part count.
            self.ch(
                "OPTIMIZE TABLE shapoclyack.shapoclyack_vulnerabilities FINAL;"
                "OPTIMIZE TABLE shapoclyack.shapoclyack_open_ports FINAL;"
            )

    def ingest(self, name: str, run_id: str) -> None:
        """Publish one run through INGEST and wait until ClickHouse has it."""
        with self.phase(name) as record, self.api(nats=True) as (_, ready):
            self.run(
                [sys.executable, "-c", _PUBLISH_RUN, run_id, str(self.args.run_hosts), self.args.nats_url, TENANT],
                **self.api_env(nats=True),
            )
            record.detail["ready_seconds"] = ready
            record.detail["ingest_seconds"] = self.wait_for(
                f"{run_id} in ClickHouse", lambda: self.run_rows(run_id) == 2 * self.args.run_hosts
            )

    def fingerprint(self) -> dict[str, Any]:
        tables = [
            row[0]
            for row in self.pg(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename"
            )
        ]
        counts = {table: self.pg(f'SELECT count(*) FROM "{table}"')[0][0] for table in tables}
        digests = {}
        for table, key in (("assets", "asset_id"), ("asset_identifiers", "tenant_id, identifier_type, identifier_value"),
                           ("tenants", "tenant_id"), ("users", "username")):
            digests[table] = self.pg(
                f"SELECT md5(coalesce(string_agg(t::text, '|' ORDER BY {key}), '')) FROM \"{table}\" t"
            )[0][0]
        return {"postgres_counts": counts, "postgres_md5": digests, "clickhouse": self.clickhouse_fingerprint()}

    def clickhouse_fingerprint(self) -> dict[str, Any]:
        # FINAL, because the restored tables and the source may be at different
        # merge states; what has to match is the deduplicated content.
        result = {}
        for table in self.ch(
            "SELECT name FROM system.tables WHERE database = 'shapoclyack' ORDER BY name FORMAT TSVRaw"
        ).split():
            count, digest = self.ch(
                f"SELECT count(), sum(cityHash64(*)) FROM shapoclyack.`{table}` FINAL FORMAT TSVRaw"
            ).split()
            result[table] = {"rows_final": int(count), "cityhash_sum": digest}
        return result

    # --- backup -------------------------------------------------------------

    def backup(self) -> tuple[Path, Path, str]:
        dump = self.work / "shapoclyack.dump"
        checksum = self.work / "shapoclyack.dump.sha256"
        with self.phase("backup_postgres") as record:
            self.run(["pg_dump", f"--dbname={self.pg_url}", *PG_DUMP_FLAGS, f"--file={dump}"])
            digest = hashlib.sha256(dump.read_bytes()).hexdigest()
            checksum.write_text(f"{digest}  {dump.name}\n", encoding="utf-8")
            record.detail["dump_bytes"] = dump.stat().st_size
            record.detail["backup_timestamp_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self.phase("backup_clickhouse") as record:
            out = self.run(
                ["sh", str(BACKUP_SCRIPT)],
                **self.ch_env(
                    CLICKHOUSE_BACKUP_POLL_SECONDS="1",
                    S3_ENDPOINT_URL=self.args.s3_endpoint,
                    S3_BUCKET=self.args.s3_bucket,
                    S3_PREFIX=self.args.s3_prefix,
                ),
            )
            line = next(item for item in out.splitlines() if item.startswith("backup_success "))
            fields = dict(part.split("=", 1) for part in line.split()[1:])
            record.detail.update(fields)
        return dump, checksum, fields["url"]

    def wipe(self) -> None:
        # The ClickHouse half is what a new PVC gives: an empty server whose
        # entrypoint runs init.sql once. The Postgres half is an empty cluster.
        # JetStream is left alone here: the INGEST replay below is the case
        # where the broker survived the datastores.
        with self.phase("wipe"):
            self.pg(f'DROP DATABASE "{self.pg_db}" WITH (FORCE)', admin=True)
            self.ch(f"DROP DATABASE {CLICKHOUSE_DATABASE} SYNC")
            self.ch(CLICKHOUSE_INIT.read_text(encoding="utf-8"))

    # --- restore ------------------------------------------------------------

    def restore(self, dump: Path, checksum: Path, backup_url: str) -> None:
        with self.phase("restore_postgres") as record:
            expected = checksum.read_text(encoding="utf-8").split()[0]
            if hashlib.sha256(dump.read_bytes()).hexdigest() != expected:
                raise DrillError("dump checksum mismatch")
            self.pg(f'CREATE DATABASE "{self.pg_db}"', admin=True)
            started = time.monotonic()
            self.run(["pg_restore", f"--dbname={self.pg_url}", *PG_RESTORE_FLAGS, str(dump)])
            record.detail["pg_restore_seconds"] = round(time.monotonic() - started, 3)
            started = time.monotonic()
            self.run([sys.executable, "-m", "api.db.migrate"], **self.api_env())
            record.detail["migrate_seconds"] = round(time.monotonic() - started, 3)
        with self.phase("restore_clickhouse_dry_run") as record:
            out = self.run(
                ["sh", str(RESTORE_CLICKHOUSE), "--local", "--dry-run", "--backup-url", backup_url],
                **self.ch_env(),
            )
            record.detail["result"] = out.strip().splitlines()[-1]
        with self.phase("restore_clickhouse") as record:
            out = self.run(
                ["sh", str(RESTORE_CLICKHOUSE), "--local", "--backup-url", backup_url],
                **self.ch_env(CLICKHOUSE_RESTORE_POLL_SECONDS="1"),
            )
            record.detail["result"] = out.strip().splitlines()[-1]

    def serve(self) -> dict[str, Any]:
        """Boot the API on the restored stores and read the tenant's assets back."""
        with self.phase("api_boot_and_serve") as record, self.api() as (base, ready):
            record.detail["ready_seconds"] = ready
            token = self._post(f"{base}/api/auth/login", {"username": DRILL_USER, "password": self.api_password})[
                "access_token"
            ]
            headers = {"Authorization": f"Bearer {token}"}
            page = self._get(f"{base}/api/assets?tenant_id={TENANT}&limit=5", headers)
            health = self._get(f"{base}/api/health", headers)
            record.detail["assets_total"] = page["total"]
            record.detail["assets_returned"] = len(page["items"])
            record.detail["health_checks"] = {
                name: check.get("status") if isinstance(check, dict) else check
                for name, check in (health.get("checks") or {}).items()
            }
        return record.detail

    def replay_ingest(self, target: dict[str, Any]) -> dict[str, Any]:
        """Close the gap between the ClickHouse backup and the disaster from INGEST.

        The durable consumer's cursor is past every message ingested before the
        disaster, so the restored tables would never see them again. Deleting
        it makes the API recreate it at DeliverPolicy.ALL — a replay of what
        the stream retains, idempotent on ReplacingMergeTree keys.
        """
        with self.phase("clickhouse_ingest_replay") as record:
            record.detail["run_b_rows_after_restore"] = self.run_rows("dr-drill-run-b")
            self.jetstream("delete-consumer", f"INGEST:{CH_INGEST_CONSUMER}")
            with self.api(nats=True) as (_, ready):
                record.detail["ready_seconds"] = ready
                record.detail["replay_seconds"] = self.wait_for(
                    "INGEST replay", lambda: self.clickhouse_fingerprint() == target
                )
            record.detail["run_b_rows_after_replay"] = self.run_rows("dr-drill-run-b")
        return record.detail

    def recreate_jetstream(self) -> dict[str, Any]:
        """A lost JetStream volume: no streams at all. The API recreates them."""
        with self.phase("jetstream_recreate") as record:
            self.jetstream("delete-stream", *STREAMS)
            with self.api(nats=True) as (_, ready):
                record.detail["ready_seconds"] = ready
                record.detail["streams"] = self.jetstream("info", *STREAMS)
        return record.detail

    @staticmethod
    def _post(url: str, body: dict) -> dict:
        request = urllib.request.Request(
            url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read())

    @staticmethod
    def _get(url: str, headers: dict[str, str]) -> dict:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
            return json.loads(response.read())

    # --- the whole thing ----------------------------------------------------

    def environment(self) -> dict[str, Any]:
        settings = {
            name: self.pg(f"SHOW {name}")[0][0]
            for name in ("server_version", "fsync", "synchronous_commit", "full_page_writes", "shared_buffers")
        }
        return {
            "host": platform.node(),
            "kernel": platform.release(),
            "cpus": os.cpu_count(),
            "python": platform.python_version(),
            "postgres": settings,
            "clickhouse_version": self.ch("SELECT version() FORMAT TSVRaw").strip(),
            "s3_endpoint": self.args.s3_endpoint or "aws",
            "nats_url": self.args.nats_url or None,
        }

    def execute(self) -> dict[str, Any]:
        nats = bool(self.args.nats_url)
        if not self.args.skip_seed:
            self.reset()
            self.seed()
        if nats:
            self.ingest("ingest_run_a_before_backup", "dr-drill-run-a")
        environment = self.environment()
        before = self.fingerprint()
        dump, checksum, backup_url = self.backup()
        at_disaster = before["clickhouse"]
        if nats:
            self.ingest("ingest_run_b_after_backup", "dr-drill-run-b")
            at_disaster = self.clickhouse_fingerprint()
        self.wipe()
        self.restore(dump, checksum, backup_url)
        after = self.fingerprint()
        served = self.serve()

        problems = [f"{section} differs after restore" for section in before if before[section] != after[section]]
        if served.get("assets_total") != before["postgres_counts"].get("assets"):
            problems.append(
                f"API served {served.get('assets_total')} assets, the source had {before['postgres_counts'].get('assets')}"
            )
        result: dict[str, Any] = {}
        if nats:
            replay = self.replay_ingest(at_disaster)
            if replay["run_b_rows_after_replay"] != 2 * self.args.run_hosts:
                problems.append("INGEST replay did not bring run B back")
            streams = self.recreate_jetstream()["streams"]
            missing = [name for name in STREAMS if not streams.get(name)]
            if missing:
                problems.append(f"streams not recreated: {missing}")

        by_name = {phase.name: phase for phase in self.phases}
        rto_phases = ("restore_postgres", "restore_clickhouse_dry_run", "restore_clickhouse", "api_boot_and_serve")
        critical = ("restore_postgres", "api_boot_and_serve")
        result.update({
            "environment": environment,
            "assets": self.args.assets,
            "phases": [asdict(phase) for phase in self.phases],
            "rto_seconds_sequential": round(sum(by_name[name].wall_seconds for name in rto_phases), 3),
            "rto_seconds_console_critical_path": round(sum(by_name[name].wall_seconds for name in critical), 3),
            "fingerprint_source": before,
            "fingerprint_restored": after,
            "clickhouse_at_disaster": at_disaster,
            "verified": not problems,
            "problems": problems,
        })
        return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--destroy-and-restore", action="store_true",
                        help="required: acknowledges that the databases (and streams) are dropped")
    parser.add_argument("--postgres-url", required=True, help="libpq URL of the drill database")
    parser.add_argument("--clickhouse-client", default="clickhouse-client",
                        help='client command, split like a shell would ("clickhouse client")')
    parser.add_argument("--clickhouse-host", default="127.0.0.1")
    parser.add_argument("--clickhouse-port", type=int, default=9000)
    parser.add_argument("--clickhouse-http-port", type=int, default=8123)
    parser.add_argument("--clickhouse-pid", type=int, default=None,
                        help="server pid, to record the CPU BACKUP and RESTORE spend there")
    parser.add_argument("--s3-endpoint", default="", help="empty for AWS S3")
    parser.add_argument("--s3-bucket", required=True)
    parser.add_argument("--s3-prefix", default="dr-drill")
    parser.add_argument("--nats-url", default="", help="also run the JetStream legs (drops its streams)")
    parser.add_argument("--run-hosts", type=int, default=50, help="hosts in each run published through INGEST")
    parser.add_argument("--assets", type=int, default=10000)
    parser.add_argument("--api-port", type=int, default=18080)
    parser.add_argument("--skip-seed", action="store_true", help="back up what is already there")
    parser.add_argument("--out", type=Path, default=None, help="write the JSON result here")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.destroy_and_restore:
        print("refusing: this drops and restores the databases; pass --destroy-and-restore", file=sys.stderr)
        return 2
    missing = [name for name in ("CLICKHOUSE_PASSWORD", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
               if not os.environ.get(name)]
    if missing:
        print(f"missing environment: {', '.join(missing)}", file=sys.stderr)
        return 2
    try:
        result = Drill(args).execute()
    except DrillError as exc:
        print(f"[drill] FAILED: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(result, indent=2, sort_keys=True, default=str)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
