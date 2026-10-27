#!/usr/bin/env python3
"""Disposable Docker control-plane recovery drill; never targets an existing stack.

Uses an explicit schema-echo fixture provider, not a language model. Every container
and the internal network has a random task-owned name and is removed afterward.
No ports are published and no network scan is executed.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
IMAGE = re.compile(r"(?:sha256:[a-f0-9]{64}|[a-z0-9][a-z0-9._/:-]*:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64})")
PROVIDER = '''import json,time
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*a): pass
 def do_POST(self):
  request=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
  response_format=request.get('response_format',{})
  wrapper=response_format.get('json_schema',{});schema=wrapper.get('schema',{})
  expected=schema.get('properties',{}).get('summary',{}).get('const')
  if response_format.get('type')!='json_schema' or wrapper.get('strict') is not True or schema.get('additionalProperties') is not False or not isinstance(expected,str):
   self.send_error(422);return
  path=Path('/drill/count'); count=int(path.read_text()) if path.exists() else 0
  path.write_text(str(count+1))
  time.sleep(float(Path('/drill/delay').read_text()))
  body=json.dumps({'choices':[{'finish_reason':'stop','message':{'content':json.dumps({'summary':expected})}}]}).encode()
  try:
   self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  except (BrokenPipeError,ConnectionResetError): pass
ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
'''
HTTP = '''import json,sys,urllib.request,urllib.error
data=json.loads(sys.stdin.read()); headers={'Content-Type':'application/json'}
if data.get('token'): headers['Authorization']='Bearer '+data['token']
if data.get('key'): headers['Idempotency-Key']=data['key']
request=urllib.request.Request('http://127.0.0.1:8080'+data['path'],
 data=json.dumps(data['body']).encode() if 'body' in data else None,
 headers=headers,method=data['method'])
try:
 response=urllib.request.urlopen(request,timeout=15)
except urllib.error.HTTPError as error: response=error
body=response.read()
try: value=json.loads(body) if body else None
except ValueError: value=None
print(json.dumps({'status':response.status,'body':value}))
'''
SEED = '''import json
from datetime import UTC,datetime
from api.settings import load_settings
from api.db import models,tenant_scope
from api.db.engine import get_session
from api.services import artifact_store,scan_scopes,tenants
from api.services.artifact_store import keys
s=load_settings();tenant_scope.configure(s);tenants.configure(s)
now=datetime.now(UTC).replace(tzinfo=None)
with tenant_scope.system('disposable operator drill source'),get_session(s.postgres_url) as db:
 db.add(models.Job(job_id='drill-source-job',tenant_id='default',run_id='drill-source',status='succeeded',queued_at=now,finished_at=now))
store=artifact_store.get_store(s);ref=keys.run_ref('drill-source','default')
for name,value in {'tenant.json':{'tenant_id':'default','job_id':'drill-source-job','publication_id':'drill-publication'},'summary.json':{'alive_hosts':1,'open_host_port_pairs':2}}.items():
 store.put_bytes(keys.run_artifact(ref,name),json.dumps(value).encode())
with tenant_scope.system('disposable operator drill scope'):
 scan_scopes.replace_scope(s,tenant_id='default',entries=[{'effect':'allow','kind':'cidr','value':'127.0.0.1/32'}],approved_by='operator-drill')
'''


def checked_image(value):
    if not IMAGE.fullmatch(value):
        raise argparse.ArgumentTypeError("Use a local image ID or name:tag@sha256 digest")
    return value


class Drill:
    def __init__(self, app_image, postgres_image, directory):
        self.app_image, self.postgres_image = app_image, postgres_image
        self.directory = Path(directory)
        self.source_root = self.directory / "source"
        self.prefix = "shapo-operator-drill-" + secrets.token_hex(6)
        self.network = self.prefix + "-network"
        self.containers = []
        self.network_created = False
        self.password = secrets.token_hex(24)
        self.login_password = secrets.token_urlsafe(32)
        self.report = {"schema_version": 1, "profile": "disposable_control_plane_with_fixture_provider",
            "source_revision": self.run(["git", "rev-parse", "HEAD"]).decode().strip(),
            "working_tree_dirty": bool(self.run(["git", "status", "--porcelain"])),
            "app_image": app_image, "postgres_image": postgres_image,
            "language_model_invoked": False, "network_scan_executed": False,
            "phases": [], "cleanup": False}

    def run(self, argv, *, data=None, timeout=120):
        result = subprocess.run(argv, input=data, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, cwd=ROOT)
        if result.returncode:
            # Keep a bounded diagnosis without exposing private connection URLs.
            lines = result.stderr.decode(errors="replace").splitlines()
            detail = lines[-1] if lines else "no diagnostic"
            for key in ("password", "login_password", "jwt_secret", "master_key"):
                secret = getattr(self, key, None)
                if secret:
                    detail = detail.replace(secret, "[redacted]")
            raise RuntimeError("Command failed: " + Path(argv[0]).name + ": " + detail[:500])
        return result.stdout + result.stderr if argv[:2] == ["docker", "logs"] else result.stdout

    def docker(self, *args, data=None, timeout=120):
        return self.run(["docker", *args], data=data, timeout=timeout)

    def phase(self, name, action):
        started = time.monotonic()
        result = action()
        self.report["phases"].append({"name": name, "status": "passed",
            "seconds": round(time.monotonic() - started, 3), "evidence": result})

    def add(self, suffix, image, *args, env_file=None, volumes=(), alias=None, postgres=False):
        name = self.prefix + "-" + suffix
        argv = ["run", "--detach", "--pull=never", "--name", name,
            "--label", "shapoclyack.operator-drill=" + self.prefix,
            "--network", self.network, "--network-alias", alias or suffix,
            "--memory", "768m", "--cpus", "1", "--pids-limit", "256"]
        if env_file:
            argv.extend(["--env-file", str(env_file)])
        if postgres:
            argv.extend(["--tmpfs", "/var/lib/postgresql/data:size=512m"])
        for source, target, mode in volumes:
            argv.extend(["-v", str(source) + ":" + target + ":" + mode])
        argv.extend([image, *args])
        self.docker(*argv)
        self.containers.append(name)
        return name

    def environment(self, filename, *, pg="pg", enabled=True):
        values = {"OCTO_ENV": "dev", "PYTHONDONTWRITEBYTECODE": "1",
            "OCTO_API_HOST": "0.0.0.0", "OCTO_API_PORT": "8080",
            "OCTO_OUTPUT_DIR": "/drill/output", "OCTO_STATE_DIR": "/drill/state",
            "OCTO_POSTGRES_URL": "postgresql+psycopg://operator_drill:" + self.password + "@" + pg + ":5432/operator_drill",
            "OCTO_API_USERS": json.dumps([{"username": "operator-drill", "password": self.login_password, "role": "admin"}]),
            "OCTO_JWT_SECRET": self.jwt_secret, "OCTO_MASTER_KEY": self.master_key,
            "OCTO_ALLOW_SCAN_START": "true", "OCTO_JOB_EXECUTION_MODE": "agent",
            "OCTO_OPERATOR_ENABLED": str(enabled).lower(), "OCTO_OPERATOR_WORKER_ENABLED": str(enabled).lower(),
            "OCTO_OPERATOR_PROVIDER": "local", "OCTO_OPERATOR_ALLOW_EXTERNAL": "false",
            "OCTO_OPERATOR_MODEL": "operator-drill-fixture", "OCTO_OPERATOR_BASE_URL": self.provider_url,
            "OCTO_OPERATOR_TIMEOUT_SECONDS": "90", "OCTO_OPERATOR_WORKER_LEASE_SECONDS": "150",
            "OCTO_OPERATOR_WORKER_POLL_SECONDS": "0.1", "OCTO_AGENT_TOKEN": ""}
        for feature in ("NATS_OUTBOX", "CH_INGEST", "SCHEDULER_DISPATCH", "REPORT_DISPATCH", "REPORTS",
                "SOFTWARE_MATCH", "RETRO_MATCH", "SLA_ESCALATION", "JOB_REAPER",
                "RUN_PUBLICATION_WORKER", "WEBHOOKS", "WEBHOOK_DISPATCH", "WEBHOOK_FANOUT",
                "TICKET_SYNC", "ENDPOINT_NATS_EVENTS", "NOTIFICATION_CHANNELS",
                "RUN_RETENTION", "RISK_SNAPSHOT_RETENTION", "SCREENSHOT_RETENTION",
                "ENDPOINT_RETENTION", "TENANT_PURGE", "ASSET_CONNECTOR", "ASSET_GROUP_WORKER"):
            values["OCTO_" + feature + "_ENABLED"] = "false"
        path = self.directory / filename
        path.write_text("".join(key + "=" + value + "\n" for key, value in values.items()))
        path.chmod(0o600)
        return path

    def app(self, suffix, command, *, env_file=None, output=None):
        volumes = [(self.source_root / name, "/app/" + name, "ro") for name in ("api", "scanner", "agent")]
        volumes.extend([(self.directory / "state", "/drill/state", "rw"),
            (output or self.directory / "output", "/drill/output", "rw")])
        return self.add(suffix, self.app_image, "python", *command,
            env_file=env_file or self.env_file, volumes=volumes)

    def wait(self, check, *, timeout=90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                result = check()
                if result:
                    return result
            except (RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired):
                pass
            time.sleep(.25)
        raise RuntimeError("Drill readiness deadline exceeded")

    def request(self, path, *, method="GET", body=None, key=None, token=True, api=None):
        values = {"path": path, "method": method}
        if body is not None:
            values["body"] = body
        if key:
            values["key"] = key
        if token and getattr(self, "token", None):
            values["token"] = self.token
        raw = self.docker("exec", "-i", api or self.api, "python", "-c", HTTP,
            data=json.dumps(values).encode(), timeout=25)
        return json.loads(raw)

    def expect(self, response, status=200):
        if response["status"] != status:
            raise RuntimeError("Unexpected drill HTTP status " + str(response["status"]))
        return response["body"]

    def task(self, key):
        return self.expect(self.request("/api/operator/sessions/" + self.session_id + "/tasks?tenant_id=default",
            method="POST", body={"tool": "summarize_run", "run_id": "drill-source", "language": "en"}, key=key), 202)

    def poll(self, task_id, statuses):
        # One exec, many HTTP polls: repeatedly creating Docker exec instances
        # under Desktop disk pressure can stall the control-plane daemon itself.
        code = '''import json,sys,time,urllib.request
data=json.loads(sys.stdin.read());deadline=time.monotonic()+90
while time.monotonic()<deadline:
 request=urllib.request.Request('http://127.0.0.1:8080'+data['path'],headers={'Authorization':'Bearer '+data['token']})
 with urllib.request.urlopen(request,timeout=5) as response: value=json.load(response)
 if value['status'] in data['statuses']:
  print(json.dumps(value));break
 time.sleep(.25)
else: raise TimeoutError('Task did not reach requested state')
'''
        payload = {"path": "/api/operator/tasks/" + task_id + "?tenant_id=default",
            "token": self.token, "statuses": sorted(statuses)}
        return json.loads(self.docker("exec", "-i", self.api, "python", "-c", code,
            data=json.dumps(payload).encode(), timeout=115))

    def count(self):
        return int((self.directory / "provider" / "count").read_text())

    def setup(self):
        # Freeze the application tree before migrations so another developer
        # editing the shared checkout cannot change a live drill's code/schema.
        manifest = []
        files = self.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"]).decode().split("\0")
        for relative in sorted(set(files)):
            if not relative.startswith(("api/", "scanner/", "agent/")):
                continue
            source = ROOT / relative
            if source.is_symlink():
                raise RuntimeError("Refusing symlink in drill source snapshot")
            if source.is_file():
                target = self.source_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
                manifest.append([relative, sha256(target.read_bytes()).hexdigest()])
        self.report["source_snapshot_sha256"] = sha256(json.dumps(manifest, separators=(",", ":")).encode()).hexdigest()
        for image in (self.app_image, self.postgres_image):
            self.docker("image", "inspect", image)
        self.docker("network", "create", "--internal", "--label", "shapoclyack.operator-drill=" + self.prefix, self.network)
        self.network_created = True
        for directory in ("state", "output", "provider"):
            path = self.directory / directory
            path.mkdir()
            path.chmod(0o777)
        (self.directory / "provider" / "provider.py").write_text(PROVIDER)
        (self.directory / "provider" / "delay").write_text("0")
        (self.directory / "provider" / "count").write_text("0")
        (self.directory / "provider" / "count").chmod(0o666)
        pg_env = self.directory / "pg.env"
        pg_env.write_text("POSTGRES_USER=operator_drill\nPOSTGRES_DB=operator_drill\nPOSTGRES_PASSWORD=" + self.password + "\n")
        pg_env.chmod(0o600)
        self.pg = self.add("postgres", self.postgres_image, env_file=pg_env, alias="pg", postgres=True)
        self.wait(lambda: self.docker("exec", self.pg, "pg_isready", "-U", "operator_drill", "-d", "operator_drill"))
        provider = self.add("provider", self.app_image, "python", "/drill/provider.py",
            volumes=[(self.directory / "provider", "/drill", "rw")])
        inspected = json.loads(self.docker("inspect", provider))[0]
        address = inspected["NetworkSettings"]["Networks"][self.network]["IPAddress"]
        self.provider_url = "http://" + address + ":8080/v1"
        self.jwt_secret, self.master_key = secrets.token_hex(32), secrets.token_hex(32)
        self.env_file = self.environment("app.env")
        migration = self.app("migrate", ["-m", "api.db.migrate"])
        if self.docker("wait", migration).strip() != b"0":
            raise RuntimeError("Drill migration failed")
        self.api = self.app("api", ["-m", "api"])
        self.wait(lambda: self.request("/api/health", token=False)["status"] == 200)
        credentials = self.expect(self.request("/api/auth/login", method="POST", token=False,
            body={"username": "operator-drill", "password": self.login_password}))
        self.token = credentials["access_token"]
        self.docker("exec", self.api, "python", "-c", SEED)
        self.session_id = self.expect(self.request("/api/operator/sessions?tenant_id=default", method="POST", body={}), 201)["session_id"]
        return {"network_internal": True, "published_ports": [], "provider": "fixed_response_fixture"}

    def queue_cancel(self):
        task = self.task("drill-queued-cancel")
        assert task["status"] == "queued"
        value = self.expect(self.request("/api/operator/tasks/" + task["task_id"] + "/cancel?tenant_id=default", method="POST", body={}))
        assert value["status"] == "cancelled" and self.count() == 0
        return {"terminal": "cancelled", "provider_calls": 0}

    def restart(self):
        queued = self.task("drill-restart")
        assert queued["status"] == "queued"
        self.docker("restart", self.api)
        self.wait(lambda: self.request("/api/health")["status"] == 200)
        assert self.expect(self.request("/api/operator/tasks/" + queued["task_id"] + "?tenant_id=default"))["status"] == "queued"
        self.worker = self.app("worker", ["-m", "api.services.local_operator.worker"])
        value = self.poll(queued["task_id"], {"succeeded", "failed"})
        assert value["status"] == "succeeded" and self.count() == 1
        self.saved_task = queued["task_id"]
        self.saved_result_sha256 = sha256(json.dumps(value["result"], sort_keys=True).encode()).hexdigest()
        self.docker("restart", self.worker)
        time.sleep(1)
        replay = self.task("drill-restart")
        assert replay["task_id"] == self.saved_task and self.count() == 1
        return {"api_restart": True, "worker_restart": True, "terminal": "succeeded", "provider_calls": 1,
            "result_sha256": self.saved_result_sha256}

    def running_cancel(self):
        (self.directory / "provider" / "delay").write_text("60")
        before = self.count()
        task = self.task("drill-running-cancel")
        self.poll(task["task_id"], {"running"})
        self.wait(lambda: self.count() == before + 1)
        self.expect(self.request("/api/operator/tasks/" + task["task_id"] + "/cancel?tenant_id=default", method="POST", body={}))
        value = self.poll(task["task_id"], {"cancelled", "failed"})
        assert value["status"] == "cancelled" and value["result"] is None
        return {"terminal": "cancelled", "result_published": False}

    def crash(self):
        before = self.count()
        task = self.task("drill-worker-crash")
        self.poll(task["task_id"], {"running"})
        self.wait(lambda: self.count() == before + 1)
        self.docker("kill", "--signal", "KILL", self.worker)
        code = '''from datetime import UTC,datetime,timedelta
from api.settings import load_settings
from api.db import models
from api.db.engine import get_session
s=load_settings()
with get_session(s.postgres_url) as db:
 row=db.get(models.OperatorTask,TASK_ID);row.lease_until=datetime.now(UTC).replace(tzinfo=None)-timedelta(seconds=1)
'''.replace("TASK_ID", repr(task["task_id"]))
        self.docker("exec", self.api, "python", "-c", code)
        self.docker("start", self.worker)
        value = self.poll(task["task_id"], {"interrupted", "failed"})
        assert value["status"] == "interrupted" and value["result"] is None
        time.sleep(1)
        assert self.count() == before + 1
        (self.directory / "provider" / "delay").write_text("0")
        return {"signal": "SIGKILL", "lease_expiry_accelerated_in_test_database": True,
            "terminal": "interrupted", "automatic_replay": False}

    def backup_restore(self):
        self.docker("stop", "--time", "15", self.worker)
        dump = self.docker("exec", self.pg, "pg_dump", "-U", "operator_drill", "-d", "operator_drill", "-Fc", "--no-owner", "--no-acl")
        self.backup_sha256 = sha256(dump).hexdigest()
        backup_path = self.directory / "operator.dump"
        backup_path.write_bytes(dump)
        backup_path.chmod(0o600)
        restored_output = self.directory / "restored-output"
        shutil.copytree(self.directory / "output", restored_output)
        restored_output.chmod(0o777)
        pg = self.add("restore-postgres", self.postgres_image, env_file=self.directory / "pg.env", alias="pgrestore", postgres=True)
        self.wait(lambda: self.docker("exec", pg, "pg_isready", "-U", "operator_drill", "-d", "operator_drill"))
        env = self.environment("restore.env", pg="pgrestore")
        migration = self.app("restore-migrate", ["-m", "api.db.migrate"], env_file=env)
        assert self.docker("wait", migration).strip() == b"0"
        self.docker("exec", "-i", pg, "pg_restore", "-U", "operator_drill", "-d", "operator_drill",
            "--clean", "--if-exists", "--no-owner", "--no-acl", "--exit-on-error", data=dump)
        api = self.app("restored-api", ["-m", "api"], env_file=env, output=restored_output)
        self.wait(lambda: self.request("/api/health", api=api)["status"] == 200)
        value = self.expect(self.request("/api/operator/tasks/" + self.saved_task + "?tenant_id=default", api=api))
        assert sha256(json.dumps(value["result"], sort_keys=True).encode()).hexdigest() == self.saved_result_sha256
        assert self.expect(self.request("/api/operator/sessions/" + self.session_id + "?tenant_id=default", api=api))["session_id"] == self.session_id
        return {"dump_sha256": self.backup_sha256, "dump_bytes": len(dump),
            "restore_into_distinct_database_container": True, "artifact_copy": True,
            "restored_result_sha256": self.saved_result_sha256, "existing_console_session_restored": True}

    def rollback(self):
        self.docker("stop", "--time", "15", self.api)
        down = self.app("schema-rollback", ["-m", "alembic", "-c", "api/db/alembic.ini", "downgrade", "0100_asset_groups"])
        assert self.docker("wait", down).strip() == b"0"
        up = self.app("schema-upgrade", ["-m", "api.db.migrate"])
        assert self.docker("wait", up).strip() == b"0"
        self.docker("start", self.api)
        self.wait(lambda: self.request("/api/health")["status"] == 200)
        value = self.expect(self.request("/api/operator/tasks/" + self.saved_task + "?tenant_id=default"))
        assert value["status"] == "succeeded"
        return {"rollback_target": "0100_asset_groups", "upgrade_target": "head",
            "traffic_stopped_during_schema_changes": True, "retained_task": "succeeded",
            "nonreserved_effect_evidence_present": False}

    def disable_delete(self):
        env = self.environment("disabled.env", enabled=False)
        api = self.app("disabled-api", ["-m", "api"], env_file=env)
        self.wait(lambda: self.request("/api/health", api=api)["status"] == 200)
        assert self.request("/api/operator/status?tenant_id=default", api=api)["status"] == 404
        result = self.expect(self.request("/api/jobs?tenant_id=default", method="POST", api=api,
            key="drill-disabled-ordinary-scan", body={"ranges": "127.0.0.1", "ports": "80", "mode": "safe"}), 202)
        assert result["status"] == "queued"
        self.expect(self.request("/api/operator/sessions/" + self.session_id + "?tenant_id=default", method="DELETE"), 204)
        assert self.request("/api/operator/tasks/" + self.saved_task + "?tenant_id=default")["status"] == 404
        return {"disabled_operator_status": 404, "ordinary_scan_control_plane": "queued_without_executor",
            "network_scan_executed": False, "session_deleted": True, "old_task_status": 404}

    def cleanup(self):
        pending = []
        for name in reversed(self.containers):
            try:
                self.docker("rm", "--force", "--volumes", name, timeout=20)
            except (RuntimeError, subprocess.TimeoutExpired):
                pending.append(name)
        if self.network_created:
            try:
                self.docker("network", "rm", self.network, timeout=20)
            except (RuntimeError, subprocess.TimeoutExpired):
                pending.append(self.network)
        self.report["cleanup"] = not pending
        self.report["cleanup_pending_resources"] = pending
        if pending:
            self.report["status"] = "failed"
            self.report["cleanup_error"] = "Docker cleanup incomplete; remove only the listed task-owned resources"

    def diagnose(self):
        diagnostics = {}
        for name in self.containers:
            if not name.endswith(("-api", "-worker", "-provider")):
                continue
            try:
                output = self.docker("logs", "--tail", "25", name, timeout=10).decode(errors="replace")
                for key in ("password", "login_password", "jwt_secret", "master_key"):
                    output = output.replace(getattr(self, key, "") or "<unconfigured-secret>", "[redacted]")
                diagnostics[name.rsplit("-", 1)[-1]] = output[-4000:]
            except (RuntimeError, subprocess.TimeoutExpired):
                diagnostics[name.rsplit("-", 1)[-1]] = "Docker diagnostic unavailable"
        self.report["fixture_diagnostics"] = diagnostics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-image", required=True, type=checked_image)
    parser.add_argument("--postgres-image", required=True, type=checked_image)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if args.report.is_symlink() or args.report.exists():
        parser.error("Report must be a new regular file")
    directory = tempfile.mkdtemp(prefix="operator-acceptance-")
    try:
        drill = Drill(args.app_image, args.postgres_image, directory)
        try:
            for name, action in (("isolated_setup", drill.setup), ("queued_cancellation", drill.queue_cancel),
                ("api_worker_restart", drill.restart), ("running_cancellation", drill.running_cancel),
                ("worker_crash_recovery", drill.crash), ("backup_restore", drill.backup_restore),
                ("schema_rollback_upgrade", drill.rollback), ("feature_disable_and_delete", drill.disable_delete)):
                print(name + ": running", flush=True)
                drill.report["current_phase"] = name
                drill.phase(name, action)
                args.report.write_text(json.dumps(drill.report, indent=2, sort_keys=True) + "\n")
                print(name + ": passed", flush=True)
            drill.report["status"] = "passed"
        except Exception as error:
            drill.report["status"] = "failed"
            drill.report["error_type"] = type(error).__name__
            drill.diagnose()
            args.report.write_text(json.dumps(drill.report, indent=2, sort_keys=True) + "\n")
            raise
        finally:
            drill.cleanup()
            if not drill.report["cleanup"]:
                drill.report["temporary_directory"] = directory
            args.report.write_text(json.dumps(drill.report, indent=2, sort_keys=True) + "\n")
    finally:
        # Preserve private recovery material while Docker still owns a mount.
        # The caller receives its task-only resource list and private path.
        if 'drill' in locals() and drill.report["cleanup"]:
            shutil.rmtree(directory)
    return 0 if drill.report["status"] == "passed" and drill.report["cleanup"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
