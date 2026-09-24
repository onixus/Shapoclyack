"""Backup and restore beyond Postgres (#333): manifests, scripts, their contracts.

Three layers, none of which needs a cluster or a ClickHouse server:

* the manifests as files — the hardened pod baseline, credentials only ever
  from a Secret, the NetworkPolicy and alert rules that have to move together
  with the CronJob;
* the rendered overlays, when ``kubectl`` is on PATH (the Kustomize CI stage
  renders every overlay; this adds the one invariant that rendering alone does
  not check: a backup CronJob never outlives the datastore it backs up);
* ``clickhouse-backup.sh`` and ``scripts/restore-clickhouse.sh`` driven through
  a stub ``clickhouse-client`` that records every statement and answers from a
  rule table. What is asserted there is the scripts' own logic — the URL they
  build, the order of statements, the verification that refuses a restore, and
  that the S3 secret never reaches argv or output. That the statements do what
  they say against a real server is what ``scripts/dr-drill.py`` measured
  (docs/disaster-recovery.md § Drill).
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
K8S = ROOT / "k8s/shapoclyack"
BACKUP_DIR = K8S / "base/backup"
CH_CRONJOB = BACKUP_DIR / "clickhouse-cronjob.yaml"
PG_CRONJOB = BACKUP_DIR / "postgres-cronjob.yaml"
BACKUP_SCRIPT = BACKUP_DIR / "clickhouse-backup.sh"
RESTORE_SCRIPT = ROOT / "scripts/restore-clickhouse.sh"
NETPOL = K8S / "base/networkpolicy-datastores.yaml"
BACKUP_RULES = K8S / "examples/prometheusrule-backup.example.yaml"
SNAPSHOT_EXAMPLE = K8S / "examples/pvc-snapshot.example.yaml"
CH_STATEFULSET = K8S / "base/clickhouse/statefulset.yaml"

SECRET = "Sup3r'Secret\\Value/+x"
ACCESS_KEY = "AKIADRILLEXAMPLE"
CH_PASSWORD = "ch-pass-never-printed"


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _load_all(path: Path) -> list[dict]:
    return [doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if doc]


def _pod(cronjob: dict) -> dict:
    return cronjob["spec"]["jobTemplate"]["spec"]["template"]["spec"]


# --------------------------------------------------------------------------- #
# The CronJob as a file
# --------------------------------------------------------------------------- #


def test_the_backup_pod_meets_the_hardened_baseline():
    cronjob = _load(CH_CRONJOB)
    pod = _pod(cronjob)
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert pod["securityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}
    volumes = {volume["name"]: volume for volume in pod["volumes"]}
    for container in pod["containers"]:
        context = container["securityContext"]
        assert context["allowPrivilegeEscalation"] is False
        assert context["readOnlyRootFilesystem"] is True
        assert context["capabilities"]["drop"] == ["ALL"]
        assert "add" not in context["capabilities"]
        for mount in container["volumeMounts"]:
            volume = volumes[mount["name"]]
            # With a read-only root, anything writable has to be an emptyDir;
            # the script volume must not be writable at all.
            assert "emptyDir" in volume or mount.get("readOnly") is True, mount


def test_the_backup_cannot_overlap_itself_or_outlive_its_deadline():
    cronjob = _load(CH_CRONJOB)
    assert cronjob["spec"]["concurrencyPolicy"] == "Forbid"
    job = cronjob["spec"]["jobTemplate"]["spec"]
    env = {item["name"]: item for item in _pod(cronjob)["containers"][0]["env"]}
    # The script gives up before Kubernetes kills it, so a slow backup ends
    # with the script's own "reason=timeout" line rather than a bare SIGKILL.
    assert int(env["CLICKHOUSE_BACKUP_TIMEOUT_SECONDS"]["value"]) < job["activeDeadlineSeconds"]


def test_credentials_come_from_secrets_and_never_from_the_command_line():
    cronjob = _load(CH_CRONJOB)
    container = _pod(cronjob)["containers"][0]
    command = " ".join(container.get("command", []) + container.get("args", []))
    for word in ("PASSWORD", "SECRET", "password", "secret", "$("):
        assert word not in command, command
    env = {item["name"]: item for item in container["env"]}
    for name in ("CLICKHOUSE_PASSWORD", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        assert "value" not in env[name], name
        assert "secretKeyRef" in env[name]["valueFrom"], name


def test_the_clickhouse_job_reads_the_same_bucket_secret_as_the_postgres_job():
    def refs(path: Path) -> dict[str, tuple[str, str]]:
        found = {}
        for container in _pod(_load(path)).get("initContainers", []) + _pod(_load(path))["containers"]:
            for item in container.get("env", []):
                ref = item.get("valueFrom", {}).get("secretKeyRef")
                if ref and ref["name"] == "shapoclyack-backup":
                    found[item["name"]] = (ref["name"], ref["key"])
        return found

    clickhouse, postgres = refs(CH_CRONJOB), refs(PG_CRONJOB)
    assert clickhouse == postgres
    assert set(clickhouse) >= {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "S3_BUCKET", "S3_PREFIX"}


def test_the_job_runs_the_script_file_the_kustomization_packages():
    kustomization = _load(BACKUP_DIR / "kustomization.yaml")
    assert "clickhouse-cronjob.yaml" in kustomization["resources"]
    generated = {item["name"]: item for item in kustomization["configMapGenerator"]}
    script_map = generated["shapoclyack-clickhouse-backup-script"]
    assert script_map["files"] == ["clickhouse-backup.sh"]
    # An overlay deletes it by this exact name (kind-restore).
    assert kustomization["generatorOptions"]["disableNameSuffixHash"] is True

    pod = _pod(_load(CH_CRONJOB))
    volumes = {volume["name"]: volume for volume in pod["volumes"]}
    container = pod["containers"][0]
    mount = next(m for m in container["volumeMounts"] if m["mountPath"] == "/opt/shapoclyack")
    assert volumes[mount["name"]]["configMap"]["name"] == "shapoclyack-clickhouse-backup-script"
    assert container["command"] == ["/bin/sh", "/opt/shapoclyack/clickhouse-backup.sh"]


def test_the_client_image_is_the_server_image():
    """BACKUP runs on the server, but the client that issues it and reads the
    manifest back should not be a different ClickHouse release; and an overlay
    that mirrors the server image with ``images:`` must move both."""
    server = _load(CH_STATEFULSET)["spec"]["template"]["spec"]["containers"][0]["image"]
    assert _pod(_load(CH_CRONJOB))["containers"][0]["image"] == server


def test_the_networkpolicy_admits_each_backup_job_to_its_own_datastore_only():
    policies = {doc["metadata"]["name"]: doc for doc in _load_all(NETPOL)}

    def admitted(policy: str) -> dict[str, set[int]]:
        result: dict[str, set[int]] = {}
        for rule in policies[policy]["spec"]["ingress"]:
            ports = {port["port"] for port in rule.get("ports", [])}
            for source in rule.get("from", []):
                component = source["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
                result.setdefault(component, set()).update(ports)
        return result

    clickhouse = admitted("shapoclyack-clickhouse-ingress")
    postgres = admitted("shapoclyack-postgres-ingress")
    assert clickhouse["clickhouse-backup"] == {9000}
    assert "backup" not in clickhouse
    assert "clickhouse-backup" not in postgres
    labels = _load(CH_CRONJOB)["spec"]["jobTemplate"]["spec"]["template"]["metadata"]["labels"]
    assert labels["app.kubernetes.io/component"] == "clickhouse-backup"


def test_the_alert_rules_name_the_cronjobs_that_exist():
    rule = _load(BACKUP_RULES)
    rules = {item["alert"]: item for group in rule["spec"]["groups"] for item in group["rules"]}
    for cronjob, prefix in (
        (_load(CH_CRONJOB), "ShapoclyackClickHouseBackup"),
        (_load(PG_CRONJOB), "ShapoclyackPostgresBackup"),
    ):
        name = cronjob["metadata"]["name"]
        assert f'cronjob="{name}"' in rules[f"{prefix}Stale"]["expr"]
        assert f'job_name=~"{name}-.*"' in rules[f"{prefix}JobFailed"]["expr"]


def test_the_snapshot_example_restores_without_risking_the_source_snapshot():
    docs = _load_all(SNAPSHOT_EXAMPLE)
    content = next(doc for doc in docs if doc["kind"] == "VolumeSnapshotContent")
    assert content["spec"]["deletionPolicy"] == "Retain"
    claim = next(doc for doc in docs if doc["kind"] == "PersistentVolumeClaim")
    assert claim["metadata"]["name"] == "scanner-data"
    assert claim["metadata"]["namespace"] == "shapoclyack-restore"
    assert claim["spec"]["dataSource"]["kind"] == "VolumeSnapshot"
    restored = next(
        doc
        for doc in docs
        if doc["kind"] == "VolumeSnapshot" and doc["metadata"]["namespace"] == "shapoclyack-restore"
    )
    assert restored["spec"]["source"] == {"volumeSnapshotContentName": content["metadata"]["name"]}
    assert claim["spec"]["dataSource"]["name"] == restored["metadata"]["name"]
    source = next(
        doc
        for doc in docs
        if doc["kind"] == "VolumeSnapshot" and doc["metadata"]["namespace"] == "network-scan"
    )
    assert source["spec"]["source"] == {"persistentVolumeClaimName": "scanner-data"}


# --------------------------------------------------------------------------- #
# Rendered overlays
# --------------------------------------------------------------------------- #


def _render(target: str) -> list[dict]:
    kubectl = shutil.which("kubectl")
    if kubectl is None:
        pytest.skip("kubectl not on PATH; the Kustomize CI stage renders every overlay")
    result = subprocess.run(
        [kubectl, "kustomize", str(K8S / target)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def _names(docs: list[dict], kind: str) -> set[str]:
    return {doc["metadata"]["name"] for doc in docs if doc["kind"] == kind}


_OVERLAYS = sorted(path.name for path in (K8S / "overlays").iterdir() if path.is_dir())


@pytest.mark.parametrize("target", ["base", *(f"overlays/{name}" for name in _OVERLAYS)])
def test_no_backup_job_outlives_the_datastore_it_backs_up(target: str):
    """A CronJob whose datastore an overlay removed fails every night — and
    the alert for that is an example an installation may not have applied."""
    docs = _render(target)
    cronjobs = _names(docs, "CronJob")
    statefulsets = _names(docs, "StatefulSet")
    configmaps = _names(docs, "ConfigMap")
    if "shapoclyack-clickhouse-backup" in cronjobs:
        assert "shapoclyack-clickhouse" in statefulsets
        assert "shapoclyack-clickhouse-backup-script" in configmaps
    else:
        assert "shapoclyack-clickhouse-backup-script" not in configmaps, "orphaned script ConfigMap"
    if "shapoclyack-postgres-backup" in cronjobs:
        assert "shapoclyack-postgres" in statefulsets


def test_the_restore_overlay_keeps_clickhouse_and_runs_no_backups():
    docs = _render("overlays/kind-restore")
    assert "shapoclyack-clickhouse" in _names(docs, "StatefulSet")
    assert not {"shapoclyack-clickhouse-backup", "shapoclyack-postgres-backup"} & _names(docs, "CronJob")
    namespaces = {doc["metadata"].get("namespace") for doc in docs if doc["kind"] != "Namespace"}
    assert namespaces <= {"shapoclyack-restore", None}


def test_the_ha_overlay_keeps_the_clickhouse_backup():
    """prod-ha hands Postgres to a managed service and deletes its dump job;
    ClickHouse stays a single in-cluster pod there, so its backup stays too."""
    docs = _render("overlays/prod-ha")
    cronjobs = _names(docs, "CronJob")
    assert "shapoclyack-clickhouse-backup" in cronjobs
    assert "shapoclyack-postgres-backup" not in cronjobs


# --------------------------------------------------------------------------- #
# The scripts, against a stub clickhouse-client
# --------------------------------------------------------------------------- #

_STUB = """#!{python}
import json, os, re, sys

state = os.environ["CH_STUB_DIR"]
sql = sys.stdin.read()
with open(os.path.join(state, "calls.jsonl"), "a", encoding="utf-8") as fh:
    fh.write(json.dumps({{"argv": sys.argv[1:], "sql": sql}}) + "\\n")
with open(os.path.join(state, "rules.json"), encoding="utf-8") as fh:
    rules = json.load(fh)
for index, rule in enumerate(rules):
    if re.search(rule["match"], sql, re.S):
        counter = os.path.join(state, "rule%d.count" % index)
        seen = int(open(counter).read()) if os.path.exists(counter) else 0
        with open(counter, "w") as fh:
            fh.write(str(seen + 1))
        reply = rule["replies"][min(seen, len(rule["replies"]) - 1)]
        sys.stdout.write(reply.get("stdout", ""))
        sys.stderr.write(reply.get("stderr", ""))
        sys.exit(reply.get("exit", 0))
sys.stderr.write("stub: no rule matches\\n")
sys.exit(97)
"""

_KUBECTL = """#!{python}
import json, os, sys

state = os.environ["CH_STUB_DIR"]
args = sys.argv[1:]
with open(os.path.join(state, "kubectl.jsonl"), "a", encoding="utf-8") as fh:
    fh.write(json.dumps(args) + "\\n")
if "get" in args:
    print("shapoclyack-clickhouse-0")
elif "exec" in args:
    rest = args[args.index("--") + 1:]
    assert rest[0] == "clickhouse-client", rest
    os.execv({stub!r}, [{stub!r}] + rest[1:])
"""


class Stub:
    """A ``clickhouse-client`` that logs argv + stdin and answers from rules."""

    def __init__(self, tmp_path: Path, rules: list[tuple[str, list[dict]]]):
        self.dir = tmp_path / "stub"
        self.dir.mkdir()
        self.client = self.dir / "clickhouse-client"
        self.client.write_text(_STUB.format(python=sys.executable), encoding="utf-8")
        self.client.chmod(0o755)
        bindir = self.dir / "bin"
        bindir.mkdir()
        kubectl = bindir / "kubectl"
        kubectl.write_text(
            _KUBECTL.format(python=sys.executable, stub=str(self.client)), encoding="utf-8"
        )
        kubectl.chmod(0o755)
        self.bindir = bindir
        (self.dir / "rules.json").write_text(
            json.dumps([{"match": match, "replies": replies} for match, replies in rules]),
            encoding="utf-8",
        )

    @property
    def calls(self) -> list[dict]:
        path = self.dir / "calls.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    @property
    def statements(self) -> list[str]:
        return [call["sql"] for call in self.calls]

    def env(self, **extra: str) -> dict[str, str]:
        env = {
            "PATH": f"{self.bindir}:{os.environ['PATH']}",
            "CH_STUB_DIR": str(self.dir),
            "CLICKHOUSE_CLIENT": str(self.client),
            "CLICKHOUSE_PASSWORD": CH_PASSWORD,
            "AWS_ACCESS_KEY_ID": ACCESS_KEY,
            "AWS_SECRET_ACCESS_KEY": SECRET,
            "CLICKHOUSE_BACKUP_POLL_SECONDS": "0",
            "CLICKHOUSE_RESTORE_POLL_SECONDS": "0",
        }
        env.update(extra)
        return env


def _run(script: Path, stub: Stub, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", str(script), *args],
        env=stub.env(**env),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def _assert_secret_contained(result: subprocess.CompletedProcess[str], stub: Stub) -> None:
    for text in (result.stdout, result.stderr):
        assert SECRET not in text
        assert CH_PASSWORD not in text
    for call in stub.calls:
        assert not any(SECRET in arg or CH_PASSWORD in arg for arg in call["argv"]), call["argv"]
    kubectl_log = stub.dir / "kubectl.jsonl"
    if kubectl_log.exists():
        assert SECRET not in kubectl_log.read_text(encoding="utf-8")


# The SQL-escaped form of SECRET, as it must appear inside a string literal.
_SECRET_IN_SQL = "Sup3r\\'Secret\\\\Value/+x"

_BACKUP_OK = [
    (r"^BACKUP DATABASE", [{"stdout": "shapoclyack-x\tCREATING_BACKUP\n"}]),
    (r"SELECT status FROM system\.backups", [{"stdout": "CREATING_BACKUP\n"}, {"stdout": "BACKUP_CREATED\n"}]),
    (r"^INSERT INTO FUNCTION s3", [{"stdout": ""}]),
    (r"SELECT count\(\), sum\(rows\)", [{"stdout": "3\t30000\n"}]),
    (r"SELECT num_files", [{"stdout": "42\t1048576\t1000000\n"}]),
]

_BACKUP_ENV = {
    "S3_BUCKET": "drill-backups",
    "S3_PREFIX": "/shapoclyack/prod/",
    "S3_ENDPOINT_URL": "http://minio.storage:9000/",
}


def test_the_backup_issues_an_async_backup_polls_it_and_writes_the_manifest(tmp_path):
    stub = Stub(tmp_path, _BACKUP_OK)
    result = _run(BACKUP_SCRIPT, stub, **_BACKUP_ENV)
    assert result.returncode == 0, result.stderr

    statements = stub.statements
    backup = statements[0]
    assert backup.startswith("BACKUP DATABASE `shapoclyack` TO S3('http://minio.storage:9000/drill-backups/shapoclyack/prod/clickhouse/")
    assert backup.rstrip().endswith("ASYNC")
    assert f"'{ACCESS_KEY}', '{_SECRET_IN_SQL}'" in backup
    # Polled until created, then the manifest, read back, then the sizes.
    assert sum("FROM system.backups" in sql and "status" in sql for sql in statements) == 2
    manifest = next(sql for sql in statements if sql.startswith("INSERT INTO FUNCTION s3"))
    assert "/manifest.jsonl'" in manifest
    assert "/data/shapoclyack/*/*/count.txt'" in manifest
    assert "/.backup'" in manifest

    line = result.stdout.strip().splitlines()[-1]
    assert line.startswith("backup_success ")
    fields = dict(part.split("=", 1) for part in line.split()[1:])
    assert fields["tables"] == "3"
    assert fields["rows"] == "30000"
    assert fields["total_size"] == "1048576"
    assert fields["url"].startswith("http://minio.storage:9000/drill-backups/shapoclyack/prod/clickhouse/")
    _assert_secret_contained(result, stub)


def test_without_an_endpoint_the_backup_goes_to_aws_s3_in_the_configured_region(tmp_path):
    stub = Stub(tmp_path, _BACKUP_OK)
    result = _run(
        BACKUP_SCRIPT, stub, S3_BUCKET="drill-backups", S3_PREFIX="", S3_ENDPOINT_URL="",
        AWS_DEFAULT_REGION="eu-central-1",
    )
    assert result.returncode == 0, result.stderr
    assert stub.statements[0].startswith(
        "BACKUP DATABASE `shapoclyack` TO S3('https://drill-backups.s3.eu-central-1.amazonaws.com/clickhouse/"
    )


@pytest.mark.parametrize("missing", ["CLICKHOUSE_PASSWORD", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "S3_BUCKET"])
def test_the_backup_names_a_missing_setting_and_contacts_nothing(tmp_path, missing):
    stub = Stub(tmp_path, _BACKUP_OK)
    result = _run(BACKUP_SCRIPT, stub, **{**_BACKUP_ENV, missing: ""})
    assert result.returncode == 2
    assert f"setting={missing}" in result.stderr
    assert stub.calls == []


@pytest.mark.parametrize(
    ("name", "value"),
    [("CLICKHOUSE_DATABASE", "shapoclyack; DROP"), ("CLICKHOUSE_DATABASE", "1db"), ("S3_BUCKET", "a/b")],
)
def test_the_backup_refuses_values_it_would_have_to_quote(tmp_path, name, value):
    stub = Stub(tmp_path, _BACKUP_OK)
    result = _run(BACKUP_SCRIPT, stub, **{**_BACKUP_ENV, name: value})
    assert result.returncode == 2
    assert f"setting={name}" in result.stderr
    assert stub.calls == []


def test_a_refused_statement_does_not_print_the_secret_the_client_echoes(tmp_path):
    """clickhouse-client appends the whole statement to an error — here with the
    secret in it, verbatim, exactly as 24.8 does (docs/disaster-recovery.md)."""
    echoed = (
        "Received exception from server (version 24.8.14):\n"
        "Code: 36. DB::Exception: Received from host:9000. DB::Exception: Host is empty in S3 URI.. (BAD_ARGUMENTS)\n"
        f"(query: BACKUP DATABASE `shapoclyack` TO S3('x', '{ACCESS_KEY}', '{SECRET}') ASYNC\n)\n"
    )
    stub = Stub(tmp_path, [(r"^BACKUP DATABASE", [{"stderr": echoed, "exit": 36}])])
    result = _run(BACKUP_SCRIPT, stub, **_BACKUP_ENV)
    assert result.returncode == 1
    assert "Host is empty in S3 URI" in result.stderr
    assert "backup_failed reason=statement_refused" in result.stderr
    assert "(query:" not in result.stderr
    _assert_secret_contained(result, stub)


def test_the_secret_is_masked_even_where_the_client_prints_it_outside_the_query_block(tmp_path):
    stub = Stub(tmp_path, [(r"^BACKUP DATABASE", [{"stderr": f"odd: {SECRET} and {CH_PASSWORD}\n", "exit": 1}])])
    result = _run(BACKUP_SCRIPT, stub, **_BACKUP_ENV)
    assert result.returncode == 1
    assert "odd: [HIDDEN] and [HIDDEN]" in result.stderr
    _assert_secret_contained(result, stub)


def test_a_failed_backup_reports_the_first_line_of_the_server_error(tmp_path):
    rules = [
        (r"^BACKUP DATABASE", [{"stdout": "x\tCREATING_BACKUP\n"}]),
        (r"SELECT status FROM system\.backups", [{"stdout": "BACKUP_FAILED\n"}]),
        (
            r"SELECT error FROM system\.backups",
            [{"stdout": "Code: 499. DB::Exception: The specified bucket does not exist. (S3_ERROR)\n0. DB::Exception::Exception\n"}],
        ),
    ]
    stub = Stub(tmp_path, rules)
    result = _run(BACKUP_SCRIPT, stub, **_BACKUP_ENV)
    assert result.returncode == 1
    assert "The specified bucket does not exist" in result.stderr
    assert "DB::Exception::Exception" not in result.stderr
    assert "status=BACKUP_FAILED" in result.stderr
    assert not any(sql.startswith("INSERT INTO FUNCTION") for sql in stub.statements)


def test_a_backup_that_vanishes_from_system_backups_fails(tmp_path):
    rules = [
        (r"^BACKUP DATABASE", [{"stdout": "x\tCREATING_BACKUP\n"}]),
        (r"SELECT status FROM system\.backups", [{"stdout": ""}]),
    ]
    stub = Stub(tmp_path, rules)
    result = _run(BACKUP_SCRIPT, stub, **_BACKUP_ENV)
    assert result.returncode == 1
    assert "reason=backup_vanished" in result.stderr


def test_a_backup_with_no_tables_is_a_failure_not_a_restore_point(tmp_path):
    rules = [*_BACKUP_OK[:3], (r"SELECT count\(\), sum\(rows\)", [{"stdout": "0\t0\n"}])]
    stub = Stub(tmp_path, rules)
    result = _run(BACKUP_SCRIPT, stub, **_BACKUP_ENV)
    assert result.returncode == 1
    assert "reason=no_tables" in result.stderr
    assert "backup_success" not in result.stdout


# --- restore ---------------------------------------------------------------

_URL = "http://minio.storage:9000/drill-backups/clickhouse/20260924T024500Z"
_SHA = "ab" * 32
_MANIFEST = (
    f"shapoclyack_controls\t0\t0\t{_SHA}\n"
    f"shapoclyack_open_ports\t4\t40000\t{_SHA}\n"
    f"shapoclyack_vulnerabilities\t3\t29992\t{_SHA}\n"
)


def _restore_rules(
    *,
    manifest: str = _MANIFEST,
    observed: str = _MANIFEST,
    target: str = "shapoclyack_controls\t0\nshapoclyack_open_ports\t0\nshapoclyack_vulnerabilities\t0\n",
    restored: str = "shapoclyack_controls\t0\t0\nshapoclyack_open_ports\t0\t40000\nshapoclyack_vulnerabilities\t0\t29992\n",
    restore_status: str = "RESTORED\n",
) -> list[tuple[str, list[dict]]]:
    return [
        (r"manifest\.jsonl", [{"stdout": manifest}]),
        (r"^SELECT\s+t\.table", [{"stdout": observed}]),
        (r"FROM system\.tables", [{"stdout": target}]),
        (r"structure_only = 1", [{"stdout": "x\tRESTORED\n"}]),
        (r"^SYSTEM (STOP|START) MERGES", [{"stdout": ""}]),
        (r"^RESTORE DATABASE .* ASYNC", [{"stdout": "x\tRESTORING\n"}]),
        (r"SELECT status FROM system\.backups", [{"stdout": "RESTORING\n"}, {"stdout": restore_status}]),
        (r"SELECT error FROM system\.backups", [{"stdout": "Code: 1. DB::Exception: broken part\ntrace\n"}]),
        (r"count\(\) FROM", [{"stdout": restored}]),
    ]


def _restore(tmp_path, *args: str, **rules) -> tuple[subprocess.CompletedProcess[str], Stub]:
    stub = Stub(tmp_path, _restore_rules(**rules))
    result = _run(RESTORE_SCRIPT, stub, "--backup-url", _URL, *args)
    _assert_secret_contained(result, stub)
    return result, stub


def test_a_dry_run_verifies_the_backup_and_restores_nothing(tmp_path):
    result, stub = _restore(tmp_path, "--local", "--dry-run")
    assert result.returncode == 0, result.stderr
    assert "restore_dry_run_ok database=shapoclyack tables=3 rows=69992" in result.stdout
    assert result.stdout.count(" ok\n") == 3
    assert not any(sql.startswith(("RESTORE", "SYSTEM")) for sql in stub.statements)


def test_a_row_count_that_differs_from_the_manifest_stops_the_restore(tmp_path):
    observed = _MANIFEST.replace("40000", "39999")
    result, stub = _restore(tmp_path, "--local", observed=observed)
    assert result.returncode == 6
    assert "table=shapoclyack_open_ports manifest_rows=40000 backup_rows=39999 MISMATCH" in result.stdout
    assert not any(sql.startswith("RESTORE") for sql in stub.statements)


def test_a_part_count_that_differs_from_the_manifest_stops_the_restore(tmp_path):
    observed = _MANIFEST.replace("\t4\t40000", "\t5\t40000")
    result, _ = _restore(tmp_path, "--local", observed=observed)
    assert result.returncode == 6


def test_a_manifest_paired_with_another_backup_is_refused_even_when_counts_agree(tmp_path):
    result, _ = _restore(tmp_path, "--local", "--dry-run", observed=_MANIFEST.replace(_SHA, "cd" * 32))
    assert result.returncode == 6
    assert "backup_metadata_sha256" in result.stdout


def test_a_table_the_backup_lacks_stops_the_restore(tmp_path):
    observed = "".join(line + "\n" for line in _MANIFEST.splitlines() if "controls" not in line)
    result, _ = _restore(tmp_path, "--local", "--dry-run", observed=observed)
    assert result.returncode == 6
    assert "table=shapoclyack_controls manifest_rows=0 backup_rows=- MISMATCH" in result.stdout


def test_a_table_name_from_the_manifest_never_reaches_a_statement_unchecked(tmp_path):
    manifest = _MANIFEST + f"x`; DROP DATABASE shapoclyack; --\t1\t1\t{_SHA}\n"
    result, stub = _restore(tmp_path, "--local", manifest=manifest)
    assert result.returncode == 6
    assert "not a plain identifier" in result.stderr
    assert len(stub.statements) == 1


def test_a_target_that_already_holds_rows_is_refused(tmp_path):
    target = "shapoclyack_controls\t0\nshapoclyack_open_ports\t17\nshapoclyack_vulnerabilities\t0\n"
    result, stub = _restore(tmp_path, "--local", target=target)
    assert result.returncode == 7
    assert "shapoclyack_open_ports(17)" in result.stderr
    assert not any(sql.startswith(("RESTORE", "SYSTEM")) for sql in stub.statements)


def test_a_restore_stops_merges_first_verifies_counts_and_starts_them_again(tmp_path):
    result, stub = _restore(tmp_path, "--local")
    assert result.returncode == 0, result.stderr
    assert "restore_success database=shapoclyack tables=3 rows=69992" in result.stdout

    statements = stub.statements
    order = [
        next(i for i, sql in enumerate(statements) if "structure_only = 1" in sql),
        max(i for i, sql in enumerate(statements) if sql.startswith("SYSTEM STOP MERGES")),
        next(i for i, sql in enumerate(statements) if sql.startswith("RESTORE DATABASE") and "ASYNC" in sql),
        next(i for i, sql in enumerate(statements) if "count() FROM" in sql),
        min(i for i, sql in enumerate(statements) if sql.startswith("SYSTEM START MERGES")),
    ]
    assert order == sorted(order), statements
    stopped = {sql.split()[-1] for sql in statements if sql.startswith("SYSTEM STOP MERGES")}
    started = {sql.split()[-1] for sql in statements if sql.startswith("SYSTEM START MERGES")}
    assert stopped == started == {
        "`shapoclyack`.`shapoclyack_controls`",
        "`shapoclyack`.`shapoclyack_open_ports`",
        "`shapoclyack`.`shapoclyack_vulnerabilities`",
    }


def test_restored_counts_that_differ_fail_the_restore_and_merges_still_restart(tmp_path):
    restored = "shapoclyack_controls\t0\t0\nshapoclyack_open_ports\t0\t39000\nshapoclyack_vulnerabilities\t0\t29992\n"
    result, stub = _restore(tmp_path, "--local", restored=restored)
    assert result.returncode == 8
    assert "table=shapoclyack_open_ports manifest_rows=40000 restored_rows=39000 MISMATCH" in result.stdout
    assert sum(sql.startswith("SYSTEM START MERGES") for sql in stub.statements) == 3


def test_a_failed_restore_reports_the_server_error_and_restarts_merges(tmp_path):
    result, stub = _restore(tmp_path, "--local", restore_status="RESTORE_FAILED\n")
    assert result.returncode == 8
    assert "broken part" in result.stderr
    assert "trace" not in result.stderr
    assert sum(sql.startswith("SYSTEM START MERGES") for sql in stub.statements) == 3


def test_a_restore_through_kubectl_runs_the_client_in_the_clickhouse_pod(tmp_path):
    result, stub = _restore(tmp_path, "--namespace", "shapoclyack-restore", "--dry-run")
    assert result.returncode == 0, result.stderr
    calls = [
        json.loads(line)
        for line in (stub.dir / "kubectl.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    execs = [call for call in calls if "exec" in call]
    assert execs
    for call in execs:
        assert call[:6] == ["-n", "shapoclyack-restore", "exec", "-i", "shapoclyack-clickhouse-0", "-c"]
        assert call[call.index("--") + 1:] == ["clickhouse-client", "--user", "default"]


def test_the_production_namespace_needs_an_explicit_override(tmp_path):
    stub = Stub(tmp_path, _restore_rules())
    result = _run(RESTORE_SCRIPT, stub, "--backup-url", _URL, "--namespace", "network-scan", "--dry-run")
    assert result.returncode == 3
    assert stub.calls == []
    allowed = _run(
        RESTORE_SCRIPT, stub, "--backup-url", _URL, "--namespace", "network-scan", "--dry-run",
        ALLOW_PRODUCTION_RESTORE="1",
    )
    assert allowed.returncode == 0, allowed.stderr


@pytest.mark.parametrize("missing", ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"])
def test_the_restore_needs_the_bucket_credentials(tmp_path, missing):
    stub = Stub(tmp_path, _restore_rules())
    result = _run(RESTORE_SCRIPT, stub, "--backup-url", _URL, "--local", **{missing: ""})
    assert result.returncode == 2
    assert missing in result.stderr
    assert stub.calls == []


def test_the_backup_and_the_restore_count_a_backup_the_same_way():
    """The restore's step 2 recounts what the backup job counted into the
    manifest; if the two queries drift apart, every restore reports a mismatch
    (or worse, two wrong counts agree)."""
    backup = BACKUP_SCRIPT.read_text(encoding="utf-8")
    restore = RESTORE_SCRIPT.read_text(encoding="utf-8")
    for fragment in (
        "FROM s3('${url_q}/metadata/${db}/*.sql', ${creds}, 'RawBLOB')",
        "FROM s3('${url_q}/data/${db}/*/*/count.txt', ${creds}, 'LineAsString')",
        "sum(toUInt64(line)) AS rows",
        "(SELECT lower(hex(SHA256(raw_blob))) FROM s3('${url_q}/.backup', ${creds}, 'RawBLOB'))",
        "decodeURLComponent(left(name, length(name) - 4)) AS table",
        "decodeURLComponent(splitByChar('/', _path)[-3]) AS table",
    ):
        assert fragment in backup, fragment
        assert fragment.replace("${db}", "${database}") in restore, fragment


# --------------------------------------------------------------------------- #
# The drill
# --------------------------------------------------------------------------- #


def _drill():
    """``scripts/dr-drill.py`` as a module; the hyphen keeps it off ``import``."""
    if "dr_drill" not in sys.modules:
        spec = importlib.util.spec_from_file_location("dr_drill", ROOT / "scripts/dr-drill.py")
        module = importlib.util.module_from_spec(spec)
        # Registered before exec: @dataclass resolves the module by name.
        sys.modules["dr_drill"] = module
        spec.loader.exec_module(module)
    return sys.modules["dr_drill"]


def test_the_drill_dumps_and_restores_with_the_flags_production_uses():
    """A drill that dumps differently from the CronJob measures something else."""
    drill = _drill()
    cronjob = PG_CRONJOB.read_text(encoding="utf-8")
    for flag in drill.PG_DUMP_FLAGS:
        assert flag in cronjob, flag
    restore = (ROOT / "scripts/restore-postgres.sh").read_text(encoding="utf-8")
    for flag in drill.PG_RESTORE_FLAGS:
        assert flag in restore, flag
    assert drill.BACKUP_SCRIPT == BACKUP_SCRIPT
    assert drill.RESTORE_CLICKHOUSE == RESTORE_SCRIPT


def test_the_drill_drops_nothing_unless_told_to(capsys):
    code = _drill().main(["--postgres-url", "postgresql://drill@localhost/drill", "--s3-bucket", "b"])
    assert code == 2
    assert "--destroy-and-restore" in capsys.readouterr().err


def test_the_drill_takes_its_credentials_from_the_environment_only(capsys, monkeypatch):
    for name in ("CLICKHOUSE_PASSWORD", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.delenv(name, raising=False)
    drill = _drill()
    code = drill.main(
        ["--destroy-and-restore", "--postgres-url", "postgresql://drill@localhost/drill", "--s3-bucket", "b"]
    )
    assert code == 2
    assert "CLICKHOUSE_PASSWORD, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY" in capsys.readouterr().err
    options = {action.dest for action in drill.build_parser()._actions}
    assert not {dest for dest in options if "password" in dest or "secret" in dest}
