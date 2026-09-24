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

import base64
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
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
DR_DOC = ROOT / "docs/disaster-recovery.md"
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


def _secret_refs(path: Path, secret: str) -> dict[str, str]:
    """``{env name: key}`` for every variable a job's pod reads from ``secret``."""
    pod = _pod(_load(path))
    found = {}
    for container in pod.get("initContainers", []) + pod["containers"]:
        for item in container.get("env", []):
            ref = item.get("valueFrom", {}).get("secretKeyRef")
            if ref and ref["name"] == secret:
                found[item["name"]] = ref["key"]
    return found


def test_the_clickhouse_job_has_a_bucket_key_of_its_own():
    """The same Secret *shape* as the Postgres job, not the same Secret. A key
    scoped to PREFIX/clickhouse/* cannot overwrite or delete the Postgres
    dumps — and BACKUP needs s3:DeleteObject for its own `.lock` object, which
    on the shared key would mean delete rights over every dump too."""
    clickhouse = _secret_refs(CH_CRONJOB, "shapoclyack-clickhouse-backup-s3")
    assert clickhouse == _secret_refs(PG_CRONJOB, "shapoclyack-backup")
    assert set(clickhouse) >= {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "S3_BUCKET", "S3_PREFIX"}
    assert _secret_refs(CH_CRONJOB, "shapoclyack-backup") == {}


def test_the_backup_job_signs_in_as_its_own_clickhouse_user():
    """Not `default`: that is the API's account, with DDL, DROP and url()."""
    env = {item["name"]: item for item in _pod(_load(CH_CRONJOB))["containers"][0]["env"]}
    assert env["CLICKHOUSE_USER"]["value"] == "shapoclyack_backup"
    assert env["CLICKHOUSE_PASSWORD"]["valueFrom"]["secretKeyRef"] == {
        "name": "shapoclyack-clickhouse-backup",
        "key": "password",
    }
    assert _secret_refs(CH_CRONJOB, "shapoclyack-clickhouse") == {}


def _users_xml() -> ET.Element:
    configmap = _load(K8S / "base/clickhouse/configmap.yaml")
    return ET.fromstring(configmap["data"]["users.xml"])


def test_the_backup_user_holds_only_what_a_backup_needs():
    """Measured on 24.8.14: BACKUP ON the database for the BACKUP, S3 plus
    CREATE TEMPORARY TABLE for the s3() reads and the manifest INSERT, SELECT on
    system.backups for the poll — and it is refused SELECT on the tables, DROP,
    INSERT, url(), RESTORE, SYSTEM and user management."""
    users = _users_xml().find("users")
    backup = users.find("shapoclyack_backup")
    assert backup is not None
    assert backup.find("password").get("from_env") == "CLICKHOUSE_BACKUP_PASSWORD"
    assert backup.find("access_management").text == "0"
    grants = sorted(query.text.strip() for query in backup.find("grants").findall("query"))
    assert grants == sorted(
        [
            "GRANT BACKUP ON shapoclyack.*",
            "GRANT S3 ON *.*",
            "GRANT CREATE TEMPORARY TABLE ON *.*",
            "GRANT SELECT ON system.backups",
        ]
    )
    default_networks = [ip.text for ip in users.find("default").find("networks")]
    assert [ip.text for ip in backup.find("networks")] == default_networks


def test_the_backup_users_password_can_never_be_empty():
    """An unset `from_env` variable is an empty password on 24.8 — one warning
    in the server log and a user anyone can sign in as. So the variable comes
    from a Secret base always generates, and the reference is never optional:
    a missing Secret is a pod that does not start, not an open account."""
    container = _load(CH_STATEFULSET)["spec"]["template"]["spec"]["containers"][0]
    env = {item["name"]: item for item in container["env"]}
    ref = env["CLICKHOUSE_BACKUP_PASSWORD"]["valueFrom"]["secretKeyRef"]
    assert (ref["name"], ref["key"]) == ("shapoclyack-clickhouse-backup", "password")
    assert not ref.get("optional", False)
    generated = {item["name"]: item for item in _load(K8S / "base/kustomization.yaml")["secretGenerator"]}
    assert any(
        literal.startswith("password=") for literal in generated["shapoclyack-clickhouse-backup"]["literals"]
    )


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


_PINNED = re.compile(r"^(?P<name>[a-z0-9./-]+:[A-Za-z0-9._-]+)@sha256:[0-9a-f]{64}$")


def test_the_client_image_is_pinned_to_the_server_release():
    """Pinned by digest (#313), and the server's release: BACKUP runs on the
    server, but the client that issues it and reads the manifest back should
    not be a different ClickHouse, and an overlay that mirrors the server image
    with ``images:`` moves both."""
    client = _pod(_load(CH_CRONJOB))["containers"][0]["image"]
    server = _load(CH_STATEFULSET)["spec"]["template"]["spec"]["containers"][0]["image"]
    match = _PINNED.match(client)
    assert match, f"{client!r} is not pinned by digest"
    assert match.group("name") == server.split("@")[0]
    if "@" in server:
        assert client == server


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


def _quantity(value: str) -> float:
    units = {"Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40}
    for suffix, factor in units.items():
        if value.endswith(suffix):
            return float(value[: -len(suffix)]) * factor
    return float(value)


def test_the_restore_overlay_runs_a_lab_sized_clickhouse():
    """The drill namespace sits next to the source lab on one kind node; the
    production 2 Gi request and 50 Gi claim are what an installation sizes,
    not what a rehearsal needs."""
    docs = _render("overlays/kind-restore")
    clickhouse = next(
        doc for doc in docs if doc["kind"] == "StatefulSet" and doc["metadata"]["name"] == "shapoclyack-clickhouse"
    )
    resources = clickhouse["spec"]["template"]["spec"]["containers"][0]["resources"]
    assert _quantity(resources["requests"]["memory"]) <= 2**30
    assert _quantity(resources["limits"]["memory"]) <= 2 * 2**30
    storage = clickhouse["spec"]["volumeClaimTemplates"][0]["spec"]["resources"]["requests"]["storage"]
    assert _quantity(storage) <= 10 * 2**30


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
        # Only complete lines: a test polling while the script runs may catch
        # the stub mid-write.
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines(keepends=True)
                if line.endswith("\n")]

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

# Answers to the two pre-flight questions the scripts ask: nothing of ours is
# still being written, and every part the backup lists is readable.
_NOTHING_IN_FLIGHT = (r"status = 'CREATING_BACKUP'", [{"stdout": ""}])
_ALL_PARTS_READABLE = (r"extractAll\(raw_blob", [{"stdout": ""}])

_BACKUP_OK = [
    _NOTHING_IN_FLIGHT,
    (r"^BACKUP DATABASE", [{"stdout": "shapoclyack-x\tCREATING_BACKUP\n"}]),
    (r"^SELECT status FROM system\.backups", [{"stdout": "CREATING_BACKUP\n"}, {"stdout": "BACKUP_CREATED\n"}]),
    _ALL_PARTS_READABLE,
    (r"^INSERT INTO FUNCTION s3", [{"stdout": ""}]),
    (r"SELECT count\(\), sum\(rows\)", [{"stdout": "3\t30000\n"}]),
    (r"SELECT num_files", [{"stdout": "42\t1048576\t1000000\n"}]),
]


def _backup_statement(stub: Stub) -> str:
    return next(sql for sql in stub.statements if sql.startswith("BACKUP DATABASE"))

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
    backup = _backup_statement(stub)
    assert backup.startswith("BACKUP DATABASE `shapoclyack` TO S3('http://minio.storage:9000/drill-backups/shapoclyack/prod/clickhouse/")
    assert backup.rstrip().endswith("ASYNC")
    assert f"'{ACCESS_KEY}', '{_SECRET_IN_SQL}'" in backup
    # Polled until created, then the manifest, read back, then the sizes.
    assert sum(sql.startswith("SELECT status FROM system.backups") for sql in statements) == 2
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
    assert _backup_statement(stub).startswith(
        "BACKUP DATABASE `shapoclyack` TO S3('https://drill-backups.s3.eu-central-1.amazonaws.com/clickhouse/"
    )


def test_the_backup_stores_every_parts_count_file(tmp_path):
    """BACKUP stores a file whose checksum it has already stored only once
    (`deduplicate_files`, on by default): a second part whose count.txt has the
    same bytes points at the first one's object. The manifest counts count.txt
    objects, so on 24.8.14 three parts of 1000 rows read as one part of 1000,
    and the restore — merges stopped, 3000 rows — exited 8 on a valid backup."""
    stub = Stub(tmp_path, _BACKUP_OK)
    result = _run(BACKUP_SCRIPT, stub, **_BACKUP_ENV)
    assert result.returncode == 0, result.stderr
    assert "deduplicate_files = 0" in _backup_statement(stub)


def test_a_backup_whose_listed_parts_are_not_all_readable_is_not_a_restore_point(tmp_path):
    """The belt to that brace: `.backup` lists every part's count.txt whether
    or not its object was deduplicated, so fewer readable objects than listed
    parts means the counts are wrong — or objects are missing — and the job
    must not write a manifest that fails the restore after the fact."""
    rules = [
        _NOTHING_IN_FLIGHT,
        *[rule for rule in _BACKUP_OK if rule[0].startswith(("^BACKUP", "^SELECT status"))],
        (r"extractAll\(raw_blob", [{"stdout": "shapoclyack_open_ports\t3\t1\n"}]),
        (r"^INSERT INTO FUNCTION s3", [{"stdout": ""}]),
    ]
    stub = Stub(tmp_path, rules)
    result = _run(BACKUP_SCRIPT, stub, **_BACKUP_ENV)
    assert result.returncode == 1
    assert "reason=parts_unreadable" in result.stderr
    assert "table=shapoclyack_open_ports listed=3 readable=1" in result.stderr
    assert not any(sql.startswith("INSERT INTO FUNCTION") for sql in stub.statements)


def test_a_backup_an_earlier_attempt_is_still_writing_is_not_started_twice(tmp_path):
    """The script gives up waiting at its timeout, but the server's BACKUP goes
    on; the Job's retry must not start a second one beside it."""
    rules = [
        (r"status = 'CREATING_BACKUP'", [{"stdout": "shapoclyack-20260924T024500Z\n"}]),
        *_BACKUP_OK[1:],
    ]
    stub = Stub(tmp_path, rules)
    result = _run(BACKUP_SCRIPT, stub, **_BACKUP_ENV)
    assert result.returncode == 1
    assert "reason=backup_in_flight" in result.stderr
    assert "running=shapoclyack-20260924T024500Z" in result.stderr
    assert not any(sql.startswith("BACKUP DATABASE") for sql in stub.statements)


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
    """clickhouse-client appends the whole statement to an error. What 24.8
    prints there is the statement as sent — the SQL-escaped literal, not the
    raw secret — so the test echoes that form."""
    echoed = (
        "Received exception from server (version 24.8.14):\n"
        "Code: 36. DB::Exception: Received from host:9000. DB::Exception: Host is empty in S3 URI.. (BAD_ARGUMENTS)\n"
        f"(query: BACKUP DATABASE `shapoclyack` TO S3('x', '{ACCESS_KEY}', '{_SECRET_IN_SQL}') ASYNC\n)\n"
    )
    stub = Stub(tmp_path, [_NOTHING_IN_FLIGHT, (r"^BACKUP DATABASE", [{"stderr": echoed, "exit": 36}])])
    result = _run(BACKUP_SCRIPT, stub, **_BACKUP_ENV)
    assert result.returncode == 1
    assert "Host is empty in S3 URI" in result.stderr
    assert "backup_failed reason=statement_refused" in result.stderr
    assert "(query:" not in result.stderr
    assert "Sup3r" not in result.stderr
    _assert_secret_contained(result, stub)


def test_a_syntax_error_that_quotes_the_statement_without_a_query_block_is_masked(tmp_path):
    """A parse error prints the tail of the statement inside its own message,
    with no `(query: …)` block to drop — so the escaped literal is masked too."""
    echoed = (
        "Code: 62. DB::Exception: Syntax error: failed at position 88 "
        f"('{ACCESS_KEY}', '{_SECRET_IN_SQL}') ASYNC'): expected end of query. (SYNTAX_ERROR)\n"
    )
    stub = Stub(tmp_path, [_NOTHING_IN_FLIGHT, (r"^BACKUP DATABASE", [{"stderr": echoed, "exit": 62}])])
    result = _run(BACKUP_SCRIPT, stub, **_BACKUP_ENV)
    assert result.returncode == 1
    assert "Syntax error" in result.stderr
    assert "Sup3r" not in result.stderr
    _assert_secret_contained(result, stub)


def test_the_secret_is_masked_even_where_the_client_prints_it_outside_the_query_block(tmp_path):
    stub = Stub(
        tmp_path,
        [_NOTHING_IN_FLIGHT, (r"^BACKUP DATABASE", [{"stderr": f"odd: {SECRET} and {CH_PASSWORD}\n", "exit": 1}])],
    )
    result = _run(BACKUP_SCRIPT, stub, **_BACKUP_ENV)
    assert result.returncode == 1
    assert "odd: [HIDDEN] and [HIDDEN]" in result.stderr
    _assert_secret_contained(result, stub)


def test_a_failed_backup_reports_the_first_line_of_the_server_error(tmp_path):
    rules = [
        _NOTHING_IN_FLIGHT,
        (r"^BACKUP DATABASE", [{"stdout": "x\tCREATING_BACKUP\n"}]),
        (r"^SELECT status FROM system\.backups", [{"stdout": "BACKUP_FAILED\n"}]),
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
        _NOTHING_IN_FLIGHT,
        (r"^BACKUP DATABASE", [{"stdout": "x\tCREATING_BACKUP\n"}]),
        (r"^SELECT status FROM system\.backups", [{"stdout": ""}]),
    ]
    stub = Stub(tmp_path, rules)
    result = _run(BACKUP_SCRIPT, stub, **_BACKUP_ENV)
    assert result.returncode == 1
    assert "reason=backup_vanished" in result.stderr


def test_a_backup_with_no_tables_is_a_failure_not_a_restore_point(tmp_path):
    rules = [*_BACKUP_OK[:5], (r"SELECT count\(\), sum\(rows\)", [{"stdout": "0\t0\n"}])]
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


_COLUMNS = (
    "shapoclyack_controls\trun_id\tString\n"
    "shapoclyack_open_ports\tport\tUInt16\n"
    "shapoclyack_vulnerabilities\tcve_id\tString\n"
)


def _restore_rules(
    *,
    manifest: str = _MANIFEST,
    observed: str = _MANIFEST,
    unreadable: str = "",
    target: str = "shapoclyack_controls\t0\nshapoclyack_open_ports\t0\nshapoclyack_vulnerabilities\t0\n",
    columns_before: str = _COLUMNS,
    columns_after: str = _COLUMNS,
    restored: str = "shapoclyack_controls\t0\t0\nshapoclyack_open_ports\t0\t40000\nshapoclyack_vulnerabilities\t0\t29992\n",
    restore_status: str = "RESTORED\n",
) -> list[tuple[str, list[dict]]]:
    return [
        (r"manifest\.jsonl", [{"stdout": manifest}]),
        (r"^SELECT\s+t\.table", [{"stdout": observed}]),
        (r"extractAll\(raw_blob", [{"stdout": unreadable}]),
        (r"FROM system\.tables", [{"stdout": target}]),
        (r"FROM system\.columns", [{"stdout": columns_before}, {"stdout": columns_after}]),
        (r"^DROP DATABASE", [{"stdout": ""}]),
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
    assert not any(sql.startswith(("RESTORE", "SYSTEM", "DROP")) for sql in stub.statements)


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
    assert not any(sql.startswith(("RESTORE", "SYSTEM", "DROP")) for sql in stub.statements)


def test_rows_in_a_table_the_backup_does_not_have_block_the_restore_too(tmp_path):
    """The restore drops the (empty) target database to rebuild it from the
    backup's schema, so every table in it counts — not only the backup's."""
    target = "local_notes\t5\nshapoclyack_controls\t0\nshapoclyack_open_ports\t0\nshapoclyack_vulnerabilities\t0\n"
    result, stub = _restore(tmp_path, "--local", target=target)
    assert result.returncode == 7
    assert "local_notes(5)" in result.stderr
    assert not any(sql.startswith(("RESTORE", "SYSTEM", "DROP")) for sql in stub.statements)


def test_a_backup_listing_parts_it_does_not_store_is_refused_before_anything_is_restored(tmp_path):
    """A backup taken with `deduplicate_files` on — by hand, or by the job
    before #333's review — stores one count.txt for several parts; its row
    counts cannot be verified, and restoring it would end in exit 8."""
    result, stub = _restore(tmp_path, "--local", unreadable="shapoclyack_open_ports\t4\t1\n")
    assert result.returncode == 6
    assert "table=shapoclyack_open_ports listed=4 readable=1" in result.stdout
    assert not any(sql.startswith(("RESTORE", "SYSTEM", "DROP")) for sql in stub.statements)


def test_an_empty_target_is_rebuilt_from_the_backups_schema(tmp_path):
    """A new PVC's first boot ran *this* release's init.sql; a backup from an
    older one has other columns, and RESTORE into the existing tables fails
    with CANNOT_RESTORE_TABLE. Empty, the database is dropped first."""
    result, stub = _restore(tmp_path, "--local")
    assert result.returncode == 0, result.stderr
    statements = stub.statements
    drop = statements.index("DROP DATABASE IF EXISTS `shapoclyack` SYNC\n")
    structure = next(i for i, sql in enumerate(statements) if "structure_only = 1" in sql)
    target = next(i for i, sql in enumerate(statements) if "FROM system.tables" in sql)
    assert target < drop < structure


def test_columns_this_release_has_and_the_backup_lacks_are_reported(tmp_path):
    """ClickHouse has no migrations here: init.sql runs on a first boot only.
    After an older backup is restored, the schema is the backup's, and the
    columns the release added have to be added by that release's upgrade step
    — which the script names rather than failing a restore that worked."""
    before = _COLUMNS + "shapoclyack_open_ports\tservice\tLowCardinality(String)\n"
    result, _ = _restore(tmp_path, "--local", columns_before=before)
    assert result.returncode == 0, result.stderr
    assert (
        "schema_drift table=shapoclyack_open_ports column=service type=LowCardinality(String) only_in=target"
        in result.stdout
    )


def test_a_restore_stops_merges_first_verifies_counts_and_starts_them_again(tmp_path):
    result, stub = _restore(tmp_path, "--local")
    assert result.returncode == 0, result.stderr
    assert "restore_success database=shapoclyack tables=3 rows=69992" in result.stdout

    statements = stub.statements
    order = [
        next(i for i, sql in enumerate(statements) if sql.startswith("DROP DATABASE")),
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
    # The data is in, so a rerun stops at the target check; say what to do.
    assert "exit 7" in result.stderr
    assert "DROP DATABASE `shapoclyack` SYNC" in result.stderr


@pytest.mark.parametrize("signame", ["SIGINT", "SIGTERM", "SIGHUP"])
def test_merges_restart_when_the_restore_is_interrupted(tmp_path, signame):
    """Ctrl-C or a dropped SSH session during the RESTORE poll. An EXIT trap
    alone does not run on a fatal signal in dash or busybox ash, and merges
    left stopped fail every later OPTIMIZE with Code 236."""
    rules = [
        (match, [{"stdout": "RESTORING\n"}]) if match.startswith("SELECT status") else (match, replies)
        for match, replies in _restore_rules()
    ]
    stub = Stub(tmp_path, rules)
    proc = subprocess.Popen(
        ["sh", str(RESTORE_SCRIPT), "--backup-url", _URL, "--local"],
        env=stub.env(CLICKHOUSE_RESTORE_POLL_SECONDS="1"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 30
    while not any("SELECT status FROM system.backups" in sql for sql in stub.statements):
        assert time.monotonic() < deadline, "restore never reached its poll"
        time.sleep(0.05)
    proc.send_signal(getattr(signal, signame))
    proc.communicate(timeout=30)
    assert proc.returncode != 0
    assert sum(sql.startswith("SYSTEM START MERGES") for sql in stub.statements) == 3


@pytest.mark.parametrize(
    "echoed",
    [
        # The block clickhouse-client appends to an error: the statement as
        # sent, so the secret is the SQL-escaped literal.
        "Received exception from server (version 24.8.14):\n"
        "Code: 499. DB::Exception: Received from host:9000. DB::Exception: Failed to get object info. (S3_ERROR)\n"
        f"(query: SELECT table FROM s3('{_URL}/manifest.jsonl', '{ACCESS_KEY}', '{_SECRET_IN_SQL}', "
        "'JSONEachRow')\n)\n",
        # A parse error quotes the statement's tail in its own message.
        f"Code: 62. DB::Exception: Syntax error: failed at position 70 ('{_SECRET_IN_SQL}', 'JSONEachRow'): "
        "Failed to get object info. (SYNTAX_ERROR)\n",
    ],
    ids=["query-block", "syntax-error"],
)
def test_the_restore_hides_the_statement_the_client_echoes(tmp_path, echoed):
    stub = Stub(tmp_path, [(r"manifest\.jsonl", [{"stderr": echoed, "exit": 211}])])
    result = _run(RESTORE_SCRIPT, stub, "--backup-url", _URL, "--local", "--dry-run")
    assert result.returncode == 4
    assert "Failed to get object info" in result.stderr
    assert "Sup3r" not in result.stderr
    # The whole block goes, not only the secret in it: it also carries the
    # bucket URL and the access key id, which a log has no use for.
    assert "(query:" not in result.stderr
    _assert_secret_contained(result, stub)


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
        "extractAll(raw_blob, '<name>data/${db}/([^/<]*)/[^/<]*/count[.]txt</name>')",
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


def test_the_drill_backs_up_equal_sized_parts_in_every_table():
    """The first 10k drill passed with the manifest bug in it: it merged
    everything before the backup and wrote no controls rows, so no two parts
    were alike. Its daily runs now land one part per table each, all the same
    size — the shape `deduplicate_files` collapsed."""
    from api.services import ch_transform

    drill = _drill()
    shapes = []
    for number in (1, 2):
        run_id = f"dr-drill-day-{number}"
        payload = {
            "tenant_id": "scale-test",
            "run_id": run_id,
            "job_id": "job-" + run_id,
            "archive_b64": base64.b64encode(drill.run_archive(run_id, 50, 100 + number)).decode(),
        }
        vulns, ports, controls = ch_transform.transform_ingest_payload(payload)
        shapes.append((len(vulns), len(ports), len(controls)))
    assert shapes[0] == shapes[1] == (50, 100, len(drill.CONTROLS))
    assert drill.build_parser().parse_args(["--postgres-url", "x", "--s3-bucket", "b"]).daily_runs >= 2


# --------------------------------------------------------------------------- #
# The runbook
# --------------------------------------------------------------------------- #


def _section(heading: str) -> str:
    text = DR_DOC.read_text(encoding="utf-8")
    start = text.index(heading)
    end = text.find("\n## ", start + len(heading))
    return text[start : end if end != -1 else len(text)]


def test_the_runbook_creates_the_artifact_claim_before_the_overlay_creates_an_empty_one():
    """`dataSource` is immutable, and the restore overlay renders `scanner-data`:
    applied first, it leaves an empty claim that no snapshot can be put into,
    and Postgres is then restored beside empty artifacts. The snapshot objects
    also need the namespace to exist."""
    steps = _section("## Full restore, in order")
    namespace = steps.index("kubectl create namespace")
    claim = steps.index("pvc-snapshot.example.yaml")
    overlay = steps.index("kubectl apply -k")
    assert namespace < claim < overlay


def test_the_runbook_lists_runs_without_downloading_them():
    """`runs.list_runs` reads each run's summary — on the S3 backend that
    syncs every run into the API pod's cache. The orphan check needs keys."""
    text = DR_DOC.read_text(encoding="utf-8")
    assert "runs.list_runs" not in text
    assert "workspace.run_refs(" in text
