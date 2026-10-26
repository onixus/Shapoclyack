#!/usr/bin/env python3
"""Freeze and evaluate the operator's actual local model against labelled cases.

The final runner never drops failures or retries failed cases. Supplied-output
contract fixtures are not used. Raw synthetic requests/responses, source copies,
runtime/model provenance and dataset hashes accompany every run.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from dataclasses import replace
from datetime import UTC, datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import socket
import subprocess
import sys
import tempfile
from time import monotonic
from types import SimpleNamespace
from unittest.mock import patch

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from api.services import advisories  # noqa: E402
from api.services.advisories import msrc, rpm  # noqa: E402
from api.services.advisories.base import AdvisoryDataset, AdvisoryRecord  # noqa: E402
from api.services.advisories.coverage import AdvisorySnapshot  # noqa: E402
from api.services.local_operator import analysis, planner, remediation  # noqa: E402
from api.services.local_operator.config import OperatorConfig  # noqa: E402
from api.services.local_operator.providers import InferenceProvider  # noqa: E402

DATASET = ROOT / "tests/fixtures/operator_domain_eval.json"
FINAL_MIN_SOAK_SECONDS = 3600
SOURCE_PATHS = (
    "api/services/local_operator/analysis.py", "api/services/local_operator/planner.py",
    "api/services/local_operator/providers.py", "api/services/local_operator/config.py",
    "api/services/local_operator/contracts.py", "api/services/local_operator/remediation.py",
    "api/services/local_operator/gateway.py", "api/services/local_operator/actions.py", "api/schemas.py",
    "api/services/local_operator/analyzer_gateway.py",
    "api/services/local_operator/data/apache24-traceenable-v1.json",
    "api/services/local_operator/data/package-upgrade-runbook-v1.json",
    "api/services/patch_gap.py", "api/services/software_cve_match.py", "api/services/package_identity.py",
    "api/services/rpm_identity.py", "api/services/version_compare.py", "api/services/advisories/base.py",
    "api/services/advisories/coverage.py", "api/services/advisories/rpm.py", "api/services/advisories/msrc.py",
    "scripts/operator-evaluate.py", "scripts/operator-capacity.py", "scripts/operator-acceptance-drill.py",
    "scripts/operator-observe.py", "scripts/operator-quality-watchdog.py", "compose.operator-mac.yml",
    "compose.operator-mac.native.yml", "scripts/operator-runtime-manifest.py", "scripts/operator-mac.sh",
    "scripts/operator-offline-bundle.py",
    "api/services/vulnerabilities.py", "api/services/job_submission.py",
)
MODEL_SHA256 = "03b74727a860a56338e042c4420bb3f04b2fec5734175f4cb9fa853daf52b7e8"
RUNTIME_OVERRIDE = None
LAUNCH_NONCE_ENV = "OPERATOR_QUALITY_LAUNCH_NONCE"
# The complete f8dc16g attempt was subsequently inspected for development.
# Conservatively include all dispatched IDs, including transport errors/503s.
# Bind this policy to the original corpus; a new independent corpus requires
# an explicit exposure review, never an automatic claim that its cases are hidden.
EXPOSED_DATASET_CANONICAL_SHA256 = "56aa6ad3c52b61f481380cc7efd0b7fa1e795d969671b41934ff3ce54d7fe5dc"
DEVELOPMENT_EXPOSURE_POLICY = {
    "version": "full-corpus-attempted-f8dc16g-v1",
    "prior_attempt_records_sha256": "5693a4c7a7b807f48c7b306fd4ce0a6251f95d07f59d764cc566eae6cb6591f6",
    "historical_pre_attempt_split": {"exposed": 11, "untouched": 179},
    "reason": "All190 attempted cases are exposed for subsequent development, including failed exchanges; original reports remain unchanged.",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(value).hexdigest()


def exposure_provenance(dataset):
    if digest(canonical(dataset).encode()) != EXPOSED_DATASET_CANONICAL_SHA256:
        raise ValueError("Dataset requires independent exposure-policy review")
    return {**DEVELOPMENT_EXPOSURE_POLICY,
            "development_exposed_case_ids": [case["case_id"] for case in dataset["cases"]],
            "untouched_case_count": 0}


def file_digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _sync_directory(directory):
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def durable_storage_preflight(directory, *, require_native=False):
    """Exercise the exact journal durability operations before any inference.

    A successful file fsync alone does not establish durable rename/unlink.
    Unsupported directory fsync is a hard error, never a best-effort success.
    """
    directory = Path(directory)
    filesystem = "unidentified"
    mountinfo = Path("/proc/self/mountinfo")
    if mountinfo.is_file():
        mounts = []
        for line in mountinfo.read_text().splitlines():
            before, separator, after = line.partition(" - ")
            fields = before.split()
            if separator and len(fields) >= 5:
                mount = fields[4].replace("\\040", " ").replace("\\134", "\\")
                if directory.resolve().is_relative_to(Path(mount)):
                    mounts.append((len(mount), after.split()[0]))
        if mounts:
            filesystem = max(mounts)[1]
    if require_native and filesystem != "ext4":
        raise ValueError("durable_storage_requires_native_ext4")
    descriptor, temporary = tempfile.mkstemp(prefix=".durability-", dir=directory)
    temporary = Path(temporary)
    renamed = temporary.with_suffix(".renamed")
    payload = b"operator-durability-preflight-v1\n"
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, renamed)
        _sync_directory(directory)
        if renamed.read_bytes() != payload:
            raise ValueError("durable_storage_readback_failed")
        renamed.unlink()
        _sync_directory(directory)
    finally:
        temporary.unlink(missing_ok=True)
        renamed.unlink(missing_ok=True)
    return {"version": "file-rename-directory-fsync-v1", "passed": True,
            "filesystem_type": filesystem, "native_ext4_required": require_native}


def validate_launch_permit(value, nonce, hostname, now):
    fields = {"schema_version", "nonce", "container_id", "requested_at", "issued_at", "expires_at"}
    if (not isinstance(value, dict) or set(value) != fields or type(value["schema_version"]) is not int
            or value["schema_version"] != 1 or value["nonce"] != nonce
            or not isinstance(nonce, str) or len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce)):
        raise ValueError("invalid_launch_permit")
    cid = value["container_id"]
    if (not isinstance(cid, str) or len(cid) != 64 or any(c not in "0123456789abcdef" for c in cid)
            or hostname != cid[:12]):
        raise ValueError("foreign_launch_permit_container")
    stamps = []
    for name in ("requested_at", "issued_at", "expires_at"):
        raw = value[name]
        if not isinstance(raw, str) or len(raw) > 64:
            raise ValueError("invalid_launch_permit_timestamp")
        stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError("invalid_launch_permit_timestamp")
        stamps.append(stamp.astimezone(UTC))
    requested, issued, expires = stamps
    if not (0 < (expires - requested).total_seconds() <= 60 and requested <= issued <= now <= expires):
        raise ValueError("expired_or_future_launch_permit")
    return value


async def authorize_launch(output, *, required):
    """A late start with no successful host ACK receives no provider authority."""
    if not required:
        return None
    nonce = os.environ.get(LAUNCH_NONCE_ENV)
    if not isinstance(nonce, str) or len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce):
        raise ValueError("missing_launch_nonce")
    output = Path(output)
    permit = output.parent / ("launch-permit-" + nonce + ".json")
    began = monotonic()
    while True:
        try:
            descriptor = os.open(permit, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            if monotonic() - began >= 60:
                raise ValueError("missing_launch_permit") from None
            await asyncio.sleep(0.1)
            continue
        with os.fdopen(descriptor, "rb") as handle:
            raw = handle.read(4097)
        if len(raw) > 4096:
            raise ValueError("oversized_launch_permit")
        value = validate_launch_permit(json.loads(raw), nonce, socket.gethostname(), datetime.now(UTC))
        # Retain authorization with the exported result, including across resume.
        descriptor, temporary = tempfile.mkstemp(prefix=".authorization-", dir=output)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, output / ("launch-authorization-" + nonce + ".json"))
            _sync_directory(output)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return {**value, "permit_sha256": digest(raw), "protocol": "native-nonce-cid-expiry-v1"}


def begin_execution(output, case, *, phase, ordinal=None, soak_iteration=None):
    if phase not in {"initial", "soak"} or (phase == "soak" and (type(soak_iteration) is not int or soak_iteration < 1)):
        raise ValueError("Invalid execution phase/iteration")
    identity = {"phase": phase, "execution_id": f"initial:{case['case_id']}" if phase == "initial" else f"soak:{soak_iteration}:{case['case_id']}"}
    if phase == "soak":
        identity["soak_iteration"] = soak_iteration
    pending = {**identity, "case_id": case["case_id"], "kind": case["kind"], "ordinal": ordinal,
               "started_at": datetime.now(UTC).isoformat(), "status": "evaluation_started"}
    output = Path(output)
    if (output / "inflight.json").exists():
        raise ValueError("Recover the previous inflight execution before starting another")
    descriptor, temporary = tempfile.mkstemp(prefix=".inflight-", dir=output)
    try:
        with os.fdopen(descriptor, "w") as handle:
            handle.write(canonical(pending) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output / "inflight.json")
        _sync_directory(output)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return identity


def complete_execution(output, record, *, phase):
    output = Path(output)
    with (output / ("soak-records.jsonl" if phase == "soak" else "records.jsonl")).open("a") as handle:
        handle.write(canonical(record) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    (output / "inflight.json").unlink(missing_ok=True)
    _sync_directory(output)


def soak_history(output):
    path = Path(output) / "soak-records.jsonl"
    records = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    last = 0
    for item in records:
        iteration = item.get("soak_iteration")
        if (type(iteration) is not int or iteration <= last or item.get("phase") != "soak"
                or item.get("execution_id") != f"soak:{iteration}:{item.get('case_id')}"):
            raise ValueError("Invalid persisted soak execution order/identity")
        last = iteration
    return records


def recover_inflight(output, records, selected):
    """A crashed request has an uncertain result, never a free final retry."""
    journal = Path(output) / "inflight.json"
    if not journal.exists():
        return records
    pending = json.loads(journal.read_text())
    phase = pending.get("phase", "initial")
    if phase not in {"initial", "soak"}:
        raise ValueError("Invalid inflight phase")
    completed = {record["case_id"] for record in records}
    case = next((case for case in selected if case["case_id"] == pending["case_id"]), None)
    if case is None:
        raise ValueError("Inflight journal refers to an unscheduled case")
    if phase == "soak":
        iteration = pending.get("soak_iteration")
        if type(iteration) is not int or iteration < 1 or pending.get("execution_id") != f"soak:{iteration}:{case['case_id']}":
            raise ValueError("Invalid soak execution identity")
        previous = soak_history(output)
        iterations = [item["soak_iteration"] for item in previous]
        existing = next((item for item in previous if item["soak_iteration"] == iteration), None)
        if existing is not None:
            if existing["case_id"] != case["case_id"]:
                raise ValueError("Soak execution identity changed")
            journal.unlink()
            _sync_directory(output)
        else:
            if iterations and iteration <= iterations[-1]:
                raise ValueError("Stale soak execution")
            complete_execution(output, {"case_id": case["case_id"], "kind": case["kind"], "language": case["language"],
                "phase": "soak", "execution_id": pending["execution_id"], "soak_iteration": iteration,
                "valid": False, "model_invoked": None, "elapsed_seconds": None,
                "error_code": "evaluation_interrupted_before_receipt", "recovered_inflight": True}, phase="soak")
        return records  # never replace the initial gold result with a soak result
    if pending.get("execution_id", f"initial:{case['case_id']}") != f"initial:{case['case_id']}":
        raise ValueError("Invalid initial execution identity")
    if pending["case_id"] not in completed:
        record = {"case_id": case["case_id"], "kind": case["kind"], "language": case["language"],
                  "phase": "initial", "execution_id": f"initial:{case['case_id']}",
                  "valid": False, "model_invoked": None, "elapsed_seconds": None,
                  "error_code": "evaluation_interrupted_before_receipt", "recovered_inflight": True}
        records.append(record)
        complete_execution(output, record, phase="initial")
    else:
        journal.unlink()
        _sync_directory(output)
    return records


def load_dataset(path=DATASET):
    data = json.loads(Path(path).read_text())
    ids = [case["case_id"] for case in data["cases"]]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate case IDs")
    counts = Counter(case["kind"] for case in data["cases"])
    if any(counts[kind] < needed for kind, needed in data["required_counts"].items()):
        raise ValueError("Dataset does not meet frozen scenario counts")
    if {case["language"] for case in data["cases"]} != {"ru", "en"}:
        raise ValueError("Both languages are required")
    return data


def runtime_provenance():
    if RUNTIME_OVERRIDE is not None:
        return RUNTIME_OVERRIDE["runtime"]
    name = "shapo-operator-inference-1"
    image = subprocess.check_output(["docker", "inspect", name, "--format", "{{.Image}}"], text=True).strip()
    command = json.loads(subprocess.check_output(["docker", "inspect", name, "--format", "{{json .Config.Cmd}}"], text=True))
    return {"container": name, "image_id": image, "command": command}


def source_provenance():
    return {path: file_digest(ROOT / path) for path in SOURCE_PATHS}


def freeze(destination, *, reviewed_by, model_path):
    data = load_dataset()
    if not reviewed_by.strip():
        raise ValueError("A named independent reviewer is required")
    if data["authoring"]["review_status"] != "reviewed":
        raise ValueError("Independent gold review must be recorded before final freeze")
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    model_hash = file_digest(model_path)
    if model_hash != MODEL_SHA256:
        raise ValueError("Model bytes differ from pinned acceptance artifact")
    runtime = runtime_provenance()
    if "--temp" not in runtime["command"] or runtime["command"][runtime["command"].index("--temp") + 1] != "0":
        raise ValueError("Freeze requires explicitly deterministic runtime sampling")
    for flag, value in (("--seed", "42"), ("--ctx-size", "8192"), ("--parallel", "1")):
        if flag not in runtime["command"] or runtime["command"][runtime["command"].index(flag) + 1] != value:
            raise ValueError("Runtime context/concurrency/seed differ from the acceptance profile")
    paths = source_provenance()
    for name in paths:
        target = destination / "sources" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    (destination / "dataset.json").write_bytes(DATASET.read_bytes())
    manifest = {"manifest_version": "1", "frozen_at": datetime.now(UTC).isoformat(),
                "reviewed_by": reviewed_by, "dataset_sha256": file_digest(DATASET),
                "thresholds": data["thresholds"], "counts": dict(Counter(c["kind"] for c in data["cases"])),
                "model_sha256": model_hash, "model_revision": "3885219b6810b007914f3a7950a8d1b469d598a5",
                "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "source_sha256": paths, "runtime": runtime, "host": platform.platform(),
                "analysis_prompt_version": analysis.PROMPT_VERSION,
                "planner_prompt_version": planner.PROMPT_VERSION,
                "development_exposure": exposure_provenance(data),
                "development_exposed_case_ids": exposure_provenance(data)["development_exposed_case_ids"],
                "scope": "Synthetic domain component/model acceptance; not a replacement for authenticated E2E/offline/soak evidence"}
    write_json(destination / "manifest.json", manifest)
    return manifest


class CapturedStream(httpx.AsyncByteStream):
    def __init__(self, stream, trace):
        self.stream, self.trace = stream, trace

    async def __aiter__(self):
        async for chunk in self.stream:
            if self.trace.first_byte_seconds is None:
                self.trace.first_byte_seconds = monotonic() - self.trace.started
            if len(self.trace.response_bytes) + len(chunk) <= 1048576:
                self.trace.response_bytes.extend(chunk)
            yield chunk

    async def aclose(self):
        await self.stream.aclose()


class TraceTransport(httpx.AsyncBaseTransport):
    def __init__(self):
        self.transport = httpx.AsyncHTTPTransport(retries=0)
        self.request_body = None
        self.response_status = None
        self.response_bytes = bytearray()
        self.first_byte_seconds = None
        self.started = monotonic()

    async def handle_async_request(self, request):
        self.started = monotonic()
        self.request_body = json.loads(request.content)
        response = await self.transport.handle_async_request(request)
        self.response_status = response.status_code
        response.stream = CapturedStream(response.stream, self)
        return response

    async def aclose(self):
        await self.transport.aclose()


def domain_remediation(case):
    """Use native remediation code and locally supplied vendor snapshot facts.

    Fixtures replace the data provider, not its comparator, identity logic or
    card renderer. No database, model mutation or network action occurs here.
    """
    data = case["domain_input"]
    row = SimpleNamespace(**data["row"])
    feed = data["feed"]
    snapshot = SimpleNamespace(**data["inventory"])
    now = datetime.fromisoformat(data["clock"].replace("Z", "+00:00"))
    if row.distro == "windows":
        dataset = msrc.MsrcDataset()
        payload = {"updated": feed.get("feed_date", "2026-10-24"),
                   "source": feed.get("source", "synthetic-vendor-reference"), "entries": [{
                       "cve_id": row.cve_id, "fixed_build": row.fixed_version,
                       "kb": row.advisory_id, "product": "Synthetic Windows product"}]}
        with tempfile.TemporaryDirectory(prefix="operator-domain-msrc-") as folder:
            path = Path(folder) / "vendor.json"
            write_json(path, payload)
            dataset.load(path)
        with patch.object(msrc, "get_dataset", return_value=dataset):
            return remediation.build_cards([row], snapshot, device_id=row.device_id,
                snapshot_id=row.snapshot_id, architecture="x86_64", language=case["language"], now=now)
    values = {"advisory_id": row.advisory_id, "cve_ids": (row.cve_id,), "release": row.distro_release,
              "source_package": row.source_package, "fixed_version": row.fixed_version,
              "state": feed.get("state", "resolved")}
    if row.distro in {"rhel", "sles", "amazonlinux"}:
        values.update(architecture=feed.get("rpm_architecture", "x86_64"), product_id="rhel-9",
                      source_sha256="b" * 64, source_updated="2026-10-24T00:00:00Z")
        records = [rpm.RpmAdvisoryRecord(**values)]
        if "ambiguous_fixed_version" in feed:
            records.append(replace(records[0], fixed_version=feed["ambiguous_fixed_version"]))
    else:
        records = [AdvisoryRecord(**values)]
    if feed.get("available") is False:
        records = []
    records = tuple(records)
    dataset = AdvisoryDataset(source=feed.get("source", "synthetic-vendor-reference"),
        updated=feed.get("feed_date", "2026-10-24"), records=records,
        index={(row.distro_release, row.source_package): records}, releases=(row.distro_release,), present=True)
    provider = AdvisorySnapshot(name=row.provider, distro=row.distro, data=dataset)
    with patch.object(advisories, "get_provider", return_value=provider):
        return remediation.build_cards([row], snapshot, device_id=row.device_id,
            snapshot_id=row.snapshot_id, architecture="x86_64", language=case["language"], now=now)


async def evaluate_one(case, config, launch_authorization=None):
    record = {"case_id": case["case_id"], "kind": case["kind"], "language": case["language"],
              "started_at": datetime.now(UTC).isoformat(), "valid": False, "model_invoked": False}
    started = monotonic()
    trace = TraceTransport()
    try:
        if "retrieval" in case:
            binding = analysis.bind(case["retrieval"])
            messages = analysis.build_prompt(case["language"], binding)
            schema = analysis.output_schema(binding, language=case["language"])
        else:
            request = planner.PlanRequest.model_validate(case["planner_request"])
            messages, schema = planner.build_prompt(request), planner.output_schema(request)
        record["request_sha256"] = digest(canonical({"messages": messages, "schema": schema}).encode())
        if launch_authorization:
            try:
                permit = {key: launch_authorization[key] for key in
                          ("schema_version", "nonce", "container_id", "requested_at", "issued_at", "expires_at")}
                validate_launch_permit(permit, os.environ.get(LAUNCH_NONCE_ENV), socket.gethostname(), datetime.now(UTC))
            except ValueError:
                record["launch_authorization_rejected"] = True
                raise
        record["model_invoked"] = True
        output = await InferenceProvider(config, transport=trace).complete(messages, response_schema=schema)
        record["model_content"] = output.content
        if "retrieval" in case:
            record["result"] = analysis.validate_output(output.content, case["language"], binding)
        else:
            record["result"] = planner.validate_output(output.content, request)
            if case["kind"] == "remediation" and record["result"]["tool"] == "find_remediation":
                record["domain_result"] = domain_remediation(case)
        record["valid"] = True
    except asyncio.CancelledError:
        record["error_type"] = "CancelledError"
        record["error_code"] = "evaluation_interrupted"
        record["interrupted"] = True
    except Exception as exc:
        # The entire request is synthetic; still retain stable failure types,
        # not arbitrary upstream exception text or exception tracebacks.
        record["error_type"] = type(exc).__name__
        code = str(exc)
        record["error_code"] = code if code.startswith("operator_") and len(code) < 100 else "evaluation_failed"
    finally:
        await trace.aclose()
        record["elapsed_seconds"] = monotonic() - started
        record["http_first_byte_seconds"] = trace.first_byte_seconds
        record["true_ttft_seconds"] = None
        record["request_wire"] = trace.request_body
        record["response_status"] = trace.response_status
        record["response_wire_sha256"] = digest(trace.response_bytes)
        record["response_wire"] = bytes(trace.response_bytes).decode("utf-8", errors="replace")
        try:
            record["native_timings"] = json.loads(record["response_wire"]).get("timings")
        except (ValueError, AttributeError):
            record["native_timings"] = None
    return record


async def sample_resources(path, stop, started):
    """Read runtime resource counters independently of the model request loop."""
    while not stop.is_set():
        sample = {"observed_at": datetime.now(UTC).isoformat(), "elapsed_seconds": monotonic() - started}
        process = None
        try:
            process = await asyncio.create_subprocess_exec("docker", "stats", "--no-stream", "--format", "{{json .}}",
                "shapo-operator-inference-1", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            output, _ = await asyncio.wait_for(process.communicate(), timeout=10)
            sample["docker_stats"] = json.loads(output)
        except (OSError, ValueError, TimeoutError):
            sample["error_code"] = "resource_sample_unavailable"
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
        with Path(path).open("a") as handle:
            handle.write(canonical(sample) + "\n")
            handle.flush()
        try:
            await asyncio.wait_for(stop.wait(), timeout=15)
        except TimeoutError:
            pass


def wilson(correct, total):
    if not total:
        return None
    z = 1.959963984540054
    p = correct / total
    scale = 1 + z * z / total
    midpoint = (p + z * z / (2 * total)) / scale
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / scale
    return [max(0.0, midpoint - half), min(1.0, midpoint + half)]


def proportion(correct, total):
    return {"correct": correct, "total": total, "value": correct / total if total else None,
            "wilson_95": wilson(correct, total)}


def macro_f1(pairs, classes):
    if not pairs:
        return 0.0
    scores = []
    for label in classes:
        tp = sum(gold == label and predicted == label for gold, predicted in pairs)
        fp = sum(gold != label and predicted == label for gold, predicted in pairs)
        fn = sum(gold == label and predicted != label for gold, predicted in pairs)
        scores.append(2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0)
    return sum(scores) / len(classes)


def quantile(values, probability):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * probability) - 1)]


def score_case(case, record):
    if not record or not record.get("valid"):
        return False
    gold, result = case["gold"], record["result"]
    if "retrieval" in case:
        selected = {item["source_id"]: item for item in result["recommendations"]}
        return (set(selected) == set(gold["source_ids"])
                and all(selected[label["source_id"]]["category"] == label["category"]
                        and selected[label["source_id"]]["proposed_priority"] == label["proposed_priority"]
                        for label in gold["labels"])
                and (not selected) == gold["abstain"])
    if result["tool"] != gold["tool"] or result["effect_executed"]:
        return False
    if "requires_confirmation" in gold and result["requires_confirmation"] != gold["requires_confirmation"]:
        return False
    if case["kind"] == "remediation":
        cards = record.get("domain_result", {}).get("items", [])
        return len(cards) == 1 and cards[0]["status"] == gold["status"] and cards[0]["target_version"] == gold["target_version"]
    return True


def unsupported_model_fields(case, record):
    try:
        raw = json.loads(record.get("model_content", "{}"))
    except ValueError:
        return 0
    if not isinstance(raw, dict):
        return 0
    allowed = {"language", "summary", "recommendations"} if "retrieval" in case else {"tool"}
    count = len(set(raw) - allowed)
    if "retrieval" in case:
        if "summary" in raw and (not isinstance(raw["summary"], str) or raw["summary"] not in {"review_required", "insufficient_evidence"}):
            count += 1
        items = raw.get("recommendations", [])
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict):
                count += len(set(item) - {"source_ref", "category", "proposed_priority", "next_steps"})
    return count


def summarize(dataset, records, *, stage):
    by_id = {record["case_id"]: record for record in records}
    cases = dataset["cases"]
    result = {"stage": stage, "expected_cases": len(cases), "completed_records": len(by_id),
              "failures_count_in_denominators": True, "metric_scope": "synthetic domain component/model benchmark",
              "true_ttft_measured": False, "subgroups": {}, "failures": []}
    for key, subset in [("all", cases)] + [(kind, [c for c in cases if c["kind"] == kind]) for kind in dataset["required_counts"]]:
        result["subgroups"][key] = proportion(sum(score_case(c, by_id.get(c["case_id"])) for c in subset), len(subset))
    for language in ("ru", "en"):
        subset = [c for c in cases if c["language"] == language]
        result["subgroups"][language] = proportion(sum(score_case(c, by_id.get(c["case_id"])) for c in subset), len(subset))
    exposure = exposure_provenance(dataset)
    exposed_ids = set(exposure["development_exposed_case_ids"])
    for name, exposed in (("development_exposed", True), ("untouched_by_development_pilot", False)):
        subset = [case for case in cases if (case["case_id"] in exposed_ids) == exposed]
        result["subgroups"][name] = proportion(sum(score_case(c, by_id.get(c["case_id"])) for c in subset), len(subset))
    result["development_exposure"] = exposure
    result["development_exposed_case_ids"] = exposure["development_exposed_case_ids"]
    pairs = {"category": [], "proposed_priority": []}
    clusters = {"category": {}, "proposed_priority": {}}
    reference_valid = reference_total = source_unique_valid = 0
    abstain_correct = abstain_total = 0
    tool_correct = tool_total = fixed_supported = fixed_total = 0
    fixed_expected = fixed_supplied = 0
    for case in cases:
        record = by_id.get(case["case_id"], {})
        if not score_case(case, record):
            result["failures"].append({"case_id": case["case_id"], "kind": case["kind"],
                                        "error_code": record.get("error_code", "wrong_answer" if record else "not_run")})
        if "retrieval" in case:
            raw = {}
            try:
                raw = json.loads(record.get("model_content", "{}"))
            except ValueError:
                pass
            selections = raw.get("recommendations", []) if isinstance(raw, dict) else []
            malformed_container = not isinstance(selections, list)
            if malformed_container:
                selections = [selections]  # malformed container cannot erase an invalid reference claim
            registered = [item for item in case["retrieval"]["items"] if item["citation"]["status"] != "stale"]
            selected, supported_ids = {}, set()
            rendered = {item["source_id"]: item for item in record.get("result", {}).get("recommendations", [])}
            for selection in selections if isinstance(selections, list) else []:
                reference_total += 1
                ref = selection.get("source_ref") if isinstance(selection, dict) else None
                source = registered[ref] if type(ref) is int and 0 <= ref < len(registered) else None
                if source is None:
                    continue
                sid = source["source_id"]
                duplicate = sid in selected
                selected[sid] = selection
                supported = (not malformed_container and not duplicate and sid in case["gold"]["source_ids"] and not
                    {"source_id", "source_hash", "snapshot_id"} & selection.keys() and
                    (not record.get("valid") or all(rendered.get(sid, {}).get(key) == source[key]
                        for key in ("source_id", "source_hash", "snapshot_id"))))
                reference_valid += bool(supported)
                if supported:
                    supported_ids.add(sid)
            source_unique_valid += len(supported_ids)
            if case["kind"] == "analysis":
                for expected in case["gold"]["labels"]:
                    actual = selected.get(expected["source_id"], {}) if record.get("valid") else {}
                    for field in pairs:
                        pair = (expected[field], actual.get(field, "__missing__"))
                        pairs[field].append(pair)
                        cluster_id = case["case_id"].replace("-ru-", "-paired-").replace("-en-", "-paired-")
                        clusters[field].setdefault(cluster_id, []).append(pair)
            abstain_total += 1
            actual_abstain = record.get("valid") and not record.get("result", {}).get("recommendations")
            abstain_correct += bool(record.get("valid") and actual_abstain == case["gold"]["abstain"])
        else:
            tool_total += 1
            tool_correct += bool(record.get("valid") and record.get("result", {}).get("tool") == case["gold"]["tool"])
            if case["kind"] == "remediation":
                fixed_expected += case["gold"]["target_version"] is not None
                for card in record.get("domain_result", {}).get("items", []):
                    if card.get("target_version") is not None:
                        fixed_total += 1
                        supported = card["target_version"] == case["gold"]["target_version"] and card["status"] == case["gold"]["status"]
                        fixed_supported += supported
                        fixed_supplied += supported
    result["tool_accuracy"] = proportion(tool_correct, tool_total)
    result["citation_precision"] = proportion(reference_valid, reference_total)
    result["abstention_accuracy"] = proportion(abstain_correct, abstain_total)
    result["fixed_claim_support"] = proportion(fixed_supported, fixed_total)
    result["fixed_claim_recall"] = proportion(fixed_supplied, fixed_expected)
    result["unsupported_reference_or_fixed_claims"] = reference_total - reference_valid + fixed_total - fixed_supported
    result["unsupported_model_fields_or_prose"] = sum(unsupported_model_fields(case, by_id.get(case["case_id"], {})) for case in cases)
    result["source_selection_recall"] = proportion(source_unique_valid, sum(len(case["gold"]["source_ids"]) for case in cases if "retrieval" in case))
    classes = {"category": ("vulnerability", "configuration", "exposure", "unknown"),
               "proposed_priority": ("high", "medium", "low", "unknown")}
    for field, values in pairs.items():
        generator = random.Random(1729)
        grouped = list(clusters[field].values())
        bootstrapped = [macro_f1([pair for group in generator.choices(grouped, k=len(grouped))
                                  for pair in group], classes[field]) for _ in range(1000)] if grouped else []
        result[field + "_macro_f1"] = {"value": macro_f1(values, classes[field]), "observations": len(values),
                                       "independent_scenario_clusters": len(grouped),
                                       "confidence_method": "1000 paired-scenario cluster bootstrap resamples, seed1729",
                                       "bootstrap_95": [quantile(bootstrapped, .025), quantile(bootstrapped, .975)]}
    def timed(record):
        value = record.get("elapsed_seconds")
        return type(value) in (int, float) and math.isfinite(value) and value >= 0
    durations = [by_id[c["case_id"]]["elapsed_seconds"] for c in cases
                 if c["case_id"] in by_id and timed(by_id[c["case_id"]])]
    valid_durations = [by_id[c["case_id"]]["elapsed_seconds"] for c in cases
                       if by_id.get(c["case_id"], {}).get("valid") is True
                       and by_id[c["case_id"]].get("model_invoked") is True and timed(by_id[c["case_id"]])]
    response_coverage = len(valid_durations) == len(cases)
    native = [record["native_timings"] for record in records if isinstance(record.get("native_timings"), dict)]
    first_bytes = [record["http_first_byte_seconds"] for record in records if isinstance(record.get("http_first_byte_seconds"), (int, float))]
    result["latency_seconds"] = {"count": len(durations), "p50": quantile(durations, .5), "p95": quantile(durations, .95),
                                  "valid_response_count": len(valid_durations), "required_response_count": len(cases),
                                  "valid_response_coverage_complete": response_coverage,
                                  "valid_response_p50": quantile(valid_durations, .5),
                                  "valid_response_p95": quantile(valid_durations, .95),
                                  "missing_duration_records": len(by_id) - len(durations),
                                  "max": max(durations) if durations else None,
                                  "http_first_byte_count": len(first_bytes), "http_first_byte_p95": quantile(first_bytes, .95),
                                  "scope": "model call plus synthetic component rendering; failures included; excludes API queue/auth"}
    result["native_generation"] = {"timing_records": len(native),
        "missing_timing_records": len(records) - len(native),
        "decoded_tokens": sum(timing.get("predicted_n", 0) for timing in native),
        "prompt_tokens": sum(timing.get("prompt_n", 0) for timing in native),
        "warm_prompt_records": sum(timing.get("cache_n", 0) > 0 for timing in native),
        "cold_prompt_records": sum(timing.get("cache_n", 0) == 0 for timing in native),
        "decode_tokens_per_second_p50": quantile([timing["predicted_per_second"] for timing in native if "predicted_per_second" in timing], .5)}
    thresholds = dataset["thresholds"]
    result["gates"] = {
        "all_cases_executed": set(by_id) == {case["case_id"] for case in cases} and all(r.get("model_invoked") for r in records),
        "tool_accuracy": tool_total > 0 and tool_correct / tool_total >= thresholds["tool_accuracy_min"],
        "planning_accuracy": (result["subgroups"]["planning"]["value"] or 0) >= thresholds["planning_accuracy_min"],
        "category_macro_f1": result["category_macro_f1"]["value"] >= thresholds["category_macro_f1_min"],
        "citation_precision": reference_total > 0 and reference_valid / reference_total >= thresholds["citation_precision_min"],
        "fixed_claim_support": fixed_total > 0 and fixed_supported / fixed_total >= thresholds["fixed_claim_support_min"],
        "fixed_claim_recall": fixed_expected > 0 and fixed_supplied == fixed_expected,
        "security": (result["subgroups"]["security"]["value"] or 0) >= thresholds["security_pass_fraction_min"],
        "no_unsupported_model_claims": result["unsupported_model_fields_or_prose"] == 0,
        "full_response_latency": response_coverage and quantile(durations, .95) <= thresholds["first_response_p95_seconds_max"],
        "task_component_latency": response_coverage and quantile(durations, .95) <= thresholds["task_p95_seconds_max"],
    }
    # The frozen thresholds carry no minimum for these: they are reported, never gated.
    result["informational_metrics"] = ["proposed_priority_macro_f1", "abstention_accuracy", "subgroups.degraded"]
    # Deprecated alias: the threshold key still says "first_response", but the
    # measured value is the time to the complete answer (no streaming TTFT).
    result["gates"]["first_response_latency"] = result["gates"]["full_response_latency"]
    gates_green = stage == "final" and all(v for k, v in result["gates"].items() if k != "first_response_latency")
    untouched = result["subgroups"]["untouched_by_development_pilot"]["total"]
    # A corpus the development pilots already saw cannot certify generalization.
    result["quality_gate_status"] = ("failed" if stage != "final" or not gates_green
                                     else "exposed_only" if untouched == 0 else "passed")
    result["quality_gate_passed"] = result["quality_gate_status"] == "passed"
    result["not_run_count"] = sum(case["case_id"] not in by_id for case in cases)
    result["executed_case_failures"] = sum(not score_case(case, by_id[case["case_id"]]) for case in cases if case["case_id"] in by_id)
    result["release_acceptance_claimed"] = False
    result["confidence_limitations"] = "Descriptive intervals on synthetic paired RU/EN scenarios; not external-domain or deployment certification"
    return result


async def run(args):
    global RUNTIME_OVERRIDE
    if args.provenance_json:
        RUNTIME_OVERRIDE = json.loads(Path(args.provenance_json).read_text())
    dataset = load_dataset()
    all_cases = dataset["cases"]
    if args.soak_seconds < 0 or (args.limit is not None and args.limit <= 0):
        raise ValueError("Invalid load duration or case limit")
    if args.case_id and set(args.case_id) - {case["case_id"] for case in all_cases}:
        raise ValueError("Unknown requested case ID")
    if args.manifest:
        manifest = json.loads(Path(args.manifest).read_text())
        if manifest["dataset_sha256"] != file_digest(DATASET) or manifest["source_sha256"] != source_provenance():
            raise ValueError("Frozen dataset or source files changed; make a new freeze and run")
        if manifest["thresholds"] != dataset["thresholds"]:
            raise ValueError("Manifest thresholds differ from the frozen gold dataset")
        if manifest["runtime"] != runtime_provenance():
            raise ValueError("Runtime differs from frozen command/image")
    elif not args.development:
        raise ValueError("Final runs require independently reviewed frozen provenance")
    output = Path(args.output)
    missing_directories = []
    cursor = output
    while not cursor.exists():
        missing_directories.append(cursor)
        cursor = cursor.parent
    output.mkdir(parents=True, exist_ok=args.resume)
    # Persist each newly created directory's link in its parent, not only the
    # later journal entries inside the output directory itself.
    for created in reversed(missing_directories):
        _sync_directory(created.parent)
    storage = durable_storage_preflight(output, require_native=args.require_native_filesystem)
    launch_authorization = await authorize_launch(output, required=getattr(args, "require_launch_permit", False))
    stage = "development" if args.development else "final"
    if args.manifest:
        (output / "manifest.json").write_bytes(Path(args.manifest).read_bytes())
    selected = [case for case in all_cases if (not args.kind or case["kind"] in args.kind)
                and (not args.case_id or case["case_id"] in args.case_id)]
    if args.limit:
        if not args.development:
            raise ValueError("Final runs cannot omit cases")
        selected = selected[:args.limit]
    if args.kind and not args.development:
        raise ValueError("Final runs cannot omit kinds")
    if args.case_id and not args.development:
        raise ValueError("Final runs cannot omit case IDs")
    if not selected:
        raise ValueError("No cases selected")
    run_metadata = {"stage": stage, "dataset_sha256": file_digest(DATASET),
               "development_exposure": exposure_provenance(dataset),
               "expected_case_ids": [case["case_id"] for case in all_cases],
               "scheduled_case_ids": [case["case_id"] for case in selected], "source_sha256": source_provenance(),
               "runtime": runtime_provenance(), "analysis_prompt_version": analysis.PROMPT_VERSION,
               "planner_prompt_version": planner.PROMPT_VERSION, "model_sha256_pinned": MODEL_SHA256,
               "model_bytes_reverified": bool(args.manifest),
               "result_journal_format": "operator-executions-v2",
               "storage_durability_preflight": storage,
               "launch_authorization_protocol": "native-nonce-cid-expiry-v1" if launch_authorization else "not_required",
               "runtime_provenance_mode": "externally_sealed_controller" if args.provenance_json else "live_docker_inspection"}
    if args.resume:
        previous = json.loads((output / "run.json").read_text())
        if previous != run_metadata:
            raise ValueError("Resume requires identical dataset/source/runtime/case selection")
    else:
        write_json(output / "run.json", run_metadata)
    config = OperatorConfig(enabled=True, provider="local", base_url=args.base_url,
                            max_output_tokens=512, timeout_seconds=120)
    run_started = monotonic()
    stop_sampling = asyncio.Event()
    sampler = None if args.external_resource_sampling else asyncio.create_task(
        sample_resources(output / "resource-samples.jsonl", stop_sampling, run_started))
    records = [json.loads(line) for line in (output / "records.jsonl").read_text().splitlines()] if args.resume else []
    if args.resume:
        records = recover_inflight(output, records, selected)
    completed = {record["case_id"] for record in records}
    if len(completed) != len(records):
        raise ValueError("Duplicate completed records; refusing biased resume")
    interrupted = False
    provider_authorized = False
    for number, case in enumerate(selected, 1):
        if case["case_id"] in completed:
            continue  # Failed cases count too; final resume never retries them.
        identity = begin_execution(output, case, phase="initial", ordinal=number)
        record = await evaluate_one(case, config, launch_authorization if not provider_authorized else None)
        provider_authorized = provider_authorized or record.get("model_invoked", False)
        record.update(identity)
        records.append(record)
        complete_execution(output, record, phase="initial")
        write_json(output / "report.json", summarize(dataset, records, stage=stage))
        print(f"{number}/{len(selected)} {case['case_id']} {'PASS' if score_case(case, record) else 'FAIL'} {record['elapsed_seconds']:.2f}s", flush=True)
        if record.get("interrupted") or record.get("launch_authorization_rejected"):
            interrupted = True
            break
    soak_records = soak_history(output) if args.resume else []
    soak_count = len(soak_records)
    soak_iteration = max((item["soak_iteration"] for item in soak_records), default=0)
    soak_errors = sum(not item["valid"] for item in soak_records)
    consecutive_errors = 0
    while not interrupted and args.soak_seconds and monotonic() - run_started < args.soak_seconds:
        case = selected[soak_iteration % len(selected)]
        soak_iteration += 1
        identity = begin_execution(output, case, phase="soak", soak_iteration=soak_iteration)
        record = await evaluate_one(case, config, launch_authorization if not provider_authorized else None)
        provider_authorized = provider_authorized or record.get("model_invoked", False)
        record.update(identity)
        soak_count += 1
        soak_errors += not record["valid"]
        consecutive_errors = 0 if record["valid"] else consecutive_errors + 1
        complete_execution(output, record, phase="soak")
        print(f"soak {soak_count} {case['case_id']} {'VALID' if record['valid'] else 'FAIL'} elapsed={monotonic() - run_started:.1f}s", flush=True)
        if record.get("interrupted") or record.get("launch_authorization_rejected") or consecutive_errors >= 3:
            break  # preserve failure rather than hammer an unavailable runtime
    stop_sampling.set()
    if sampler is not None:
        await sampler
    report = summarize(dataset, records, stage=stage)
    report["storage_durability_preflight"] = storage
    report["launch_authorization"] = launch_authorization
    report["raw_records_sha256"] = file_digest(output / "records.jsonl")
    report["source_unchanged_after_run"] = (not args.manifest or manifest["source_sha256"] == source_provenance())
    if not report["source_unchanged_after_run"]:
        report["quality_gate_passed"] = False
        report["quality_gate_status"] = "failed"
    report["load"] = {"requested_seconds": args.soak_seconds or None,
                      "elapsed_seconds": monotonic() - run_started,
                      "initial_requests": len(records), "additional_requests": soak_count,
                      "additional_errors": soak_errors, "max_inference_concurrency": 1,
                      "fake_idle_seconds": 0,
                      "duration_met": not args.soak_seconds or monotonic() - run_started >= args.soak_seconds,
                      "resource_sampling_mode": "external_controller" if args.external_resource_sampling else "internal_docker_stats",
                      "resource_samples_sha256": file_digest(output / "resource-samples.jsonl") if (output / "resource-samples.jsonl").exists() else None}
    if (output / "soak-records.jsonl").exists():
        report["load"]["raw_additional_sha256"] = file_digest(output / "soak-records.jsonl")
    report["load"]["gate_passed"] = (report["load"]["duration_met"] and len(records) + soak_count >= 30
        and all(record.get("valid") for record in records) and soak_errors == 0) if args.soak_seconds else None
    report["load"]["final_min_soak_seconds"] = FINAL_MIN_SOAK_SECONDS
    report["load"]["final_soak_requirement_met"] = args.development or args.soak_seconds >= FINAL_MIN_SOAK_SECONDS
    report["run_gate_passed"] = bool(report["quality_gate_passed"] and report["load"]["final_soak_requirement_met"] and (
        report["load"]["gate_passed"] if args.soak_seconds else True))
    write_json(output / "report.json", report)
    print(json.dumps({"stage": stage, "report": str(output / "report.json"),
                      "quality_gate_passed": report["quality_gate_passed"],
                      "quality_gate_status": report["quality_gate_status"], "load_gate_passed": report["load"]["gate_passed"],
                      "run_gate_passed": report["run_gate_passed"], "failures": len(report["failures"])}))
    return 0 if args.development or report["run_gate_passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    freeze_parser = commands.add_parser("freeze")
    freeze_parser.add_argument("--output", required=True)
    freeze_parser.add_argument("--reviewed-by", required=True)
    freeze_parser.add_argument("--model-path", default=str(ROOT / ".operator-models/Qwen3.5-9B-Q4_K_M.gguf"))
    run_parser = commands.add_parser("run")
    run_parser.add_argument("--output", required=True)
    run_parser.add_argument("--manifest")
    run_parser.add_argument("--development", action="store_true")
    run_parser.add_argument("--limit", type=int)
    run_parser.add_argument("--case-id", action="append")
    run_parser.add_argument("--soak-seconds", type=int, default=0)
    run_parser.add_argument("--resume", action="store_true")
    run_parser.add_argument("--provenance-json")
    run_parser.add_argument("--external-resource-sampling", action="store_true")
    run_parser.add_argument("--require-native-filesystem", action="store_true",
                            help="Require Linux ext4 results storage in addition to durable journal preflight")
    run_parser.add_argument("--require-launch-permit", action="store_true",
                            help="Do not call the provider without a fresh host-issued native-volume launch permit")
    run_parser.add_argument("--kind", choices=("analysis", "remediation", "planning", "degraded", "security"), action="append")
    run_parser.add_argument("--base-url", default="http://127.0.0.1:8082/v1")
    args = parser.parse_args()
    if args.command == "freeze":
        result = freeze(args.output, reviewed_by=args.reviewed_by, model_path=args.model_path)
        print(json.dumps({"manifest": str(Path(args.output) / "manifest.json"), "dataset_sha256": result["dataset_sha256"]}))
        return 0
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
