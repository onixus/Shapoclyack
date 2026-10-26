#!/usr/bin/env python3
"""Host-side deadline controller for one newly launched sealed quality runner.

Only its own immutable, nonce-labelled runner can receive a signal. Model
containers are never addressed. Acceptance thresholds and evaluator artifacts
are not modified; any deadline violation makes this controller fail.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
import sys
import time
from uuid import uuid4

REQUEST_SECONDS = 120
CLEANUP_SECONDS = 30
HARD_SECONDS = REQUEST_SECONDS + CLEANUP_SECONDS
STARTUP_SECONDS = 60
DOCKER_SECONDS = 5
LABEL = "shapoclyack.operator-quality-watchdog"
PREFIX = "shapo-operator-quality-watchdog-"
CANCEL_SIGNAL = None
LAUNCH_NONCE_ENV = "OPERATOR_QUALITY_LAUNCH_NONCE"


def request_controller_stop(number, _frame=None):
    # Do not abandon a possibly queued start. The normal monitor/reaper stops
    # only our owned runner and remains alive until terminal proof is obtained.
    global CANCEL_SIGNAL
    CANCEL_SIGNAL = number


def docker(arguments):
    return subprocess.run(["docker", *arguments], check=True, capture_output=True,
                          text=True, timeout=DOCKER_SECONDS).stdout


class Receipt:
    def __init__(self, path):
        self.path = Path(path)
        self.events_path = self.path.with_suffix(self.path.suffix + ".jsonl")
        if self.path.exists() or self.events_path.exists() or self.path.is_symlink() or self.events_path.is_symlink():
            raise ValueError("Refusing to overwrite watchdog evidence")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.events = []
        self.persistence_failures = 0

    def record(self, kind, **fields):
        event = {"at": datetime.now(UTC).isoformat(), "monotonic": time.monotonic(), "kind": kind, **fields}
        self.events.append(event)
        with self.events_path.open("a") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def finish(self, **fields):
        temporary = self.path.with_name(self.path.name + "." + uuid4().hex + ".tmp")
        with temporary.open("x") as handle:
            json.dump({"schema_version": 1, "events": self.events, **fields}, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)
        descriptor = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def read_journal(directory):
    path = Path(directory) / "inflight.json"
    if not path.exists():
        return None
    if path.is_symlink():
        raise ValueError("Symlink journal")
    with path.open("rb") as handle:
        raw = handle.read(8193)
    if len(raw) > 8192:
        raise ValueError("Oversized journal")
    return json.loads(raw)


CONTAINER_JOURNAL_READER = """import json,sys
from pathlib import Path
p=Path(sys.argv[1])/'inflight.json'
if p.is_symlink(): raise ValueError('Symlink journal')
if not p.exists(): print('null')
else:
 with p.open('rb') as f: raw=f.read(8193)
 if len(raw)>8192: raise ValueError('Oversized journal')
 print(json.dumps(json.loads(raw)))
"""


def container_path(value):
    if (not isinstance(value, str) or not value.startswith("/") or len(value) > 512
            or any(part in {"", ".", ".."} for part in value[1:].split("/"))
            or str(PurePosixPath(value)) != value):
        raise ValueError("A canonical absolute container output directory is required")
    return value


def read_container_journal(cid, name, nonce, directory, command=docker):
    directory = container_path(directory)
    if not owned_state(cid, name, nonce, command).get("Running"):
        return None  # the terminal export retains any unresolved durable journal
    raw = command(["exec", cid, "python", "-c", CONTAINER_JOURNAL_READER, directory])
    if len(raw.encode()) > 8192:
        raise ValueError("Oversized container journal")
    return json.loads(raw)


def require_native_output_mount(cid, name, nonce, directory, command=docker):
    directory = container_path(directory)
    value = owned_inspection(cid, name, nonce, command)
    mounts = [mount for mount in value.get("Mounts", [])
              if directory == mount.get("Destination") or directory.startswith(mount.get("Destination", "") + "/")]
    if not mounts:
        raise ValueError("Native output directory has no volume mount")
    selected = max(mounts, key=lambda mount: len(mount["Destination"]))
    if selected.get("Type") != "volume" or selected.get("Driver") != "local" or selected.get("RW") is not True:
        raise ValueError("Native output requires a writable local Docker volume")
    return {key: selected.get(key) for key in ("Type", "Name", "Driver", "Destination", "RW")}


NATIVE_PERMIT_WRITER = """import os,sys,tempfile
from pathlib import Path
directory=Path(sys.argv[1]);raw=sys.argv[2].encode();nonce=sys.argv[3]
target=directory/('launch-permit-'+nonce+'.json')
if target.exists() or target.is_symlink(): raise ValueError('Permit already exists')
fd,temporary=tempfile.mkstemp(prefix='.launch-permit-',dir=directory)
try:
 with os.fdopen(fd,'wb') as f: f.write(raw);f.flush();os.fsync(f.fileno())
 os.replace(temporary,target)
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
 try: os.fsync(fd)
 finally: os.close(fd)
finally: Path(temporary).unlink(missing_ok=True)
print('launch-permit-fsynced')
"""


def publish_launch_permit(cid, name, nonce, directory, requested_at, receipt, command=docker):
    if not owned_state(cid, name, nonce, command).get("Running"):
        raise ValueError("Launch permit requires verified owned Running state")
    requested = datetime.fromisoformat(requested_at)
    issued = datetime.now(UTC)
    expires = requested + timedelta(seconds=STARTUP_SECONDS)
    if requested.tzinfo is None or not requested <= issued < expires:
        raise ValueError("Launch authorization window expired")
    value = {"schema_version": 1, "nonce": nonce, "container_id": cid,
             "requested_at": requested.isoformat(), "issued_at": issued.isoformat(), "expires_at": expires.isoformat()}
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"))
    # This call occurs only once, after a successful start ACK. If this RPC is
    # uncertain, sticky failed supervision still owns any delivered authority.
    command(["exec", cid, "python", "-c", NATIVE_PERMIT_WRITER,
             str(PurePosixPath(container_path(directory)).parent), raw, nonce])
    receipt.record("launch_permit_acknowledged", container_id=cid, nonce=nonce,
                   expires_at=value["expires_at"], permit_sha256=hashlib.sha256(raw.encode()).hexdigest())
    return value


def export_native_results(cid, name, nonce, directory, destination, command=docker):
    """Copy only terminal owned results, retain native evidence on every failure."""
    if not confirmed_terminal(owned_state(cid, name, nonce, command)):
        raise ValueError("Cannot export results before confirmed terminal state")
    directory = container_path(directory)
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError("Refusing to overwrite exported evidence")
    temporary = destination.with_name("." + destination.name + ".export-" + uuid4().hex)
    # Docker cp of an absent destination creates it with source-directory contents.
    # No -L: never follow a symlink supplied by the container.
    command(["cp", cid + ":" + directory, str(temporary)])
    if not temporary.is_dir() or temporary.is_symlink():
        raise ValueError("Missing exported result directory")
    hashes = {}
    for path in temporary.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError("Exported results contain an unsupported entry")
        with path.open("rb") as handle:
            hashes[path.name] = hashlib.file_digest(handle, "sha256").hexdigest()
            os.fsync(handle.fileno())
    descriptor = os.open(temporary, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.rename(temporary, destination)
    descriptor = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {"directory": str(destination), "sha256": hashes, "native_evidence_retained": True}


def confirmed_terminal(state):
    if not isinstance(state, dict) or state.get("Running") is not False:
        return False
    if state.get("Dead") is True or state.get("Status") in {"dead", "removed"}:
        return True
    started = state.get("StartedAt")
    return (state.get("Status") == "exited" and isinstance(started, str) and bool(started)
            and not started.startswith(("0000-", "0001-")))


def supervise_terminal(cid, name, nonce, receipt, *, reason, command=docker, sleep=time.sleep):
    """Sticky failed supervision; bounded RPCs, no total give-up or start retry.

    A timed-out start may execute after a successful inspection of CREATED.
    Only a completed start followed by EXITED/DEAD, or verified missing CID,
    resolves that risk. The controller must not exit while it remains unknown.
    """
    def persist(method, *args, **fields):
        try:
            method(*args, **fields)
        except OSError as exc:
            receipt.persistence_failures += 1
            # Evidence I/O failure must not abandon a queued/running workload.
            # Do not claim durable success; retry checkpoints on later cycles.
            try:
                print(json.dumps({"status": "failed", "terminal_supervision_pending": True,
                                  "receipt_write_failed": type(exc).__name__}), file=sys.stderr, flush=True)
            except OSError:
                pass  # cleanup still takes priority when both evidence streams fail

    persist(receipt.record, "terminal_supervision_started", container_id=cid, reason=reason)
    while True:
        state = None
        try:
            state = owned_state(cid, name, nonce, command)
        except subprocess.CalledProcessError as exc:
            error = (exc.stderr or "").lower()
            if ("no such object: " + cid in error or "no such container: " + cid in error):
                state = {"Status": "removed", "Running": False}
            else:
                persist(receipt.record, "terminal_inspect_failed", exception=type(exc).__name__)
        except (subprocess.SubprocessError, ValueError, OSError, KeyError, IndexError, TypeError) as exc:
            persist(receipt.record, "terminal_inspect_failed", exception=type(exc).__name__)
        if confirmed_terminal(state):
            persist(receipt.record, "terminal_state_confirmed", container_id=cid, state=state)
            return state
        if state is not None:
            persist(receipt.record, "terminal_state_pending", container_id=cid, state=state)
            if state.get("Running"):
                try:
                    send_owned(cid, name, nonce, "SIGKILL", receipt, command)
                except (subprocess.SubprocessError, ValueError, OSError, KeyError, IndexError, TypeError) as exc:
                    persist(receipt.record, "terminal_signal_failed", exception=type(exc).__name__)
        persist(receipt.finish, container_id=cid, name=name, status="failed", reason=reason,
                terminal_supervision_pending=True, controller_removal_requested=False,
                receipt_persistence_failures=receipt.persistence_failures)
        sleep(2.0)


class CaseClock:
    """Bind source UTC once, then use monotonic time so clocks cannot reset it."""
    def __init__(self):
        self.current = None
        self.seen = set()
        self.started = None
        self.source_started_at = None
        self.case_id = None
        self.phase = None
        self.soak_iteration = 0

    def update(self, journal, monotonic_now, utc_now):
        if journal is None:
            self.current = None
            return False
        case = journal.get("case_id")
        if not isinstance(case, str) or not case or len(case) > 256 or journal.get("status") != "evaluation_started":
            raise ValueError("Invalid inflight identity")
        stamp = journal.get("started_at")
        phase = journal.get("phase", "initial")
        iteration = journal.get("soak_iteration")
        if phase not in {"initial", "soak"}:
            raise ValueError("Invalid execution phase")
        expected = f"initial:{case}" if phase == "initial" else f"soak:{iteration}:{case}"
        identity = journal.get("execution_id", expected if phase == "initial" else None)
        if identity != expected:
            raise ValueError("Invalid execution identity")
        if identity == self.current:
            if stamp != self.source_started_at:
                raise ValueError("Inflight clock changed")
            return False
        if phase == "initial" and (case in self.seen or self.soak_iteration):
            raise ValueError("Repeated inflight case")
        if phase == "soak" and (type(iteration) is not int or iteration <= self.soak_iteration):
            raise ValueError("Non-increasing soak iteration")
        source = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if source.tzinfo is None:
            raise ValueError("Inflight UTC required")
        age = (utc_now - source.astimezone(UTC)).total_seconds()
        if age < -5:
            raise ValueError("Inflight clock is in the future")
        self.current, self.source_started_at = identity, stamp
        self.case_id, self.phase = case, phase
        self.started = monotonic_now - max(0, age)
        if phase == "initial":
            self.seen.add(case)
        else:
            self.soak_iteration = iteration
        return True


def owned_inspection(cid, name, nonce, command=docker):
    value = json.loads(command(["inspect", cid]))[0]
    if not isinstance(value, dict) or not isinstance(value.get("Config"), dict):
        raise ValueError("Malformed runner inspection")
    labels = value["Config"].get("Labels")
    if (value.get("Id") != cid or value.get("Name") != "/" + name
            or not isinstance(labels, dict) or labels.get(LABEL) != nonce):
        raise ValueError("Runner ownership mismatch; refusing signal")
    if not isinstance(value.get("State"), dict):
        raise ValueError("Malformed runner state")
    return value


def owned_state(cid, name, nonce, command=docker):
    return owned_inspection(cid, name, nonce, command)["State"]


def send_owned(cid, name, nonce, number, receipt, command=docker):
    state = owned_state(cid, name, nonce, command)
    if state.get("Running"):
        command(["kill", "--signal", number, cid])
        receipt.record("runner_signal", signal=number, container_id=cid)


def monitor(cid, name, nonce, directory, receipt, *, command=docker,
            monotonic=time.monotonic, utc_now=lambda: datetime.now(UTC), sleep=time.sleep,
            initial_failure=None, journal_reader=None, poll_seconds=0.5):
    clock = CaseClock()
    began = monotonic()
    last_progress = began
    invalid_since = None
    violation = initial_failure
    hard_at = began + CLEANUP_SECONDS if initial_failure else None
    soft_sent = False

    def check_deadline(at, reason):
        nonlocal violation, hard_at
        if violation is None and clock.current is not None and at - clock.started >= REQUEST_SECONDS:
            violation, hard_at = reason, clock.started + HARD_SECONDS
            receipt.record("watchdog_failure", reason=violation, case_id=clock.case_id, execution_id=clock.current,
                           elapsed_seconds=at - clock.started, request_seconds=REQUEST_SECONDS,
                           cleanup_seconds=CLEANUP_SECONDS, hard_seconds=HARD_SECONDS)

    while True:
        now = monotonic()
        if CANCEL_SIGNAL is not None and violation is None:
            violation, hard_at = "controller_stop_requested", now + CLEANUP_SECONDS
            receipt.record("watchdog_failure", reason=violation, signal=CANCEL_SIGNAL)
        # Even a Docker inspection failure must not reset an observed deadline.
        try:
            journal = (journal_reader or read_journal)(directory)
            now = monotonic()
            previous_case = clock.current
            same = isinstance(journal, dict) and journal.get("execution_id", f"initial:{journal.get('case_id')}") == previous_case
            # A vanished/replaced journal is not a completion receipt. Preserve
            # the previous deadline before update can clear/reset its clock.
            check_deadline(now, "case_deadline_exceeded" if same else "case_completion_control_gap")
            changed = clock.update(journal, now, utc_now())
            invalid_since = None
            if changed:
                last_progress = now
                receipt.record("case_observed", case_id=clock.case_id, execution_id=clock.current,
                               phase=clock.phase, soak_iteration=clock.soak_iteration if clock.phase == "soak" else None,
                               source_started_at=clock.source_started_at, bound_monotonic=clock.started)
            if journal is None and previous_case is not None:
                last_progress = now
        except (ValueError, TypeError, KeyError, AttributeError, OSError, subprocess.SubprocessError) as exc:
            invalid_since = now if invalid_since is None else invalid_since
            if now - invalid_since >= 3 and violation is None:
                violation, hard_at = "invalid_inflight_journal", now + CLEANUP_SECONDS
                receipt.record("watchdog_failure", reason=violation, exception=type(exc).__name__)
        check_deadline(monotonic(), "case_deadline_exceeded")
        if violation is None and clock.current is None and now - last_progress >= STARTUP_SECONDS:
            violation, hard_at = "runner_startup_or_progress_timeout", now + CLEANUP_SECONDS
            receipt.record("watchdog_failure", reason=violation)
        try:
            state = owned_state(cid, name, nonce, command)
        except (subprocess.SubprocessError, ValueError, KeyError, IndexError, TypeError) as exc:
            receipt.record("docker_inspect_failed", exception=type(exc).__name__)
            if violation is None:
                violation, hard_at = "runner_state_unavailable", now + CLEANUP_SECONDS
            state = None
        # inspect itself can span the deadline and return an exited runner.
        # Without a durable timed completion receipt, that gap is uncertain.
        check_deadline(monotonic(), "case_completion_control_gap")
        if confirmed_terminal(state):
            receipt.record("runner_exited", exit_code=state.get("ExitCode"), oom_killed=state.get("OOMKilled"))
            return {"status": "failed" if violation or state.get("ExitCode") != 0 or state.get("OOMKilled") else "passed",
                    "reason": violation, "container_state": state, "duration_seconds": monotonic() - began}
        if state is not None and not state.get("Running") and violation is None:
            violation, hard_at = "runner_terminal_state_unconfirmed", monotonic() + CLEANUP_SECONDS
            receipt.record("watchdog_failure", reason=violation, state=state)
        if violation is not None:
            number = "SIGKILL" if monotonic() >= hard_at else "SIGINT"
            if number == "SIGKILL" or not soft_sent:
                try:
                    send_owned(cid, name, nonce, number, receipt, command)
                except (subprocess.SubprocessError, ValueError, KeyError, IndexError, TypeError) as exc:
                    receipt.record("docker_signal_failed", signal=number, exception=type(exc).__name__)
                soft_sent = True
                if number == "SIGKILL":
                    # Do not wait indefinitely for a stalled Docker daemon.
                    try:
                        state = owned_state(cid, name, nonce, command)
                    except (subprocess.SubprocessError, ValueError, KeyError, IndexError, TypeError):
                        state = None
                    return {"status": "failed", "reason": violation, "container_state": state,
                            "duration_seconds": monotonic() - began, "hard_deadline_reached": True}
        sleep(poll_seconds)


def launch(args):
    cidfile = Path(args.cidfile)
    if cidfile.exists() or cidfile.is_symlink() or cidfile.parent.is_symlink():
        raise ValueError("A new non-symlink cidfile is required")
    runtime = args.runtime_arguments
    native_directory = getattr(args, "container_run_directory", None)
    if native_directory:
        container_path(native_directory)
        if args.run_directory.exists() or args.run_directory.is_symlink():
            raise ValueError("Native evidence export requires a new host results directory")
        if "--require-native-filesystem" not in runtime:
            raise ValueError("Native mode requires evaluator ext4 durability preflight")
        if "--require-launch-permit" not in runtime:
            raise ValueError("Native mode requires evaluator launch authorization")
    if runtime[:1] == ["--"]:
        runtime = runtime[1:]
    forbidden = {"--name", "--cidfile", "--label", "--label-file", "-l", "--rm", "--detach", "-d", "--restart"}
    if not runtime or any(value.split("=", 1)[0] in forbidden for value in runtime):
        raise ValueError("Runtime args cannot override controller identity, evidence retention or restart policy")
    nonce = uuid4().hex
    name = PREFIX + nonce
    receipt = Receipt(args.receipt)
    receipt.record("launch", name=name, nonce=nonce, request_seconds=REQUEST_SECONDS,
                   cleanup_seconds=CLEANUP_SECONDS, hard_seconds=HARD_SECONDS,
                   controller_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    cid = None
    start_requested = False
    monitor_options = {}
    if native_directory:
        monitor_options = {"journal_reader": lambda _: read_container_journal(cid, name, nonce, native_directory),
                           "poll_seconds": 2.0}
    result = {"status": "failed", "reason": "launch_failed"}
    try:
        # Separate create from start: if creation times out before the CLI can
        # write its cidfile, no untracked evaluator can begin executing.
        environment = ["--env", LAUNCH_NONCE_ENV + "=" + nonce] if native_directory else []
        docker(["create", "--pull=never", "--name", name, "--cidfile", str(cidfile),
                "--label", LABEL + "=" + nonce, *environment, *runtime])
        if cidfile.is_symlink():
            raise ValueError("Symlink cidfile")
        cid = cidfile.read_text().strip()
        if not re.fullmatch(r"[a-f0-9]{64}", cid):
            raise ValueError("Invalid immutable container ID")
        owned_state(cid, name, nonce)
        if native_directory:
            mount = require_native_output_mount(cid, name, nonce, native_directory)
            receipt.record("native_result_volume", mount=mount, container_directory=native_directory,
                           host_export_directory=str(args.run_directory), poll_seconds=2.0)
        if CANCEL_SIGNAL is not None:
            raise ValueError("Controller cancelled before start")
        requested_at = datetime.now(UTC).isoformat()
        receipt.record("runner_start_requested", container_id=cid, name=name, nonce=nonce, requested_at=requested_at)
        start_requested = True  # set BEFORE the only start RPC, which may time out
        docker(["start", cid])
        if native_directory:
            publish_launch_permit(cid, name, nonce, native_directory, requested_at, receipt, command=docker)
        result = monitor(cid, name, nonce, args.run_directory, receipt, **monitor_options)
    except (subprocess.SubprocessError, ValueError, OSError, KeyError, IndexError, TypeError) as exc:
        receipt.record("controller_failed", exception=type(exc).__name__)
        # A timed-out start may already be running our verified container. Its
        # fresh cidfile plus all three identity checks are still mandatory.
        try:
            if not cidfile.is_symlink() and cidfile.is_file() and cidfile.stat().st_size <= 128:
                candidate = cidfile.read_text().strip()
                if re.fullmatch(r"[a-f0-9]{64}", candidate):
                    owned_state(candidate, name, nonce)
                    cid = candidate
                    result = monitor(cid, name, nonce, args.run_directory, receipt,
                                     initial_failure="launch_or_controller_failed", **monitor_options)
        except (subprocess.SubprocessError, ValueError, OSError, KeyError, IndexError, TypeError) as cleanup_error:
            receipt.record("launch_cleanup_unavailable", exception=type(cleanup_error).__name__)
    finally:
        if cid and start_requested and not confirmed_terminal(result.get("container_state")):
            # A failed start/cleanup inspection is not evidence of a stopped
            # runner. In particular CREATED can precede a late queued start.
            result.update(status="failed", reason=result.get("reason") or "terminal_state_unconfirmed")
            result["container_state"] = supervise_terminal(cid, name, nonce, receipt,
                reason=result["reason"], command=docker)
            result["terminal_supervision_pending"] = False
            result["receipt_persistence_failures"] = receipt.persistence_failures
        if native_directory and cid:
            try:
                exported = export_native_results(cid, name, nonce, native_directory, args.run_directory)
                receipt.record("native_results_exported", **exported)
                result["native_results_export"] = exported
            except (subprocess.SubprocessError, ValueError, OSError, KeyError, IndexError, TypeError) as exc:
                receipt.record("native_results_export_failed", exception=type(exc).__name__)
                result.update(status="failed", native_results_export_failed=True,
                              native_evidence_retained=True)
        receipt.finish(container_id=cid, name=name, **result)
    return 0 if result["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cidfile", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--run-directory", required=True, type=Path)
    parser.add_argument("--container-run-directory",
                        help="Poll a native Docker-volume journal and export terminal evidence into new --run-directory")
    parser.add_argument("runtime_arguments", nargs=argparse.REMAINDER,
                        help="Existing sealed Docker options, immutable image and evaluator argv after --")
    args = parser.parse_args()
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        for number in previous:
            signal.signal(number, request_controller_stop)
        return launch(args)
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    raise SystemExit(main())
