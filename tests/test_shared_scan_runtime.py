"""Process-group and argv contracts exercised without any external scan."""

from __future__ import annotations

import ast
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from agent import worker
from agent.runtime.invocation import (
    INPUT_FLAGS,
    ScanInvocation,
    input_arguments,
    paths_from_arguments,
)
from agent.runtime.process import run_process, terminate_process
from api.services import local_scan_executor, job_submission
from tests import scanner_gate
from tests.conftest import requires_postgres


def test_real_parser_accepts_every_shared_option(monkeypatch, tmp_path):
    from scanner.main import parse_args

    paths = {name: str(tmp_path / "путь с пробелом" / name) for name in INPUT_FLAGS}
    invocation = ScanInvocation(
        "конфиг with spaces.yaml",
        mode="fast",
        run_id="custom-run",
        delta=True,
        skip_nse=True,
        notify=True,
        export_defectdojo=True,
        inputs=paths,
    )
    argv = invocation.argv(sys.executable)
    monkeypatch.setattr(sys, "argv", ["scanner.main"] + argv[3:])
    parsed = parse_args()
    assert parsed.mode == "fast" and parsed.run_id == "custom-run"
    assert (
        parsed.delta and parsed.skip_nse and parsed.notify and parsed.export_defectdojo
    )
    for name, flag in INPUT_FLAGS.items():
        assert getattr(parsed, flag[2:].replace("-", "_")) == paths[name]


def test_local_and_sensor_share_invocation_and_preserve_empty_files(tmp_path):
    inputs = {name: "" for name in INPUT_FLAGS}
    inputs["ranges.txt"] = "2001:db8::/64\n"
    sensor_args = worker._write_inputs(tmp_path, inputs)
    invocation = ScanInvocation(
        "config",
        mode="safe",
        run_id="custom",
        delta=True,
        skip_nse=True,
        notify=True,
        export_defectdojo=True,
        inputs=paths_from_arguments(sensor_args),
    )
    local = job_submission.build_command(
        None,
        mode="safe",
        run_id="custom",
        delta=True,
        skip_nse=True,
        notify=True,
        export_defectdojo=True,
        config_path="config",
        target_args=sensor_args,
    )
    assert local == invocation.argv(sys.executable)
    assert (tmp_path / "ranges.txt").read_text() == "2001:db8::/64\n"
    assert (tmp_path / "scan_scope.json").read_text() == ""
    assert worker._write_inputs(tmp_path / "absent", {}) == []
    assert not (tmp_path / "absent").exists()
    legacy = worker._write_inputs(tmp_path / "legacy", {"ranges.txt": ""})
    assert set(paths_from_arguments(legacy)) == {"ranges.txt", "domains.txt"}
    assert (tmp_path / "legacy/domains.txt").read_text() == ""


@pytest.mark.parametrize("paths", [{"unknown.json": "x"}, {"ranges.txt": "x"}])
def test_incompatible_input_contract_refuses(paths):
    with pytest.raises(ValueError):
        input_arguments(paths)


def test_unknown_wire_input_refused_before_writes(tmp_path):
    with pytest.raises(ValueError, match="unsupported"):
        worker._write_inputs(
            tmp_path / "job", {"scan_scope.json": "{}", "../escape": "x"}
        )
    assert not (tmp_path / "job").exists()
    with pytest.raises(ValueError):
        paths_from_arguments(["--ports-file", "a", "--ports-file", "b"])
    with pytest.raises(ValueError):
        ScanInvocation("config", mode="unsupported").argv(sys.executable)


@pytest.mark.parametrize("adapter", ["local", "sensor"])
@pytest.mark.parametrize("exit_code", [0, 7])
def test_adapters_normal_and_nonzero(adapter, exit_code, monkeypatch, tmp_path):
    # Both pipes exceed kernel buffers; sequential pipe reads would deadlock.
    command = [
        sys.executable,
        "-c",
        f"import sys;sys.stdout.write('o'*200000);sys.stderr.write('e'*200000);sys.exit({exit_code})",
    ]
    if adapter == "local":
        result = local_scan_executor.run_scanner("runtime-test", command)
        assert result.returncode == exit_code
        assert len(result.stdout) == len(result.stderr) == 200000
    else:
        monkeypatch.setattr(ScanInvocation, "argv", lambda *_: command)
        run = tmp_path / "out/runs/run"
        run.mkdir(parents=True)
        (run / "result.json").write_text("{}")
        tmp_path.joinpath("work").mkdir()
        code, error, archive = worker._run_scan(
            config=tmp_path / "config",
            job={"run_id": "run"},
            workdir=tmp_path / "work",
            output_dir=tmp_path / "out",
        )
        assert code == exit_code
        assert (archive is not None) == (exit_code == 0)
        if exit_code:
            assert error == "e" * 2000


@pytest.mark.parametrize("adapter", ["local", "sensor"])
def test_adapters_spawn_error_and_precancel(adapter, monkeypatch, tmp_path):
    def fail(*args, **kwargs):
        raise OSError("spawn denied")

    monkeypatch.setattr(subprocess, "Popen", fail)
    if adapter == "local":
        with pytest.raises(OSError, match="spawn denied"):
            local_scan_executor.run_scanner("runtime-test", ["missing"])
        local_scan_executor._draining.set()
        try:
            assert (
                local_scan_executor.run_scanner("runtime-test", ["missing"]).returncode
                == 143
            )
        finally:
            local_scan_executor._draining.clear()
    else:
        kwargs = dict(
            config=tmp_path / "config",
            job={"run_id": "run"},
            workdir=tmp_path / "work",
            output_dir=tmp_path / "out",
        )
        assert "spawn denied" in worker._run_scan(**kwargs)[1]
        event = threading.Event()
        event.set()
        code, error, archive = worker._run_scan(**kwargs, cancel_event=event)
        assert code == 143 and "cancelled" in error and archive is None


@pytest.mark.parametrize("reason", ["timeout", "cancelled"])
def test_runtime_distinguishes_timeout_cancel(reason):
    event = threading.Event()
    timer = threading.Timer(0.1, event.set)
    if reason == "cancelled":
        timer.start()
    try:
        result = run_process(
            [sys.executable, "-c", "import time;time.sleep(60)"],
            timeout=0.15 if reason == "timeout" else None,
            cancel_event=event,
            shutdown_budget=0.5,
        )
    finally:
        if reason == "cancelled":
            timer.join()
    assert result.reason == reason
    assert result.returncode == (124 if reason == "timeout" else 143)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")
@pytest.mark.parametrize("parent_exits", [False, True])
def test_ignored_term_child_and_inherited_pipes_are_bounded(tmp_path, parent_exits):
    marker = tmp_path / "child"
    child_script = (
        "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)"
    )
    script = (
        "import subprocess,sys,pathlib,time;"
        f"child=subprocess.Popen([sys.executable,'-c',{child_script!r}]);"
        f"pathlib.Path({str(marker)!r}).write_text(str(child.pid));"
        + (
            "time.sleep(.1)"
            if parent_exits
            else "import signal;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)"
        )
    )
    start = time.monotonic()
    result = run_process(
        [sys.executable, "-c", script], timeout=0.3, shutdown_budget=0.6
    )
    assert result.reason == "timeout"
    assert time.monotonic() - start < 1.8
    pid = int(marker.read_text())
    end = time.monotonic() + 2
    while scanner_gate.is_running(pid) and time.monotonic() < end:
        time.sleep(0.01)
    assert not scanner_gate.is_running(pid)


def test_repeat_termination_and_exit_cancel_race():
    event = threading.Event()
    handles = []
    result = run_process(
        [sys.executable, "-c", 'print("done")'],
        on_spawn=handles.append,
        cancel_event=event,
        shutdown_budget=0.2,
    )
    assert result.returncode == 0
    event.set()
    for _ in range(2):
        terminate_process(handles[0], shutdown_budget=0.1, term_grace=0.02)
    assert handles[0].stdout.closed and handles[0].stderr.closed


def test_shared_runtime_has_no_business_dependencies():
    for name in ("process", "invocation"):
        path = Path("agent/runtime") / f"{name}.py"
        tree = ast.parse(path.read_text())
        imports = [
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        ]
        imports += [
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        ]
        assert not any(
            x.split(".")[0] in {"api", "fastapi", "sqlalchemy", "scanner"}
            for x in imports
        )
        assert not any(
            word in path.read_text()
            for word in ("get_session(", "job.status", "tenant_id")
        )


def test_required_input_names_do_not_treat_option_values_as_flags():
    from agent.runtime.invocation import required_input_names

    assert required_input_names(
        [
            "python",
            "-m",
            "scanner.main",
            "--config",
            "--scan-policy",
            "--scan-scope",
            "/replica/private/scope.json",
        ]
    ) == {"scan_scope.json"}


def test_document_presence_is_separate_from_content(tmp_path):
    from api.services import job_control, job_inputs
    from tests.conftest import make_settings

    settings = make_settings(tmp_path)
    directory = job_inputs.job_inputs_dir(settings, "job")
    directory.mkdir(parents=True)
    (directory / "scan_scope.json").write_text("")
    assert job_control._read_job_inputs(
        settings, "job", required={"scan_scope.json"}
    ) == {"scan_scope.json": ""}
    with pytest.raises(job_inputs.JobInputsUnavailable, match="scan_policy.json"):
        job_control._read_job_inputs(settings, "job", required={"scan_policy.json"})
    assert job_control._read_job_inputs(settings, "legacy", required=set()) == {}


@requires_postgres
@pytest.mark.parametrize(
    "name", ["scan_scope.json", "scan_policy.json", "config_overlay.json"]
)
def test_claim_missing_admitted_document_retains_queue_and_lease(
    tmp_path, monkeypatch, name
):
    from tests.conftest import auth_headers, configured_client, make_settings
    from api.db import models
    from api.db.engine import get_session
    from api.services import jobs, job_inputs

    settings = make_settings(tmp_path, job_execution_mode="agent")
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    agent = client.post(
        "/api/agent/register",
        headers={"Authorization": "Bearer test-agent-token"},
        json={
            "hostname": "runtime",
            "capabilities": ["scan_policy", "config_overlay.v1"],
        },
    )
    assert agent.status_code == 200
    started = client.post(
        "/api/jobs",
        headers=auth_headers(client, "operator"),
        json={"mode": "balanced", "ranges": "127.0.0.1\n", "domains": "\n"},
    )
    assert started.status_code == 202, started.text
    job_id = started.json()["job_id"]
    # Establish a persisted mandatory input without widening the job policy.
    # The scope is real admission output; policy/overlay model the same contract.
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if name != "scan_scope.json":
            row.command = list(row.command) + [INPUT_FLAGS[name], str(tmp_path / name)]
    directory = job_inputs.job_inputs_dir(settings, job_id)
    path = directory / name
    content = path.read_text() if path.exists() else "{}"
    path.unlink(missing_ok=True)
    refused = client.post(
        f"/api/agent/jobs/claim?agent_id={agent.json()['agent_id']}",
        headers={"Authorization": "Bearer test-agent-token"},
    )
    assert refused.status_code == 503, refused.text
    assert name in refused.json()["detail"] and "restore" in refused.json()["detail"]
    assert str(tmp_path) not in refused.text

    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        assert row.status == "queued"
        assert (
            row.attempts == 0
            and row.assigned_agent_id is None
            and row.claimed_until is None
        )
    path.write_text(content)
    claim = jobs.claim_job(settings, agent.json()["agent_id"])
    assert claim.job_id == job_id
    assert claim.inputs[name] == content
    assert "/replica/" not in str(claim.inputs)


@pytest.mark.parametrize("adapter", ["local", "sensor"])
@pytest.mark.parametrize("reason", ["timeout", "cancelled"])
def test_both_adapters_running_cancel_and_timeout(
    adapter, reason, monkeypatch, tmp_path
):
    command = [sys.executable, "-c", "import time;time.sleep(60)"]
    event = local_scan_executor._draining if adapter == "local" else threading.Event()
    event.clear()
    timer = threading.Timer(0.15, event.set)
    real_run = run_process
    if adapter == "local":
        # Local policy remains unlimited. Inject a finite explicit runtime
        # deadline to verify this adapter's result forwarding without changing it.
        monkeypatch.setattr(
            local_scan_executor,
            "run_process",
            lambda argv, **kwargs: real_run(
                argv,
                timeout=0.15 if reason == "timeout" else None,
                shutdown_budget=0.4,
                **kwargs,
            ),
        )
    else:
        monkeypatch.setattr(ScanInvocation, "argv", lambda *_: command)
        monkeypatch.setattr(
            worker,
            "run_process",
            lambda argv, **kwargs: real_run(argv, shutdown_budget=0.4, **kwargs),
        )
        run = tmp_path / "out/runs/run"
        run.mkdir(parents=True)
        (run / "partial.json").write_text("{}")
        (tmp_path / "work").mkdir()
    if reason == "cancelled":
        timer.start()
    try:
        if adapter == "local":
            assert local_scan_executor.run_scanner(
                "runtime-test", command
            ).returncode == (124 if reason == "timeout" else 143)
        else:
            code, error, archive = worker._run_scan(
                config=tmp_path / "config",
                job={"run_id": "run"},
                workdir=tmp_path / "work",
                output_dir=tmp_path / "out",
                timeout=0.15 if reason == "timeout" else None,
                cancel_event=event,
            )
            assert code == (124 if reason == "timeout" else 143)
            assert ("timed out" if reason == "timeout" else "cancelled") in error
            assert (archive is not None) == (reason == "cancelled")
    finally:
        if reason == "cancelled":
            timer.join()
        event.clear()


def test_shutdown_during_spawn_retains_barrier_until_late_child_stops(monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    real_popen = subprocess.Popen

    def delayed_spawn(*args, **kwargs):
        entered.set()
        assert release.wait(2)
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", delayed_spawn)
    results = []
    thread = threading.Thread(
        target=lambda: results.append(
            local_scan_executor.run_scanner(
                "late-spawn", [sys.executable, "-c", "import time;time.sleep(60)"]
            )
        )
    )
    local_scan_executor.register_thread(thread)
    thread.start()
    try:
        assert entered.wait(1)
        start = time.monotonic()
        assert not local_scan_executor.stop_all(timeout=0.05)
        assert time.monotonic() - start < 0.3
        assert local_scan_executor._draining.is_set()
        release.set()
        thread.join(2)
        assert not thread.is_alive()
        assert results[0].returncode == 143
        assert local_scan_executor.stop_all(timeout=1)
        assert not local_scan_executor._draining.is_set()
    finally:
        release.set()
        thread.join(2)
        local_scan_executor.stop_all(timeout=2)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_local_stop_uses_one_budget_for_multiple_processes(tmp_path):
    results = []
    threads = []
    ready = []
    for index in range(3):
        marker = tmp_path / f"ready-{index}"
        ready.append(marker)
        command = [
            sys.executable,
            "-c",
            "import signal,pathlib,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            f'pathlib.Path({str(marker)!r}).write_text("ready");time.sleep(60)',
        ]
        thread = threading.Thread(
            target=lambda argv=command, index=index: results.append(
                local_scan_executor.run_scanner(f"budget-{index}", argv)
            )
        )
        local_scan_executor.register_thread(thread)
        thread.start()
        threads.append(thread)
    try:
        end = time.monotonic() + 3
        while not all(marker.exists() for marker in ready) and time.monotonic() < end:
            time.sleep(0.01)
        assert all(marker.exists() for marker in ready)
        start = time.monotonic()
        local_scan_executor.stop_all(timeout=0.35)
        assert time.monotonic() - start < 0.8
        for thread in threads:
            thread.join(2)
        assert all(not thread.is_alive() for thread in threads)
        assert len(results) == 3
        assert all(result.returncode != 0 for result in results)
        assert local_scan_executor.stop_all(timeout=1)
    finally:
        local_scan_executor.stop_all(timeout=2)
        for thread in threads:
            thread.join(2)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX groups")
def test_natural_exit_still_cleans_child_with_closed_pipes(tmp_path, monkeypatch):
    marker = tmp_path / "child"
    child_script = (
        "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)"
    )
    script = (
        "import subprocess,sys,pathlib,time;"
        f'child=subprocess.Popen([sys.executable,"-c",{child_script!r}],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);'
        f"pathlib.Path({str(marker)!r}).write_text(str(child.pid));time.sleep(.15)"
    )
    handles = []
    finished = []
    start = time.monotonic()
    result = run_process(
        [sys.executable, "-c", script],
        shutdown_budget=0.6,
        on_spawn=handles.append,
        on_finish=lambda _: finished.append(True),
    )
    assert result.returncode == 0 and result.reason == "exited"
    assert time.monotonic() - start < 1.8
    pid = int(marker.read_text())
    end = time.monotonic() + 2
    while scanner_gate.is_running(pid) and time.monotonic() < end:
        time.sleep(0.01)
    assert not scanner_gate.is_running(pid)
    assert finished == [True]
    assert handles[0]._scan_stopped is True

    # Once cleanup releases ownership, a stale handle must not signal a
    # potentially reused PGID on a repeated stop.
    def unexpected_signal(*args):
        raise AssertionError("completed group must not be signalled twice")

    monkeypatch.setattr("os.killpg", unexpected_signal)
    terminate_process(handles[0])


@pytest.mark.parametrize("adapter", ["local", "sensor"])
def test_adapter_exit_concurrent_with_cancel_has_no_leaked_ownership(
    adapter, monkeypatch, tmp_path
):
    command = [sys.executable, "-c", "import time;time.sleep(.03)"]
    if adapter == "sensor":
        monkeypatch.setattr(ScanInvocation, "argv", lambda *_: command)
        run = tmp_path / "out/runs/run"
        run.mkdir(parents=True)
        (run / "result.json").write_text("{}")
        (tmp_path / "work").mkdir()
    for _ in range(3):
        event = (
            local_scan_executor._draining if adapter == "local" else threading.Event()
        )
        event.clear()
        timer = threading.Timer(0.03, event.set)
        timer.start()
        try:
            if adapter == "local":
                code = local_scan_executor.run_scanner("exit-race", command).returncode
                assert not local_scan_executor.processes
            else:
                code, error, archive = worker._run_scan(
                    config=tmp_path / "config",
                    job={"run_id": "run"},
                    workdir=tmp_path / "work",
                    output_dir=tmp_path / "out",
                    cancel_event=event,
                )
                assert archive is not None
                assert error is None if code == 0 else "cancelled" in error
            assert code in {0, 143}
        finally:
            timer.join()
            event.clear()


@pytest.mark.parametrize("gone_at", ["term", "probe"])
def test_esrch_latches_group_gone_without_later_signals(monkeypatch, gone_at):
    import signal
    from unittest.mock import MagicMock

    proc = MagicMock(pid=12345)
    calls = []

    def killpg(pid, sig):
        calls.append(sig)
        if sig == (signal.SIGTERM if gone_at == "term" else 0):
            raise ProcessLookupError()
        if sig == signal.SIGKILL:
            pytest.fail("SIGKILL must not follow observed ESRCH / reused PGID")

    monkeypatch.setattr("os.killpg", killpg)
    terminate_process(proc, shutdown_budget=0.2, term_grace=0.1)
    terminate_process(proc, shutdown_budget=0.2)
    assert calls == ([signal.SIGTERM] if gone_at == "term" else [signal.SIGTERM, 0])


def test_concurrent_termination_has_one_owner_and_lock_wait_counts_budget(monkeypatch):
    import signal
    from unittest.mock import MagicMock

    proc = MagicMock(pid=12345)
    entered = threading.Event()
    release = threading.Event()
    calls = []

    def killpg(pid, sig):
        calls.append(sig)
        if sig == signal.SIGTERM:
            entered.set()
            assert release.wait(2)

    monkeypatch.setattr("os.killpg", killpg)
    first = threading.Thread(
        target=lambda: terminate_process(proc, shutdown_budget=0.3, term_grace=0)
    )
    first.start()
    try:
        assert entered.wait(1)
        start = time.monotonic()
        terminate_process(proc, shutdown_budget=0.04, term_grace=0)
        assert time.monotonic() - start < 0.2
        assert calls == [signal.SIGTERM]
        release.set()
        first.join(1)
        assert not first.is_alive()
        terminate_process(proc, shutdown_budget=0.04)
        assert calls == [signal.SIGTERM, signal.SIGKILL]
        assert proc.wait.call_count == 1
    finally:
        release.set()
        first.join(1)


def test_short_waiter_tightens_existing_owner_grace_and_reap(monkeypatch):
    import signal
    from unittest.mock import MagicMock

    proc = MagicMock(pid=12345)
    entered = threading.Event()
    calls = []

    def killpg(pid, sig):
        calls.append(sig)
        if sig == signal.SIGTERM:
            entered.set()

    monkeypatch.setattr("os.killpg", killpg)
    # Simulate a still-unreaped process to test tightening the reaping budget,
    # not just a cooperative mock wait that returns immediately.
    proc.wait.side_effect = subprocess.TimeoutExpired("fake", 0.02)
    owner = threading.Thread(
        target=lambda: terminate_process(proc, shutdown_budget=2, term_grace=1)
    )
    owner.start()
    try:
        assert entered.wait(1)
        start = time.monotonic()
        terminate_process(proc, shutdown_budget=0.05, term_grace=0)
        owner.join(0.3)
        assert not owner.is_alive()
        assert time.monotonic() - start < 0.3
        assert calls.count(signal.SIGTERM) == calls.count(signal.SIGKILL) == 1
        assert proc._scan_stopped is True
    finally:
        owner.join(3)
