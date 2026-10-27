"""Host deadline and container-ownership regressions; no model or Docker calls."""
import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location("quality_watchdog", Path(__file__).parents[1] / "scripts/operator-quality-watchdog.py")
watchdog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watchdog)
CID = "a" * 64
NONCE = "test-nonce"
NAME = watchdog.PREFIX + NONCE
BASE = datetime(2026, 10, 25, tzinfo=UTC)


def journal(case="case-1", at=BASE):
    return {"case_id": case, "started_at": at.isoformat(), "status": "evaluation_started"}


def state(running=True):
    return {"Id": CID, "Name": "/" + NAME, "Config": {"Labels": {watchdog.LABEL: NONCE}},
            "State": {"Running": running, "Status": "running" if running else "exited",
                      "StartedAt": BASE.isoformat(), "ExitCode": 137 if not running else 0, "OOMKilled": False}}


def test_case_clock_cannot_reset_deadline_or_retry_completed_case():
    clock = watchdog.CaseClock()
    assert clock.update(journal(), 100, BASE + timedelta(seconds=40))
    assert clock.started == 60  # source age included on first host observation
    assert not clock.update(journal(), 110, BASE + timedelta(days=1))
    assert clock.started == 60  # subsequent wall clock changes do not extend it
    with pytest.raises(ValueError, match="clock changed"):
        clock.update(journal(at=BASE + timedelta(seconds=1)), 110, BASE)
    clock.update(None, 111, BASE)
    with pytest.raises(ValueError, match="Repeated"):
        clock.update(journal(), 112, BASE)


@pytest.mark.parametrize("alter", ["id", "name", "label"])
def test_signals_never_address_foreign_or_replaced_container(tmp_path, alter):
    value = state()
    if alter == "id":
        value["Id"] = "b" * 64
    elif alter == "name":
        value["Name"] = "/main-model"
    else:
        value["Config"]["Labels"][watchdog.LABEL] = "foreign"
    calls = []
    def command(argv):
        calls.append(argv)
        return json.dumps([value])
    with pytest.raises(ValueError, match="ownership mismatch"):
        watchdog.send_owned(CID, NAME, NONCE, "SIGKILL", watchdog.Receipt(tmp_path / "receipt.json"), command)
    assert calls == [["inspect", CID]]


def test_hung_close_gets_sigint_at120_and_kill_at150_not_an_acceptance_pass(tmp_path, monkeypatch):
    current = [0.0]
    signals = []
    killed = [False]
    def command(argv):
        if argv[0] == "inspect":
            return json.dumps([state(not killed[0])])
        assert argv[0:2] == ["kill", "--signal"] and argv[-1] == CID
        signals.append((argv[2], current[0]))
        if argv[2] == "SIGKILL":
            killed[0] = True
        return CID
    monkeypatch.setattr(watchdog, "read_journal", lambda _: journal())
    receipt = watchdog.Receipt(tmp_path / "receipt.json")
    result = watchdog.monitor(CID, NAME, NONCE, tmp_path, receipt, command=command,
        monotonic=lambda: current[0], utc_now=lambda: BASE + timedelta(seconds=current[0]),
        sleep=lambda seconds: current.__setitem__(0, current[0] + seconds))
    assert signals == [("SIGINT", 120.0), ("SIGKILL", 150.0)]
    assert result["status"] == "failed" and result["hard_deadline_reached"]
    assert result["reason"] == "case_deadline_exceeded"
    assert result["duration_seconds"] == 150
    receipt.finish(**result)
    assert json.loads(receipt.path.read_text())["status"] == "failed"
    assert receipt.events_path.read_text().count('"runner_signal"') == 2


def test_docker_failure_is_bounded_and_recorded_without_unverified_kill(tmp_path, monkeypatch):
    current = [0.0]
    calls = []
    def command(argv):
        calls.append(argv)
        raise watchdog.subprocess.TimeoutExpired(argv, 5)
    monkeypatch.setattr(watchdog, "read_journal", lambda _: None)
    receipt = watchdog.Receipt(tmp_path / "receipt.json")
    result = watchdog.monitor(CID, NAME, NONCE, tmp_path, receipt, command=command,
        monotonic=lambda: current[0], utc_now=lambda: BASE,
        sleep=lambda seconds: current.__setitem__(0, current[0] + seconds))
    assert result["status"] == "failed" and result["reason"] == "runner_state_unavailable"
    assert result["duration_seconds"] == 30
    assert all(argv[0] == "inspect" for argv in calls)
    assert any(event["kind"] == "docker_signal_failed" for event in receipt.events)


def test_existing_cidfile_and_identity_overrides_cannot_be_adopted(tmp_path):
    args = SimpleNamespace(cidfile=tmp_path / "runner.cid", receipt=tmp_path / "receipt.json",
                           runtime_arguments=["image"], run_directory=tmp_path)
    args.cidfile.write_text(CID)
    with pytest.raises(ValueError, match="new non-symlink"):
        watchdog.launch(args)
    args.cidfile.unlink()
    args.runtime_arguments = ["--name=foreign", "image"]
    with pytest.raises(ValueError, match="override"):
        watchdog.launch(args)


@pytest.mark.parametrize("runtime", [["--restart=always", "image"], ["--restart", "on-failure:3", "image"], ["--restart=no", "image"]])
def test_runner_restart_policy_cannot_replay_an_attempt(tmp_path, runtime):
    args = SimpleNamespace(cidfile=tmp_path / "runner.cid", receipt=tmp_path / "receipt.json",
                           runtime_arguments=runtime, run_directory=tmp_path)
    with pytest.raises(ValueError, match="restart policy"):
        watchdog.launch(args)
    assert not args.cidfile.exists() and not args.receipt.exists()


def test_fsync_receipt_preserves_failure_and_refuses_evidence_overwrite(tmp_path):
    receipt = watchdog.Receipt(tmp_path / "receipt.json")
    receipt.record("watchdog_failure", reason="case_deadline_exceeded")
    receipt.finish(status="failed")
    assert json.loads(receipt.path.read_text())["events"][0]["reason"] == "case_deadline_exceeded"
    with pytest.raises(ValueError, match="overwrite"):
        watchdog.Receipt(receipt.path)


def test_overdue_case_is_failed_even_when_runner_exits_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(watchdog, "read_journal", lambda _: journal())
    value = state(False)
    value["State"]["ExitCode"] = 0
    result = watchdog.monitor(CID, NAME, NONCE, tmp_path, watchdog.Receipt(tmp_path / "receipt.json"),
        command=lambda _: json.dumps([value]), monotonic=lambda: 0,
        utc_now=lambda: BASE + timedelta(seconds=121))
    assert result["status"] == "failed" and result["reason"] == "case_deadline_exceeded"


def test_new_runner_is_created_then_identity_verified_before_start(tmp_path, monkeypatch):
    args = SimpleNamespace(cidfile=tmp_path / "new.cid", receipt=tmp_path / "receipt.json",
                           runtime_arguments=["--", "--network", "none", "sha256:" + "b" * 64], run_directory=tmp_path)
    calls = []
    def command(argv):
        calls.append(argv)
        if argv[0] == "create":
            assert argv[argv.index("--cidfile") + 1] == str(args.cidfile)
            assert argv[argv.index("--label") + 1].startswith(watchdog.LABEL + "=")
            args.cidfile.write_text(CID)
        return CID
    def verified(cid, name, nonce):
        assert cid == CID and name == watchdog.PREFIX + nonce
        calls.append(["verified", cid])
        return state(False)["State"]
    monkeypatch.setattr(watchdog, "docker", command)
    monkeypatch.setattr(watchdog, "owned_state", verified)
    monkeypatch.setattr(watchdog, "monitor", lambda *a, **kw: {
        "status": "passed", "reason": None, "container_state": state(False)["State"]})
    assert watchdog.launch(args) == 0
    assert [row[0] for row in calls] == ["create", "verified", "start"]
    assert calls[-1] == ["start", CID]


def test_long_soak_repeats_gold_case_with_unique_monotonic_execution_without_timeout(tmp_path, monkeypatch):
    current = [0.0]
    def inflight(_):
        iteration = int(current[0] // 50) + 1
        return {**journal(at=BASE + timedelta(seconds=(iteration - 1) * 50)),
                "phase": "soak", "soak_iteration": iteration, "execution_id": f"soak:{iteration}:case-1"}
    monkeypatch.setattr(watchdog, "read_journal", inflight)
    def command(argv):
        assert argv[0] == "inspect"  # no control signal in healthy hour-long soak
        value = state(current[0] < 3700)
        value["State"]["ExitCode"] = 0
        return json.dumps([value])
    receipt = watchdog.Receipt(tmp_path / "receipt.json")
    result = watchdog.monitor(CID, NAME, NONCE, tmp_path, receipt, command=command,
        monotonic=lambda: current[0], utc_now=lambda: BASE + timedelta(seconds=current[0]),
        sleep=lambda seconds: current.__setitem__(0, current[0] + seconds))
    assert result["status"] == "passed" and result["duration_seconds"] == 3700
    observed = [event for event in receipt.events if event["kind"] == "case_observed"]
    assert len(observed) == 75 and len({event["execution_id"] for event in observed}) == 75
    assert {event["case_id"] for event in observed} == {"case-1"}


@pytest.mark.parametrize("iteration", [1, 0, True])
def test_soak_iteration_cannot_repeat_or_move_backwards(iteration):
    clock = watchdog.CaseClock()
    first = {**journal(), "phase": "soak", "soak_iteration": 1, "execution_id": "soak:1:case-1"}
    clock.update(first, 0, BASE)
    clock.update(None, 1, BASE)
    with pytest.raises(ValueError, match="Non-increasing"):
        clock.update({**journal(), "phase": "soak", "soak_iteration": iteration,
                      "execution_id": f"soak:{iteration}:case-1"}, 2, BASE)


@pytest.mark.parametrize("transition", ["vanished", "next_case", "exit_during_inspect"])
def test_poll_gap_past120_cannot_erase_previous_case_deadline(tmp_path, monkeypatch, transition):
    current = [0.0]
    def inflight(_):
        if current[0] < 120:
            return journal()
        if transition == "vanished":
            return None
        return journal("case-2", BASE + timedelta(seconds=123))
    monkeypatch.setattr(watchdog, "read_journal", inflight)
    def command(argv):
        assert argv[0] == "inspect"
        if current[0] < 120:
            if transition == "exit_during_inspect" and current[0] >= 119:
                current[0] = 124  # Docker call spans the previous deadline
                running = False
            else:
                running = True
        else:
            running = False
        value = state(running)
        value["State"]["ExitCode"] = 0
        return json.dumps([value])
    # No signal is needed after the first late inspection when the runner is
    # already exited. Otherwise the sticky violation is asserted by the next
    # inspection (send_owned rechecks state before signalling).
    receipt = watchdog.Receipt(tmp_path / "receipt.json")
    result = watchdog.monitor(CID, NAME, NONCE, tmp_path, receipt, command=command,
        monotonic=lambda: current[0], utc_now=lambda: BASE + timedelta(seconds=current[0]),
        sleep=lambda seconds: current.__setitem__(0, min(119, current[0] + seconds) if current[0] < 119 else 124))
    assert result["status"] == "failed" and result["reason"] == "case_completion_control_gap"
    failure = next(row for row in receipt.events if row["kind"] == "watchdog_failure")
    assert failure["execution_id"] == "initial:case-1" and failure["elapsed_seconds"] == 124


def test_native_journal_is_bounded_and_read_only_after_identity_check():
    calls = []
    def command(argv):
        calls.append(argv)
        return json.dumps([state()]) if argv[0] == "inspect" else json.dumps(journal())
    assert watchdog.read_container_journal(CID, NAME, NONCE, "/artifacts/results", command) == journal()
    assert calls[0] == ["inspect", CID]
    assert calls[1][:4] == ["exec", CID, "python", "-c"]
    assert calls[1][-1] == "/artifacts/results"
    with pytest.raises(ValueError, match="Oversized"):
        watchdog.read_container_journal(CID, NAME, NONCE, "/artifacts/results",
            lambda argv: json.dumps([state()]) if argv[0] == "inspect" else " " * 8193)


@pytest.mark.parametrize("directory", ["relative", "/a/../b", "/a//b", "/a/", "/"])
def test_native_journal_rejects_ambiguous_paths(directory):
    with pytest.raises(ValueError, match="canonical absolute"):
        watchdog.container_path(directory)


@pytest.mark.parametrize("kind,writable", [("bind", True), ("volume", False)])
def test_native_mode_refuses_host_bind_and_readonly_results(kind, writable):
    value = state()
    value["Mounts"] = [{"Type": kind, "Driver": "local", "Name": "owned",
                       "Destination": "/artifacts", "RW": writable}]
    with pytest.raises(ValueError, match="writable local Docker volume"):
        watchdog.require_native_output_mount(CID, NAME, NONCE, "/artifacts/results", lambda _: json.dumps([value]))


def test_terminal_export_fsyncs_new_host_copy_and_retains_uncertain_journal(tmp_path):
    destination = tmp_path / "results"
    calls = []
    def command(argv):
        calls.append(argv)
        if argv[0] == "inspect":
            return json.dumps([state(False)])
        assert argv[:2] == ["cp", CID + ":/artifacts/results"]
        temporary = Path(argv[-1])
        temporary.mkdir()
        (temporary / "records.jsonl").write_text('{"valid":false}\n')
        (temporary / "inflight.json").write_text(json.dumps(journal()))
        return ""
    proof = watchdog.export_native_results(CID, NAME, NONCE, "/artifacts/results", destination, command)
    assert proof["native_evidence_retained"] and len(proof["sha256"]) == 2
    assert json.loads((destination / "inflight.json").read_text()) == journal()
    with pytest.raises(ValueError, match="overwrite"):
        watchdog.export_native_results(CID, NAME, NONCE, "/artifacts/results", destination, command)
    assert [call[0] for call in calls] == ["inspect", "cp", "inspect"]


def test_export_never_copies_running_or_foreign_results(tmp_path):
    calls = []
    def command(argv):
        calls.append(argv)
        return json.dumps([state(True)])
    with pytest.raises(ValueError, match="terminal"):
        watchdog.export_native_results(CID, NAME, NONCE, "/artifacts/results", tmp_path / "results", command)
    assert calls == [["inspect", CID]]


def test_native_export_failure_cannot_turn_successful_exit_into_pass(tmp_path, monkeypatch):
    args = SimpleNamespace(cidfile=tmp_path / "native.cid", receipt=tmp_path / "watchdog.json",
        runtime_arguments=["image", "--require-native-filesystem", "--require-launch-permit"], run_directory=tmp_path / "results",
        container_run_directory="/artifacts/results")
    def command(argv):
        if argv[0] == "create":
            args.cidfile.write_text(CID)
        return CID
    monkeypatch.setattr(watchdog, "docker", command)
    monkeypatch.setattr(watchdog, "owned_state", lambda *_: state(False)["State"])
    monkeypatch.setattr(watchdog, "require_native_output_mount", lambda *_: {"Type": "volume", "RW": True})
    monkeypatch.setattr(watchdog, "publish_launch_permit", lambda *a, **kw: {})
    def monitor(*a, **kw):
        assert kw["poll_seconds"] == 2 and callable(kw["journal_reader"])
        return {"status": "passed", "reason": None, "container_state": state(False)["State"]}
    monkeypatch.setattr(watchdog, "monitor", monitor)
    def failed_export(*_):
        raise OSError("Host export unavailable")
    monkeypatch.setattr(watchdog, "export_native_results", failed_export)
    assert watchdog.launch(args) == 1
    result = json.loads(args.receipt.read_text())
    assert result["status"] == "failed" and result["native_results_export_failed"]
    assert result["native_evidence_retained"]


def test_two_second_native_poll_keeps_old_boundary_failure(tmp_path):
    current = [0.0]
    def read(_):
        if current[0] < 119:
            return journal()
        current[0] = 124  # bounded RPC plus host gap crosses old deadline
        return journal("case-2", BASE + timedelta(seconds=123))
    def command(_):
        value = state(current[0] < 124)
        value["State"]["ExitCode"] = 0
        return json.dumps([value])
    result = watchdog.monitor(CID, NAME, NONCE, tmp_path, watchdog.Receipt(tmp_path / "receipt.json"),
        command=command, journal_reader=read, poll_seconds=2,
        monotonic=lambda: current[0], utc_now=lambda: BASE + timedelta(seconds=current[0]),
        sleep=lambda seconds: current.__setitem__(0, min(119, current[0] + seconds)))
    assert result["status"] == "failed" and result["reason"] == "case_completion_control_gap"


def test_created_and_never_started_exit_are_not_terminal_after_start_timeout():
    assert not watchdog.confirmed_terminal({"Status": "created", "Running": False})
    assert not watchdog.confirmed_terminal({"Status": "exited", "Running": False, "StartedAt": "0001-01-01T00:00:00Z"})
    assert watchdog.confirmed_terminal(state(False)["State"])


def test_reaper_retains_failure_through_unavailable_daemon_created_and_late_start(tmp_path):
    inspect_calls = [0]
    signals = []
    sleeps = []
    killed = [False]
    def command(argv):
        if argv[0] == "inspect":
            inspect_calls[0] += 1
            if inspect_calls[0] <= 2:
                raise watchdog.subprocess.TimeoutExpired(argv, 5)
            value = state(not killed[0])
            if inspect_calls[0] == 3:
                value["State"] = {"Status": "created", "Running": False, "StartedAt": "0001-01-01T00:00:00Z"}
            return json.dumps([value])
        assert argv == ["kill", "--signal", "SIGKILL", CID]
        signals.append(argv)
        killed[0] = True
        return CID
    receipt = watchdog.Receipt(tmp_path / "receipt.json")
    result = watchdog.supervise_terminal(CID, NAME, NONCE, receipt, reason="launch_failed",
        command=command, sleep=lambda seconds: sleeps.append(seconds))
    assert watchdog.confirmed_terminal(result)
    assert len(signals) == 1 and len(sleeps) == 4
    pending = json.loads(receipt.path.read_text())
    assert pending["status"] == "failed" and pending["terminal_supervision_pending"]
    assert any(event["kind"] == "terminal_state_confirmed" for event in receipt.events)
    assert inspect_calls[0] == 6  # includes the ownership recheck before signal


@pytest.mark.parametrize("native", [False, True])
def test_timedout_start_and_cleanup_inspect_cannot_exit_before_late_runner_is_stopped(tmp_path, monkeypatch, native):
    args = SimpleNamespace(cidfile=tmp_path / "runner.cid", receipt=tmp_path / "watchdog.json",
        runtime_arguments=["image", "--require-native-filesystem", "--require-launch-permit"] if native else ["image"],
        run_directory=tmp_path / "results", container_run_directory="/artifacts/results" if native else None)
    calls = []
    inspections = [0]
    killed = [False]
    def command(argv):
        calls.append(argv)
        if argv[0] == "create":
            args.cidfile.write_text(CID)
        elif argv[0] == "start":
            raise watchdog.subprocess.TimeoutExpired(argv, 5)
        elif argv[0] == "kill":
            assert argv == ["kill", "--signal", "SIGKILL", CID]
            killed[0] = True
        return CID
    def owned(*_):
        inspections[0] += 1
        if inspections[0] == 2:
            raise watchdog.subprocess.TimeoutExpired(["inspect", CID], 5)
        if inspections[0] in {1, 3}:
            return {"Status": "created", "Running": False, "StartedAt": "0001-01-01T00:00:00Z"}
        return state(not killed[0])["State"]
    original = watchdog.supervise_terminal
    monkeypatch.setattr(watchdog, "docker", command)
    monkeypatch.setattr(watchdog, "owned_state", owned)
    monkeypatch.setattr(watchdog, "require_native_output_mount", lambda *_: {"Type": "volume", "RW": True})
    monkeypatch.setattr(watchdog, "publish_launch_permit", lambda *a, **kw: pytest.fail("Failed start issued launch permit"))
    monkeypatch.setattr(watchdog, "export_native_results", lambda *_: {"native_evidence_retained": True})
    monkeypatch.setattr(watchdog, "supervise_terminal", lambda *a, **kw: original(*a, **kw, sleep=lambda _: None))
    assert watchdog.launch(args) == 1
    result = json.loads(args.receipt.read_text())
    assert result["status"] == "failed" and result["reason"] == "launch_failed"
    assert result["terminal_supervision_pending"] is False
    assert watchdog.confirmed_terminal(result["container_state"])
    assert len([call for call in calls if call[0] == "start"]) == 1  # no retry
    assert len([call for call in calls if call[0] == "kill"]) == 1
    assert any(event["kind"] == "terminal_state_pending" and event["state"]["Status"] == "created"
               for event in result["events"])


def test_reaper_only_exact_confirmed_missing_cid_resolves_pending_start(tmp_path):
    calls = [0]
    def command(argv):
        calls[0] += 1
        if calls[0] == 1:
            raise watchdog.subprocess.CalledProcessError(1, argv, stderr="Docker daemon unavailable")
        raise watchdog.subprocess.CalledProcessError(1, argv, stderr="Error: No such object: " + CID)
    result = watchdog.supervise_terminal(CID, NAME, NONCE, watchdog.Receipt(tmp_path / "receipt.json"),
        reason="launch_failed", command=command, sleep=lambda _: None)
    assert result["Status"] == "removed" and calls[0] == 2


def test_controller_sigterm_requests_cleanup_without_unwinding_supervision(monkeypatch):
    monkeypatch.setattr(watchdog, "CANCEL_SIGNAL", None)
    watchdog.request_controller_stop(watchdog.signal.SIGTERM)
    assert watchdog.CANCEL_SIGNAL == watchdog.signal.SIGTERM


def test_receipt_fsync_failures_do_not_abandon_late_start_cleanup(tmp_path, monkeypatch):
    receipt = watchdog.Receipt(tmp_path / "receipt.json")
    real_record, real_finish = receipt.record, receipt.finish
    writes = [0]
    def record(*a, **kw):
        writes[0] += 1
        if writes[0] <= 2:
            raise OSError("ENOSPC")
        return real_record(*a, **kw)
    def finish(**kw):
        if writes[0] < 4:
            raise OSError("EIO")
        return real_finish(**kw)
    monkeypatch.setattr(receipt, "record", record)
    monkeypatch.setattr(receipt, "finish", finish)
    inspections = [0]
    killed = [False]
    def command(argv):
        if argv[0] == "inspect":
            inspections[0] += 1
            value = state(not killed[0])
            if inspections[0] == 1:
                value["State"] = {"Status": "created", "Running": False}
            return json.dumps([value])
        assert argv == ["kill", "--signal", "SIGKILL", CID]
        killed[0] = True
        return CID
    terminal = watchdog.supervise_terminal(CID, NAME, NONCE, receipt, reason="launch_failed",
        command=command, sleep=lambda _: None)
    assert watchdog.confirmed_terminal(terminal) and killed[0]
    assert receipt.persistence_failures >= 3
    assert any(event["kind"] == "terminal_state_confirmed" for event in receipt.events)


def test_launch_permit_is_written_only_to_verified_running_owned_cid(tmp_path):
    calls = []
    def command(argv):
        calls.append(argv)
        return json.dumps([state()]) if argv[0] == "inspect" else "launch-permit-fsynced"
    value = watchdog.publish_launch_permit(CID, NAME, NONCE, "/artifacts/results", (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
        watchdog.Receipt(tmp_path / "receipt.json"), command)
    assert value["container_id"] == CID and value["nonce"] == NONCE
    assert (datetime.fromisoformat(value["expires_at"]) - datetime.fromisoformat(value["requested_at"])).total_seconds() == 60
    assert calls[0] == ["inspect", CID] and calls[1][:4] == ["exec", CID, "python", "-c"]
    assert calls[1][-3] == "/artifacts" and json.loads(calls[1][-2]) == value


def test_launch_permit_is_never_written_for_created_state(tmp_path):
    calls = []
    def command(argv):
        calls.append(argv)
        value = state()
        value["State"] = {"Status": "created", "Running": False}
        return json.dumps([value])
    with pytest.raises(ValueError, match="verified owned Running"):
        watchdog.publish_launch_permit(CID, NAME, NONCE, "/artifacts/results", BASE.isoformat(),
            watchdog.Receipt(tmp_path / "receipt.json"), command)
    assert calls == [["inspect", CID]]
