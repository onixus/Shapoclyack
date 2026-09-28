"""What a sensor keeps of its own runs on disk (agent/run_retention.py).

The scan below is fake, but the layout is not: it resolves its directories and
writes ``latest_run.json`` through the scanner's own ``resolve_run_paths``, from
the scanner's own default config. If the scanner ever moves the pointer the
next run diffs against, these tests go red rather than the sweep quietly
removing the baseline on every sensor.
"""

from __future__ import annotations

import contextlib
import os
import threading
from pathlib import Path
from typing import Any

import pytest
import yaml

from agent import run_retention, worker
from scanner.pipeline import run_ids
from scanner.pipeline.config_schema import load_config
from scanner.pipeline.run_context import resolve_run_paths
from scanner.pipeline.utils import load_yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
HOUR = 3600.0


class _Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class _Client:
    """The two calls ``_execute_job`` makes; ``upload`` decides the API's answer."""

    def __init__(self) -> None:
        self.upload_error: BaseException | None = None
        self.uploads: list[dict[str, Any]] = []

    def heartbeat(self, agent_id: str, **_kwargs: Any) -> dict[str, Any]:
        return {"cancel_requested": False}

    def upload_results(self, job_id: str, **kwargs: Any) -> dict[str, Any]:
        self.uploads.append({"job_id": job_id, **kwargs})
        if self.upload_error is not None:
            raise self.upload_error
        return {"job_id": job_id, "status": "succeeded"}


class _Sensor:
    """An output dir, a state dir and a scanner config naming both."""

    def __init__(self, root: Path) -> None:
        self.output_dir = root / "output"
        self.state_dir = root / "state"
        self.runs = self.output_dir / "runs"
        raw = load_yaml(REPO_ROOT / "scanner" / "config" / "default.yaml")
        raw["runtime"]["output_dir"] = str(self.output_dir)
        raw["runtime"]["state_dir"] = str(self.state_dir)
        self.config = root / "config.yaml"
        self.config.write_text(yaml.safe_dump(raw), encoding="utf-8")
        self.clock = _Clock(os.path.getmtime(self.config) + 60.0)

    def retention(self, **kwargs: Any) -> run_retention.RunRetention:
        kwargs.setdefault("retention_hours", 72.0)
        kwargs.setdefault("max_bytes", 0)
        return run_retention.RunRetention(
            self.output_dir, config=self.config, clock=self.clock, **kwargs
        )

    def scan(self, *, exit_code: int = 0, cancel: bool = False, size: int = 10):
        """A stand-in for ``_run_scan`` that lays the run out as the scanner does."""

        def _run_scan(*, job, workdir, cancel_event=None, **_kwargs):
            runtime = load_config(load_yaml(self.config)).runtime
            paths = resolve_run_paths(runtime, run_id=str(job["run_id"]), resume=False)
            paths.output_dir.mkdir(parents=True, exist_ok=True)
            paths.state_dir.mkdir(parents=True, exist_ok=True)
            (paths.output_dir / "alive_ips.txt").write_text("10.0.0.1\n", encoding="utf-8")
            (paths.output_dir / "payload.bin").write_bytes(b"x" * size)
            (paths.state_dir / "checkpoint.json").write_text("{}", encoding="utf-8")
            if cancel and cancel_event is not None:
                # What the heartbeat thread does when the API asks for a stop.
                cancel_event.set()
                archive = workdir / f"{job['run_id']}.tar.gz"
                worker._tar_directory(paths.output_dir, archive)  # noqa: SLF001
                return 143, "cancelled on the operator's request", archive
            if exit_code != 0:
                return exit_code, "scanner crashed", None
            archive = workdir / f"{job['run_id']}.tar.gz"
            worker._tar_directory(paths.output_dir, archive)  # noqa: SLF001
            return 0, None, archive

        return _run_scan

    def execute(self, monkeypatch, client, retention, run_id: str, **scan: Any) -> None:
        monkeypatch.setattr(worker, "_run_scan", self.scan(**scan))
        worker._execute_job(  # noqa: SLF001
            client,
            agent_id="agent-1",
            job={"job_id": f"job-{run_id}", "run_id": run_id, "attempt": 1},
            config=self.config,
            output_dir=self.output_dir,
            heartbeat_interval=60.0,
            retention=retention,
        )

    def make_run(self, run_id: str, *, age_hours: float = 0.0, size: int = 10) -> Path:
        """A run already on disk, last written ``age_hours`` before the clock."""
        run_dir = self.runs / run_id
        run_dir.mkdir(parents=True)
        (run_dir / "payload.bin").write_bytes(b"x" * size)
        stamp = self.clock.now - age_hours * HOUR
        for path in (run_dir / "payload.bin", run_dir):
            os.utime(path, (stamp, stamp))
        return run_dir

    def point_at(self, run_id: str) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        (self.state_dir / "latest_run.json").write_text(
            f'{{"run_id": "{run_id}"}}\n', encoding="utf-8"
        )


@pytest.fixture
def sensor(tmp_path: Path) -> _Sensor:
    return _Sensor(tmp_path)


def test_the_run_id_rule_is_the_scanners():
    """The copy is what stands between an API run id and ``rmtree``."""
    assert run_retention.RUN_ID_RE.pattern == run_ids.RUN_ID_RE.pattern


# --- the end of a job --------------------------------------------------------


def test_an_acknowledged_run_is_removed_once_the_next_scan_no_longer_diffs_against_it(
    monkeypatch, sensor
):
    """Removed after the API acknowledged it — but not the instant it did.

    Right after its own upload a run is still the baseline: the next scan's
    diff.json is computed against it, and that is where the API's asset events
    come from. So the first run stays until the second one replaces it, and the
    second one's acknowledgement is what removes it, state directory included.
    """
    client = _Client()
    retention = sensor.retention()

    sensor.execute(monkeypatch, client, retention, "20260924T100000Z-aaaaaa")
    assert (sensor.runs / "20260924T100000Z-aaaaaa").is_dir()

    sensor.execute(monkeypatch, client, retention, "20260924T110000Z-bbbbbb")

    assert not (sensor.runs / "20260924T100000Z-aaaaaa").exists()
    assert not (sensor.state_dir / "runs" / "20260924T100000Z-aaaaaa").exists()
    assert (sensor.runs / "20260924T110000Z-bbbbbb" / "alive_ips.txt").is_file()
    assert len(client.uploads) == 2


@pytest.mark.parametrize(
    ("error", "escapes"),
    [
        (RuntimeError("POST /api/agent/jobs/j/results -> network error: timed out"), True),
        (worker.AgentResultRejected("POST /api/agent/jobs/j/results -> 409: stale"), False),
        (worker.AgentResultInFlight("POST /api/agent/jobs/j/results -> 409: in flight"), False),
    ],
    ids=["network", "rejected", "in-flight"],
)
def test_a_run_the_api_did_not_acknowledge_is_kept(monkeypatch, sensor, error, escapes):
    """Kept after the next run took over as baseline, which is the moment an
    acknowledged one goes. The age limit removes it later, not the job end."""
    client = _Client()
    retention = sensor.retention()

    client.upload_error = error
    with pytest.raises(RuntimeError) if escapes else contextlib.nullcontext():
        sensor.execute(monkeypatch, client, retention, "20260924T100000Z-aaaaaa")
    client.upload_error = None
    sensor.execute(monkeypatch, client, retention, "20260924T110000Z-bbbbbb")

    assert (sensor.runs / "20260924T100000Z-aaaaaa" / "payload.bin").is_file()


def test_a_scan_that_sent_no_archive_is_kept_even_though_the_upload_was_acknowledged(
    monkeypatch, sensor
):
    """A failed scan uploads its exit code, not its directory: the API
    acknowledging that says nothing about what is on disk, and the partial
    output is what an operator debugs the failure from."""
    client = _Client()
    retention = sensor.retention()

    sensor.execute(monkeypatch, client, retention, "20260924T100000Z-aaaaaa", exit_code=1)
    sensor.execute(monkeypatch, client, retention, "20260924T110000Z-bbbbbb")

    assert client.uploads[0]["archive_path"] is None
    assert (sensor.runs / "20260924T100000Z-aaaaaa").is_dir()


def test_partial_results_still_owed_after_a_cancellation_survive_every_limit(
    monkeypatch, sensor
):
    """#360: the API takes a cancelled scan's archive late, and the sensor's
    run directory is the only copy. Neither the byte budget nor the age limit
    removes it while it may still be delivered; after that it is an ordinary
    unacknowledged run."""
    client = _Client()
    retention = sensor.retention(retention_hours=0.01, max_bytes=1)

    client.upload_error = RuntimeError("network error")
    with pytest.raises(RuntimeError):
        sensor.execute(
            monkeypatch, client, retention, "20260924T100000Z-aaaaaa", cancel=True, size=100
        )
    client.upload_error = None
    assert client.uploads[0]["cancelled"] is True
    sensor.execute(monkeypatch, client, retention, "20260924T110000Z-bbbbbb")

    owed = sensor.runs / "20260924T100000Z-aaaaaa"
    sensor.clock.now += run_retention.OWED_PROTECTION_SECONDS - 60
    assert retention.sweep() == []
    assert owed.is_dir()

    sensor.clock.now += 120
    assert retention.sweep() == ["20260924T100000Z-aaaaaa"]


def test_delivered_partial_results_of_a_cancellation_are_not_owed(monkeypatch, sensor):
    client = _Client()
    retention = sensor.retention()

    sensor.execute(monkeypatch, client, retention, "20260924T100000Z-aaaaaa", cancel=True)
    sensor.execute(monkeypatch, client, retention, "20260924T110000Z-bbbbbb")

    assert not (sensor.runs / "20260924T100000Z-aaaaaa").exists()


# --- the sweep ---------------------------------------------------------------


def test_the_age_limit_removes_old_runs_and_keeps_young_ones(sensor):
    sensor.make_run("20260920T000000Z-old000", age_hours=73)
    sensor.make_run("20260924T000000Z-young0", age_hours=71)
    sensor.make_run("20260924T100000Z-latest", age_hours=1)
    sensor.point_at("20260924T100000Z-latest")

    assert sensor.retention(retention_hours=72).sweep() == ["20260920T000000Z-old000"]
    assert (sensor.runs / "20260924T000000Z-young0").is_dir()


def test_an_age_limit_of_zero_is_no_age_limit(sensor):
    sensor.make_run("20250101T000000Z-ancien", age_hours=24 * 365)
    sensor.make_run("20260924T100000Z-latest")
    sensor.point_at("20260924T100000Z-latest")

    assert sensor.retention(retention_hours=0).sweep() == []


def test_the_byte_budget_removes_the_oldest_removable_runs_first(sensor):
    sensor.make_run("20260921T000000Z-a00000", age_hours=30, size=400)
    sensor.make_run("20260922T000000Z-b00000", age_hours=20, size=400)
    sensor.make_run("20260923T000000Z-c00000", age_hours=10, size=400)
    sensor.make_run("20260924T000000Z-d00000", age_hours=1, size=400)
    sensor.point_at("20260924T000000Z-d00000")

    removed = sensor.retention(max_bytes=900).sweep()

    assert removed == ["20260921T000000Z-a00000", "20260922T000000Z-b00000"]
    assert sorted(p.name for p in sensor.runs.iterdir()) == [
        "20260923T000000Z-c00000",
        "20260924T000000Z-d00000",
    ]


def test_the_sweep_skips_the_run_in_progress(sensor):
    """Old and over budget, and still not removed while its job runs — then
    removed by the sweep that ends the job, since it is past the age limit and
    another run is the baseline."""
    active = sensor.make_run("20260920T000000Z-active", age_hours=100, size=1000)
    sensor.make_run("20260924T000000Z-latest", age_hours=1)
    sensor.point_at("20260924T000000Z-latest")
    retention = sensor.retention(retention_hours=1, max_bytes=10)

    with retention.job("20260920T000000Z-active"):
        assert retention.sweep() == []
        assert active.is_dir()
    assert not active.exists()


def test_the_run_in_progress_is_skipped_by_a_sweep_from_another_thread(sensor):
    active = sensor.make_run("20260920T000000Z-active", age_hours=100)
    sensor.make_run("20260924T000000Z-latest", age_hours=1)
    sensor.point_at("20260924T000000Z-latest")
    retention = sensor.retention(retention_hours=1)
    swept: list[list[str]] = []

    with retention.job("20260920T000000Z-active"):
        thread = threading.Thread(target=lambda: swept.append(retention.sweep()))
        thread.start()
        thread.join()
        assert active.is_dir()
    assert swept == [[]]


def test_the_baseline_survives_every_limit_even_once_acknowledged(sensor):
    """Removing it fails nothing: the next run has no diff and publishes no
    asset events, which nobody notices. So no limit removes it."""
    sensor.make_run("20260901T000000Z-basel0", age_hours=500, size=1000)
    sensor.make_run("20260924T000000Z-newer0", age_hours=1)
    sensor.point_at("20260901T000000Z-basel0")
    retention = sensor.retention(retention_hours=1, max_bytes=1)
    retention.mark_delivered("20260901T000000Z-basel0")

    retention.sweep()

    assert (sensor.runs / "20260901T000000Z-basel0").is_dir()


def test_without_the_scanners_pointer_the_newest_run_is_kept(sensor, tmp_path):
    """No config (or no PyYAML) means ``latest_run.json`` cannot be found; the
    newest run is what the scanner last started, and keeping it is cheaper
    than guessing wrong."""
    sensor.make_run("20260922T000000Z-older0", age_hours=100)
    sensor.make_run("20260924T000000Z-newest", age_hours=99)
    retention = run_retention.RunRetention(
        sensor.output_dir, config=tmp_path / "missing.yaml", retention_hours=1, clock=sensor.clock
    )

    assert retention.sweep() == ["20260922T000000Z-older0"]


def test_only_this_sensors_runs_are_removed_from_a_directory_an_api_also_uses(sensor):
    """``runs/_tenants`` is the API's local artifact store. A flat ``runs/<id>``
    next to it that this sensor did not write may be the API's only copy of a
    legacy run, so the sweep leaves it alone."""
    (sensor.runs / "_tenants" / "t1" / "20260101T000000Z-apirun").mkdir(parents=True)
    legacy = sensor.make_run("20250101T000000Z-legacy", age_hours=5000, size=1000)
    ours = sensor.make_run("20260920T000000Z-ours00", age_hours=100)
    sensor.make_run("20260924T000000Z-latest")
    sensor.point_at("20260924T000000Z-latest")
    retention = sensor.retention(retention_hours=1, max_bytes=1)
    with retention.job("20260920T000000Z-ours00"):
        pass  # the sweep ending the job sees it as this sensor's own

    assert not ours.exists()
    assert legacy.is_dir()
    assert (sensor.runs / "_tenants" / "t1" / "20260101T000000Z-apirun").is_dir()


def test_nothing_outside_runs_is_touched_whatever_the_api_calls_a_run(sensor):
    sensor.make_run("20260924T000000Z-latest")
    sensor.point_at("..")
    link_target = sensor.output_dir.parent / "elsewhere"
    link_target.mkdir()
    (link_target / "keep.txt").write_text("x", encoding="utf-8")
    (sensor.runs / "20250101T000000Z-linked").symlink_to(link_target)
    retention = sensor.retention(retention_hours=0.001, max_bytes=1)

    for bad in ("..", "../..", "", "a/b"):
        with retention.job(bad):
            retention.mark_delivered(bad)
    sensor.clock.now += 10 * HOUR
    retention.sweep()

    assert (link_target / "keep.txt").is_file()
    assert (sensor.runs / "20250101T000000Z-linked").is_symlink()
    # Nor is anything written outside: the ledger is keyed by the run id too.
    # Every one of those ids was refused, so not even the ledger was created.
    assert sorted(os.listdir(sensor.output_dir)) == ["runs"]


def test_an_idle_sensor_sweeps_on_startup_before_it_reaches_the_api(monkeypatch, sensor):
    """A sensor restarted onto a full disk must not need the API to free it."""
    import argparse

    sensor.make_run("20260101T000000Z-stale0", age_hours=24 * 30)
    sensor.make_run("20260924T000000Z-latest", age_hours=1)
    sensor.point_at("20260924T000000Z-latest")

    class _Unreachable:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def set_token(self, token: str) -> None:
            pass

        def register(self, **kwargs: Any) -> dict[str, Any]:
            raise KeyboardInterrupt  # stop the loop at its first call to the API

    monkeypatch.setattr(worker, "AgentClient", _Unreachable)
    args = argparse.Namespace(
        api_url="http://127.0.0.1:8080",
        token="static-token",
        timeout=1.0,
        provisioning_key="",
        jwt_refresh_seconds=0,
        agent_id="a1",
        hostname="edge-1",
        label=None,
        nats_url="",
        poll_interval=0.01,
        config=str(sensor.config),
        output_dir=str(sensor.output_dir),
        scan_timeout=1.0,
        run_retention_hours=72.0,
        run_max_bytes=0,
    )

    assert worker.run_loop(args) == 0
    assert not (sensor.runs / "20260101T000000Z-stale0").exists()
    assert (sensor.runs / "20260924T000000Z-latest").is_dir()


def test_the_limits_are_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("OCTO_AGENT_RUN_RETENTION_HOURS", "12.5")
    monkeypatch.setenv("OCTO_AGENT_RUN_MAX_BYTES", "1048576")

    args = worker.build_parser().parse_args([])

    assert args.run_retention_hours == 12.5
    assert args.run_max_bytes == 1048576
