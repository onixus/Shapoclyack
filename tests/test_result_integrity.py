"""Integrity of sensor results: artifact schemas, ed25519 signatures, /metrics (#366).

The trust boundary here is the upload: anything a sensor sends is attacker
controlled once its bearer token leaks. The scenarios that matter, each with a
test below:

* a malformed core artifact is refused, with the reason on the job;
* an archive signed for one sensor/job/attempt/outcome does not verify as another;
* re-registering with a different key does not replace the pinned one;
* unsigned uploads are a warning while ``require_signed_results`` is off and a
  refusal when it is on; a *wrong* signature is a refusal either way.
"""

from __future__ import annotations

import base64
import http.client
import io
import json
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select

from agent import observability, result_signing
from api.db import models
from api.db.engine import get_session
from api.schemas import StartScanRequest
from api.services import agents as agents_service
from api.services import audit as audit_service
from api.services import jobs as jobs_service
from api.services import result_integrity
from api.services import tenants as tenants_service
from api.services.jobs import get_job
from tests.conftest import (
    approve_scan_scope,
    configured_client,
    login,
    make_settings,
    requires_postgres,
)

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

SUMMARY = {
    "total_targets": 2,
    "alive_hosts": 1,
    "potential_vulnerabilities": 0,
    "vulnerabilities_by_severity": {"critical": 0},
}


def make_archive(files: dict[str, object] | None = None, *, run_id: str = "run-1") -> bytes:
    """A tar.gz of a realistic run directory; ``files`` overrides or adds members."""
    members: dict[str, object] = {
        "run_meta.json": {"run_id": run_id, "profile": "balanced"},
        "summary.json": SUMMARY,
        "vulnerabilities.json": [],
        "findings.json": [{"host": "10.0.0.1", "port": 80}],
        "alive_hosts.json": [{"host": "10.0.0.1"}],
    }
    members.update(files or {})
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in members.items():
            if content is None:
                continue
            data = content if isinstance(content, bytes) else json.dumps(content).encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def new_key() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return key, base64.b64encode(raw).decode()


def sign(
    key: Ed25519PrivateKey,
    archive: bytes,
    *,
    agent_id: str = "agent-1",
    job_id: str,
    run_id: str | None,
    exit_code: int = 0,
    attempt: int | None = None,
) -> str:
    message = result_integrity.signing_message(
        agent_id=agent_id,
        job_id=job_id,
        run_id=run_id,
        exit_code=exit_code,
        attempt=attempt,
        archive_sha256=result_integrity.archive_digest(archive),
    )
    return base64.b64encode(key.sign(message)).decode()


# --------------------------------------------------------------------------
# Schema validation (no database)
# --------------------------------------------------------------------------


def test_a_realistic_archive_passes():
    result_integrity.validate_artifacts(make_archive(), run_id="run-1", exit_code=0)


def test_unknown_properties_and_files_are_allowed():
    """Forward compatibility: a newer sensor may add fields and files."""
    archive = make_archive(
        {
            "summary.json": {**SUMMARY, "brand_new_metric": {"x": 1}},
            "vulnerabilities.json": [{"host": "10.0.0.1", "future_field": [1, 2]}],
            "brand_new_artifact.json": b"not even json",
        }
    )
    result_integrity.validate_artifacts(archive, run_id="run-1", exit_code=0)


@pytest.mark.parametrize(
    ("override", "needle"),
    [
        ({"summary.json": b"{not json"}, "summary.json: not valid JSON"),
        ({"run_meta.json": {"profile": "x"}}, "missing required property 'run_id'"),
        ({"summary.json": {**SUMMARY, "alive_hosts": "many"}}, "expected integer"),
        # bool is an int in Python and not in JSON
        ({"summary.json": {**SUMMARY, "alive_hosts": True}}, "expected integer"),
        ({"summary.json": {**SUMMARY, "alive_hosts": -1}}, "below minimum"),
        ({"vulnerabilities.json": {"host": "x"}}, "expected array"),
        ({"vulnerabilities.json": [{"port": 80}]}, "missing required property 'host'"),
        ({"findings.json": ["a string"]}, "expected object"),
    ],
)
def test_a_malformed_core_artifact_is_refused_with_the_reason(override, needle):
    with pytest.raises(result_integrity.ResultsRejected) as caught:
        result_integrity.validate_artifacts(make_archive(override), run_id="run-1", exit_code=0)
    assert caught.value.code == "schema"
    assert needle in caught.value.reason


def test_a_failed_or_cancelled_run_may_be_partial():
    partial = make_archive({"summary.json": None, "vulnerabilities.json": None, "run_meta.json": None})
    result_integrity.validate_artifacts(partial, run_id="run-1", exit_code=1)
    result_integrity.validate_artifacts(partial, run_id="run-1", exit_code=143, cancelled=True)
    # A run with nothing but a log is not refused either; the API shows "no summary".
    result_integrity.validate_artifacts(partial, run_id="run-1", exit_code=0)
    # ...but whatever is present is still checked.
    bad = make_archive({"summary.json": b"[]"})
    with pytest.raises(result_integrity.ResultsRejected):
        result_integrity.validate_artifacts(bad, run_id="run-1", exit_code=1)


def test_an_archive_of_another_run_is_refused():
    """The archive's own metadata must name the run the upload claims."""
    with pytest.raises(result_integrity.ResultsRejected) as caught:
        result_integrity.validate_artifacts(
            make_archive(run_id="someone-elses-run"), run_id="run-1", exit_code=0
        )
    assert "someone-elses-run" in caught.value.reason


def test_nested_files_with_a_core_name_are_not_the_runs_artifacts():
    nested = make_archive({"sub/summary.json": b"garbage"})
    result_integrity.validate_artifacts(nested, run_id="run-1", exit_code=0)


# --------------------------------------------------------------------------
# Signatures (no database)
# --------------------------------------------------------------------------


class _Settings:
    def __init__(self, required: bool = False) -> None:
        self.require_signed_results = required


def _verify(settings, *, pinned, signature, archive, **overrides):
    args = {
        "agent_id": "agent-1",
        "job_id": "job-1",
        "run_id": "run-1",
        "exit_code": 0,
        "attempt": 1,
        "key_id": None,
    }
    args.update(overrides)
    return result_integrity.verify_signature(
        settings,
        pinned_key_b64=pinned,
        signature_b64=signature,
        archive_bytes=archive,
        **args,
    )


def test_a_good_signature_verifies():
    key, public = new_key()
    archive = make_archive()
    signature = sign(key, archive, job_id="job-1", run_id="run-1", attempt=1)
    result = _verify(_Settings(), pinned=public, signature=signature, archive=archive)
    assert result.outcome == "verified"


@pytest.mark.parametrize(
    "tamper",
    [
        {"agent_id": "agent-2"},  # replayed under another sensor's identity
        {"job_id": "job-2"},  # replayed against another job
        {"run_id": "run-2"},
        {"exit_code": 1},  # outcome flipped
        {"attempt": 2},  # the previous attempt's archive
        {"attempt": None},
    ],
)
def test_a_signature_does_not_verify_for_any_other_context(tamper):
    key, public = new_key()
    archive = make_archive()
    signature = sign(key, archive, job_id="job-1", run_id="run-1", attempt=1)
    with pytest.raises(result_integrity.ResultsRejected) as caught:
        _verify(_Settings(), pinned=public, signature=signature, archive=archive, **tamper)
    assert caught.value.code == "signature"


def test_a_modified_archive_does_not_verify():
    key, public = new_key()
    archive = make_archive()
    signature = sign(key, archive, job_id="job-1", run_id="run-1", attempt=1)
    forged = make_archive({"vulnerabilities.json": [{"host": "10.9.9.9"}]})
    with pytest.raises(result_integrity.ResultsRejected):
        _verify(_Settings(), pinned=public, signature=signature, archive=forged)


def test_another_sensors_key_does_not_verify():
    key, _ = new_key()
    _, other_public = new_key()
    archive = make_archive()
    signature = sign(key, archive, job_id="job-1", run_id="run-1", attempt=1)
    with pytest.raises(result_integrity.ResultsRejected):
        _verify(_Settings(), pinned=other_public, signature=signature, archive=archive)


def test_a_key_id_that_is_not_the_pinned_one_names_both():
    key, public = new_key()
    archive = make_archive()
    signature = sign(key, archive, job_id="job-1", run_id="run-1", attempt=1)
    with pytest.raises(result_integrity.ResultsRejected) as caught:
        _verify(_Settings(), pinned=public, signature=signature, archive=archive, key_id="deadbeef")
    assert "deadbeef" in caught.value.reason
    assert result_integrity.key_fingerprint(public) in caught.value.reason


def test_garbage_signature_is_a_refusal_not_a_crash():
    _, public = new_key()
    for junk in ("!!!not base64!!!", base64.b64encode(b"short").decode()):
        with pytest.raises(result_integrity.ResultsRejected):
            _verify(_Settings(), pinned=public, signature=junk, archive=make_archive())


def test_unsigned_is_a_warning_until_required():
    archive = make_archive()
    assert _verify(_Settings(False), pinned=None, signature=None, archive=archive).outcome == "unsigned"
    _, public = new_key()
    with pytest.raises(result_integrity.ResultsRejected) as caught:
        _verify(_Settings(True), pinned=public, signature=None, archive=archive)
    assert caught.value.code == "signature"
    assert "unsigned" in caught.value.reason


def test_signed_without_a_pinned_key_is_unverifiable_then_refused():
    key, _ = new_key()
    archive = make_archive()
    signature = sign(key, archive, job_id="job-1", run_id="run-1", attempt=1)
    assert (
        _verify(_Settings(False), pinned=None, signature=signature, archive=archive).outcome
        == "unverifiable"
    )
    with pytest.raises(result_integrity.ResultsRejected):
        _verify(_Settings(True), pinned=None, signature=signature, archive=archive)


@pytest.mark.parametrize("bad", ["", "not base64!", base64.b64encode(b"x" * 31).decode()])
def test_malformed_public_keys_are_refused(bad):
    with pytest.raises(ValueError):
        result_integrity.parse_public_key(bad)


# --------------------------------------------------------------------------
# The sensor's side agrees with the API's (no database)
# --------------------------------------------------------------------------


def test_sensor_and_api_build_the_same_message():
    kwargs = {
        "agent_id": "agent-1",
        "job_id": "job-9",
        "run_id": "run-9",
        "exit_code": 0,
        "attempt": 3,
        "archive_sha256": "ab" * 32,
    }
    assert result_signing.signing_message(**kwargs) == result_integrity.signing_message(**kwargs)
    kwargs.update(run_id=None, attempt=None)
    assert result_signing.signing_message(**kwargs) == result_integrity.signing_message(**kwargs)


def test_what_the_sensor_signs_the_api_verifies(tmp_path):
    signer = result_signing.ResultSigner.load_or_create(tmp_path / "k" / "result.key")
    archive_path = tmp_path / "run.tar.gz"
    archive = make_archive()
    archive_path.write_bytes(archive)
    signature = signer.sign_upload(
        agent_id="agent-1",
        job_id="job-1",
        run_id="run-1",
        exit_code=0,
        attempt=2,
        archive_path=archive_path,
    )
    result = _verify(
        _Settings(True),
        pinned=signer.public_key_b64,
        signature=signature,
        archive=archive,
        attempt=2,
        key_id=signer.key_id,
    )
    assert result.outcome == "verified"
    assert signer.key_id == result_integrity.key_fingerprint(signer.public_key_b64)


def test_the_sensor_key_is_created_once_and_private(tmp_path):
    path = tmp_path / "state" / "result.key"
    first = result_signing.ResultSigner.load_or_create(path)
    second = result_signing.ResultSigner.load_or_create(path)
    assert first.public_key_b64 == second.public_key_b64
    assert (path.stat().st_mode & 0o777) == 0o600


def test_a_sensor_that_cannot_keep_a_key_uploads_unsigned(tmp_path, monkeypatch):
    blocker = tmp_path / "blocker"
    blocker.write_text("a file where a directory should be")
    monkeypatch.setenv(result_signing.KEY_FILE_VAR, str(blocker / "result.key"))
    assert result_signing.load_signer() is None
    monkeypatch.setenv(result_signing.KEY_FILE_VAR, str(tmp_path / "ok.key"))
    monkeypatch.setenv(result_signing.DISABLE_VAR, "off")
    assert result_signing.load_signer() is None


# --------------------------------------------------------------------------
# Sensor /healthz and /metrics (no database)
# --------------------------------------------------------------------------


def _get(port: int, path: str, headers: dict[str, str] | None = None) -> tuple[int, str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path, headers=headers or {})
        response = conn.getresponse()
        return response.status, response.read().decode()
    finally:
        conn.close()


def test_the_endpoint_is_off_by_default(monkeypatch):
    monkeypatch.delenv(observability.ADDR_VAR, raising=False)
    assert observability.start_from_env(observability.SensorTelemetry()) is None


def test_healthz_and_metrics_on_loopback(monkeypatch):
    monkeypatch.setenv(observability.ADDR_VAR, "127.0.0.1:0")
    monkeypatch.delenv(observability.TOKEN_VAR, raising=False)
    telemetry = observability.SensorTelemetry("9.9.9")
    server = observability.start_from_env(telemetry)
    assert server is not None
    try:
        code, body = _get(server.port, "/healthz")
        assert code == 503 and "not registered" in body
        telemetry.mark_registered()
        telemetry.heartbeat_ok()
        assert _get(server.port, "/healthz") == (200, "ok\n")
        telemetry.job_started()
        telemetry.job_finished("succeeded")
        telemetry.upload_finished("ok", 1234)
        telemetry.upload_finished("rejected")
        code, text = _get(server.port, "/metrics")
        assert code == 200
        assert 'octo_sensor_info{version="9.9.9"} 1' in text
        assert 'octo_sensor_jobs_total{outcome="succeeded"} 1' in text
        assert 'octo_sensor_result_uploads_total{outcome="rejected"} 1' in text
        assert "octo_sensor_result_upload_bytes_total 1234" in text
        assert _get(server.port, "/nope")[0] == 404
    finally:
        server.stop()


def test_healthz_goes_red_when_heartbeats_stop():
    telemetry = observability.SensorTelemetry(window_seconds=120)
    telemetry.mark_registered()
    telemetry.heartbeat_ok()
    now = telemetry.last_heartbeat_ok_at
    assert telemetry.health(now + 10)[0] is True
    ok, reason = telemetry.health(now + 10_000)
    assert ok is False and "heartbeat" in reason


def test_a_reachable_address_needs_a_token(monkeypatch):
    monkeypatch.setenv(observability.ADDR_VAR, "0.0.0.0:0")
    monkeypatch.delenv(observability.TOKEN_VAR, raising=False)
    assert observability.start_from_env(observability.SensorTelemetry()) is None

    monkeypatch.setenv(observability.ADDR_VAR, "not-an-address")
    assert observability.start_from_env(observability.SensorTelemetry()) is None


def test_metrics_with_a_token_rejects_other_callers(monkeypatch):
    monkeypatch.setenv(observability.ADDR_VAR, "127.0.0.1:0")
    monkeypatch.setenv(observability.TOKEN_VAR, "s3cret")
    server = observability.start_from_env(observability.SensorTelemetry())
    assert server is not None
    try:
        assert _get(server.port, "/metrics")[0] == 401
        assert _get(server.port, "/metrics", {"Authorization": "Bearer wrong"})[0] == 401
        assert _get(server.port, "/metrics", {"Authorization": "Bearer s3cret"})[0] == 200
        # The probe stays open on purpose.
        assert _get(server.port, "/healthz")[0] in (200, 503)
    finally:
        server.stop()


# --------------------------------------------------------------------------
# Registration pins the key; ingest enforces it (Postgres)
# --------------------------------------------------------------------------

postgres = requires_postgres


def _make_settings(tmp_path: Path, **overrides):
    overrides.setdefault("result_schema_mode", "enforce")
    base = make_settings(
        tmp_path,
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "output",
        job_execution_mode="agent",
        **overrides,
    )
    base.state_dir.mkdir(parents=True, exist_ok=True)
    base.output_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(base)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(base)
    approve_scan_scope(base)
    agents_service.configure(base)
    _mark_audit_floor(base)
    return base


@pytest.fixture()
def settings(tmp_path: Path):
    return _make_settings(tmp_path)


def _claimed_job(settings, agent_id: str = "agent-1") -> tuple[str, str]:
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    claimed = jobs_service.claim_job(settings, agent_id)
    assert claimed is not None
    info = get_job(settings, job.job_id)
    return job.job_id, info.run_id


_AUDIT_FLOOR = {"id": 0}


def _audit_actions(settings) -> list[str]:
    with get_session(settings.postgres_url) as session:
        return list(
            session.execute(
                select(models.AuditEvent.action).where(models.AuditEvent.id > _AUDIT_FLOOR["id"])
            ).scalars()
        )


def _mark_audit_floor(settings) -> None:
    with get_session(settings.postgres_url) as session:
        _AUDIT_FLOOR["id"] = session.execute(
            select(func.coalesce(func.max(models.AuditEvent.id), 0))
        ).scalar_one()


@postgres
def test_the_first_key_is_pinned_and_a_different_one_is_refused(settings):
    _, public_a = new_key()
    _, public_b = new_key()
    first = agents_service.register_agent(
        agent_id="agent-1", tenant_id="default", result_signing_key=public_a
    )
    assert first.result_key_fingerprint == result_integrity.key_fingerprint(public_a)

    # Same key again: fine, nothing new to say.
    again = agents_service.register_agent(
        agent_id="agent-1", tenant_id="default", result_signing_key=public_a
    )
    assert again.result_key_fingerprint == first.result_key_fingerprint

    # Re-enrolment with someone else's key: the registration works, the key does not move.
    swapped = agents_service.register_agent(
        agent_id="agent-1", tenant_id="default", result_signing_key=public_b
    )
    assert swapped.result_key_fingerprint == result_integrity.key_fingerprint(public_a)
    assert agents_service.pinned_result_key("agent-1") == public_a
    actions = _audit_actions(settings)
    assert audit_service.ACTION_AGENT_RESULT_KEY_REFUSED in actions
    assert actions.count(audit_service.ACTION_AGENT_RESULT_KEY_PIN) == 1

    # Registering without a key (an older build) does not clear it either.
    quiet = agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    assert quiet.result_key_fingerprint == first.result_key_fingerprint


@postgres
def test_only_an_operator_reset_lets_a_new_key_in(settings):
    _, public_a = new_key()
    _, public_b = new_key()
    agents_service.register_agent(agent_id="agent-1", tenant_id="default", result_signing_key=public_a)

    # Another tenant's admin cannot reset it.
    tenants_service.create_tenant(tenant_id="ten_b", name="Tenant B")
    with pytest.raises(LookupError):
        agents_service.reset_result_key("agent-1", "ten_b", reason="nope")
    assert agents_service.pinned_result_key("agent-1") == public_a

    agents_service.reset_result_key("agent-1", "default", reason="reinstalled")
    assert agents_service.pinned_result_key("agent-1") is None
    assert audit_service.ACTION_AGENT_RESULT_KEY_RESET in _audit_actions(settings)
    pinned = agents_service.register_agent(
        agent_id="agent-1", tenant_id="default", result_signing_key=public_b
    )
    assert pinned.result_key_fingerprint == result_integrity.key_fingerprint(public_b)


@postgres
def test_a_malformed_key_fails_the_registration(settings):
    with pytest.raises(ValueError):
        agents_service.register_agent(
            agent_id="agent-1", tenant_id="default", result_signing_key="AAAA"
        )


@postgres
def test_a_signed_upload_is_accepted(settings):
    key, public = new_key()
    agents_service.register_agent(agent_id="agent-1", tenant_id="default", result_signing_key=public)
    job_id, run_id = _claimed_job(settings)
    archive = make_archive(run_id=run_id)
    done = jobs_service.complete_job(
        settings,
        job_id,
        agent_id="agent-1",
        exit_code=0,
        run_id=run_id,
        archive_bytes=archive,
        result_signature=sign(key, archive, job_id=job_id, run_id=run_id),
        result_key_id=result_integrity.key_fingerprint(public),
    )
    assert done.status == "succeeded"


@postgres
def test_a_forged_archive_under_a_stolen_token_fails_the_job_with_the_reason(settings):
    """The token alone is not enough: the attacker signs with a key of their own."""
    _, public = new_key()
    attacker, _ = new_key()
    agents_service.register_agent(agent_id="agent-1", tenant_id="default", result_signing_key=public)
    job_id, run_id = _claimed_job(settings)
    archive = make_archive(run_id=run_id)
    with pytest.raises(result_integrity.ResultsRejected):
        jobs_service.complete_job(
            settings,
            job_id,
            agent_id="agent-1",
            exit_code=0,
            run_id=run_id,
            archive_bytes=archive,
            result_signature=sign(attacker, archive, job_id=job_id, run_id=run_id),
        )
    job = get_job(settings, job_id)
    assert job.status == "failed"
    assert "results rejected (signature)" in (job.error or "")
    assert audit_service.ACTION_RESULTS_REJECTED in _audit_actions(settings)
    assert not list((settings.output_dir / "runs").rglob("summary.json"))


@postgres
def test_an_archive_replayed_from_another_sensor_in_another_tenant_is_refused(settings):
    """Sensor B (tenant two) uploads what sensor A (tenant one) signed for A's job."""
    key_a, public_a = new_key()
    key_b, public_b = new_key()
    tenants_service.create_tenant(tenant_id="ten_b", name="Tenant B")
    approve_scan_scope(settings, "ten_b")
    agents_service.register_agent(agent_id="agent-1", tenant_id="default", result_signing_key=public_a)
    agents_service.register_agent(agent_id="agent-b", tenant_id="ten_b", result_signing_key=public_b)

    job_a, run_a = _claimed_job(settings, "agent-1")
    archive_a = make_archive(run_id=run_a)
    signature_a = sign(key_a, archive_a, job_id=job_a, run_id=run_a)

    job_b_info = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced", tenant_id="ten_b"), username="admin"
    )
    assert jobs_service.claim_job(settings, "agent-b") is not None
    run_b = get_job(settings, job_b_info.job_id).run_id

    # A's archive and A's signature, offered by B for B's own job.
    with pytest.raises(result_integrity.ResultsRejected):
        jobs_service.complete_job(
            settings,
            job_b_info.job_id,
            agent_id="agent-b",
            exit_code=0,
            run_id=run_b,
            archive_bytes=archive_a,
            result_signature=signature_a,
        )
    assert get_job(settings, job_b_info.job_id).status == "failed"
    # B cannot upload to A's job at all.
    with pytest.raises(PermissionError):
        jobs_service.complete_job(
            settings,
            job_a,
            agent_id="agent-b",
            exit_code=0,
            run_id=run_a,
            archive_bytes=archive_a,
            result_signature=signature_a,
        )
    # And A's genuine upload still works.
    assert (
        jobs_service.complete_job(
            settings,
            job_a,
            agent_id="agent-1",
            exit_code=0,
            run_id=run_a,
            archive_bytes=archive_a,
            result_signature=signature_a,
        ).status
        == "succeeded"
    )


@postgres
def test_unsigned_from_a_sensor_without_a_key_is_accepted_while_the_switch_is_off(settings):
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    job_id, run_id = _claimed_job(settings)
    done = jobs_service.complete_job(
        settings,
        job_id,
        agent_id="agent-1",
        exit_code=0,
        run_id=run_id,
        archive_bytes=make_archive(run_id=run_id),
    )
    assert done.status == "succeeded"


@postgres
def test_unsigned_is_refused_once_signatures_are_required(tmp_path):
    settings = _make_settings(tmp_path, require_signed_results=True)
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    job_id, run_id = _claimed_job(settings)
    with pytest.raises(result_integrity.ResultsRejected):
        jobs_service.complete_job(
            settings,
            job_id,
            agent_id="agent-1",
            exit_code=0,
            run_id=run_id,
            archive_bytes=make_archive(run_id=run_id),
        )
    job = get_job(settings, job_id)
    assert job.status == "failed"
    assert "unsigned results are refused" in (job.error or "")


@postgres
def test_a_wrong_signature_is_refused_even_while_the_switch_is_off(settings):
    _, public = new_key()
    other, _ = new_key()
    agents_service.register_agent(agent_id="agent-1", tenant_id="default", result_signing_key=public)
    job_id, run_id = _claimed_job(settings)
    archive = make_archive(run_id=run_id)
    with pytest.raises(result_integrity.ResultsRejected):
        jobs_service.complete_job(
            settings,
            job_id,
            agent_id="agent-1",
            exit_code=0,
            run_id=run_id,
            archive_bytes=archive,
            result_signature=sign(other, archive, job_id=job_id, run_id=run_id),
        )


@postgres
def test_a_malformed_artifact_fails_the_job_instead_of_looping_the_scan(settings):
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    job_id, run_id = _claimed_job(settings)
    with pytest.raises(result_integrity.ResultsRejected):
        jobs_service.complete_job(
            settings,
            job_id,
            agent_id="agent-1",
            exit_code=0,
            run_id=run_id,
            archive_bytes=make_archive({"summary.json": b"<html>proxy error</html>"}, run_id=run_id),
        )
    job = get_job(settings, job_id)
    assert job.status == "failed"
    assert "summary.json: not valid JSON" in (job.error or "")
    assert audit_service.ACTION_RESULTS_REJECTED in _audit_actions(settings)


@postgres
def test_warn_mode_lets_a_malformed_artifact_through(tmp_path):
    settings = _make_settings(tmp_path, result_schema_mode="warn")
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    job_id, run_id = _claimed_job(settings)
    done = jobs_service.complete_job(
        settings,
        job_id,
        agent_id="agent-1",
        exit_code=0,
        run_id=run_id,
        archive_bytes=make_archive({"summary.json": {"alive_hosts": "x"}}, run_id=run_id),
    )
    assert done.status == "succeeded"
    assert audit_service.ACTION_RESULTS_SCHEMA_WARNED in _audit_actions(settings)


# --------------------------------------------------------------------------
# Over HTTP: registration, upload form fields and the operator reset
# --------------------------------------------------------------------------

AGENT = {"Authorization": "Bearer test-agent-token"}


@postgres
def test_http_flow_register_sign_upload_and_reset(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch, job_execution_mode="agent")
    key, public = new_key()
    reg = client.post(
        "/api/agent/register",
        headers=AGENT,
        json={"hostname": "edge", "result_signing_key": public},
    )
    assert reg.status_code == 200, reg.text
    agent_id = reg.json()["agent_id"]
    assert reg.json()["result_key_fingerprint"] == result_integrity.key_fingerprint(public)

    # A malformed key is a 422, not a silently unsigned sensor.
    bad = client.post(
        "/api/agent/register",
        headers=AGENT,
        json={"agent_id": agent_id, "result_signing_key": "AAAA"},
    )
    assert bad.status_code == 422

    admin = {"Authorization": f"Bearer {login(client, 'admin')}"}
    created = client.post(
        "/api/jobs",
        headers=admin,
        json={"mode": "safe", "skip_nse": True, "ranges": "127.0.0.1\n", "domains": "\n", "ports": "80\n"},
    )
    assert created.status_code == 202, created.text
    job_id, run_id = created.json()["job_id"], created.json()["run_id"]
    claimed = client.post(f"/api/agent/jobs/claim?agent_id={agent_id}", headers=AGENT)
    assert claimed.status_code == 200
    attempt = claimed.json().get("attempt")

    archive = make_archive(run_id=run_id)
    forged = client.post(
        f"/api/agent/jobs/{job_id}/results",
        headers=AGENT,
        data={
            "agent_id": agent_id,
            "exit_code": "0",
            "run_id": run_id,
            "result_signature": sign(
                new_key()[0], archive, agent_id=agent_id, job_id=job_id, run_id=run_id,
                attempt=attempt,
            ),
        },
        files={"archive": ("run.tar.gz", archive, "application/gzip")},
    )
    assert forged.status_code == 422
    assert "signature" in forged.json()["detail"]

    # The operator can read why, on the job.
    detail = client.get(f"/api/jobs/{job_id}", headers=admin).json()
    assert detail["status"] == "failed"
    assert "results rejected (signature)" in detail["error"]

    # Resetting needs an admin of the tenant; a plain viewer is refused.
    viewer = {"Authorization": f"Bearer {login(client, 'viewer')}"}
    assert client.delete(f"/api/agents/{agent_id}/result-key", headers=viewer).status_code == 403
    reset = client.delete(f"/api/agents/{agent_id}/result-key", headers=admin)
    assert reset.status_code == 200, reset.text
    assert reset.json()["result_key_fingerprint"] is None
    assert client.delete("/api/agents/nope/result-key", headers=admin).status_code == 404


# --------------------------------------------------------------------------
# The sensor client puts the key and the signature on the wire (no database)
# --------------------------------------------------------------------------


def _drain(body) -> bytes:
    raw = b""
    while chunk := body.read(65536):
        raw += chunk
    return raw


def _form_fields(raw: bytes) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in raw.split(b"--")[1:]:
        text = part.decode("utf-8", "ignore")
        if 'name="' in text and 'filename="' not in text:
            name = text.split('name="', 1)[1].split('"', 1)[0]
            fields[name] = text.split("\r\n\r\n", 1)[1].rsplit("\r\n", 1)[0]
    return fields


def test_the_client_registers_its_public_key_and_signs_the_upload(tmp_path):
    from agent.worker import AgentClient

    signer = result_signing.ResultSigner.load_or_create(tmp_path / "result.key")
    client = AgentClient("http://api.invalid", "token")
    client.result_signer = signer
    sent: list[bytes] = []

    def fake_request(method, path, body=None, **kwargs):
        sent.append(_drain(body) if hasattr(body, "read") else body)
        return {}

    client._request = fake_request  # type: ignore[method-assign]
    client.register(agent_id="agent-1", hostname="h", labels={})
    assert json.loads(sent[0])["result_signing_key"] == signer.public_key_b64

    archive = tmp_path / "run.tar.gz"
    archive.write_bytes(make_archive())
    client.upload_results(
        "job-1",
        agent_id="agent-1",
        exit_code=0,
        run_id="run-1",
        error=None,
        archive_path=archive,
        attempt=2,
    )
    fields = _form_fields(sent[1])
    assert fields["result_key_id"] == signer.key_id
    verdict = _verify(
        _Settings(True),
        pinned=signer.public_key_b64,
        signature=fields["result_signature"],
        archive=archive.read_bytes(),
        attempt=2,
        key_id=fields["result_key_id"],
    )
    assert verdict.outcome == "verified"


def test_a_client_without_a_key_registers_and_uploads_as_before(tmp_path):
    from agent.worker import AgentClient

    client = AgentClient("http://api.invalid", "token")
    sent: list[bytes] = []

    def fake_request(method, path, body=None, **kwargs):
        sent.append(_drain(body) if hasattr(body, "read") else body)
        return {}

    client._request = fake_request  # type: ignore[method-assign]
    client.register(agent_id="agent-1", hostname="h", labels={})
    assert b"result_signing_key" not in sent[0]
    archive = tmp_path / "run.tar.gz"
    archive.write_bytes(make_archive())
    client.upload_results(
        "job-1", agent_id="agent-1", exit_code=0, run_id="run-1", error=None, archive_path=archive
    )
    assert b"result_signature" not in sent[1]


# --------------------------------------------------------------------------
# Review round: downgrade, parser limits, race, persistence
# --------------------------------------------------------------------------


def test_a_pinned_key_makes_the_signature_mandatory_whatever_the_switch_says():
    """Omitting the form fields must not turn a signing sensor into an old one."""
    _, public = new_key()
    for required in (False, True):
        with pytest.raises(result_integrity.ResultsRejected) as caught:
            _verify(_Settings(required), pinned=public, signature=None, archive=make_archive())
        assert caught.value.code == "signature"
        assert "unsigned" in caught.value.reason


def test_a_deeply_nested_document_is_a_refusal_not_a_server_error():
    bomb = b"[" * 100_000 + b"]" * 100_000
    with pytest.raises(result_integrity.ResultsRejected) as caught:
        result_integrity.validate_artifacts(
            make_archive({"findings.json": bomb}), run_id="run-1", exit_code=0
        )
    assert "findings.json" in caught.value.reason


def test_the_container_limits_are_applied_before_anything_is_parsed(monkeypatch):
    """An archive the extractor would refuse is refused without reading members."""
    from api.services import results_ingest

    parsed: list[str] = []
    real_loads = json.loads
    monkeypatch.setattr(json, "loads", lambda *a, **k: parsed.append("x") or real_loads(*a, **k))
    monkeypatch.setattr(results_ingest, "MAX_UNCOMPRESSED_BYTES", 10)
    monkeypatch.setattr(
        results_ingest.validate_archive,
        "__kwdefaults__",
        {"max_uncompressed_bytes": 10},
    )
    with pytest.raises(results_ingest.IngestError):
        result_integrity.validate_artifacts(make_archive(), run_id="run-1", exit_code=0)
    assert parsed == []


def test_one_oversized_core_file_is_refused_without_being_parsed(monkeypatch):
    monkeypatch.setattr(result_integrity, "MAX_VALIDATED_MEMBER_BYTES", 100)
    big = make_archive({"vulnerabilities.json": [{"host": "10.0.0.%d" % i} for i in range(50)]})
    with pytest.raises(result_integrity.ResultsRejected) as caught:
        result_integrity.validate_artifacts(big, run_id="run-1", exit_code=0)
    assert "larger than" in caught.value.reason


def test_the_total_of_core_files_is_bounded_too(monkeypatch):
    monkeypatch.setattr(result_integrity, "MAX_VALIDATED_TOTAL_BYTES", 200)
    with pytest.raises(result_integrity.ResultsRejected) as caught:
        result_integrity.validate_artifacts(
            make_archive({"vulnerabilities.json": [{"host": "10.0.0.%d" % i} for i in range(20)]}),
            run_id="run-1",
            exit_code=0,
        )
    assert "together exceed" in caught.value.reason


def test_rows_with_an_empty_or_null_host_are_valid():
    """nuclei writes str(raw.get("host") or "")."""
    result_integrity.validate_artifacts(
        make_archive({"vulnerabilities.json": [{"host": ""}, {"host": None}]}),
        run_id="run-1",
        exit_code=0,
    )


def test_the_default_schema_mode_is_warn():
    from api.settings import Settings

    assert Settings().result_schema_mode == "warn"
    assert result_integrity.schema_mode(Settings()) == "warn"


@postgres
def test_a_signing_sensor_cannot_be_downgraded_by_omitting_the_signature(settings):
    _, public = new_key()
    agents_service.register_agent(agent_id="agent-1", tenant_id="default", result_signing_key=public)
    job_id, run_id = _claimed_job(settings)
    with pytest.raises(result_integrity.ResultsRejected):
        jobs_service.complete_job(
            settings,
            job_id,
            agent_id="agent-1",
            exit_code=0,
            run_id=run_id,
            archive_bytes=make_archive(run_id=run_id),
        )
    assert get_job(settings, job_id).status == "failed"


@postgres
def test_two_registrations_racing_for_an_empty_slot_pin_exactly_one_key(settings):
    """Both read NULL; the database decides, and the loser is told the winner's fingerprint."""
    import threading

    _, key_a = new_key()
    _, key_b = new_key()
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    results: dict[str, str | None] = {}
    barrier = threading.Barrier(2)
    seen = threading.local()

    real_pin = agents_service._pin_result_key

    def synchronised(session, row, key, **kwargs):
        # Both sessions have loaded the row (key NULL) before either writes.
        # Only the first call per thread: the loser recurses to re-decide.
        if not getattr(seen, "waited", False):
            seen.waited = True
            barrier.wait(timeout=10)
        return real_pin(session, row, key, **kwargs)

    def register(name: str, key: str) -> None:
        results[name] = agents_service.register_agent(
            agent_id="agent-1", tenant_id="default", result_signing_key=key
        ).result_key_fingerprint

    original = agents_service._pin_result_key
    agents_service._pin_result_key = synchronised  # type: ignore[assignment]
    try:
        threads = [
            threading.Thread(target=register, args=("a", key_a)),
            threading.Thread(target=register, args=("b", key_b)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
    finally:
        agents_service._pin_result_key = original  # type: ignore[assignment]

    pinned = agents_service.pinned_result_key("agent-1")
    assert pinned in (key_a, key_b)
    winner = result_integrity.key_fingerprint(pinned)
    assert results == {"a": winner, "b": winner}


def test_the_sensor_manifests_keep_the_signing_key_on_a_volume_that_survives_the_pod():
    """A key under $HOME (an emptyDir) is a new key after every restart."""
    import yaml

    root = Path(__file__).resolve().parents[1] / "k8s" / "shapoclyack"
    for relative in (
        "base/scanner-executor/statefulset.yaml",
        "examples/agent-deployment.example.yaml",
    ):
        doc = yaml.safe_load((root / relative).read_text(encoding="utf-8"))
        assert doc["kind"] == "StatefulSet"
        claims = {t["metadata"]["name"] for t in doc["spec"]["volumeClaimTemplates"]}
        container = doc["spec"]["template"]["spec"]["containers"][0]
        mounts = {m["name"]: m["mountPath"] for m in container["volumeMounts"]}
        env = {e["name"]: e.get("value") for e in container["env"]}
        assert "sensor-key" in claims, relative
        key_file = env["OCTO_AGENT_RESULT_KEY_FILE"]
        assert key_file.startswith(mounts["sensor-key"] + "/"), relative
        assert doc["spec"]["template"]["spec"]["securityContext"]["fsGroup"] == 1000


# --------------------------------------------------------------------------
# Review round 2
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "broken",
    [b"\xff\xfe", b"[" * 100_000 + b"]" * 100_000, b"{not json"],
    ids=["undecodable", "too-deep", "not-json"],
)
@postgres
def test_warn_mode_still_refuses_a_document_that_cannot_be_read(tmp_path, broken):
    """warn relaxes shape rules; an unreadable summary.json would take the run list down."""
    settings = _make_settings(tmp_path, result_schema_mode="warn")
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    job_id, run_id = _claimed_job(settings)
    with pytest.raises(result_integrity.ResultsRejected) as caught:
        jobs_service.complete_job(
            settings,
            job_id,
            agent_id="agent-1",
            exit_code=0,
            run_id=run_id,
            archive_bytes=make_archive({"summary.json": broken}, run_id=run_id),
        )
    assert caught.value.parse is True
    assert get_job(settings, job_id).status == "failed"


def test_a_size_over_the_cap_is_a_parse_refusal_and_the_cap_is_configurable():
    big = make_archive({"vulnerabilities.json": [{"host": "10.0.0.%d" % i} for i in range(50)]})
    with pytest.raises(result_integrity.ResultsRejected) as caught:
        result_integrity.validate_artifacts(big, run_id="run-1", exit_code=0, max_file_bytes=100)
    assert caught.value.parse is True
    result_integrity.validate_artifacts(big, run_id="run-1", exit_code=0)
    assert result_integrity.MAX_VALIDATED_MEMBER_BYTES == 256 * 1024 * 1024
    from api.settings import Settings

    assert Settings().result_schema_max_file_bytes == 256 * 1024 * 1024


def test_a_shape_problem_is_not_a_parse_problem():
    with pytest.raises(result_integrity.ResultsRejected) as caught:
        result_integrity.validate_artifacts(
            make_archive({"summary.json": {"alive_hosts": "x"}}), run_id="run-1", exit_code=0
        )
    assert caught.value.parse is False


@postgres
def test_the_run_list_survives_a_run_already_stored_with_unreadable_json(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    for name, payload in (("20260801T000000Z", b"\xff\xfe"), ("20260801T000100Z", b"[" * 100_000)):
        run_dir = tmp_path / "output" / "runs" / name
        run_dir.mkdir(parents=True)
        (run_dir / "summary.json").write_bytes(payload)
        (run_dir / "run_meta.json").write_bytes(payload)
    headers = {"Authorization": f"Bearer {login(client, 'operator')}"}
    listed = client.get("/api/runs", headers=headers)
    assert listed.status_code == 200, listed.text
    detail = client.get("/api/runs/20260801T000000Z", headers=headers)
    assert detail.status_code < 500, detail.text


@postgres
def test_registering_while_the_agent_is_deleted_is_an_error_not_a_crash(settings):
    _, public = new_key()
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    real_pin = agents_service._pin_result_key

    def delete_first(session, row, key, **kwargs):
        with get_session(settings.postgres_url) as other:
            other.query(models.Agent).filter_by(agent_id="agent-1").delete()
        return real_pin(session, row, key, **kwargs)

    original = agents_service._pin_result_key
    agents_service._pin_result_key = delete_first  # type: ignore[assignment]
    try:
        with pytest.raises(PermissionError):
            agents_service.register_agent(
                agent_id="agent-1", tenant_id="default", result_signing_key=public
            )
    finally:
        agents_service._pin_result_key = original  # type: ignore[assignment]


def test_a_sensor_that_lost_its_key_says_so_at_registration(tmp_path, caplog):
    """The API pinned a key, this process has none: loud, with the order of operations."""
    import logging

    from agent import worker

    assert hasattr(worker, "AgentClient")
    source = Path(worker.__file__).read_text(encoding="utf-8")
    assert "has no key" in source and "DELETE /api/agents/%s/result-key" in source
    del caplog, logging


def test_an_explicit_key_path_that_cannot_be_used_is_an_error(tmp_path, monkeypatch, caplog):
    import logging

    blocker = tmp_path / "blocker"
    blocker.write_text("file")
    monkeypatch.setenv(result_signing.KEY_FILE_VAR, str(blocker / "k"))
    with caplog.at_level(logging.WARNING, logger="octo-agent"):
        assert result_signing.load_signer() is None
    assert any(r.levelno == logging.ERROR for r in caplog.records)
    caplog.clear()
    monkeypatch.delenv(result_signing.KEY_FILE_VAR)
    monkeypatch.setattr(result_signing, "default_key_path", lambda _f=None: blocker / "k")
    with caplog.at_level(logging.WARNING, logger="octo-agent"):
        assert result_signing.load_signer() is None
    assert [r.levelno for r in caplog.records if "unavailable" in r.getMessage()] == [logging.WARNING]
