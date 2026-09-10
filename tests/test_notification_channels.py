"""Per-tenant notification channels for finished runs (#351).

The defect: ``scanner/pipeline/alerts.py`` read ``OCTO_SLACK_WEBHOOK`` and
``scanner/pipeline/defectdojo.py`` read ``OCTO_DEFECTDOJO_*``, so on an MSSP
installation every tenant's scan announced itself in one Slack channel and
every tenant's findings were imported into one DefectDojo product.

The test that matters is :func:`test_fan_out_reaches_only_the_runs_own_tenant`:
two tenants, one channel each, one finished run — and the assertion is that
tenant B's webhook URL is never dialed. The rest is the surface around it.

Every send is driven with an injected transport (``post_fn=``) rather than a
listening socket, exactly as the webhook dispatch tests are.
"""

from __future__ import annotations

import base64
import io
import json
import tarfile
import threading
import time
from pathlib import Path

import pytest

from api.db import models
from api.db.engine import get_session
from api.services import agents as agents_service
from api.services import jobs as jobs_service
from api.services import tenants as tenants_service
from api.services.crypto import envelope
from api.services.crypto import startup as crypto_startup
from api.services.integrations import channel_transports as transports
from api.services.integrations import channels
from api.services.integrations import delivery as delivery_transport
from api.db import reencrypt_secrets
from api.settings import ENV_PROD, InsecureConfigurationError, Settings
from tests.conftest import (
    approve_scan_scope,
    auth_headers,
    configured_client,
    login,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres

KEY_A = base64.b64encode(b"A" * 32).decode("ascii")
KEY_B = (b"B" * 32).hex()

SLACK_A = "https://hooks.slack.example/services/TENANT-A"
SLACK_B = "https://hooks.slack.example/services/TENANT-B"


@pytest.fixture(autouse=True)
def _clean_provider():
    """The KEK provider is module state; no test may inherit another's key."""
    envelope.reset_for_tests()
    yield
    envelope.reset_for_tests()


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    value = make_settings(tmp_path)
    tenants_service.configure(value)
    tenants_service.load_tenants(value)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(value)
    channels.configure(value)
    channels.reset_for_tests()
    return value


def _use(key: str, previous: str = "") -> None:
    envelope.configure(
        envelope.LocalKeyProvider.from_env(
            {envelope.MASTER_KEY_ENV: key, envelope.PREVIOUS_KEYS_ENV: previous}
        )
    )


def _slack(settings: Settings, **overrides) -> dict:
    payload = {
        "tenant_id": "default",
        "name": "soc",
        "kind": "slack",
        "secret": SLACK_A,
        "created_by": "admin",
    }
    payload.update(overrides)
    return channels.create_channel(**payload)


def _row(settings: Settings, channel_id: str) -> models.NotificationChannel:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.NotificationChannel, channel_id)
        assert row is not None
        session.expunge(row)
        return row


def _run_dir(settings: Settings, run_id: str, *, findings: list[dict] | None = None) -> Path:
    """A finished run's artifacts, as the fan-out reads them off disk."""
    run_dir = settings.output_dir / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "summary.json").write_text(
        json.dumps(
            {
                "alive_hosts": 2,
                "open_host_port_pairs": 4,
                "potential_vulnerabilities": 1,
                "vulnerabilities_by_severity": {"critical": 1, "high": 0},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps(
            findings
            if findings is not None
            else [
                {
                    "host": "10.0.0.1",
                    "port": "22",
                    "script_id": "vulners",
                    "cve": "CVE-2026-1",
                    "cvss": 9.8,
                    "severity": "critical",
                }
            ]
        ),
        encoding="utf-8",
    )
    return run_dir


class _Recorder:
    """A ``delivery.post`` stand-in that remembers where it was asked to go."""

    def __init__(self, ok: bool = True) -> None:
        self.calls: list[tuple[str, bytes, dict]] = []
        self._ok = ok

    def __call__(self, url, body, headers, **kwargs):
        self.calls.append((url, body, headers))
        if self._ok:
            return delivery_transport.DeliveryResult(
                ok=True, status_code=200, error=None, retryable=False
            )
        return delivery_transport.DeliveryResult(
            ok=False, status_code=503, error="HTTP 503", retryable=True
        )

    @property
    def urls(self) -> list[str]:
        return [url for url, _, _ in self.calls]


# --------------------------------------------------------------------------
# The isolation this issue is about
# --------------------------------------------------------------------------


def test_fan_out_reaches_only_the_runs_own_tenant(settings):
    """Tenant A's finished run must not be announced in tenant B's channel."""
    _use(KEY_A)
    tenants_service.create_tenant(tenant_id="ten_a", name="Tenant A")
    tenants_service.create_tenant(tenant_id="ten_b", name="Tenant B")
    channel_a = _slack(settings, tenant_id="ten_a", name="a-soc", secret=SLACK_A)
    channel_b = _slack(settings, tenant_id="ten_b", name="b-soc", secret=SLACK_B)

    recorder = _Recorder()
    results = channels.notify_run_complete(
        tenant_id="ten_a",
        run_id="run-a",
        run_dir=_run_dir(settings, "run-a"),
        post_fn=recorder,
    )

    assert recorder.urls == [SLACK_A]
    assert SLACK_B not in recorder.urls
    assert [item["channel_id"] for item in results] == [channel_a["channel_id"]]
    assert results[0]["status"] == "ok"
    # And the run summary really is in the body that went to A.
    assert b"run-a" in recorder.calls[0][1]

    # Tenant B's channel was not merely unselected — it was never attempted, so
    # nothing was recorded against it.
    assert _row(settings, channel_b["channel_id"]).last_send_at is None
    assert _row(settings, channel_a["channel_id"]).last_status == "ok"


def test_a_disabled_channel_is_not_sent_to(settings):
    """Only what the body actually covers: one tenant, one muted channel.

    The name used to promise "and other tenants' runs" as well, which is
    :func:`test_fan_out_reaches_only_the_runs_own_tenant`'s job — a name
    claiming coverage that lives elsewhere is how the route's missing
    cross-tenant test went unnoticed for a whole review.
    """
    _use(KEY_A)
    tenants_service.create_tenant(tenant_id="ten_a", name="Tenant A")
    off = _slack(settings, tenant_id="ten_a", name="muted", enabled=False)

    recorder = _Recorder()
    assert (
        channels.notify_run_complete(
            tenant_id="ten_a",
            run_id="run-a",
            run_dir=_run_dir(settings, "run-a"),
            post_fn=recorder,
        )
        == []
    )
    assert recorder.urls == []
    assert _row(settings, off["channel_id"]).last_status is None


def test_defectdojo_channel_imports_into_its_own_tenants_product(settings):
    """The bulk export, per tenant: own instance, own token, own product."""
    _use(KEY_A)
    tenants_service.create_tenant(tenant_id="ten_a", name="Tenant A")
    channels.create_channel(
        tenant_id="ten_a",
        name="dd",
        kind="defectdojo",
        endpoint="https://dojo.example.com",
        secret="tenant-a-token",
        config={"product_name": "Tenant A", "engagement_name": "Continuous"},
        min_severity="high",
        created_by="admin",
    )

    recorder = _Recorder()
    results = channels.notify_run_complete(
        tenant_id="ten_a",
        run_id="run-dd",
        run_dir=_run_dir(settings, "run-dd"),
        post_fn=recorder,
    )

    assert results[0]["status"] == "ok"
    url, body, headers = recorder.calls[0]
    assert url == "https://dojo.example.com/api/v2/reimport-scan/"
    assert headers["Authorization"] == "Token tenant-a-token"
    assert b'name="product_name"\r\n\r\nTenant A' in body
    assert b'name="engagement_name"\r\n\r\nContinuous' in body
    assert b"CVE-2026-1" in body


def test_a_missing_findings_artifact_is_a_failure_not_a_clean_bill(settings):
    """"No vulnerabilities.json" must never read like "no vulnerabilities".

    The fallback used to be ``[]``, so a run whose archive lost the artifact
    walked into the "no findings ≥ high" branch and recorded ``skipped`` with
    ``ok=True``: nothing imported into DefectDojo, no warning in the job log,
    and an operator reading ``last_status`` in the console concluding the
    tenant was clean.
    """
    _use(KEY_A)
    tenants_service.create_tenant(tenant_id="ten_a", name="Tenant A")
    channel = channels.create_channel(
        tenant_id="ten_a",
        name="dd",
        kind="defectdojo",
        endpoint="https://dojo.example.com",
        secret="tenant-a-token",
        config={"product_name": "Tenant A"},
        created_by="admin",
    )
    run_dir = _run_dir(settings, "run-truncated")
    (run_dir / "vulnerabilities.json").unlink()

    recorder = _Recorder()
    results = channels.notify_run_complete(
        tenant_id="ten_a", run_id="run-truncated", run_dir=run_dir, post_fn=recorder
    )

    assert results[0]["status"] == "error"
    assert "vulnerabilities.json" in results[0]["detail"]
    # Nothing was uploaded, and the row says why rather than saying "skipped".
    assert recorder.calls == []
    assert "vulnerabilities.json" in (_row(settings, channel["channel_id"]).last_status or "")


def test_an_unreadable_findings_artifact_is_reported_the_same_way(settings):
    """A half-written file is the same failure as a missing one."""
    _use(KEY_A)
    tenants_service.create_tenant(tenant_id="ten_a", name="Tenant A")
    channels.create_channel(
        tenant_id="ten_a",
        name="dd",
        kind="defectdojo",
        endpoint="https://dojo.example.com",
        secret="tenant-a-token",
        config={"product_name": "Tenant A"},
        created_by="admin",
    )
    run_dir = _run_dir(settings, "run-torn")
    (run_dir / "vulnerabilities.json").write_text('[{"host": "10.0.0.1"', encoding="utf-8")

    results = channels.notify_run_complete(
        tenant_id="ten_a", run_id="run-torn", run_dir=run_dir, post_fn=_Recorder()
    )
    assert results[0]["status"] == "error"


def test_defectdojo_sends_nothing_when_the_run_is_under_the_floor(settings):
    """An empty reimport with close_old_findings would close the last scan's work."""
    _use(KEY_A)
    tenants_service.create_tenant(tenant_id="ten_a", name="Tenant A")
    channels.create_channel(
        tenant_id="ten_a",
        name="dd",
        kind="defectdojo",
        endpoint="https://dojo.example.com",
        secret="tenant-a-token",
        config={"product_name": "Tenant A", "close_old_findings": True},
        min_severity="critical",
        created_by="admin",
    )
    run_dir = _run_dir(
        settings,
        "run-quiet",
        findings=[{"host": "10.0.0.9", "port": "80", "script_id": "http-title", "severity": "low"}],
    )

    recorder = _Recorder()
    results = channels.notify_run_complete(
        tenant_id="ten_a", run_id="run-quiet", run_dir=run_dir, post_fn=recorder
    )

    assert recorder.calls == []
    assert results[0]["status"] == "skipped"
    assert "no findings" in results[0]["detail"]


def test_one_failing_channel_does_not_stop_the_others(settings):
    _use(KEY_A)
    tenants_service.create_tenant(tenant_id="ten_a", name="Tenant A")
    _slack(settings, tenant_id="ten_a", name="first", secret=SLACK_A)
    _slack(settings, tenant_id="ten_a", name="second", secret=SLACK_B)

    recorder = _Recorder(ok=False)
    results = channels.notify_run_complete(
        tenant_id="ten_a",
        run_id="run-a",
        run_dir=_run_dir(settings, "run-a"),
        post_fn=recorder,
    )

    assert sorted(recorder.urls) == sorted([SLACK_A, SLACK_B])
    assert [item["status"] for item in results] == ["error", "error"]


def test_a_channel_under_a_lost_key_costs_the_tenant_only_that_channel(settings):
    """A row nobody can decrypt must not take the tenant's other channels down."""
    _use(KEY_A)
    tenants_service.create_tenant(tenant_id="ten_a", name="Tenant A")
    lost = _slack(settings, tenant_id="ten_a", name="lost", secret=SLACK_B)
    _use(KEY_B)  # KEY_A is not even in OCTO_MASTER_KEY_PREVIOUS
    healthy = _slack(settings, tenant_id="ten_a", name="healthy", secret=SLACK_A)

    recorder = _Recorder()
    results = channels.notify_run_complete(
        tenant_id="ten_a",
        run_id="run-a",
        run_dir=_run_dir(settings, "run-a"),
        post_fn=recorder,
    )

    assert recorder.urls == [SLACK_A]
    by_id = {item["channel_id"]: item for item in results}
    assert by_id[healthy["channel_id"]]["status"] == "ok"
    assert by_id[lost["channel_id"]]["status"] == "error"
    # And no ciphertext was POSTed anywhere in place of the URL.
    assert envelope.FORMAT_VERSION + ":" not in repr(recorder.urls)


def test_email_channel_mails_this_tenants_recipients_only(settings, monkeypatch):
    """``OCTO_SMTP_TO`` was the installation's list; ``config.to`` is a tenant's."""
    _use(KEY_A)
    settings.report_smtp_host = "relay.internal"
    settings.report_smtp_from = "alerts@shapoclyack.example"
    settings.report_smtp_starttls = False
    tenants_service.create_tenant(tenant_id="ten_a", name="Tenant A")
    tenants_service.create_tenant(tenant_id="ten_b", name="Tenant B")
    channels.create_channel(
        tenant_id="ten_a", name="a-mail", kind="email", config={"to": ["a@example.com"]}
    )
    channels.create_channel(
        tenant_id="ten_b", name="b-mail", kind="email", config={"to": ["b@example.com"]}
    )

    sent: list[str] = []

    class _Smtp:
        def __init__(self, host, port, timeout=None):
            sent.append(f"connect:{host}")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def send_message(self, message):
            sent.append(message["To"])

    monkeypatch.setattr("api.services.integrations.channel_transports.smtplib.SMTP", _Smtp)
    results = channels.notify_run_complete(
        tenant_id="ten_a", run_id="run-a", run_dir=_run_dir(settings, "run-a")
    )

    assert results[0]["status"] == "ok"
    assert sent == ["connect:relay.internal", "a@example.com"]


def test_email_obeys_the_documented_channel_timeout(settings, monkeypatch):
    """The knob the docs advertise is the one the transport uses.

    ``OCTO_NOTIFICATION_CHANNEL_TIMEOUT_SECONDS`` is documented as *the*
    per-send budget, but email alone reached for ``report_smtp_timeout_seconds``
    — so an operator with a slow relay raised the documented knob and the
    connection still gave up after 20 seconds.
    """
    _use(KEY_A)
    settings.report_smtp_host = "relay.internal"
    settings.report_smtp_from = "alerts@shapoclyack.example"
    settings.report_smtp_starttls = False
    settings.report_smtp_timeout_seconds = 20
    settings.notification_channel_timeout_seconds = 120
    channels.create_channel(
        tenant_id="default", name="mail", kind="email", config={"to": ["ops@example.com"]}
    )

    timeouts: list[float | None] = []

    class _Smtp:
        def __init__(self, host, port, timeout=None):
            timeouts.append(timeout)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def send_message(self, message):
            return None

    monkeypatch.setattr("api.services.integrations.channel_transports.smtplib.SMTP", _Smtp)
    channels.notify_run_complete(
        tenant_id="default", run_id="run-a", run_dir=_run_dir(settings, "run-a")
    )

    assert timeouts == [120]


def test_email_channel_says_so_when_the_installation_has_no_relay(settings):
    _use(KEY_A)
    settings.report_smtp_host = ""
    channels.create_channel(
        tenant_id="default", name="mail", kind="email", config={"to": ["ops@example.com"]}
    )

    results = channels.notify_run_complete(
        tenant_id="default", run_id="run-a", run_dir=_run_dir(settings, "run-a")
    )

    # ``skipped``, not ``error``: there is nothing wrong with the channel, and
    # naming the channel would send the operator to the wrong place.
    assert results[0]["status"] == "skipped"
    assert "OCTO_REPORT_SMTP_HOST" in results[0]["detail"]


def test_teams_gets_a_message_card_and_mattermost_its_channel():
    """Each receiver's native body; a bare text payload is rejected by Teams."""
    teams = json.loads(transports.chat_body("msteams", "hello"))
    assert teams["@type"] == "MessageCard" and teams["summary"]
    assert teams["text"] == "hello"

    assert json.loads(transports.chat_body("slack", "hello")) == {"text": "hello"}
    assert json.loads(transports.chat_body("mattermost", "hello", {"channel": "soc"})) == {
        "text": "hello",
        "channel": "soc",
    }


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def test_create_validates_the_knobs_each_adapter_needs(settings):
    _use(KEY_A)
    with pytest.raises(ValueError, match="Unknown tenant_id"):
        _slack(settings, tenant_id="nope")
    with pytest.raises(ValueError, match="unknown channel kind"):
        _slack(settings, kind="carrier-pigeon")
    with pytest.raises(ValueError, match="unknown severity"):
        _slack(settings, min_severity="apocalyptic")
    with pytest.raises(transports.ChannelSpecError, match="incoming-webhook URL"):
        _slack(settings, secret=None)
    # A chat URL in the column that is *not* encrypted is refused outright.
    with pytest.raises(transports.ChannelSpecError, match="goes in secret"):
        _slack(settings, endpoint=SLACK_A)
    with pytest.raises(transports.ChannelSpecError, match="product_name is required"):
        channels.create_channel(
            tenant_id="default",
            name="dd",
            kind="defectdojo",
            endpoint="https://dojo.example.com",
            secret="token",
            config={},
        )
    with pytest.raises(transports.ChannelSpecError, match="not an email address"):
        channels.create_channel(
            tenant_id="default",
            name="mail",
            kind="email",
            config={"to": ["ops@example.com, attacker@evil.example"]},
        )


def test_a_chat_url_pointing_inward_is_refused_unless_opted_in(settings):
    _use(KEY_A)
    with pytest.raises(delivery_transport.WebhookTargetError, match="non-public"):
        _slack(settings, secret="http://127.0.0.1:9000/hook")

    settings.webhook_allow_private_targets = True
    assert _slack(settings, secret="http://127.0.0.1:9000/hook")["has_secret"] is True


def test_channel_count_is_capped_per_tenant(settings):
    _use(KEY_A)
    settings.notification_channel_max_per_tenant = 2
    _slack(settings, name="one")
    _slack(settings, name="two")
    with pytest.raises(ValueError, match="limit 2"):
        _slack(settings, name="three")


def test_kind_cannot_be_patched(settings):
    _use(KEY_A)
    created = _slack(settings)
    with pytest.raises(ValueError, match="cannot be changed"):
        channels.update_channel(created["channel_id"], kind="defectdojo")


# --------------------------------------------------------------------------
# Secrets at rest (#310)
# --------------------------------------------------------------------------


def test_the_credential_is_encrypted_and_never_read_back(settings):
    _use(KEY_A)
    created = _slack(settings, secret=SLACK_A)

    row = _row(settings, created["channel_id"])
    assert envelope.is_encrypted(row.secret)
    assert SLACK_A not in row.secret
    assert row.key_id == envelope.current_key_id()

    # Not even once, unlike a webhook signing secret: the operator supplied it.
    assert "secret" not in created
    assert created["has_secret"] is True
    fetched = channels.get_channel(created["channel_id"])
    assert "secret" not in fetched
    assert SLACK_A not in repr(fetched)
    assert envelope.FORMAT_VERSION + ":" not in repr(fetched)


def test_an_email_channel_stores_no_key_id_because_it_holds_no_secret(settings):
    _use(KEY_A)
    created = channels.create_channel(
        tenant_id="default",
        name="mail",
        kind="email",
        config={"to": ["ops@example.com"]},
    )
    row = _row(settings, created["channel_id"])
    assert (row.secret, row.key_id) == (None, None)
    assert row.config == {"to": ["ops@example.com"]}


def test_reencrypt_command_covers_channel_rows(settings):
    """``python -m api.db.reencrypt_secrets`` has to reach this table too."""
    # Written with no key configured, as a pre-#351 row would be.
    created = _slack(settings, secret=SLACK_A)
    assert _row(settings, created["channel_id"]).secret == SLACK_A

    _use(KEY_A)
    assert reencrypt_secrets.run(settings.postgres_url, dry_run=True).changed == 1
    assert _row(settings, created["channel_id"]).secret == SLACK_A

    assert reencrypt_secrets.run(settings.postgres_url).changed == 1
    row = _row(settings, created["channel_id"])
    assert envelope.is_encrypted(row.secret) and row.key_id == envelope.current_key_id()
    # Resumable: a second pass has nothing left to do.
    assert reencrypt_secrets.run(settings.postgres_url) == reencrypt_secrets.Outcome(
        scanned=1, changed=0, skipped=1
    )

    # A default pass is not a rotation; --rotate is.
    _use(KEY_B, previous=KEY_A)
    assert reencrypt_secrets.run(settings.postgres_url).changed == 0
    assert reencrypt_secrets.run(settings.postgres_url, rotate=True).changed == 1
    assert _row(settings, created["channel_id"]).key_id == envelope.current_key_id()

    assert reencrypt_secrets.run(settings.postgres_url, decrypt=True).changed == 1
    row = _row(settings, created["channel_id"])
    assert (row.secret, row.key_id) == (SLACK_A, None)


def test_prod_refuses_to_store_a_channel_credential_without_a_key(settings):
    settings.env = ENV_PROD
    with pytest.raises(InsecureConfigurationError) as excinfo:
        _slack(settings, name="new-in-prod")
    assert envelope.MASTER_KEY_ENV in str(excinfo.value)
    assert channels.list_channels("default") == []

    _use(KEY_A)
    created = _slack(settings, name="new-in-prod")
    assert envelope.is_encrypted(_row(settings, created["channel_id"]).secret)


def test_the_startup_check_counts_channel_credentials(settings):
    """An installation whose only secret is a Slack URL still needs the key."""
    _slack(settings, secret=SLACK_A)  # plaintext: no key configured
    settings.env = ENV_PROD
    with pytest.raises(InsecureConfigurationError, match="notification_channels"):
        crypto_startup.bootstrap(settings)


# --------------------------------------------------------------------------
# Off the request thread
# --------------------------------------------------------------------------


def _archive() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in (
            ("summary.json", b'{"alive_hosts": 1}\n'),
            ("vulnerabilities.json", b"[]\n"),
        ):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_a_silent_channel_neither_delays_nor_precedes_the_jobs_status(settings, monkeypatch):
    """The two halves of the review's worst finding, in one test.

    ``complete_job`` is called from ``async def upload_results`` with no
    thread-pool hop, so a fan-out that spends its whole per-channel budget
    against a receiver that drops packets used to block the API's event loop —
    and it ran *before* ``_update_job``, so the job stayed non-terminal while
    it did. The agent's own 60s timeout then fired, its retry met the
    still-reserved idempotency key, and the upload it had already delivered was
    reported to it as a 409.

    So: the call must return before the send finishes, and the send must see a
    job that is already ``succeeded``.
    """
    _use(KEY_A)
    approve_scan_scope(settings)
    agents_service.configure(settings)
    channel = _slack(settings, tenant_id="default", name="soc")

    released = threading.Event()
    observed: list[str] = []

    def _hanging_post(url, body, headers, **kwargs):
        """Stands in for a receiver that accepts the connection and says nothing."""
        job = jobs_service.get_job(settings, job_id)
        observed.append(job.status if job else "gone")
        assert released.wait(30.0), "the fan-out thread was never released"
        return delivery_transport.DeliveryResult(
            ok=True, status_code=200, error=None, retryable=False
        )

    monkeypatch.setattr(channels, "_default_post", _hanging_post)

    from api.schemas import StartScanRequest

    settings.job_execution_mode = "agent"
    job_id = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced"), username="admin"
    ).job_id
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    jobs_service.claim_job(settings, "agent-1")
    run_id = jobs_service.get_job(settings, job_id).run_id

    started = time.monotonic()
    completed = jobs_service.complete_job(
        settings,
        job_id,
        agent_id="agent-1",
        exit_code=0,
        run_id=run_id,
        archive_bytes=_archive(),
    )
    elapsed = time.monotonic() - started

    # The upload was answered, with a terminal status, while the channel is
    # still hanging. One second is generous: the request's share of the work is
    # a Thread.start().
    assert completed.status == "succeeded"
    assert elapsed < 1.0, f"complete_job waited {elapsed:.1f}s on the channel"
    assert released.is_set() is False

    released.set()
    assert channels.join_senders(), "the fan-out thread did not finish"
    # And it really did send — off the request, after the status was written.
    assert observed == ["succeeded"]
    assert _row(settings, channel["channel_id"]).last_status == "ok"


# --------------------------------------------------------------------------
# The API surface
# --------------------------------------------------------------------------


@pytest.fixture()
def client(tmp_path: Path, monkeypatch):
    value = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=value)
    _use(KEY_A)
    channels.reset_for_tests()
    return client


def _create(client, headers, **overrides) -> dict:
    payload = {"name": "soc", "kind": "slack", "secret": SLACK_A}
    payload.update(overrides)
    return client.post("/api/notification-channels", json=payload, headers=headers)


def test_api_crud_round_trip_and_write_only_secret(client):
    admin = auth_headers(client, "admin")
    created = _create(client, admin)
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["channel_id"].startswith("nc_")
    assert body["has_secret"] is True
    assert "secret" not in body or body.get("secret") is None
    assert SLACK_A not in created.text

    listed = client.get("/api/notification-channels", headers=auth_headers(client, "operator"))
    assert [item["channel_id"] for item in listed.json()] == [body["channel_id"]]

    patched = client.patch(
        f"/api/notification-channels/{body['channel_id']}",
        json={"enabled": False, "min_severity": "critical"},
        headers=admin,
    )
    assert patched.status_code == 200
    assert (patched.json()["enabled"], patched.json()["min_severity"]) == (False, "critical")

    assert (
        client.delete(f"/api/notification-channels/{body['channel_id']}", headers=admin).status_code
        == 204
    )
    assert client.get("/api/notification-channels", headers=admin).json() == []


def test_api_writes_need_admin_and_reads_need_operator(client):
    assert _create(client, auth_headers(client, "operator")).status_code == 403
    assert _create(client, auth_headers(client, "viewer")).status_code == 403
    created = _create(client, auth_headers(client, "admin")).json()
    assert client.get("/api/notification-channels", headers=auth_headers(client, "viewer")).status_code == 403
    assert (
        client.delete(
            f"/api/notification-channels/{created['channel_id']}",
            headers=auth_headers(client, "operator"),
        ).status_code
        == 403
    )


def test_api_rejects_a_channel_it_could_not_send_on(client):
    admin = auth_headers(client, "admin")
    assert _create(client, admin, secret=None).status_code == 422
    assert _create(client, admin, endpoint=SLACK_A).status_code == 422
    assert (
        _create(client, admin, kind="defectdojo", endpoint="https://dojo.example.com", config={}).status_code
        == 422
    )


def test_api_records_who_pointed_the_alerts_where(client):
    admin = auth_headers(client, "admin")
    created = _create(client, admin).json()

    trail = client.get(
        "/api/audit",
        params={"action": "notification_channel.create"},
        headers=admin,
    )
    assert trail.status_code == 200, trail.text
    rows = trail.json()["items"]
    assert [row["resource_id"] for row in rows] == [created["channel_id"]]
    assert rows[0]["actor"] == "admin"
    assert rows[0]["after"]["kind"] == "slack"
    # The credential is not in the trail. Nor, as it happens, is the boolean
    # saying one exists: audit's redactor keys on the field *name* and
    # ``has_secret`` ends in ``_secret``. Over-redaction is the direction that
    # default has to fail in, so this asserts it rather than working around it.
    assert SLACK_A not in trail.text
    assert rows[0]["after"]["has_secret"] == "[redacted]"


# --------------------------------------------------------------------------
# The tenant boundary on the route
# --------------------------------------------------------------------------


def _make_tenant(client, tenant_id: str) -> None:
    created = client.post(
        "/api/tenants",
        headers=auth_headers(client, "admin"),
        json={"name": tenant_id, "tenant_id": tenant_id},
    )
    assert created.status_code == 201, created.text


def _grant(client, username: str, tenant_id: str, role: str = "admin") -> None:
    granted = client.put(
        f"/api/tenants/{tenant_id}/members/{username}",
        headers=auth_headers(client, "admin"),
        json={"role": role},
    )
    assert granted.status_code == 200, granted.text


def test_a_channel_in_another_tenant_is_not_readable_or_mutable(client):
    """The test this feature shipped without.

    Every API test above ran as one tenant, so a mutation deleting the
    ``tenant_id`` comparison in ``_require_own_channel`` passed the whole
    suite — the fan-out's own isolation test does not touch the route, which
    is a different mechanism. ``404`` rather than ``403``, as for jobs and
    schedules: whether an id exists is not the caller's business.
    """
    _make_tenant(client, "ten_a")
    _make_tenant(client, "ten_b")
    # Tenant admin in ten_a and nowhere else. Not the seeded ``admin``, who is
    # a platform admin and is *meant* to see across tenants.
    _grant(client, "operator", "ten_a", "admin")
    theirs = _create(
        client, auth_headers(client, "admin"), tenant_id="ten_b", secret=SLACK_B
    ).json()["channel_id"]
    intruder = {"Authorization": f"Bearer {login(client, 'operator')}"}

    assert client.get(f"/api/notification-channels/{theirs}", headers=intruder).status_code == 404
    assert (
        client.patch(
            f"/api/notification-channels/{theirs}", json={"enabled": False}, headers=intruder
        ).status_code
        == 404
    )
    assert (
        client.delete(f"/api/notification-channels/{theirs}", headers=intruder).status_code == 404
    )
    # None of the three touched it, and the list stays empty for ten_a.
    assert client.get("/api/notification-channels", headers=intruder).json() == []
    survivor = client.get(
        f"/api/notification-channels/{theirs}", headers=auth_headers(client, "admin")
    )
    assert survivor.status_code == 200
    assert survivor.json()["enabled"] is True


def test_the_service_scopes_the_writes_too(settings):
    """The second layer, asserted where the route cannot vouch for it.

    ``update_channel``/``delete_channel`` took an id and nothing else, so the
    route was the only thing standing between tenant B's admin and tenant A's
    Slack URL. They now take the scope as part of the predicate; this is the
    test that fails if either the route or the service check is removed.
    """
    _use(KEY_A)
    tenants_service.create_tenant(tenant_id="ten_a", name="Tenant A")
    tenants_service.create_tenant(tenant_id="ten_b", name="Tenant B")
    theirs = _slack(settings, tenant_id="ten_b", name="theirs", secret=SLACK_B)["channel_id"]

    assert channels.update_channel(theirs, tenant_id="ten_a", name="hijacked") is None
    assert channels.delete_channel(theirs, tenant_id="ten_a") is False
    # Untouched, and still reachable by its owner and by the unscoped
    # platform admin (``tenant_id=None``).
    assert _row(settings, theirs).name == "theirs"
    assert channels.update_channel(theirs, tenant_id="ten_b", name="renamed")["name"] == "renamed"
    assert channels.delete_channel(theirs, tenant_id=None) is True


def test_timestamps_carry_the_same_offset_on_the_way_out_and_back(client):
    """A row just written and the same row read back must agree on the ``Z``.

    ``created_at`` is an aware ``datetime`` in Python and a naive column in
    Postgres, so ``isoformat()`` alone gave the POST response an offset and the
    following GET none — and a consumer parses an offsetless timestamp as
    local time.
    """
    admin = auth_headers(client, "admin")
    created = _create(client, admin).json()
    fetched = client.get(
        f"/api/notification-channels/{created['channel_id']}", headers=admin
    ).json()

    assert created["created_at"].endswith("Z")
    assert fetched["created_at"].endswith("Z")
    assert fetched["created_at"] == created["created_at"]
