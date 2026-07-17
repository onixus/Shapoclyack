from __future__ import annotations

from scanner.pipeline.alerts import (
    format_alert_message,
    send_alerts,
    send_smtp_alert,
)
from scanner.pipeline.config_schema import (
    AlertsConfig,
    SlackAlertConfig,
    SmtpAlertConfig,
    TelegramAlertConfig,
)


def test_format_alert_message_includes_diff_counts():
    text = format_alert_message(
        run_id="run1",
        summary={
            "alive_hosts": 3,
            "open_host_port_pairs": 5,
            "potential_vulnerabilities": 2,
            "vulnerabilities_by_severity": {
                "critical": 1,
                "high": 1,
                "medium": 0,
                "low": 0,
                "unknown": 0,
            },
        },
        diff={
            "counts": {
                "hosts_added": 1,
                "hosts_removed": 0,
                "ports_added": 2,
                "ports_removed": 0,
                "vulns_added": 1,
                "vulns_removed": 0,
            },
            "vulnerabilities": {
                "added": [
                    {
                        "host": "10.0.0.1",
                        "port": "22",
                        "cve": "CVE-2016-10012",
                        "severity": "critical",
                    }
                ]
            },
        },
        min_severity="high",
    )
    assert "run1" in text
    assert "hosts +1/-0" in text
    assert "CVE-2016-10012" in text


def test_send_alerts_skipped_when_disabled():
    result = send_alerts(
        AlertsConfig(enabled=False),
        run_id="r",
        summary={},
        diff=None,
    )
    assert result["attempted"] is False
    assert result["skipped_reason"] == "alerts.disabled"


def test_send_alerts_on_diff_only_without_changes():
    result = send_alerts(
        AlertsConfig(enabled=True, on_diff_only=True),
        run_id="r",
        summary={"alive_hosts": 1},
        diff={"has_changes": False},
    )
    assert result["attempted"] is False
    assert result["skipped_reason"] == "no_diff_changes"


def test_send_alerts_reports_missing_credentials():
    cfg = AlertsConfig(
        enabled=True,
        slack=SlackAlertConfig(enabled=True, webhook_url=""),
        telegram=TelegramAlertConfig(enabled=True, bot_token="", chat_id=""),
    )
    result = send_alerts(cfg, run_id="r", summary={"alive_hosts": 0}, diff=None)
    assert result["attempted"] is True
    assert "missing" in (result["slack"] or "")
    assert "missing" in (result["telegram"] or "")


def test_smtp_missing_recipients(monkeypatch):
    monkeypatch.delenv("OCTO_SMTP_TO", raising=False)
    monkeypatch.delenv("OCTO_SMTP_FROM", raising=False)
    result = send_smtp_alert(
        SmtpAlertConfig(enabled=True, from_addr="", to_addrs=[]),
        subject="t",
        text="body",
    )
    assert "missing" in result["status"]


def test_smtp_blocked_when_dkim_required(monkeypatch):
    monkeypatch.setattr(
        "scanner.pipeline.alerts.check_dkim_record",
        lambda domain, selector, timeout=10: {"ok": False, "reason": "empty", "records": []},
    )
    result = send_smtp_alert(
        SmtpAlertConfig(
            enabled=True,
            from_addr="alerts@example.com",
            to_addrs=["ops@example.com"],
            require_dkim=True,
            dkim_selector="mail",
        ),
        subject="t",
        text="body",
    )
    assert "dkim_required" in result["status"]


def test_smtp_send_success(monkeypatch):
    class FakeSMTP:
        def __init__(self, *args, **kwargs):
            self.sent = None

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def starttls(self):
            return None

        def login(self, user, password):
            return None

        def send_message(self, message):
            self.sent = message

    monkeypatch.setattr("scanner.pipeline.alerts.smtplib.SMTP", FakeSMTP)
    monkeypatch.setattr(
        "scanner.pipeline.alerts.validate_smtp_deliverability",
        lambda config, from_addr: {"ok": True, "dkim": None, "ptr": None, "blocked_reason": None},
    )
    result = send_smtp_alert(
        SmtpAlertConfig(
            enabled=True,
            host="127.0.0.1",
            port=25,
            from_addr="alerts@example.com",
            to_addrs=["ops@example.com"],
        ),
        subject="scan done",
        text="hello",
    )
    assert result["status"] == "ok"


def test_send_alerts_includes_smtp(monkeypatch):
    monkeypatch.setattr(
        "scanner.pipeline.alerts.send_smtp_alert",
        lambda config, subject, text: {"status": "ok", "validation": {"ok": True}},
    )
    cfg = AlertsConfig(
        enabled=True,
        smtp=SmtpAlertConfig(enabled=True, from_addr="a@b.c", to_addrs=["x@y.z"]),
    )
    result = send_alerts(cfg, run_id="r1", summary={"alive_hosts": 1}, diff=None)
    assert result["smtp"] == "ok"
