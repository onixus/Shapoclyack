from __future__ import annotations

from scanner.pipeline.alerts import format_alert_message, send_alerts
from scanner.pipeline.config_schema import AlertsConfig, SlackAlertConfig, TelegramAlertConfig


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
