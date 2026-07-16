from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

from .config_schema import AlertsConfig
from .report import SEVERITY_ORDER


def _env_or(value: str, env_name: str) -> str:
    return value or os.environ.get(env_name, "")


def _meets_min_severity(severity: str, minimum: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(minimum, 0)


def format_alert_message(
    *,
    run_id: str,
    summary: dict[str, Any],
    diff: dict[str, Any] | None,
    min_severity: str,
) -> str:
    sev = summary.get("vulnerabilities_by_severity") or {}
    lines = [
        f"*Octo-man scan complete* (`{run_id}`)",
        f"Alive hosts: {summary.get('alive_hosts', 0)}",
        f"Open host:port: {summary.get('open_host_port_pairs', 0)}",
        (
            "Vulnerabilities: "
            f"{summary.get('potential_vulnerabilities', 0)} "
            f"(critical {sev.get('critical', 0)}, high {sev.get('high', 0)}, "
            f"medium {sev.get('medium', 0)}, low {sev.get('low', 0)})"
        ),
    ]

    if diff is not None:
        counts = diff.get("counts") or {}
        lines.append(
            "Diff vs previous: "
            f"hosts +{counts.get('hosts_added', 0)}/-{counts.get('hosts_removed', 0)}, "
            f"ports +{counts.get('ports_added', 0)}/-{counts.get('ports_removed', 0)}, "
            f"vulns +{counts.get('vulns_added', 0)}/-{counts.get('vulns_removed', 0)}"
        )
        added = (diff.get("vulnerabilities") or {}).get("added") or []
        notable = [
            item
            for item in added
            if _meets_min_severity(str(item.get("severity") or "unknown"), min_severity)
        ][:10]
        if notable:
            lines.append(f"New vulns (≥ {min_severity}):")
            for item in notable:
                location = f"{item.get('host')}:{item.get('port')}" if item.get("port") else item.get("host")
                cve = item.get("cve") or item.get("script_id") or "unknown"
                lines.append(f"• [{str(item.get('severity', 'unknown')).upper()}] {location} {cve}")
    return "\n".join(lines)


def _post_json(url: str, payload: dict[str, Any], timeout: int = 15) -> None:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        response.read()


def send_slack_alert(webhook_url: str, text: str) -> None:
    _post_json(webhook_url, {"text": text})


def send_telegram_alert(bot_token: str, chat_id: str, text: str) -> None:
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    _post_json(url, {"chat_id": chat_id, "text": text, "disable_web_page_preview": True})


def send_alerts(
    config: AlertsConfig,
    *,
    run_id: str,
    summary: dict[str, Any],
    diff: dict[str, Any] | None,
) -> dict[str, Any]:
    """Send configured notifications. Fail-soft: log errors, never raise."""
    result: dict[str, Any] = {"attempted": False, "slack": None, "telegram": None, "skipped_reason": None}

    if not config.enabled:
        result["skipped_reason"] = "alerts.disabled"
        return result

    if config.on_diff_only and (diff is None or not diff.get("has_changes")):
        result["skipped_reason"] = "no_diff_changes"
        logging.info("Alerts skipped: on_diff_only and no changes vs previous run")
        return result

    text = format_alert_message(
        run_id=run_id,
        summary=summary,
        diff=diff,
        min_severity=config.min_severity,
    )
    result["attempted"] = True
    result["message"] = text

    slack_url = _env_or(config.slack.webhook_url, "OCTO_SLACK_WEBHOOK")
    if config.slack.enabled and slack_url:
        try:
            send_slack_alert(slack_url, text)
            result["slack"] = "ok"
            logging.info("Slack alert sent")
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            result["slack"] = f"error: {exc}"
            logging.warning("Slack alert failed: %s", exc)
    elif config.slack.enabled:
        result["slack"] = "error: missing webhook_url / OCTO_SLACK_WEBHOOK"
        logging.warning("Slack alert enabled but webhook URL is empty")

    tg_token = _env_or(config.telegram.bot_token, "OCTO_TELEGRAM_BOT_TOKEN")
    tg_chat = _env_or(config.telegram.chat_id, "OCTO_TELEGRAM_CHAT_ID")
    if config.telegram.enabled and tg_token and tg_chat:
        try:
            send_telegram_alert(tg_token, tg_chat, text)
            result["telegram"] = "ok"
            logging.info("Telegram alert sent")
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            result["telegram"] = f"error: {exc}"
            logging.warning("Telegram alert failed: %s", exc)
    elif config.telegram.enabled:
        result["telegram"] = "error: missing bot_token/chat_id (or env vars)"
        logging.warning("Telegram alert enabled but credentials are incomplete")

    return result
