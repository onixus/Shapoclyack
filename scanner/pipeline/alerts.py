from __future__ import annotations

import json
import logging
import os
import smtplib
import socket
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from typing import Any

from .config_schema import AlertsConfig, SmtpAlertConfig
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


def _smtp_to_addrs(config: SmtpAlertConfig) -> list[str]:
    env_to = os.environ.get("OCTO_SMTP_TO", "").strip()
    if env_to:
        return [part.strip() for part in env_to.split(",") if part.strip()]
    return [addr.strip() for addr in config.to_addrs if addr.strip()]


def lookup_txt_records(name: str, timeout: int = 10) -> list[str]:
    """Resolve TXT via Cloudflare DNS-over-HTTPS (no dig dependency)."""
    query = urllib.parse.urlencode({"name": name, "type": "TXT"})
    url = f"https://cloudflare-dns.com/dns-query?{query}"
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/dns-json"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    answers = payload.get("Answer") or []
    texts: list[str] = []
    for answer in answers:
        data = str(answer.get("data") or "").strip().strip('"')
        if data:
            texts.append(data)
    return texts


def check_dkim_record(domain: str, selector: str, timeout: int = 10) -> dict[str, Any]:
    if not domain or not selector:
        return {"ok": False, "reason": "missing_domain_or_selector", "records": []}
    name = f"{selector}._domainkey.{domain}".lower()
    try:
        records = lookup_txt_records(name, timeout=timeout)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        return {"ok": False, "reason": f"lookup_error: {exc}", "name": name, "records": []}
    has_v = any("v=DKIM1" in rec.upper() or "DKIM1" in rec.upper() for rec in records)
    return {"ok": bool(records) and has_v, "name": name, "records": records, "reason": None if records else "empty"}


def check_ptr_record(host: str) -> dict[str, Any]:
    """Validate that ``host`` (name or IP) has a PTR mapping."""
    if not host:
        return {"ok": False, "reason": "missing_host"}
    try:
        infos = socket.getaddrinfo(host, None)
        ip = infos[0][4][0] if infos else ""
        if not ip:
            return {"ok": False, "reason": "unresolvable", "host": host}
        ptr_name, aliases, _ = socket.gethostbyaddr(ip)
        names = [ptr_name] + list(aliases or [])
        return {"ok": True, "host": host, "ip": ip, "ptr": names}
    except (socket.gaierror, socket.herror, OSError) as exc:
        return {"ok": False, "reason": str(exc), "host": host}


def validate_smtp_deliverability(config: SmtpAlertConfig, from_addr: str) -> dict[str, Any]:
    """Optional DKIM TXT + PTR checks before sending via Maddy/relay."""
    validation: dict[str, Any] = {"ok": True, "dkim": None, "ptr": None, "blocked_reason": None}
    from_domain = ""
    if "@" in from_addr:
        from_domain = from_addr.rsplit("@", 1)[-1].strip().lower()

    if config.dkim_selector or config.require_dkim:
        dkim = check_dkim_record(from_domain, config.dkim_selector or "default", timeout=config.timeout_seconds)
        validation["dkim"] = dkim
        if config.require_dkim and not dkim.get("ok"):
            validation["ok"] = False
            validation["blocked_reason"] = "dkim_required"
            return validation

    if config.require_ptr:
        ptr_host = (config.ptr_hostname or config.host or "").strip()
        ptr = check_ptr_record(ptr_host)
        validation["ptr"] = ptr
        if not ptr.get("ok"):
            validation["ok"] = False
            validation["blocked_reason"] = "ptr_required"
    return validation


def send_smtp_alert(config: SmtpAlertConfig, subject: str, text: str) -> dict[str, Any]:
    """Send alert mail via local Maddy (or any SMTP relay). Fail-soft result dict."""
    host = _env_or(config.host, "OCTO_SMTP_HOST") or "127.0.0.1"
    port_raw = os.environ.get("OCTO_SMTP_PORT", "").strip()
    port = int(port_raw) if port_raw else config.port
    from_addr = _env_or(config.from_addr, "OCTO_SMTP_FROM")
    to_addrs = _smtp_to_addrs(config)
    username = _env_or(config.username, "OCTO_SMTP_USERNAME")
    password = _env_or(config.password, "OCTO_SMTP_PASSWORD")

    if not from_addr or not to_addrs:
        return {"status": "error: missing from/to (OCTO_SMTP_FROM / OCTO_SMTP_TO)", "validation": None}

    # Use resolved host for validation when env overrides host.
    cfg = config.model_copy(update={"host": host, "port": port})
    validation = validate_smtp_deliverability(cfg, from_addr)
    if not validation["ok"]:
        return {"status": f"error: validation blocked ({validation['blocked_reason']})", "validation": validation}

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = from_addr
    message["To"] = ", ".join(to_addrs)
    message.set_content(text)

    with smtplib.SMTP(host, port, timeout=config.timeout_seconds) as smtp:
        if config.use_starttls:
            smtp.starttls()
        if username and password:
            smtp.login(username, password)
        smtp.send_message(message)
    return {"status": "ok", "validation": validation}


def send_alerts(
    config: AlertsConfig,
    *,
    run_id: str,
    summary: dict[str, Any],
    diff: dict[str, Any] | None,
) -> dict[str, Any]:
    """Send configured notifications. Fail-soft: log errors, never raise."""
    result: dict[str, Any] = {
        "attempted": False,
        "slack": None,
        "telegram": None,
        "smtp": None,
        "skipped_reason": None,
    }

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

    if config.smtp.enabled:
        try:
            smtp_result = send_smtp_alert(
                config.smtp,
                subject=f"Octo-man scan complete ({run_id})",
                text=text.replace("*", "").replace("`", ""),
            )
            result["smtp"] = smtp_result.get("status")
            result["smtp_validation"] = smtp_result.get("validation")
            if smtp_result.get("status") == "ok":
                logging.info("SMTP alert sent")
            else:
                logging.warning("SMTP alert failed: %s", smtp_result.get("status"))
        except (smtplib.SMTPException, TimeoutError, OSError, ValueError) as exc:
            result["smtp"] = f"error: {exc}"
            logging.warning("SMTP alert failed: %s", exc)

    return result
