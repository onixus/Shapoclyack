"""Bounded ServiceNow Table API reads feeding the existing safe importer.

The token is tenant-bound encrypted data, never a response field. All pages
are fetched and validated before the importer can write. No remote deletes,
operator overrides or automatic identifier linking are permitted.
"""
from __future__ import annotations

import json
import re
import threading
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode, urlsplit

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import asset_import, crypto, tenants, audit as audit_service
from api.services.integrations import delivery
from api.services.leader_lock import ASSET_IMPORT_LOCK_ID, LeaderLock

_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_TABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
PAGE_SIZE = 200
MAX_PAGE_BYTES = 1024 * 1024


def now():
    return datetime.now(UTC).replace(tzinfo=None)


def validate_config(base_url, table, mapping):
    parsed = urlsplit(base_url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise ValueError("ServiceNow base URL must be an HTTPS origin without credentials or path")
    if not _TABLE.fullmatch(table):
        raise ValueError("invalid ServiceNow table name")
    allowed = {*asset_import.KEY_COLUMNS, *asset_import.CONTEXT_COLUMNS}
    # Remote sys_id is provenance, never our globally unique asset primary key.
    allowed.remove("asset_id")
    if not mapping or not ({"ip", "fqdn"} & mapping.keys()):
        raise ValueError("map at least one asset identity: ip or fqdn")
    if len(mapping) > 32 or any(
        target not in allowed and not (target.startswith("tag:") and asset_import._TAG_KEY_RE.fullmatch(target[4:]))
        or not isinstance(source, str) or not _FIELD.fullmatch(source)
        for target, source in mapping.items()
    ):
        raise ValueError("invalid field mapping: use import fields and ServiceNow field paths")
    # Resolves/validates at configuration AND each wire attempt; no redirects.
    delivery.validate_url(base_url, allow_private=False)


def public(row):
    return {name: getattr(row, name) for name in (
        "base_url", "table", "field_mapping", "enabled", "interval_seconds",
        "last_run_at", "next_run_at", "last_error", "last_counts",
    )} | {"credential_configured": bool(row.token_encrypted)}


def get(settings, tenant_id):
    with get_session(settings.postgres_url) as session:
        row = session.get(models.AssetImportConnector, tenant_id)
        return public(row) if row else None


def save(settings, tenant_id, body, *, audit=None):
    validate_config(body.base_url, body.table, body.field_mapping)
    if not crypto.encryption_enabled():
        raise ValueError("Configure OCTO_MASTER_KEY before storing a connector credential")
    with get_session(settings.postgres_url) as session:
        row = session.get(models.AssetImportConnector, tenant_id, with_for_update=True)
        if row is None:
            if not body.token:
                raise ValueError("ServiceNow bearer token is required for a new connector")
            row = models.AssetImportConnector(tenant_id=tenant_id)
            session.add(row)
        if row.base_url and row.base_url.rstrip("/").lower() != body.base_url.rstrip("/").lower() and not body.token:
            raise ValueError("A replacement token is required when changing the ServiceNow origin")
        for name in ("base_url", "table", "field_mapping", "enabled", "interval_seconds"):
            setattr(row, name, getattr(body, name))
        if body.token:
            row.token_encrypted = crypto.encrypt_secret(body.token, context=f"asset-import:{tenant_id}")
        row.next_run_at = now() + timedelta(seconds=row.interval_seconds)
        row.last_error = None
        audit_service.record(session, audit, action="asset.connector.configure", resource_type="asset_connector", resource_id="servicenow", tenant_id=tenant_id,
            after={"enabled": body.enabled, "interval_seconds": body.interval_seconds, "credential_changed": bool(body.token)})
        session.flush()
        return public(row)


def fetch(row, *, scheduled=False):
    validate_config(row.base_url, row.table, row.field_mapping)
    token = crypto.decrypt_secret(row.token_encrypted, context=f"asset-import:{row.tenant_id}")
    deadline = time.monotonic() + 60
    records = []
    seen = set()
    # One extra page allows an exact 5,000-record source; never silently truncate.
    for offset in range(0, asset_import.MAX_ROWS + PAGE_SIZE, PAGE_SIZE):
        if scheduled and _stop.is_set():
            raise ValueError("ServiceNow worker is stopping")
        if time.monotonic() >= deadline:
            raise ValueError("ServiceNow import exceeded its 60-second fetch budget")
        query = urlencode({
            "sysparm_fields": ",".join(sorted(set(row.field_mapping.values()) | {"sys_id"})),
            "sysparm_limit": PAGE_SIZE, "sysparm_offset": offset,
            "sysparm_query": "ORDERBYsys_id", "sysparm_display_value": "false",
            "sysparm_exclude_reference_link": "true",
        })
        result = delivery.request(
            "GET", f"{row.base_url.rstrip('/')}/api/now/table/{row.table}?{query}", b"",
            {"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout_seconds=max(1, min(10, int(deadline - time.monotonic()))), allow_private=False, capture_body=True,
            response_limit_bytes=MAX_PAGE_BYTES,
        )
        if not result.ok:
            # Never persist upstream error bodies, URLs or credentials.
            raise ValueError(f"ServiceNow request failed (HTTP {result.status_code or 'unavailable'})")
        try:
            page = json.loads(result.body or "")["result"]
        except (ValueError, KeyError, TypeError):
            raise ValueError("ServiceNow returned an invalid Table API document") from None
        if not isinstance(page, list) or len(page) > PAGE_SIZE:
            raise ValueError("ServiceNow returned an invalid page")
        for item in page:
            if not isinstance(item, dict) or not isinstance(item.get("sys_id"), str) or not item["sys_id"]:
                raise ValueError("ServiceNow record is missing sys_id")
            if item["sys_id"] in seen:
                raise ValueError("ServiceNow pagination repeated sys_id; retry with a stable source")
            seen.add(item["sys_id"])
            record = {}
            for target, source in row.field_mapping.items():
                value = item.get(source)
                # Reference fields may carry a value wrapper; display labels are
                # not identities or email addresses and must never be substituted.
                if isinstance(value, dict):
                    value = value.get("value")
                record[target] = value
            records.append(record)
        if len(records) > asset_import.MAX_ROWS:
            raise ValueError("ServiceNow source exceeds 5000 assets; narrow the configured table")
        if len(page) < PAGE_SIZE:
            break
    content = json.dumps(records, ensure_ascii=False)
    # Enforce the same total byte/cell limits as file imports before applying.
    asset_import.parse(content, format="json")
    return content


def run(settings, tenant_id, *, dry_run=True, scheduled=False, expected_next_run=None, actor="servicenow-scheduler", audit=None):
    # Lock the configuration while reading/applying, fencing edits and concurrent
    # manual/scheduled runs. The tenant advisory import lock still fences files.
    with get_session(settings.postgres_url) as session:
        row = session.get(models.AssetImportConnector, tenant_id, with_for_update=True)
        if row is None:
            raise ValueError("ServiceNow connector is not configured")
        if scheduled and (not row.enabled or (expected_next_run is not None and row.next_run_at != expected_next_run)):
            return None
        if not session.scalar(select(models.Tenant.tenant_id).where(
            models.Tenant.tenant_id == tenant_id,
            models.Tenant.tenant_id.in_(tenants.active_tenant_ids()),
        )):
            raise ValueError("tenant is not active")
        content = fetch(row, scheduled=scheduled)
        if scheduled and _stop.is_set():
            raise ValueError("ServiceNow worker is stopping")
        report = asset_import.run_import(
            settings, tenant_id=tenant_id, content=content, format="json", dry_run=dry_run,
            context_source="cmdb", overwrite_operator_edits=False,
            link_new_identifiers=False, actor=actor, audit=audit or audit_service.system_context(actor),
        )
        if not dry_run:
            row.last_run_at = now()
            row.next_run_at = now() + timedelta(seconds=row.interval_seconds)
            row.last_counts = report["counts"]
            row.last_error = None
        return report


def tick(settings):
    with get_session(settings.postgres_url) as session:
        due = list(session.scalars(select(models.AssetImportConnector.tenant_id).where(
            models.AssetImportConnector.enabled.is_(True),
            models.AssetImportConnector.next_run_at <= now(),
            models.AssetImportConnector.tenant_id.in_(tenants.active_tenant_ids()),
        ).order_by(models.AssetImportConnector.next_run_at).limit(20)))
    for tenant_id in due:
        if _stop.is_set():
            break
        reserved = None
        try:
            # Recheck enabled/due under the lock, not only at enumeration time.
            with get_session(settings.postgres_url) as session:
                row = session.get(models.AssetImportConnector, tenant_id, with_for_update=True)
                if row is None or not row.enabled or row.next_run_at > now():
                    continue
                # Reserve the next slot before network work; failures retain a
                # bounded retry cadence and never spin on every worker tick.
                row.next_run_at = now() + timedelta(seconds=row.interval_seconds)
                reserved = row.next_run_at
            run(settings, tenant_id, dry_run=False, scheduled=True, expected_next_run=reserved)
        except Exception:
            with get_session(settings.postgres_url) as session:
                row = session.get(models.AssetImportConnector, tenant_id)
                if row and reserved is not None and row.next_run_at == reserved:
                    row.last_run_at = now()
                    row.last_error = "ServiceNow sync failed; check endpoint, credential, mapping and source limits"


_stop = threading.Event()
_thread = None


def start_worker(settings):
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()

    def loop():
        lock = LeaderLock(settings.postgres_url, object_id=ASSET_IMPORT_LOCK_ID, name="asset-import")
        try:
            while not _stop.wait(30):
                try:
                    if lock.acquire():
                        tick(settings)
                except Exception:
                    # A failed tick must not kill future schedules. Diagnostics
                    # are deliberately credential-free in the per-tenant state.
                    continue
        finally:
            lock.release()

    _thread = threading.Thread(target=loop, daemon=True, name="asset-import")
    _thread.start()


def stop_worker():
    _stop.set()
    if _thread:
        _thread.join(timeout=12)
        if _thread.is_alive():
            raise RuntimeError("ServiceNow worker did not stop within its network deadline")
