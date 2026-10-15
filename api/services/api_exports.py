"""Bounded keyset export pages. Database sessions close before response streaming."""

from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import json
import time
from collections.abc import Iterator

from fastapi.encoders import jsonable_encoder
from sqlalchemy import select

from api.db import models
from api.db.engine import get_session

# Explicit public export contract: no raw evidence, credentials or ORM internals.
COLUMNS = {
    "assets": (
        "asset_id",
        "tenant_id",
        "status",
        "first_seen",
        "last_seen",
        "owner_email",
        "business_service",
        "environment",
        "exposure_level",
        "asset_criticality",
    ),
    "vulnerabilities": (
        "vuln_id",
        "tenant_id",
        "asset_id",
        "title",
        "cve",
        "severity",
        "state",
        "assignee",
        "source",
        "contextual_score",
        "first_seen_at",
        "last_seen_at",
        "due_at",
    ),
}
MODELS = {"assets": models.Asset, "vulnerabilities": models.Vulnerability}


def _encode(document: dict, secret: str) -> str:
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        )
        .decode()
        .rstrip("=")
    )
    signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return payload + "." + signature


def _decode(cursor: str, *, tenant_id: str, resource: str, secret: str) -> str:
    try:
        payload, signature = cursor.split(".")
        expected = hmac.new(
            secret.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if (
            data["tenant"] != tenant_id
            or data["resource"] != resource
            or data["expires"] < time.time()
            or data["v"] != 1
        ):
            raise ValueError
        if not isinstance(data["after"], str) or len(data["after"]) > 256:
            raise ValueError
        return data["after"]
    except (ValueError, KeyError, TypeError, UnicodeError) as exc:
        raise ValueError("Invalid or expired export cursor") from exc


def export_page(
    settings, *, tenant_id: str, resource: str, cursor: str | None, limit: int
):
    after = (
        _decode(
            cursor, tenant_id=tenant_id, resource=resource, secret=settings.jwt_secret
        )
        if cursor
        else ""
    )
    model = MODELS[resource]
    columns = COLUMNS[resource]
    key = getattr(model, columns[0])
    with get_session(settings.postgres_url) as session:
        records = (
            session.execute(
                select(*(getattr(model, name) for name in columns))
                .where(model.tenant_id == tenant_id, key > after)
                .order_by(key)
                .limit(limit + 1)
            )
            .mappings()
            .all()
        )
        rows = [jsonable_encoder(dict(row)) for row in records[:limit]]
    next_cursor = None
    if len(records) > limit:
        next_cursor = _encode(
            {
                "v": 1,
                "tenant": tenant_id,
                "resource": resource,
                "after": rows[-1][columns[0]],
                "expires": int(time.time()) + 86400,
            },
            settings.jwt_secret,
        )
    return rows, next_cursor


def stream_rows(resource: str, rows: list[dict], format: str) -> Iterator[str]:
    if format == "ndjson":
        for row in rows:
            yield json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
        return
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS[resource])
    writer.writeheader()
    yield buffer.getvalue()
    buffer.seek(0)
    buffer.truncate()
    for row in rows:
        # Spreadsheet formulas may hide behind whitespace/control characters.
        writer.writerow(
            {
                key: "'" + value
                if isinstance(value, str)
                and (
                    value.startswith(("\t", "\r", "\n"))
                    or value.lstrip().startswith(("=", "+", "-", "@"))
                )
                else value
                for key, value in row.items()
            }
        )
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate()
