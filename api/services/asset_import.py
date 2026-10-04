"""Bulk import of operator context from a CMDB or directory export (#350).

``PATCH /api/assets/{id}`` was the whole CMDB story: an integrator wrote a
script that looked every host up by id and patched it, one request per asset,
and an asset the scanner had never seen could not be registered at all. This
module takes the export itself — CSV or JSON — and reports, row by row, what it
would do or did.

**Identity is the registry's, not the file's.** A row names its asset by the
keys the registry already matches on: ``asset_id``, an ``ip`` or an ``fqdn``,
looked up in ``asset_identifiers`` exactly as a scan's host record is
(:func:`api.services.assets._find_existing_asset_id`), and a new asset gets the
id a scan would have given it (``ip_identity_key`` / ``fqdn_identity_key``), so
the first scan that reaches it lands on the imported row instead of opening a
second one. The import never *merges* two assets: an IP that belongs to one
asset and an FQDN that belongs to another is a ``conflict`` the report names,
because the evidence for a merge is a scan's (forward DNS plus a certificate,
``asset_identity_links``) and a wrong merge is worse than two rows. Nor does it
*link* on the file's word alone: a row that finds an asset by one identifier
and carries another the registry has never seen is ``new_identifier`` unless
the request says ``link_new_identifiers`` — a load balancer's VIP that today's
export pairs with a different name would otherwise hand that name, and every
later scan of it, to yesterday's asset.

**A cell that is absent or empty leaves the field alone.** There is no way to
clear a field from an import, in either format: a JSON ``null`` and a blank CSV
cell both mean "this export has nothing to say". An export that happened to
lack the owner column used to be the kind of input that flattened ``owner_*``
across a whole selection, and a nightly sync from a CMDB with gaps is exactly
that input. Clearing is ``PATCH`` with an explicit ``null``, one asset at a
time, by a person.

**The operator's hand edit wins by default.** A field whose last write was an
operator's (``asset_context_events.source == "operator"``, or a value with no
event of that field behind it at all) is not overwritten by an import that
disagrees with it: the row is a ``conflict`` with code ``operator_override``
and names the fields. ``overwrite_operator_edits`` is the explicit way to let
the CMDB win. A row is applied whole or not at all, so a conflict on one field
does not half-update the asset.

**Dry run is the default and writes nothing.** The plan is built from reads
only; applying it is a second pass over the same plan in the same transaction,
so the preview and the apply cannot disagree about what a row means — only
about the data, if somebody changed it in between, which is why the apply
recomputes rather than trusting a preview's answer.

**One import per tenant at a time, without fencing anyone else.** Applies
into one tenant are serialised by a transaction-scoped advisory lock, not by a
row lock on ``tenants``: ``SELECT … FOR UPDATE`` there conflicts with the
``FOR KEY SHARE`` every foreign-key check on a tenant-owned table takes, so it
stalled scan ingest, job starts and sensor registration for the length of the
import, and deadlocked with a scan that had already updated one of the file's
assets. The asset rows themselves are locked up front in id order — the order
the scan ingest takes them in too (``assets._lock_known_assets``). A deadlock
or serialization failure that still happens is retried; past the retries, and
on an identifier a concurrent writer registered first, the apply rolls back
whole and the route answers ``409``.

**The role is the route's business.** ``asset.import`` (tenant ``admin`` and
the platform admin): an import registers assets, which spends the tenant's
asset quota, and writes the context of every asset in the file at once.
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError, OperationalError

from api.db import models
from api.db.engine import get_session
from api.services import audit as audit_service
from api.services import quotas
from api.services.assets import (
    DATA_CLASSIFICATIONS,
    ENVIRONMENTS,
    EXPOSURE_LEVELS,
)
from api.settings import Settings
from scanner.pipeline.asset_identity import fqdn_identity_key, ip_identity_key
from scanner.pipeline.cert_names import is_dns_name

LOG = logging.getLogger("shapoclyack.asset_import")

#: The body ceiling, in UTF-8 bytes of ``content``. A CMDB export of five
#: thousand hosts with a dozen columns is well under a megabyte.
MAX_BYTES = 2 * 1024 * 1024
#: Data rows (the CSV header is not one). One request, one transaction: past
#: this the caller splits the file, which keeps a single import's row locks and
#: its report bounded.
MAX_ROWS = 5000

#: ``context_source`` an import may claim. ``operator`` is deliberately absent:
#: it is what marks a hand edit, and an import that could write it would make
#: its own values unoverwritable by the next import.
IMPORT_SOURCES = ("cmdb", "ad", "other")

#: Row outcomes, in the order the report counts them.
OUTCOMES = ("create", "update", "unchanged", "conflict", "invalid")

KEY_COLUMNS = ("asset_id", "ip", "fqdn")
#: Free-text context and its length ceiling (``business_service`` matches the
#: PATCH schema's 200).
TEXT_FIELDS = {"owner_email": 254, "business_unit": 200, "business_service": 200}
ENUM_FIELDS = {
    "environment": ENVIRONMENTS,
    "data_classification": DATA_CLASSIFICATIONS,
    "exposure_level": EXPOSURE_LEVELS,
}
CONTEXT_COLUMNS = (*TEXT_FIELDS, *ENUM_FIELDS, "asset_criticality")

#: The names CMDB exports actually use, folded onto ours. Applied after the
#: header is lower-cased and its spaces and dashes turned into underscores.
COLUMN_ALIASES = {
    "criticality": "asset_criticality",
    "owner": "owner_email",
    "team": "business_unit",
    "service": "business_service",
    "env": "environment",
    "classification": "data_classification",
    "exposure": "exposure_level",
    "hostname": "fqdn",
    "ip_address": "ip",
}

TAG_PREFIX = "tag:"
_TAG_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")
_TAG_VALUE_MAX = 256
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+$")
#: Leading characters a spreadsheet evaluates instead of displaying — the set
#: ``routes/audit.py`` neutralises on export. Refused on the way *in*: none of
#: these fields has a legitimate value that starts with one, and a value that
#: is stored is a value some later export hands to Excel.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

#: ``IN`` lists are chunked to stay far from Postgres' bind-parameter limit.
_CHUNK = 1000
#: How many asset ids of each kind the audit row lists before it counts.
_AUDIT_ID_LIMIT = 100

#: Advisory-lock class of the per-tenant import lock, ``(class, hash of the
#: tenant)``. Not ``leader_lock.LOCK_CLASS_ID``: its object ids 1–n are
#: session locks a replica holds for its lifetime, and a tenant whose hash
#: landed on one would wait for a rollout. "SHAI" in ASCII.
IMPORT_LOCK_CLASS_ID = 0x53484149
#: Attempts at an apply that Postgres aborted as a deadlock (``40P01``) or a
#: serialization failure (``40001``). Each starts from a fresh plan.
_ATTEMPTS = 3
_RETRYABLE_SQLSTATES = frozenset({"40P01", "40001"})
#: The constraints a concurrent writer of the same identity trips: the scan
#: (or a PATCH-free path) registered the identifier, or created the asset
#: under the id this file would give it. Any other integrity error is a bug,
#: not a race, and a ``409`` would tell the client to retry it forever.
_IDENTITY_CONSTRAINTS = frozenset({"uq_asset_identifier", "assets_pkey"})


class ImportRejected(ValueError):
    """The file as a whole cannot be read — not one row's problem. → 422."""


class ImportTooLarge(ImportRejected):
    """Over :data:`MAX_BYTES` or :data:`MAX_ROWS`. → 413."""


class ImportRace(Exception):
    """The apply lost to a concurrent writer and rolled back whole. → 409.

    Either another writer registered one of the file's identifiers between
    the plan and the commit, or Postgres aborted the transaction as a deadlock
    on every attempt. Sending the same file again re-plans against what is
    there now.
    """


@dataclass
class _Row:
    number: int
    keys: dict[str, str] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)
    source: str | None = None
    errors: list[str] = field(default_factory=list)


@dataclass
class _Plan:
    row: int
    status: str
    key: str
    code: str | None = None
    message: str | None = None
    asset_id: str | None = None
    changes: dict[str, tuple[Any, Any]] = field(default_factory=dict)
    tag_changes: dict[str, tuple[str | None, str]] = field(default_factory=dict)
    identifiers_added: list[tuple[str, str]] = field(default_factory=list)
    conflicting_fields: list[str] = field(default_factory=list)
    source: str = "cmdb"

    def as_dict(self) -> dict[str, Any]:
        changes = {name: {"old": old, "new": new} for name, (old, new) in self.changes.items()}
        for tag_key, (old, new) in self.tag_changes.items():
            changes[f"{TAG_PREFIX}{tag_key}"] = {"old": old, "new": new}
        return {
            "row": self.row,
            "status": self.status,
            "key": self.key,
            "code": self.code,
            "message": self.message,
            "asset_id": self.asset_id,
            "changes": changes,
            "identifiers_added": [f"{kind}:{value}" for kind, value in self.identifiers_added],
            "conflicting_fields": self.conflicting_fields,
        }


def _now() -> datetime:
    """Naive UTC, like every other writer of ``assets`` (see ``assets._now``)."""
    return datetime.now(UTC).replace(tzinfo=None)


def content_digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# --- Reading the file --------------------------------------------------------


def _normalise_column(raw: str) -> str:
    name = (raw or "").strip()
    lowered = name.lower()
    if lowered.startswith(TAG_PREFIX):
        # The tag key keeps its case: ``tag:Owner-Team`` is the key the CMDB
        # used, and the asset detail shows it back as such.
        return TAG_PREFIX + name[len(TAG_PREFIX):].strip()
    lowered = re.sub(r"[\s\-]+", "_", lowered)
    return COLUMN_ALIASES.get(lowered, lowered)


def _known_column(name: str) -> bool:
    return (
        name in KEY_COLUMNS
        or name in CONTEXT_COLUMNS
        or name == "context_source"
        or name.startswith(TAG_PREFIX)
    )


def _sniff_delimiter(header_line: str) -> str:
    """``,`` unless the header says otherwise.

    Excel in a Russian (or German, French…) locale saves "CSV" with ``;``, and
    a header split on the wrong one reads as a single unknown column. The
    header is ours to recognise, so whichever of the three separators it uses
    most is the one.
    """
    counts = {sep: header_line.count(sep) for sep in (",", ";", "\t")}
    best = max(counts, key=lambda sep: counts[sep])
    return best if counts[best] > 0 else ","


def _csv_records(content: str) -> Iterable[dict[str, Any]]:
    header_line = content.split("\n", 1)[0]
    reader = csv.reader(
        io.StringIO(content, newline=""), delimiter=_sniff_delimiter(header_line), strict=True
    )
    try:
        header = next(reader)
    except StopIteration:
        raise ImportRejected("CSV: the file is empty") from None
    except csv.Error as exc:
        raise ImportRejected(f"CSV: {exc}") from exc
    columns = [_normalise_column(name) for name in header]
    seen: set[str] = set()
    for name in columns:
        if not name:
            continue
        if name in seen:
            raise ImportRejected(f"CSV: column {name!r} appears twice")
        seen.add(name)
    count = 0
    try:
        for cells in reader:
            if not any(cell.strip() for cell in cells):
                continue
            count += 1
            if count > MAX_ROWS:
                raise ImportTooLarge(f"more than {MAX_ROWS} rows; split the file")
            if len(cells) > len(columns):
                raise ImportRejected(
                    f"CSV: line {reader.line_num} has {len(cells)} cells for "
                    f"{len(columns)} columns"
                )
            record: dict[str, Any] = {}
            for name, cell in zip(columns, cells):
                if name:
                    record[name] = cell
            yield record
    except csv.Error as exc:
        raise ImportRejected(f"CSV: line {reader.line_num}: {exc}") from exc


def _json_records(content: str) -> list[dict[str, Any]]:
    try:
        document = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ImportRejected(f"JSON: {exc.msg} at line {exc.lineno}") from exc
    if isinstance(document, dict) and isinstance(document.get("assets"), list):
        document = document["assets"]
    if not isinstance(document, list):
        raise ImportRejected('JSON: expected an array of rows, or {"assets": [...]}')
    if len(document) > MAX_ROWS:
        raise ImportTooLarge(f"more than {MAX_ROWS} rows; split the file")
    records: list[dict[str, Any]] = []
    for index, item in enumerate(document, start=1):
        if not isinstance(item, dict):
            raise ImportRejected(f"JSON: row {index} is not an object")
        record: dict[str, Any] = {}
        for raw_name, value in item.items():
            name = _normalise_column(str(raw_name))
            if name == "tags":
                if value is None:
                    continue
                if not isinstance(value, dict):
                    raise ImportRejected(f"JSON: row {index}: tags must be an object")
                for tag_key, tag_value in value.items():
                    record[f"{TAG_PREFIX}{str(tag_key).strip()}"] = tag_value
                continue
            record[name] = value
        records.append(record)
    return records


def parse(content: str, *, format: str) -> tuple[list[_Row], list[str]]:
    """``content`` → validated rows, plus the columns the import ignored.

    Raises :class:`ImportRejected` for a file that cannot be read at all; a
    bad *cell* is that row's ``invalid``, never the file's.
    """
    if len(content.encode("utf-8")) > MAX_BYTES:
        raise ImportTooLarge(f"import exceeds {MAX_BYTES} bytes")
    content = content.removeprefix("﻿")
    if "�" in content:
        # The browser (or the integration) decoded the file with the wrong
        # charset, and every name with a non-ASCII letter in it is already
        # lost. Refused rather than stored as "Ð˜Ð²Ð°Ð½Ð¾Ð²".
        raise ImportRejected(
            "content contains U+FFFD replacement characters: decode the file in its "
            "real encoding (UTF-8 or Windows-1251) before importing"
        )
    if "\x00" in content:
        raise ImportRejected("content contains NUL bytes: this is not a text export")
    if format == "csv":
        records = list(_csv_records(content))
    elif format == "json":
        records = _json_records(content)
    else:
        raise ImportRejected("format must be csv or json")

    ignored: list[str] = []
    rows: list[_Row] = []
    for number, record in enumerate(records, start=1):
        for name in record:
            if not _known_column(name) and name not in ignored:
                ignored.append(name)
        rows.append(_validate(number, record))
    return rows, ignored


def _text(value: Any) -> str | None:
    """A cell as a stripped string, or ``None`` for "nothing to say"."""
    if value is None:
        return None
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (int, float, str)):
        text = str(value).strip()
        return text or None
    raise TypeError("expected a scalar value")


def _validate(number: int, record: dict[str, Any]) -> _Row:
    row = _Row(number=number)
    for name, raw in record.items():
        if not _known_column(name):
            continue
        try:
            value = _text(raw)
        except TypeError:
            row.errors.append(f"{name}: expected a scalar value")
            continue
        if value is None:
            continue
        if _CONTROL_RE.search(value):
            row.errors.append(f"{name}: contains control characters")
            continue
        if name.startswith(TAG_PREFIX):
            _validate_tag(row, name[len(TAG_PREFIX):], value)
        elif name == "ip":
            try:
                row.keys["ip"] = str(ipaddress.ip_address(value))
            except ValueError:
                row.errors.append(f"ip: {value!r} is not an IP address")
        elif name == "fqdn":
            fqdn = value.rstrip(".").lower()
            if is_dns_name(fqdn):
                row.keys["fqdn"] = fqdn
            else:
                row.errors.append(f"fqdn: {value!r} is not a DNS name")
        elif name == "asset_id":
            if len(value) > 64:
                row.errors.append("asset_id: longer than 64 characters")
            else:
                row.keys["asset_id"] = value
        elif name == "context_source":
            if value.lower() not in IMPORT_SOURCES:
                row.errors.append(f"context_source must be one of {', '.join(IMPORT_SOURCES)}")
            else:
                row.source = value.lower()
        elif name == "asset_criticality":
            try:
                as_number = float(value)
            except ValueError:
                as_number = -1.0
            if not as_number.is_integer() or not 0 <= as_number <= 4:
                row.errors.append(f"asset_criticality: {value!r} is not an integer 0-4")
            else:
                row.context["asset_criticality"] = int(as_number)
        elif name in ENUM_FIELDS:
            allowed = ENUM_FIELDS[name]
            if value.lower() not in allowed:
                row.errors.append(f"{name} must be one of {', '.join(allowed)}")
            else:
                row.context[name] = value.lower()
        elif name in TEXT_FIELDS:
            if value.startswith(_FORMULA_PREFIXES):
                row.errors.append(f"{name}: a value starting with {value[0]!r} is a spreadsheet formula")
            elif len(value) > TEXT_FIELDS[name]:
                row.errors.append(f"{name}: longer than {TEXT_FIELDS[name]} characters")
            elif name == "owner_email" and not _EMAIL_RE.match(value):
                row.errors.append(f"owner_email: {value!r} is not an email address")
            else:
                row.context[name] = value
    if not row.keys and not row.errors:
        row.errors.append("no identity key: the row needs asset_id, ip or fqdn")
    return row


def _validate_tag(row: _Row, tag_key: str, value: str) -> None:
    if not _TAG_KEY_RE.match(tag_key):
        row.errors.append(f"tag {tag_key!r}: keys are 1-64 letters, digits, '.', '_' or '-'")
    elif value.startswith(_FORMULA_PREFIXES):
        row.errors.append(f"tag:{tag_key}: a value starting with {value[0]!r} is a spreadsheet formula")
    elif len(value) > _TAG_VALUE_MAX:
        row.errors.append(f"tag:{tag_key}: longer than {_TAG_VALUE_MAX} characters")
    else:
        row.tags[tag_key] = value


# --- Planning ----------------------------------------------------------------


def _chunks(values: list[str]) -> Iterable[list[str]]:
    for start in range(0, len(values), _CHUNK):
        yield values[start:start + _CHUNK]


def _identifier_owners(session, tenant_id: str, rows: list[_Row]) -> dict[tuple[str, str], str]:
    owners: dict[tuple[str, str], str] = {}
    for kind in ("ip", "fqdn"):
        values = sorted({row.keys[kind] for row in rows if kind in row.keys})
        for chunk in _chunks(values):
            for value, asset_id in session.execute(
                select(models.AssetIdentifier.identifier_value, models.AssetIdentifier.asset_id).where(
                    models.AssetIdentifier.tenant_id == tenant_id,
                    models.AssetIdentifier.identifier_type == kind,
                    models.AssetIdentifier.identifier_value.in_(chunk),
                )
            ):
                owners[(kind, value)] = asset_id
    return owners


def _load_assets(
    session, tenant_id: str, asset_ids: set[str], *, lock: bool
) -> dict[str, models.Asset]:
    found: dict[str, models.Asset] = {}
    for chunk in _chunks(sorted(asset_ids)):
        query = select(models.Asset).where(
            models.Asset.tenant_id == tenant_id, models.Asset.asset_id.in_(chunk)
        )
        if lock:
            # Id order, the order the scan ingest locks in as well: two writers
            # that queue on the same rows in one order cannot deadlock.
            query = query.order_by(models.Asset.asset_id).with_for_update()
        for asset in session.execute(query).scalars():
            found[asset.asset_id] = asset
    return found


def _load_tags(session, asset_ids: list[str]) -> dict[str, dict[str, models.AssetTag]]:
    tags: dict[str, dict[str, models.AssetTag]] = {}
    for chunk in _chunks(asset_ids):
        for tag in session.execute(
            select(models.AssetTag).where(models.AssetTag.asset_id.in_(chunk))
        ).scalars():
            tags.setdefault(tag.asset_id, {})[tag.key] = tag
    return tags


def _last_sources(session, tenant_id: str, asset_ids: list[str]) -> dict[tuple[str, str], str | None]:
    """``(asset_id, field) -> source`` of the newest context event of each field."""
    out: dict[tuple[str, str], str | None] = {}
    for chunk in _chunks(asset_ids):
        newest = (
            select(func.max(models.AssetContextEvent.id))
            .where(
                models.AssetContextEvent.tenant_id == tenant_id,
                models.AssetContextEvent.asset_id.in_(chunk),
            )
            .group_by(models.AssetContextEvent.asset_id, models.AssetContextEvent.field)
        )
        for asset_id, field_name, source in session.execute(
            select(
                models.AssetContextEvent.asset_id,
                models.AssetContextEvent.field,
                models.AssetContextEvent.source,
            ).where(models.AssetContextEvent.id.in_(newest))
        ):
            out[(asset_id, field_name)] = source
    return out


def _operator_owned(
    asset: models.Asset, field_name: str, last_sources: dict[tuple[str, str], str | None]
) -> bool:
    """Whether the current value of ``field_name`` is an operator's hand edit.

    Decided per field: the newest event of *that* field. A value with no event
    behind it — set before #146 audited context, or carried over by an identity
    merge — has no provenance and is treated as the operator's: an import that
    cannot tell whose a value is must not be the one that decides it was
    nobody's. Every import write records an event, so a value an import wrote
    is never in that position.

    The asset's own ``context_source`` is deliberately not consulted. It is one
    column for the whole asset and an import rewrites it whenever it changes
    *any* field, so reading it here let an import that only filled an empty
    owner unprotect the hand-set team next to it for the import after.
    """
    key = (asset.asset_id, field_name)
    if key in last_sources:
        return last_sources[key] == "operator"
    return getattr(asset, field_name) not in (None, "")


def _identity_key(tenant_id: str, ident: tuple[str, str]) -> str:
    kind, value = ident
    return ip_identity_key(tenant_id, value) if kind == "ip" else fqdn_identity_key(tenant_id, value)


def _describe(row: _Row) -> str:
    return " / ".join(row.keys[name] for name in KEY_COLUMNS if name in row.keys)


def plan(
    session,
    settings: Settings,
    *,
    tenant_id: str,
    rows: list[_Row],
    context_source: str,
    overwrite_operator_edits: bool,
    link_new_identifiers: bool = False,
    lock: bool = False,
) -> tuple[list[_Plan], dict[str, models.Asset], dict[str, dict[str, models.AssetTag]]]:
    """Decide every row's outcome from reads only. Nothing is added to ``session``."""
    owners = _identifier_owners(session, tenant_id, rows)
    wanted: set[str] = set(owners.values())
    for row in rows:
        if "asset_id" in row.keys:
            wanted.add(row.keys["asset_id"])
        if "ip" in row.keys:
            wanted.add(ip_identity_key(tenant_id, row.keys["ip"]))
        elif "fqdn" in row.keys:
            wanted.add(fqdn_identity_key(tenant_id, row.keys["fqdn"]))
    assets = _load_assets(session, tenant_id, wanted, lock=lock)
    existing_ids = sorted(assets)
    tags = _load_tags(session, existing_ids)
    last_sources = _last_sources(session, tenant_id, existing_ids)
    capacity = quotas.asset_capacity_in_session(session, settings, tenant_id)

    plans: list[_Plan] = []
    #: Identifiers and assets an earlier row of this file already spoke for.
    claimed_identifiers: dict[tuple[str, str], int] = {}
    claimed_assets: dict[str, int] = {}
    created = 0

    for row in rows:
        source = row.source or context_source
        entry = _Plan(row=row.number, status="invalid", key=_describe(row), source=source)
        plans.append(entry)
        if row.errors:
            entry.code = "invalid_value"
            entry.message = "; ".join(row.errors)
            continue

        identifiers = [(kind, row.keys[kind]) for kind in ("ip", "fqdn") if kind in row.keys]
        earlier = next(
            (claimed_identifiers[ident] for ident in identifiers if ident in claimed_identifiers),
            None,
        )
        named = row.keys.get("asset_id")
        if named is not None and named not in assets:
            entry.code = "unknown_asset"
            entry.message = f"no asset {named!r} in this tenant"
            continue

        matched = {owners[ident] for ident in identifiers if ident in owners}
        if named is not None:
            others = matched - {named}
            if others:
                entry.status = "conflict"
                entry.code = "identifier_owned_by_other_asset"
                entry.message = (
                    f"{_describe(row)} belongs to asset {sorted(others)[0]}, not {named}"
                )
                continue
            matched = {named}
        if len(matched) > 1:
            entry.status = "conflict"
            entry.code = "ambiguous_match"
            entry.message = (
                "the row's identifiers belong to different assets: "
                + ", ".join(sorted(matched))
                + " (an import never merges assets)"
            )
            continue

        if not matched:
            # No identifier is registered — but an asset may still carry the
            # id a scan would have given it, its identifier lost to a merge.
            # Updating that row is the honest reading; a second asset under
            # the same id is not possible anyway.
            primary = (
                ip_identity_key(tenant_id, row.keys["ip"])
                if "ip" in row.keys
                else fqdn_identity_key(tenant_id, row.keys["fqdn"])
            )
            if primary in assets:
                matched = {primary}

        target = next(iter(matched), None)
        if earlier is not None or (target is not None and target in claimed_assets):
            entry.status = "conflict"
            entry.code = "duplicate_in_file"
            entry.message = f"row {earlier if earlier is not None else claimed_assets[target]} already names this asset"
            continue

        # Claimed before the outcome is decided: a conflicting row still names
        # its asset, and a second row for it is a duplicate either way.
        for ident in identifiers:
            claimed_identifiers[ident] = row.number
        if target is not None:
            claimed_assets[target] = row.number

        if target is None:
            if capacity is not None and created >= capacity:
                entry.status = "conflict"
                entry.code = "quota_exhausted"
                entry.message = "the tenant's asset quota is reached; the asset was not registered"
                continue
            created += 1
            new_id = (
                ip_identity_key(tenant_id, row.keys["ip"])
                if "ip" in row.keys
                else fqdn_identity_key(tenant_id, row.keys["fqdn"])
            )
            entry.status = "create"
            entry.asset_id = new_id
            entry.changes = {name: (None, value) for name, value in row.context.items()}
            entry.tag_changes = {key: (None, value) for key, value in row.tags.items()}
            entry.identifiers_added = identifiers
        else:
            asset = assets[target]
            entry.asset_id = target
            entry.identifiers_added = [ident for ident in identifiers if ident not in owners]
            # An identifier whose identity key *is* this asset's id is the one
            # the asset was registered under, its row lost to a merge: putting
            # it back links nothing new.
            linked = [
                ident
                for ident in entry.identifiers_added
                if _identity_key(tenant_id, ident) != target
            ]
            if linked and not link_new_identifiers:
                entry.status = "conflict"
                entry.code = "new_identifier"
                entry.conflicting_fields = [f"{kind}:{value}" for kind, value in linked]
                entry.message = (
                    f"{', '.join(entry.conflicting_fields)} is not registered; linking it to "
                    f"asset {target} on the file's word needs link_new_identifiers"
                )
                entry.identifiers_added = []
                continue
            for name, value in row.context.items():
                old = getattr(asset, name)
                if old != value:
                    entry.changes[name] = (old, value)
            current_tags = tags.get(target, {})
            for key, value in row.tags.items():
                old_tag = current_tags.get(key)
                if old_tag is None or old_tag.value != value:
                    entry.tag_changes[key] = (old_tag.value if old_tag else None, value)
            protected = [
                name
                for name in entry.changes
                if _operator_owned(asset, name, last_sources)
            ]
            if protected and not overwrite_operator_edits:
                entry.status = "conflict"
                entry.code = "operator_override"
                entry.conflicting_fields = protected
                entry.message = (
                    "an operator set "
                    + ", ".join(protected)
                    + " by hand; pass overwrite_operator_edits to replace it"
                )
                entry.changes = {name: entry.changes[name] for name in protected}
                entry.tag_changes = {}
                entry.identifiers_added = []
                continue
            if entry.changes or entry.tag_changes or entry.identifiers_added:
                entry.status = "update"
            else:
                entry.status = "unchanged"
    return plans, assets, tags


# --- Applying ----------------------------------------------------------------


def _stringify(value: Any) -> str | None:
    return None if value is None else str(value)


def _event(
    session,
    *,
    asset_id: str,
    tenant_id: str,
    now: datetime,
    name: str,
    old: Any,
    new: Any,
    actor: str,
    source: str,
) -> None:
    session.add(
        models.AssetContextEvent(
            asset_id=asset_id,
            tenant_id=tenant_id,
            occurred_at=now,
            field=name,
            old_value=_stringify(old),
            new_value=_stringify(new),
            actor=actor,
            source=source,
        )
    )


def _apply(
    session,
    *,
    tenant_id: str,
    plans: list[_Plan],
    assets: dict[str, models.Asset],
    tags: dict[str, dict[str, models.AssetTag]],
    actor: str,
) -> None:
    """Write the ``create`` and ``update`` rows of a plan into ``session``.

    Every field change gets its ``asset_context_events`` row, tags included
    (``field = "tag:<key>"``), with the import's ``context_source`` as the
    event's source — which is what lets the next import tell a CMDB value from
    a hand edit.
    """
    now = _now()
    applied = [entry for entry in plans if entry.status in ("create", "update")]
    created: dict[str, models.Asset] = {}
    for entry in applied:
        if entry.status != "create":
            continue
        assert entry.asset_id is not None
        created[entry.asset_id] = models.Asset(
            asset_id=entry.asset_id,
            tenant_id=tenant_id,
            # Registered, not observed: ``last_seen`` starts at the import
            # (the column is not nullable, and the staleness rule ages it like
            # any other), while the three coverage columns stay NULL — the
            # asset reads as "never scanned", which is what a CMDB record the
            # scanner has not reached yet is.
            status="active",
            first_seen=now,
            last_seen=now,
        )
    session.add_all(created.values())
    # Once, for every new asset: the identifiers, tags and events below
    # reference them, and a flush per row was a round trip per row.
    session.flush()
    for entry in applied:
        asset_id = entry.asset_id
        assert asset_id is not None
        asset = created.get(asset_id) or assets[asset_id]
        for name, (old, new) in entry.changes.items():
            setattr(asset, name, new)
            _event(
                session, asset_id=asset_id, tenant_id=tenant_id, now=now, name=name,
                old=old, new=new, actor=actor, source=entry.source,
            )
        if entry.changes:
            asset.context_source = entry.source
        current = tags.get(asset_id, {})
        for key, (old, new) in entry.tag_changes.items():
            existing = current.get(key)
            if existing is None:
                session.add(models.AssetTag(asset_id=asset_id, key=key, value=new))
            else:
                existing.value = new
            _event(
                session, asset_id=asset_id, tenant_id=tenant_id, now=now,
                name=f"{TAG_PREFIX}{key}", old=old, new=new, actor=actor, source=entry.source,
            )
        for kind, value in entry.identifiers_added:
            session.add(
                models.AssetIdentifier(
                    asset_id=asset_id,
                    tenant_id=tenant_id,
                    identifier_type=kind,
                    identifier_value=value,
                )
            )


def _audit_document(report: dict[str, Any], plans: list[_Plan]) -> dict[str, Any]:
    """One row per import, naming the assets it touched — bounded.

    Five thousand ids would push the document past the audit trail's 16 KiB
    cap and turn it into ``{"truncated": true}``; the first hundred of each
    kind and a count say what happened, and the per-field history is in
    ``asset_context_events`` as usual.
    """
    document: dict[str, Any] = {
        "format": report["format"],
        "sha256": report["sha256"],
        "context_source": report["context_source"],
        "overwrite_operator_edits": report["overwrite_operator_edits"],
        "link_new_identifiers": report["link_new_identifiers"],
        "counts": report["counts"],
    }
    for status, label in (("create", "created"), ("update", "updated")):
        ids = [entry.asset_id for entry in plans if entry.status == status and entry.asset_id]
        document[label] = ids[:_AUDIT_ID_LIMIT]
        if len(ids) > _AUDIT_ID_LIMIT:
            document[f"{label}_omitted"] = len(ids) - _AUDIT_ID_LIMIT
    return document


def changed_nothing(report: dict[str, Any]) -> bool:
    return not (report["counts"]["create"] or report["counts"]["update"])


def _lock_tenant_imports(session, settings: Settings, tenant_id: str) -> None:
    """Hold this tenant's import lock until the transaction ends.

    Advisory, so it fences other imports of the tenant and nothing else — the
    row lock on ``tenants`` it replaces also fenced every foreign-key check
    against the tenant. Released at commit or rollback, including by a backend
    that died. SQLite (dev and the test fallback) has no advisory locks and one
    writer at a time anyway.
    """
    if not settings.postgres_url.startswith("postgres"):
        return
    digest = hashlib.blake2b(tenant_id.encode("utf-8"), digest_size=4).digest()
    session.execute(
        text("SELECT pg_advisory_xact_lock(:class_id, :object_id)"),
        {"class_id": IMPORT_LOCK_CLASS_ID, "object_id": int.from_bytes(digest, "big", signed=True)},
    )


def _sqlstate(exc: OperationalError) -> str | None:
    return getattr(exc.orig, "sqlstate", None)


def _constraint(exc: IntegrityError) -> str | None:
    return getattr(getattr(exc.orig, "diag", None), "constraint_name", None)


def run_import(
    settings: Settings,
    *,
    tenant_id: str,
    content: str,
    format: str,
    dry_run: bool,
    context_source: str,
    overwrite_operator_edits: bool,
    actor: str,
    link_new_identifiers: bool = False,
    audit: audit_service.AuditContext | None = None,
) -> dict[str, Any]:
    """Plan the import and, unless ``dry_run``, apply it in one transaction.

    The report lists every data row with its outcome; ``counts`` sums them. A
    ``dry_run`` is a read-only pass — nothing is added to the session, so
    nothing can commit, and it takes no locks. An apply takes the tenant's
    import lock first, so two imports into one tenant run one after the other
    rather than both planning against a registry the other is about to change.
    """
    if context_source not in IMPORT_SOURCES:
        raise ValueError(f"context_source must be one of {', '.join(IMPORT_SOURCES)}")
    rows, ignored = parse(content, format=format)
    options = {
        "context_source": context_source,
        "overwrite_operator_edits": overwrite_operator_edits,
        "link_new_identifiers": link_new_identifiers,
    }
    for attempt in range(1, _ATTEMPTS + 1):
        try:
            with get_session(settings.postgres_url) as session:
                if not dry_run:
                    _lock_tenant_imports(session, settings, tenant_id)
                plans, assets, tags = plan(
                    session, settings, tenant_id=tenant_id, rows=rows, lock=not dry_run, **options
                )
                report = _report(
                    plans, ignored=ignored, content=content, format=format, dry_run=dry_run, **options
                )
                if not dry_run:
                    _apply(
                        session, tenant_id=tenant_id, plans=plans, assets=assets, tags=tags,
                        actor=actor,
                    )
                    audit_service.record(
                        session,
                        audit,
                        action=audit_service.ACTION_ASSET_IMPORT,
                        resource_type="asset",
                        resource_id=f"import:{report['sha256'][:16]}",
                        tenant_id=tenant_id,
                        after=_audit_document(report, plans),
                    )
                    session.flush()
            break
        except OperationalError as exc:
            if _sqlstate(exc) not in _RETRYABLE_SQLSTATES:
                raise
            # The other side of the cycle is a scan or a PATCH; the ingest
            # locks in the import's order, so this is rare, and a fresh plan
            # is the whole remedy.
            LOG.info(
                "asset import for tenant %s aborted by Postgres (%s), attempt %d of %d",
                tenant_id, _sqlstate(exc), attempt, _ATTEMPTS,
            )
            if attempt == _ATTEMPTS:
                raise ImportRace(
                    "the import kept colliding with concurrent writes to these assets; "
                    "nothing was applied, send the file again"
                ) from exc
        except IntegrityError as exc:
            if _constraint(exc) not in _IDENTITY_CONSTRAINTS:
                raise
            # A scan registered one of the file's identifiers (or the asset
            # under the id this file gives it) between the plan and the commit.
            # The whole import rolled back with it; nothing half-applied is
            # left to reconcile.
            LOG.info("asset import for tenant %s lost a race: %s", tenant_id, exc.orig)
            raise ImportRace(
                "another writer registered one of these identifiers while the import ran; "
                "nothing was applied, send the file again"
            ) from exc
    if not dry_run:
        quotas.record_asset_refusal(tenant_id, report["codes"].get("quota_exhausted", 0))
    return report


def _report(
    plans: list[_Plan],
    *,
    ignored: list[str],
    content: str,
    format: str,
    dry_run: bool,
    context_source: str,
    overwrite_operator_edits: bool,
    link_new_identifiers: bool,
) -> dict[str, Any]:
    counts = {outcome: 0 for outcome in OUTCOMES}
    codes: dict[str, int] = {}
    for entry in plans:
        counts[entry.status] += 1
        if entry.code:
            codes[entry.code] = codes.get(entry.code, 0) + 1
    return {
        "dry_run": dry_run,
        "format": format,
        "sha256": content_digest(content),
        "context_source": context_source,
        "overwrite_operator_edits": overwrite_operator_edits,
        "link_new_identifiers": link_new_identifiers,
        "total": len(plans),
        "counts": counts,
        "codes": codes,
        "ignored_columns": ignored,
        "rows": [entry.as_dict() for entry in plans],
        "replayed": False,
    }

