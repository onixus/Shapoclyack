"""Bounded, transactional tenant classification; context never grants scan authority."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import and_, delete, func, select, text

from api.db import models
from api.db.engine import get_session
from api.services import asset_group_rules as engine
from api.services import assets

MAX_GROUPS = 100
MAX_BATCH = 500
MAX_OS_ENDPOINTS = 16


def _now():
    return datetime.now(UTC).replace(tzinfo=None)


def _lock_tenant(session, tenant_id):
    tenant = session.scalar(
        select(models.Tenant)
        .where(models.Tenant.tenant_id == tenant_id)
        .with_for_update(read=True)
        .execution_options(populate_existing=True)
    )
    if tenant is None or tenant.status != "active":
        raise LookupError("Tenant not found")
    if session.bind.dialect.name == "postgresql":
        # Independent of Tenant FK key-share locks held by inventory imports.
        session.execute(
            text("SELECT pg_advisory_xact_lock(578, hashtext(:tenant))"),
            {"tenant": tenant_id},
        )


def _group(session, tenant_id, group_id, *, deleted=False):
    row = session.execute(
        select(models.AssetGroup)
        .where(
            models.AssetGroup.tenant_id == tenant_id, models.AssetGroup.id == group_id
        )
        .with_for_update()
    ).scalar_one_or_none()
    if row is None or (row.deleted and not deleted):
        raise LookupError("Asset group not found")
    return row


def _document(row):
    return {
        key: getattr(row, key)
        for key in (
            "id",
            "name",
            "description",
            "enabled",
            "priority",
            "version",
            "rules",
            "context",
            "created_at",
            "updated_at",
        )
    }


def _revision(session, row, actor):
    doc = _document(row)
    doc.pop("created_at")
    doc.pop("updated_at")
    session.add(
        models.AssetGroupVersion(
            tenant_id=row.tenant_id,
            group_id=row.id,
            version=row.version,
            document=doc,
            actor=actor,
            created_at=_now(),
        )
    )


def _validate(data):
    allowed = {"name", "description", "enabled", "priority", "rules", "context"}
    if set(data) - allowed:
        raise ValueError("Unknown group fields")
    if "name" in data and (
        not isinstance(data["name"], str)
        or not data["name"].strip()
        or len(data["name"]) > 160
    ):
        raise ValueError("name must contain 1-160 characters")
    if "description" in data and (
        not isinstance(data["description"], str) or len(data["description"]) > 2000
    ):
        raise ValueError("description must contain at most 2000 characters")
    if "priority" in data and (
        type(data["priority"]) is not int or not 0 <= data["priority"] <= 10000
    ):
        raise ValueError("priority must be an integer 0-10000")
    if "enabled" in data and type(data["enabled"]) is not bool:
        raise ValueError("enabled must be boolean")
    out = dict(data)
    if "rules" in out:
        out["rules"] = engine.validate_rules(out["rules"])
    if "context" in out:
        out["context"] = engine.validate_context(out["context"])
    return out


def save_group(settings, tenant_id, data, *, group_id=None, actor=None):
    data = _validate(data)
    with get_session(settings.postgres_url) as session:
        # Same tenant lock serializes rule edits, sweeps and manual recalculations.
        _lock_tenant(session, tenant_id)
        if group_id:
            row = _group(session, tenant_id, group_id)
            row.version += 1
            for key, value in data.items():
                setattr(row, key, value)
            row.updated_at = _now()
        else:
            if "name" not in data or "rules" not in data:
                raise ValueError("name and rules are required")
            count = session.scalar(
                select(func.count())
                .select_from(models.AssetGroup)
                .where(
                    models.AssetGroup.tenant_id == tenant_id,
                    models.AssetGroup.deleted.is_(False),
                )
            )
            if count >= MAX_GROUPS:
                raise ValueError("Tenant group limit reached (100)")
            row = models.AssetGroup(
                id=uuid4().hex,
                tenant_id=tenant_id,
                created_at=_now(),
                updated_at=_now(),
                **data,
            )
            session.add(row)
            session.flush()
        _revision(session, row, actor)
        return _document(row)


def delete_group(settings, tenant_id, group_id, *, actor=None):
    with get_session(settings.postgres_url) as session:
        _lock_tenant(session, tenant_id)
        row = _group(session, tenant_id, group_id)
        row.enabled = False
        row.deleted = True
        row.version += 1
        row.updated_at = _now()
        _revision(session, row, actor)


def list_groups(settings, tenant_id, *, offset=0, limit=50, q=None):
    with get_session(settings.postgres_url) as session:
        query = select(models.AssetGroup).where(
            models.AssetGroup.tenant_id == tenant_id,
            models.AssetGroup.deleted.is_(False),
        )
        if q:
            query = query.where(models.AssetGroup.name.ilike(f"%{q[:200]}%"))
        total = session.scalar(select(func.count()).select_from(query.subquery()))
        rows = session.scalars(
            query.order_by(models.AssetGroup.priority.desc(), models.AssetGroup.id)
            .offset(offset)
            .limit(limit)
        ).all()
        ids = [row.id for row in rows]
        counts = (
            dict(
                session.execute(
                    select(models.AssetGroupMembership.group_id, func.count())
                    .where(
                        models.AssetGroupMembership.tenant_id == tenant_id,
                        models.AssetGroupMembership.group_id.in_(ids),
                    )
                    .group_by(models.AssetGroupMembership.group_id)
                ).all()
            )
            if ids
            else {}
        )
        latest_by_group = {}
        if ids:
            query = (
                select(models.AssetGroupEvaluation)
                .where(
                    models.AssetGroupEvaluation.tenant_id == tenant_id,
                    models.AssetGroupEvaluation.group_id.in_(ids),
                )
                .distinct(models.AssetGroupEvaluation.group_id)
                .order_by(
                    models.AssetGroupEvaluation.group_id,
                    models.AssetGroupEvaluation.started_at.desc(),
                    models.AssetGroupEvaluation.id,
                )
            )
            for evaluation in session.scalars(query):
                latest_by_group.setdefault(evaluation.group_id, evaluation)
        success_by_group = (
            dict(
                session.execute(
                    select(
                        models.AssetGroupEvaluation.group_id,
                        func.max(models.AssetGroupEvaluation.completed_at),
                    )
                    .where(
                        models.AssetGroupEvaluation.tenant_id == tenant_id,
                        models.AssetGroupEvaluation.group_id.in_(ids),
                        models.AssetGroupEvaluation.status == "completed",
                    )
                    .group_by(models.AssetGroupEvaluation.group_id)
                ).all()
            )
            if ids
            else {}
        )
        items = []
        for row in rows:
            doc = _document(row)
            doc["member_count"] = counts.get(row.id, 0)
            latest = latest_by_group.get(row.id)
            doc["latest_evaluation"] = _evaluation(latest) if latest else None
            doc["last_success_at"] = success_by_group.get(row.id)
            items.append(doc)
        return items, total


def get_group(settings, tenant_id, group_id):
    with get_session(settings.postgres_url) as session:
        return _document(_group(session, tenant_id, group_id))


def revoke_managed_fields(session, tenant_id, asset_id, fields):
    """Explicit writes, even same-value/null, permanently reclaim field ownership."""
    if fields:
        session.execute(
            delete(models.AssetGroupProvenance).where(
                models.AssetGroupProvenance.tenant_id == tenant_id,
                models.AssetGroupProvenance.asset_id == asset_id,
                models.AssetGroupProvenance.field.in_(list(fields)),
            )
        )


def _snapshot(session, tenant_id, asset):
    snapshot = {field: getattr(asset, field) for field in assets.CONTEXT_FIELDS}
    snapshot["status"] = asset.status
    for kind in ("ip", "fqdn"):
        snapshot[kind] = list(
            session.scalars(
                select(models.AssetIdentifier.identifier_value).where(
                    models.AssetIdentifier.tenant_id == tenant_id,
                    models.AssetIdentifier.asset_id == asset.asset_id,
                    models.AssetIdentifier.identifier_type == kind,
                )
            )
        )
    snapshot["tags"] = dict(
        session.execute(
            select(models.AssetTag.key, models.AssetTag.value)
            .join(models.Asset, models.Asset.asset_id == models.AssetTag.asset_id)
            .where(
                models.Asset.tenant_id == tenant_id,
                models.AssetTag.asset_id == asset.asset_id,
            )
        ).all()
    )
    return snapshot


def _plan(session, tenant_id, asset, groups, *, snapshot, managed, latest_events):
    # Predicates see external context, never a previous rule's output. This
    # makes retries stable and prevents feedback/oscillation between rules.
    for field, provenance in managed.items():
        if snapshot[field] == provenance.value.get("value"):
            snapshot[field] = provenance.previous.get("value")
    matches = {}
    evaluations = {}
    candidates = {}
    for group in groups:
        if not group["enabled"]:
            continue
        result = engine.evaluate_rules(group["rules"], snapshot)
        evaluations[group["id"]] = result["reasons"]
        if result["matched"]:
            matches[group["id"]] = result["reasons"]
            for field, value in group["context"].items():
                candidates.setdefault(field, []).append((group, value))
    changes, conflicts, winners = {}, [], {}
    for field, proposals in candidates.items():
        top = max(group["priority"] for group, _ in proposals)
        leaders = [
            (group, value) for group, value in proposals if group["priority"] == top
        ]
        if any(value != leaders[0][1] for _, value in leaders):
            conflicts.append(
                {
                    "field": field,
                    "group_ids": sorted(group["id"] for group, _ in leaders),
                    "reason": "equal_priority",
                }
            )
            continue
        group, value = min(leaders, key=lambda pair: pair[0]["id"])
        winners[field] = (group, value)
    for field in set(managed) | set(winners):
        old = getattr(asset, field)
        provenance = managed.get(field)
        owned = provenance is not None and old == provenance.value.get("value")
        if field in winners:
            group, value = winners[field]
            # Latest explicit context event protects even an explicit null.
            event = latest_events.get(field)
            protected = not owned and (
                old is not None or (event is not None and event.source != "group_rule")
            )
            if protected:
                conflicts.append(
                    {
                        "field": field,
                        "group_ids": [group["id"]],
                        "reason": "protected_source",
                    }
                )
                continue
            if old != value or (
                owned
                and (
                    provenance.group_id != group["id"]
                    or provenance.version != group["version"]
                )
            ):
                changes[field] = {
                    "old": old,
                    "new": value,
                    "group_id": group["id"],
                    "version": group["version"],
                    "source": "group_rule",
                    "reason": matches[group["id"]],
                }
        elif owned and not any(
            conflict["field"] == field and conflict["reason"] == "equal_priority"
            for conflict in conflicts
        ):
            changes[field] = {
                "old": old,
                "new": provenance.previous.get("value"),
                "group_id": provenance.group_id,
                "release": True,
                "version": provenance.version,
                "source": "group_rule",
                "reason": provenance.reason,
            }
    return matches, changes, conflicts, winners, managed, evaluations


def _evaluation(row):
    return {
        key: getattr(row, key)
        for key in (
            "id",
            "group_id",
            "version",
            "status",
            "started_at",
            "completed_at",
            "report",
            "error",
        )
    }


def _endpoint_os_snapshot(observations, *, now, freshness_hours):
    """Only explicit, fresh, reconciled endpoint facts confirm an OS family.

    Network ``asset_os`` rows are scanner guesses and never enter this path.
    All endpoint rows linked to an asset must agree: absence or ambiguity is
    unknown, including for negative conditions.
    """
    now = now.replace(tzinfo=UTC) if now.tzinfo is None else now.astimezone(UTC)
    cutoff = now - timedelta(hours=freshness_hours)
    future = now + timedelta(minutes=5)
    evidence = {
        "source": "endpoint_inventory",
        "state": "missing",
        "freshness_hours": freshness_hours,
        "observations": [],
    }
    states, families = set(), set()
    incomplete = len(observations) > MAX_OS_ENDPOINTS
    for observation in observations[:MAX_OS_ENDPOINTS]:
        device, snapshot = observation
        family = (device.os_family or "").strip().casefold()
        if family == "darwin":
            family = "macos"
        detail = {
            "device_id": device.device_id,
            "snapshot_id": snapshot.snapshot_id if snapshot is not None else None,
            "reconciliation_status": device.reconciliation_status,
            "family": family or None,
        }
        state = "confirmed"
        if device.reconciliation_status != "linked":
            state = "conflict"
        elif snapshot is None:
            state = "missing"
        elif family not in {"windows", "linux", "macos"}:
            state = "unknown"
        if snapshot is not None:
            for key in ("collected_at", "received_at"):
                value = getattr(snapshot, key)
                value = (
                    value.replace(tzinfo=UTC)
                    if value.tzinfo is None
                    else value.astimezone(UTC)
                )
                detail[key] = value.isoformat()
                if state == "confirmed" and (value < cutoff or value > future):
                    state = "stale"
        detail["state"] = state
        evidence["observations"].append(detail)
        states.add(state)
        if state == "confirmed":
            families.add(family)
    if observations:
        if "conflict" in states or len(families) > 1:
            evidence["state"] = "conflict"
        elif "stale" in states:
            evidence["state"] = "stale"
        elif "missing" in states:
            evidence["state"] = "missing"
        elif "unknown" in states:
            evidence["state"] = "unknown"
        else:
            evidence["state"] = "confirmed"
    if incomplete:
        evidence["state"] = "incomplete"
        evidence["observations_truncated"] = True
        evidence["endpoint_count_lower_bound"] = MAX_OS_ENDPOINTS + 1
    return {
        "os_family": next(iter(families)) if evidence["state"] == "confirmed" else None,
        "_os_evidence": evidence,
    }


def _batch(
    session,
    tenant_id,
    *,
    group_id=None,
    draft=None,
    after_asset_id=None,
    limit=200,
    apply=False,
    actor=None,
    endpoint_stale_hours=48,
):
    if not 1 <= limit <= MAX_BATCH:
        raise ValueError("limit must be 1-500")
    groups = [
        _document(row)
        for row in session.scalars(
            select(models.AssetGroup)
            .where(
                models.AssetGroup.tenant_id == tenant_id,
                models.AssetGroup.deleted.is_(False),
            )
            .order_by(models.AssetGroup.id)
        )
    ]
    if group_id:
        selected = _group(session, tenant_id, group_id)
    else:
        selected = None
    if draft is not None:
        normalized = _validate(draft)
        synthetic = {
            "id": group_id or "preview",
            "name": "Preview",
            "description": "",
            "enabled": True,
            "priority": 0,
            "version": 1,
            "context": {},
            **(_document(selected) if selected else {}),
            **normalized,
        }
        if "rules" not in synthetic:
            raise ValueError("rules are required")
        groups = [group for group in groups if group["id"] != synthetic["id"]] + [
            synthetic
        ]
        group_id = synthetic["id"]
    query = select(models.Asset).where(models.Asset.tenant_id == tenant_id)
    if after_asset_id:
        query = query.where(models.Asset.asset_id > after_asset_id)
    if apply:
        query = query.with_for_update()
    rows = list(session.scalars(query.order_by(models.Asset.asset_id).limit(limit + 1)))
    has_more = len(rows) > limit
    rows = rows[:limit]
    report = {
        "items": [],
        "evaluated": len(rows),
        "matched": 0,
        "entrants": 0,
        "exits": 0,
        "changed": 0,
        "conflicts": 0,
        "has_more": has_more,
        "next_asset_id": rows[-1].asset_id if has_more else None,
    }
    now = _now()
    ids = [asset.asset_id for asset in rows]
    snapshots = {
        asset.asset_id: {
            **{field: getattr(asset, field) for field in assets.CONTEXT_FIELDS},
            "status": asset.status,
            "ip": [],
            "fqdn": [],
            "tags": {},
        }
        for asset in rows
    }
    os_observations = {aid: [] for aid in ids}
    if ids:
        ranked_devices = (
            select(
                models.EndpointDevice.device_id,
                func.row_number()
                .over(
                    partition_by=models.EndpointDevice.asset_id,
                    order_by=models.EndpointDevice.device_id,
                )
                .label("position"),
            )
            .where(
                models.EndpointDevice.tenant_id == tenant_id,
                models.EndpointDevice.asset_id.in_(ids),
            )
            .subquery()
        )
        bounded_device_ids = select(ranked_devices.c.device_id).where(
            ranked_devices.c.position <= MAX_OS_ENDPOINTS + 1
        )
        endpoint_query = (
            select(models.EndpointDevice, models.EndpointInventorySnapshot)
            .outerjoin(
                models.EndpointInventorySnapshot,
                and_(
                    models.EndpointInventorySnapshot.snapshot_id
                    == models.EndpointDevice.latest_snapshot_id,
                    models.EndpointInventorySnapshot.device_id
                    == models.EndpointDevice.device_id,
                    models.EndpointInventorySnapshot.tenant_id == tenant_id,
                ),
            )
            .where(
                models.EndpointDevice.tenant_id == tenant_id,
                models.EndpointDevice.asset_id.in_(ids),
                models.EndpointDevice.device_id.in_(bounded_device_ids),
            )
            .order_by(models.EndpointDevice.asset_id, models.EndpointDevice.device_id)
        )
        for device, snapshot in session.execute(endpoint_query):
            os_observations[device.asset_id].append((device, snapshot))
    for aid in ids:
        snapshots[aid].update(
            _endpoint_os_snapshot(
                os_observations[aid], now=now, freshness_hours=endpoint_stale_hours
            )
        )
    memberships = {aid: {} for aid in ids}
    provenance_rows = {aid: {} for aid in ids}
    latest = {aid: {} for aid in ids}
    if ids:
        for identifier in session.scalars(
            select(models.AssetIdentifier).where(
                models.AssetIdentifier.tenant_id == tenant_id,
                models.AssetIdentifier.asset_id.in_(ids),
            )
        ):
            if identifier.identifier_type in ("ip", "fqdn"):
                snapshots[identifier.asset_id][identifier.identifier_type].append(
                    identifier.identifier_value
                )
        for tag in session.scalars(
            select(models.AssetTag)
            .join(models.Asset, models.Asset.asset_id == models.AssetTag.asset_id)
            .where(
                models.Asset.tenant_id == tenant_id, models.AssetTag.asset_id.in_(ids)
            )
        ):
            snapshots[tag.asset_id]["tags"][tag.key] = tag.value
        for member in session.scalars(
            select(models.AssetGroupMembership).where(
                models.AssetGroupMembership.tenant_id == tenant_id,
                models.AssetGroupMembership.asset_id.in_(ids),
            )
        ):
            memberships[member.asset_id][member.group_id] = member
        for item in session.scalars(
            select(models.AssetGroupProvenance).where(
                models.AssetGroupProvenance.tenant_id == tenant_id,
                models.AssetGroupProvenance.asset_id.in_(ids),
            )
        ):
            provenance_rows[item.asset_id][item.field] = item
        # One latest event per asset/field; DISTINCT ON avoids loading full audit histories.
        events = (
            select(models.AssetContextEvent)
            .where(
                models.AssetContextEvent.tenant_id == tenant_id,
                models.AssetContextEvent.asset_id.in_(ids),
            )
            .distinct(models.AssetContextEvent.asset_id, models.AssetContextEvent.field)
            .order_by(
                models.AssetContextEvent.asset_id,
                models.AssetContextEvent.field,
                models.AssetContextEvent.id.desc(),
            )
        )
        for event in session.scalars(events):
            latest[event.asset_id].setdefault(event.field, event)
    global_counts = {"matched": 0, "entrants": 0, "exits": 0}
    global_transitions = []
    group_reports = {
        group["id"]: {
            "evaluated": len(rows),
            "matched": 0,
            "entrants": 0,
            "exits": 0,
            "changed": 0,
            "conflicts": 0,
            "has_more": has_more,
            "next_asset_id": report["next_asset_id"],
            "transitions": [],
            "count_semantics": "Per batch: group matches, membership transitions, assets with winning assignments or releases owned by this group, and conflicts involving this group",
        }
        for group in groups
    }
    for asset in rows:
        existing = memberships[asset.asset_id]
        matches, changes, conflicts, winners, managed, evaluations = _plan(
            session,
            tenant_id,
            asset,
            groups,
            snapshot=snapshots[asset.asset_id],
            managed=provenance_rows[asset.asset_id],
            latest_events=latest[asset.asset_id],
        )
        global_counts["matched"] += int(bool(matches))
        global_entrant = bool(set(matches) - set(existing))
        global_exited = bool(set(existing) - set(matches))
        global_counts["entrants"] += int(global_entrant)
        global_counts["exits"] += int(global_exited)
        if global_entrant or global_exited or changes:
            global_transitions.append(
                {
                    "asset_id": asset.asset_id,
                    "matched": bool(matches),
                    "entrant": global_entrant,
                    "exited": global_exited,
                    "reasons": [
                        reason for reasons in matches.values() for reason in reasons
                    ],
                    "changes": changes,
                    "conflicts": conflicts,
                    "entered_group_ids": sorted(set(matches) - set(existing)),
                    "exited_group_ids": sorted(set(existing) - set(matches)),
                }
            )
        matched = group_id in matches if group_id else bool(matches)
        entrant = (
            group_id in matches and group_id not in existing
            if group_id
            else bool(set(matches) - set(existing))
        )
        exited = (
            group_id in existing and group_id not in matches
            if group_id
            else bool(set(existing) - set(matches))
        )
        report["matched"] += int(matched)
        report["entrants"] += int(entrant)
        report["exits"] += int(exited)
        report["changed"] += int(bool(changes))
        report["conflicts"] += len(conflicts)
        report["items"].append(
            {
                "asset_id": asset.asset_id,
                "matched": matched,
                "entrant": entrant,
                "exited": exited,
                "reasons": evaluations.get(group_id, [])
                if group_id
                else [reason for reasons in matches.values() for reason in reasons],
                "changes": changes,
                "conflicts": conflicts,
            }
        )
        for gid, group_report in group_reports.items():
            group_changes = {
                field: change
                for field, change in changes.items()
                if change["group_id"] == gid
            }
            group_conflicts = [
                conflict for conflict in conflicts if gid in conflict["group_ids"]
            ]
            group_entrant = gid in matches and gid not in existing
            group_exited = gid in existing and gid not in matches
            group_report["matched"] += int(gid in matches)
            group_report["entrants"] += int(group_entrant)
            group_report["exits"] += int(group_exited)
            group_report["changed"] += int(bool(group_changes))
            group_report["conflicts"] += len(group_conflicts)
            if group_entrant or group_exited or group_changes:
                group_report["transitions"].append(
                    {
                        "asset_id": asset.asset_id,
                        "matched": gid in matches,
                        "entrant": group_entrant,
                        "exited": group_exited,
                        "reasons": evaluations.get(gid, []),
                        "changes": group_changes,
                        "conflicts": group_conflicts,
                    }
                )
        if not apply:
            continue
        for gid, member in existing.items():
            if gid not in matches:
                session.delete(member)
        by_id = {group["id"]: group for group in groups}
        for gid, reasons in matches.items():
            member = existing.get(gid)
            if member is None:
                member = models.AssetGroupMembership(
                    tenant_id=tenant_id,
                    group_id=gid,
                    asset_id=asset.asset_id,
                    version=by_id[gid]["version"],
                    reasons=reasons,
                    evaluated_at=now,
                )
                session.add(member)
            else:
                member.version = by_id[gid]["version"]
                member.reasons = reasons
                member.evaluated_at = now
        for field, change in changes.items():
            if change["old"] == change["new"]:
                continue
            setattr(asset, field, change["new"])
            session.add(
                models.AssetContextEvent(
                    tenant_id=tenant_id,
                    asset_id=asset.asset_id,
                    occurred_at=now,
                    field=field,
                    old_value=assets._stringify(change["old"]),
                    new_value=assets._stringify(change["new"]),
                    actor=actor,
                    source="group_rule",
                )
            )
        for field in set(managed) | set(winners):
            provenance = managed.get(field)
            if field not in winners:
                if any(
                    conflict["field"] == field
                    and conflict["reason"] == "equal_priority"
                    for conflict in conflicts
                ):
                    continue
                if provenance:
                    session.delete(provenance)
                continue
            group, value = winners[field]
            if field not in changes and (
                provenance is None
                or getattr(asset, field) != provenance.value.get("value")
            ):
                continue
            if provenance is None:
                provenance = models.AssetGroupProvenance(
                    tenant_id=tenant_id,
                    asset_id=asset.asset_id,
                    field=field,
                    group_id=group["id"],
                    version=group["version"],
                    value={"value": value},
                    previous={
                        "value": changes[field]["old"],
                        "source": asset.context_source,
                    },
                    reason=matches[group["id"]],
                    updated_at=now,
                )
                session.add(provenance)
            else:
                provenance.group_id = group["id"]
                provenance.version = group["version"]
                provenance.value = {"value": value}
                provenance.reason = matches[group["id"]]
                provenance.updated_at = now
    if apply:
        # Receipts with transitions are append-only. For unchanged batches keep
        # one latest diagnostic per group/status/version rather than adding
        # millions of identical worker heartbeat rows.
        latest_diagnostics = {}
        history_query = (
            select(models.AssetGroupEvaluation)
            .where(
                models.AssetGroupEvaluation.tenant_id == tenant_id,
                (
                    models.AssetGroupEvaluation.group_id.in_(
                        [group["id"] for group in groups]
                    )
                )
                | models.AssetGroupEvaluation.group_id.is_(None),
            )
            .distinct(
                models.AssetGroupEvaluation.group_id, models.AssetGroupEvaluation.status
            )
            .order_by(
                models.AssetGroupEvaluation.group_id,
                models.AssetGroupEvaluation.status,
                models.AssetGroupEvaluation.started_at.desc(),
                models.AssetGroupEvaluation.id,
            )
        )
        for diagnostic in session.scalars(history_query):
            latest_diagnostics.setdefault(
                (diagnostic.group_id, diagnostic.status), diagnostic
            )

        def persist(evaluation):
            previous = latest_diagnostics.get((evaluation.group_id, evaluation.status))
            if (
                previous is not None
                and previous.version == evaluation.version
                and not previous.report.get("transitions")
                and not evaluation.report.get("transitions")
            ):
                previous.started_at = evaluation.started_at
                previous.completed_at = evaluation.completed_at
                previous.report = evaluation.report
                return previous
            session.add(evaluation)
            return evaluation

        evaluation = models.AssetGroupEvaluation(
            id=uuid4().hex,
            tenant_id=tenant_id,
            group_id=None,
            version=None,
            status="partial" if has_more else "completed",
            started_at=now,
            completed_at=now,
            report={
                **{key: value for key, value in report.items() if key != "items"},
                **global_counts,
                "transitions": global_transitions,
            },
            error=None,
        )
        evaluation = persist(evaluation)
        report["evaluation_id"] = evaluation.id
        for group in groups:
            per_group_evaluation = models.AssetGroupEvaluation(
                id=uuid4().hex,
                tenant_id=tenant_id,
                group_id=group["id"],
                version=group["version"],
                status=evaluation.status,
                started_at=now,
                completed_at=now,
                report=group_reports[group["id"]],
                error=None,
            )
            per_group_evaluation = persist(per_group_evaluation)
            if group["id"] == group_id:
                report["evaluation_id"] = per_group_evaluation.id
    return report


def preview(
    settings, tenant_id, draft, *, group_id=None, limit=100, after_asset_id=None
):
    with get_session(settings.postgres_url) as session:
        return _batch(
            session,
            tenant_id,
            endpoint_stale_hours=settings.endpoint_stale_hours,
            group_id=group_id,
            draft=draft,
            limit=limit,
            after_asset_id=after_asset_id,
        )


def _recalculate(
    settings, tenant_id, *, group_id=None, limit=200, after_asset_id=None, actor=None
):
    with get_session(settings.postgres_url) as session:
        _lock_tenant(session, tenant_id)
        return _batch(
            session,
            tenant_id,
            endpoint_stale_hours=settings.endpoint_stale_hours,
            group_id=group_id,
            limit=limit,
            after_asset_id=after_asset_id,
            apply=True,
            actor=actor,
        )


def _reconcile_batch(settings, tenant_id, *, limit=200, actor=None):
    with get_session(settings.postgres_url) as session:
        tenant = session.get(models.Tenant, tenant_id)
        if tenant is None or tenant.status != "active":
            return {"evaluated": 0, "has_more": False}
        _lock_tenant(session, tenant_id)
        state = session.get(models.AssetGroupSweep, tenant_id)
        if state is None:
            state = models.AssetGroupSweep(
                tenant_id=tenant_id, after_asset_id=None, updated_at=_now()
            )
            session.add(state)
        report = _batch(
            session,
            tenant_id,
            endpoint_stale_hours=settings.endpoint_stale_hours,
            limit=limit,
            after_asset_id=state.after_asset_id,
            apply=True,
            actor=actor,
        )
        state.after_asset_id = report["next_asset_id"]
        state.updated_at = _now()
        return report


def list_members(settings, tenant_id, group_id, *, offset=0, limit=50):
    with get_session(settings.postgres_url) as session:
        _group(session, tenant_id, group_id)
        query = select(models.AssetGroupMembership).where(
            models.AssetGroupMembership.tenant_id == tenant_id,
            models.AssetGroupMembership.group_id == group_id,
        )
        total = session.scalar(select(func.count()).select_from(query.subquery()))
        items = [
            {
                key: getattr(row, key)
                for key in ("asset_id", "version", "reasons", "evaluated_at")
            }
            for row in session.scalars(
                query.order_by(models.AssetGroupMembership.asset_id)
                .offset(offset)
                .limit(limit)
            )
        ]
        return items, total


def list_evaluations(settings, tenant_id, group_id, *, offset=0, limit=50):
    with get_session(settings.postgres_url) as session:
        _group(session, tenant_id, group_id)
        query = select(models.AssetGroupEvaluation).where(
            models.AssetGroupEvaluation.tenant_id == tenant_id,
            models.AssetGroupEvaluation.group_id == group_id,
        )
        total = session.scalar(select(func.count()).select_from(query.subquery()))
        return [
            _evaluation(row)
            for row in session.scalars(
                query.order_by(
                    models.AssetGroupEvaluation.started_at.desc(),
                    models.AssetGroupEvaluation.id,
                )
                .offset(offset)
                .limit(limit)
            )
        ], total


def _record_failure(settings, tenant_id, group_id, error):
    # The failed transaction rolled back its cursor, membership and context.
    # A separate transaction makes its diagnostic durable without exposing SQL.
    with get_session(settings.postgres_url) as session:
        groups = list(
            session.scalars(
                select(models.AssetGroup).where(
                    models.AssetGroup.tenant_id == tenant_id,
                    models.AssetGroup.deleted.is_(False),
                )
            )
        )
        now = _now()
        for group in groups:
            if group_id is None or group.id == group_id:
                session.add(
                    models.AssetGroupEvaluation(
                        id=uuid4().hex,
                        tenant_id=tenant_id,
                        group_id=group.id,
                        version=group.version,
                        status="failed",
                        started_at=now,
                        completed_at=now,
                        report={},
                        error=f"Recalculation failed ({type(error).__name__}); retry this batch",
                    )
                )


def recalculate(
    settings, tenant_id, *, group_id=None, limit=200, after_asset_id=None, actor=None
):
    try:
        return _recalculate(
            settings,
            tenant_id,
            group_id=group_id,
            limit=limit,
            after_asset_id=after_asset_id,
            actor=actor,
        )
    except (LookupError, ValueError):
        raise
    except Exception as error:
        try:
            _record_failure(settings, tenant_id, group_id, error)
        except Exception:
            pass
        raise


def reconcile_batch(settings, tenant_id, *, limit=200, actor=None):
    try:
        return _reconcile_batch(settings, tenant_id, limit=limit, actor=actor)
    except Exception as error:
        try:
            _record_failure(settings, tenant_id, None, error)
        except Exception:
            pass
        raise
