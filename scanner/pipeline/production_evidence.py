"""Precise observations inside stable legacy remediation containers."""
from __future__ import annotations
from typing import Any
from .finding_evidence import EVIDENCE_SCHEMA, aggregate, canonical_json, digest, observation, subject, timestamp


def combine(rows: list[dict], *, artifact_sha: str | None = None) -> list[dict]:
    groups: dict[tuple, list[tuple[int, dict]]] = {}
    for index, row in enumerate(rows):
        issue = str(row.get('cve') or '').upper() or 'script:' + str(row.get('script_id') or '')
        key = str(row.get('host') or '').lower(), str(row.get('port') or ''), issue
        groups.setdefault(key, []).append((index, row))
    result = []
    for key, members in sorted(groups.items()):
        # Latest dated cohort, deterministic tie breaking; no source ranking.
        members.sort(key=lambda pair: (timestamp(pair[1].get('observed_at') or pair[1].get('timestamp')) or '', canonical_json(pair[1])))
        representative = dict(members[-1][1])
        observations, incomplete = [], False
        for index, row in members:
            mapped = {**row, 'rule_id': row.get('rule_id') or row.get('script_id'),
                      'observed_at': row.get('observed_at') or row.get('timestamp')}
            try:
                observations.append(observation(mapped, tenant_id='unpublished', run_id='unpublished',
                    source=str(row.get('source') or 'unknown'), artifact_ref={
                        'path': 'report_sources.json', 'sha256': artifact_sha or digest(rows), 'locator': '/' + str(index)}))
            except (ValueError, TypeError, OverflowError):
                incomplete = True
        evidence = aggregate(observations)
        evidence.update(mode='production', projection_incomplete=incomplete, identity_policy='legacy-remediation-container-v1')
        representative['finding_evidence'] = evidence
        detectors = {}
        for _, row in members:
            for detector in [row, *(d for d in row.get('also_detected_by') or [] if isinstance(d, dict))]:
                d = {k: detector[k] for k in ('source', 'script_id', 'protocol', 'ruleset_version') if detector.get(k) is not None}
                detectors[canonical_json(d)] = d
        own = {k: representative[k] for k in ('source', 'script_id', 'protocol', 'ruleset_version') if representative.get(k) is not None}
        others = [d for _, d in sorted(detectors.items()) if d != own]
        representative.pop('also_detected_by', None)
        if others:
            representative['also_detected_by'] = others
        result.append(representative)
    return result


def scoped(evidence: Any, *, tenant_id: str, run_id: str) -> dict | None:
    """Validate then rebind uploader context to authenticated run ownership."""
    if evidence is None:
        return None
    if not isinstance(evidence, dict):
        return incomplete_evidence()
    rows = []
    try:
        if (evidence.get('schema') != EVIDENCE_SCHEMA or evidence.get('mode') not in {'shadow', 'production'}
                or not isinstance(evidence.get('findings'), list)
                or len(evidence['findings']) > MAX_HISTORY_OBSERVATIONS
                or not isinstance(evidence.get('projection_incomplete'), bool)):
            return incomplete_evidence()
        for group in evidence['findings']:
            if not isinstance(group, dict) or not isinstance(group.get('observations'), list):
                return incomplete_evidence()
            for item in group['observations']:
                if len(rows) >= MAX_HISTORY_OBSERVATIONS:
                    return incomplete_evidence()
                validate_observation(item)
                rebound = {**item, 'tenant_id': tenant_id, 'run_id': run_id}
                material = {k: v for k, v in rebound.items() if k not in {'observation_id', 'artifact_refs', 'artifact_refs_truncated'}}
                rebound['observation_id'] = 'obs:' + digest(material)
                rows.append(rebound)
        result = aggregate(rows)
        if (evidence.get('observation_count') != result['observation_count']
                or evidence.get('finding_count') != result['finding_count']):
            return incomplete_evidence()
        result.update(mode='production' , identity_policy='legacy-remediation-container-v1', projection_incomplete=evidence.get('projection_incomplete') is not False)
        return result
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return incomplete_evidence()


MAX_HISTORY_OBSERVATIONS = 10000


def validate_observation(item: dict) -> None:
    aggregate([item])
    target = item['subject']
    if not isinstance(target, dict) or set(target) != {'host', 'port', 'protocol', 'scheme', 'authority', 'sni', 'object_id'}:
        raise ValueError('invalid subject')
    normalized = subject({'host': target['host'], 'port': target['port'], 'protocol': target['protocol'], 'sni': target['sni']})
    if any(normalized[k] != target[k] for k in ('host', 'port', 'protocol', 'sni')):
        raise ValueError('noncanonical subject')
    if any(target[k] is not None and not isinstance(target[k], str) for k in ('scheme', 'authority', 'object_id')):
        raise ValueError('invalid subject fields')
    if target['scheme'] not in (None, 'http', 'https'):
        raise ValueError('invalid scheme')



def incomplete_evidence() -> dict:
    result = aggregate([])
    result.update(mode='production', identity_policy='legacy-remediation-container-v1', projection_incomplete=True)
    return result


def merge(previous: Any, current: dict | None) -> dict | None:
    if current is None:
        return previous if isinstance(previous, dict) else None
    incomplete = False
    rows = {}
    for data in (previous, current):
        if data is None:
            continue
        if not isinstance(data, dict):
            incomplete = True
            continue
        incomplete |= data.get('projection_incomplete') is not False
        try:
            for group in data.get('findings', []):
                for item in group['observations']:
                    validate_observation(item)
                    oid = item['observation_id']
                    if oid in rows:
                        # Preserve duplicate artifact references through the
                        # same bounded union used by the public contract.
                        merged = aggregate([rows[oid], item])
                        rows[oid] = merged['findings'][0]['observations'][0]
                    elif len(rows) < MAX_HISTORY_OBSERVATIONS:
                        rows[oid] = item
                    else:
                        incomplete = True
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
            incomplete = True
    result = aggregate(list(rows.values()))
    result.update(mode='production', identity_policy='legacy-remediation-container-v1', projection_incomplete=incomplete)
    return result


def attach_raw(rows: list[dict], projection: dict) -> None:
    """Attach raw observations only to existing tasks; never invent a task.

    Compare literal normalized endpoint names, never DNS/IP inference. Raw
    HTTP objects stay distinct even when a legacy report row lost its path.
    """
    from .finding_evidence import subject
    for row in rows:
        try:
            endpoint = subject(row)
        except (ValueError, TypeError):
            continue
        matches = []
        for group in projection.get('findings', []):
            identity = group['identity']
            target = identity['subject']
            if (target['host'], target['port']) != (endpoint['host'], endpoint['port']):
                continue
            for item in group['observations']:
                if row.get('cve'):
                    match = str(row['cve']).upper() == item.get('cve')
                else:
                    rule = str(row.get('script_id') or '').split(':', 1)[-1]
                    match = item.get('rule_id') == rule
                if match:
                    matches.append(item)
        if matches:
            raw = aggregate(matches)
            raw['projection_incomplete'] = projection.get('projection_incomplete', True)
            row['finding_evidence'] = merge(row.get('finding_evidence'), raw)


def closure_gaps(evidence: Any) -> list[dict]:
    """Legacy endpoint coverage cannot attest HTTP object/SNI checks.

    Preserve positives from partial data but fail closed for negative decisions.
    Simple, single transport endpoint observations retain existing #451 gates.
    """
    if not isinstance(evidence, dict):
        return []
    reason = None
    if evidence.get('projection_incomplete') is not False:
        reason = 'evidence_incomplete'
    else:
        subjects = [g['identity']['subject'] for g in evidence.get('findings', [])]
        if any(s.get('authority') or s.get('sni') or s.get('object_id') for s in subjects):
            reason = 'precise_subject_coverage_unproven'
        elif len({canonical_json(s) for s in subjects}) > 1:
            reason = 'multiple_subject_coverage_unproven'
    return [{'detector': 'evidence', 'ref': None, 'host': None, 'port': None, 'reason': reason}] if reason else []
