"""Precise observations inside stable legacy remediation containers."""
from __future__ import annotations

from scanner.pipeline.non_cve_policy import actionable
from typing import Any
from .finding_evidence import EVIDENCE_SCHEMA, aggregate, canonical_json, digest, observation, subject, timestamp


def combine(rows: list[dict], *, artifact_sha: str | None = None) -> list[dict]:
    groups: dict[tuple, list[tuple[int, dict]]] = {}
    for index, row in enumerate(rows):
        issue = str(row.get('cve') or '').upper() or 'script:' + str(row.get('script_id') or '')
        key = str(row.get('host') or '').lower(), str(row.get('port') or ''), issue
        if actionable(row):
            # New actionable observations use precise subjects. CVE and legacy
            # remediation containers retain their historic grouping unchanged.
            key = ('non-cve-v1', str(row.get('rule_id') or row.get('script_id') or ''), canonical_json(subject(row)))
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
        result.update(mode='production', identity_policy='legacy-remediation-container-v1', projection_incomplete=evidence.get('projection_incomplete') is not False)
        return result
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return incomplete_evidence()


MAX_HISTORY_OBSERVATIONS = 10000


def validate_observation(item: dict) -> None:
    """Hashes prove content, never authenticity or that content is safe."""
    import math
    import re
    from .finding_evidence import OBSERVATION_SCHEMA, MAX_ARTIFACT_REFS, safe_text, http_authority
    required = {'schema', 'tenant_id', 'run_id', 'source', 'engine_version', 'ruleset_version',
                'rule_id', 'rule_digest', 'matcher', 'observed_at', 'subject', 'cve', 'title',
                'evidence_kind', 'confidence', 'severity', 'requires_confirmation', 'preview',
                'evidence_digest', 'observation_id', 'artifact_refs'}
    if not isinstance(item, dict) or set(item) - required != (set(item) & {'artifact_refs_truncated'}) or not required <= set(item):
        raise ValueError('invalid observation fields')
    if item['schema'] != OBSERVATION_SCHEMA or item['source'] not in {'pulse', 'pulse-plugin', 'nuclei', 'nmap-nse', 'unknown'}:
        raise ValueError('invalid observation source')
    for key in ('tenant_id', 'run_id'):
        value = item[key]
        if not isinstance(value, str) or not value or len(value) > 128 or any(ord(c) < 32 for c in value):
            raise ValueError('invalid context')
    for key, limit in [('engine_version', 80), ('ruleset_version', 80), ('rule_id', 256),
                       ('matcher', 256), ('title', 256), ('preview', 512)]:
        value = item[key]
        if value is None and key not in {'title', 'preview'}:
            continue
        if not isinstance(value, str) or value != safe_text(value, limit):
            raise ValueError('unsafe observation text')
    for key in ('rule_digest', 'evidence_digest'):
        if not isinstance(item[key], str) or not re.fullmatch('[0-9a-f]{64}', item[key]):
            raise ValueError('invalid digest')
    if item['cve'] is not None and (not isinstance(item['cve'], str) or not re.fullmatch(r'CVE-\d{4}-\d{3,7}', item['cve'])):
        raise ValueError('invalid CVE')
    if item['observed_at'] is not None and timestamp(item['observed_at']) != item['observed_at']:
        raise ValueError('invalid observation time')
    confidence = item['confidence']
    if confidence is not None and (type(confidence) not in (int, float) or not math.isfinite(confidence) or not 0 <= confidence <= 100):
        raise ValueError('invalid confidence')
    if not isinstance(item['requires_confirmation'], bool) or item['severity'] not in {'critical', 'high', 'medium', 'low', 'info', 'unknown'}:
        raise ValueError('invalid assessment')
    if item['evidence_kind'] not in {'version_match', 'keyword_hypothesis', 'exposure', 'tls_observation', 'template_match', 'nse_report', 'plugin_report', 'unclassified'}:
        raise ValueError('invalid evidence kind')
    if not isinstance(item['artifact_refs'], list) or not 1 <= len(item['artifact_refs']) <= MAX_ARTIFACT_REFS:
        raise ValueError('artifact reference limit')
    target = item['subject']
    if not isinstance(target, dict) or set(target) != {'host', 'port', 'protocol', 'scheme', 'authority', 'sni', 'object_id'}:
        raise ValueError('invalid subject')
    normalized = subject({'host': target['host'], 'port': target['port'], 'protocol': target['protocol'], 'sni': target['sni']})
    if any(normalized[k] != target[k] for k in ('host', 'port', 'protocol', 'sni')):
        raise ValueError('noncanonical subject')
    if target['scheme'] not in (None, 'http', 'https'):
        raise ValueError('invalid scheme')
    if target['scheme'] is not None:
        if target['protocol'] != 'tcp' or target['port'] is None or http_authority(target['authority'], target['port']) != target['authority']:
            raise ValueError('conflicting HTTP subject')
    elif target['authority'] is not None:
        raise ValueError('authority without scheme')
    object_id = target['object_id']
    if object_id is not None and (not isinstance(object_id, str) or not re.fullmatch(r'(?:url|object|url-object):[0-9a-f]{64}', object_id)):
        raise ValueError('invalid object digest')
    aggregate([item])


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
            if actionable(row) and target != endpoint:
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
            fallback = row.get('finding_evidence') or incomplete_evidence()
            originals = [item for group in fallback.get('findings', []) for item in group['observations']]
            raw_rows = [{**item, 'artifact_refs': list(item['artifact_refs'])} for item in matches]
            retained = []
            for original in originals:
                associated = []
                for raw in raw_rows:
                    # These are two representations of the same upstream event,
                    # not an assertion that unknown subjects match all objects.
                    same_rule = (original['rule_id'] or '').removeprefix(original['source'] + ':') == raw['rule_id']
                    if original['source'] == 'pulse' and original['cve']:
                        same_rule = original['rule_id'] in {'pulse:local', 'pulse:nvd', 'pulse:' + str(raw['rule_id'])}
                    compatible = all(original['subject'][key] in (None, 'unknown') or original['subject'][key] == raw['subject'][key]
                                     for key in ('protocol', 'scheme', 'authority', 'sni', 'object_id'))
                    compatible = compatible and (original['observed_at'] is None or original['observed_at'] == raw['observed_at'])
                    if original['source'] == raw['source'] and same_rule and compatible:
                        associated.append(raw)
                if associated:
                    for raw in associated:
                        raw['artifact_refs'].extend(original['artifact_refs'])
                else:
                    retained.append(original)
            evidence = aggregate([*retained, *raw_rows])
            evidence.update(mode='production', identity_policy='legacy-remediation-container-v1',
                            projection_incomplete=fallback.get('projection_incomplete') is not False or projection.get('projection_incomplete') is not False)
            row['finding_evidence'] = evidence


def closure_gaps(evidence: Any, *, covered_subjects: list[dict] | None = None) -> list[dict]:
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
        if subjects and covered_subjects and all(s in covered_subjects for s in subjects):
            return []
        if any(s.get('authority') or s.get('sni') or s.get('object_id') for s in subjects):
            reason = 'precise_subject_coverage_unproven'
        elif len({canonical_json(s) for s in subjects}) > 1:
            reason = 'multiple_subject_coverage_unproven'
    return [{'detector': 'evidence', 'ref': None, 'host': None, 'port': None, 'reason': reason}] if reason else []
