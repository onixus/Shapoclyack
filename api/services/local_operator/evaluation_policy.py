"""Reviewed synthetic holdout provenance and one-shot local exposure accounting.

Attestations are administrator-reviewed evidence, not cryptographic identity or
proof against a privileged operator changing the ledger. No model is called.
"""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MAX_BYTES = 16 * 1024 * 1024
HASH = re.compile(r"[a-f0-9]{64}\Z")
ROLE = "independent_synthetic_holdout_v1"
CANONICALIZATION = "sha256-canonical-messages-schema-v1"


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def read_json(path):
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("Regular evaluation input required")
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Oversized evaluation input")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate evaluation key")
            result[key] = value
        return result

    return raw, json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid number")))


def _keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("Invalid reviewed policy fields")


def _hash(value):
    if not isinstance(value, str) or not HASH.fullmatch(value):
        raise ValueError("Invalid provenance digest")
    return value


def _name(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        raise ValueError("Named independent authorship/review required")
    return value


def _time(value):
    if not isinstance(value, str):
        raise ValueError("Review UTC timestamp required")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("Review UTC timestamp required")
    return stamp.astimezone(UTC)


def protocol(baseline):
    return {"required_counts": baseline["required_counts"], "thresholds": baseline["thresholds"],
            "rubric": baseline["rubric"], "languages": ["en", "ru"],
            "kind_language_counts": {kind: {lang: count // 2 for lang in ("en", "ru")}
                                     for kind, count in baseline["required_counts"].items()}}


def _scenario(case):
    # Gold, IDs and editorial labels cannot turn a reused input into unseen data.
    return digest(canonical({key: case[key] for key in ("kind", "language", "retrieval", "planner_request", "domain_input")
                             if key in case}))


def review_material(dataset, baseline, project):
    """Produce hashes to review; this does not approve novelty or create a policy."""
    if not isinstance(dataset, dict) or dataset.get("dataset_role") != ROLE:
        raise ValueError("Explicit holdout dataset role required")
    for key in ("rubric", "thresholds", "required_counts"):
        if canonical(dataset.get(key)) != canonical(baseline[key]):
            raise ValueError("Holdout protocol differs from original")
    cases = dataset.get("cases")
    needed = protocol(baseline)["kind_language_counts"]
    if not isinstance(cases, list) or len(cases) != sum(baseline["required_counts"].values()):
        raise ValueError("Complete holdout counts required")
    ids, families, projections, scenarios = [], {}, {}, []
    old_ids = {case["case_id"] for case in baseline["cases"]}
    old_scenarios = {_scenario(case) for case in baseline["cases"]}
    old_projections = {project(case) for case in baseline["cases"]}
    counts = Counter()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("Holdout case must be an object")
        cid, family = case.get("case_id"), case.get("scenario_family")
        if not isinstance(cid, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}", cid):
            raise ValueError("Invalid holdout case ID")
        if cid in old_ids or cid in ids:
            raise ValueError("Reused holdout case ID")
        if not isinstance(family, str) or not family.strip() or len(family) > 200:
            raise ValueError("Independent scenario family required")
        kind, language = case.get("kind"), case.get("language")
        if kind not in needed or language not in needed[kind]:
            raise ValueError("Unknown holdout subgroup")
        counts[(kind, language)] += 1
        families.setdefault(family, []).append((kind, language))
        scenario, projected = _scenario(case), _hash(project(case))
        if scenario in old_scenarios or scenario in scenarios:
            raise ValueError("Reused raw scenario")
        if projected in old_projections or projected in projections.values():
            raise ValueError("Model-visible input collision; no unseen-input waiver")
        ids.append(cid)
        scenarios.append(scenario)
        projections[cid] = projected
    if any(counts[(kind, lang)] != count for kind, langs in needed.items() for lang, count in langs.items()):
        raise ValueError("Holdout kind/language counts differ")
    if any(len(pair) != 2 or pair[0][0] != pair[1][0] or {x[1] for x in pair} != {"ru", "en"}
           for pair in families.values()):
        raise ValueError("Scenario family must be one equivalent RU/EN pair")
    return {"dataset_canonical_sha256": digest(canonical(dataset)),
            "protocol_sha256": digest(canonical(protocol(baseline))),
            "case_set_sha256": digest(canonical(sorted(scenarios))),
            "case_projection_sha256": projections, "unseen_case_ids": sorted(ids)}


@dataclass(frozen=True)
class ReviewedHoldout:
    dataset_sha256: str
    dataset_canonical_sha256: str
    policy_sha256: str
    prior_inputs_sha256: str
    material_json: str
    policy_json: str

    def exposure(self, dataset):
        if digest(canonical(dataset)) != self.dataset_canonical_sha256:
            raise ValueError("Reviewed holdout changed")
        return {"version": ROLE, "reviewed_policy_sha256": self.policy_sha256,
                "prior_inputs_sha256": self.prior_inputs_sha256,
                "development_exposed_case_ids": [], "untouched_case_count": len(dataset["cases"]),
                "scope": "new synthetic local holdout; external certification and training contamination not established"}


def approve(dataset_path, policy_path, trusted_policy_sha256, prior_inputs_path, baseline, project):
    """Validate exact independently trusted policy bytes before any inference."""
    dataset_raw, data = read_json(dataset_path)
    policy_raw, policy = read_json(policy_path)
    prior_raw, prior = read_json(prior_inputs_path)
    if digest(policy_raw) != _hash(trusted_policy_sha256):
        raise ValueError("Untrusted holdout policy bytes")
    _keys(policy, {"schema_version", "role", "dataset_sha256", "dataset_canonical_sha256", "protocol_sha256",
                   "case_set_sha256", "case_projection_sha256", "unseen_case_ids", "development_exposed_case_ids",
                   "prior_inputs_sha256", "author", "review", "claims"})
    material = review_material(data, baseline, project)
    if type(policy["schema_version"]) is not int or policy["schema_version"] != 1 or policy["role"] != ROLE:
        raise ValueError("Invalid holdout policy version")
    if policy["dataset_sha256"] != digest(dataset_raw) or any(policy.get(k) != v for k, v in material.items()):
        raise ValueError("Holdout policy binding mismatch")
    if policy["development_exposed_case_ids"] != []:
        raise ValueError("Mixed exposed/unseen corpus cannot certify holdout")
    _keys(policy["author"], {"name", "completed_at", "blind_to_prior_outputs"})
    _keys(policy["review"], {"name", "reviewed_at", "before_model_outputs", "gold_reviewed", "scenario_novelty_reviewed"})
    author, review = policy["author"], policy["review"]
    if _name(author["name"]).strip().casefold() == _name(review["name"]).strip().casefold():
        raise ValueError("Author and reviewer must differ")
    if author["blind_to_prior_outputs"] is not True or any(review[k] is not True for k in
            ("before_model_outputs", "gold_reviewed", "scenario_novelty_reviewed")):
        raise ValueError("Independent pre-output review required")
    if not _time(author["completed_at"]) <= _time(review["reviewed_at"]) <= datetime.now(UTC):
        raise ValueError("Invalid review chronology")
    _keys(policy["claims"], {"synthetic_only", "human_domain_expert_reviewed", "external_certification", "pretraining_contamination_unknown"})
    if policy["claims"] != {"synthetic_only": True, "human_domain_expert_reviewed": False,
                            "external_certification": False, "pretraining_contamination_unknown": True}:
        raise ValueError("Unsupported certification claim")
    # Equality alone permits 1/0 to masquerade as boolean attestations.
    if any(type(v) is not bool for v in policy["claims"].values()):
        raise ValueError("Strict claim booleans required")
    authoring = data.get("authoring", {})
    if (not isinstance(authoring, dict) or not isinstance(authoring.get("independent_review"), dict) or
            authoring.get("review_status") != "reviewed" or
            authoring.get("independent_review", {}).get("reviewer") != review["name"] or
            authoring.get("human_domain_expert_reviewed") is not False):
        raise ValueError("Dataset independent review mismatch")
    _keys(prior, {"schema_version", "canonicalization", "reviewer", "reviewed_at", "model_input_sha256", "attempt_evidence_sha256"})
    if (type(prior["schema_version"]) is not int or prior["schema_version"] != 1 or
            prior["canonicalization"] != CANONICALIZATION or _name(prior["reviewer"]) != review["name"] or
            not _time(prior["reviewed_at"]) <= _time(review["reviewed_at"])):
        raise ValueError("Prior local request inventory review required")
    for key in ("model_input_sha256", "attempt_evidence_sha256"):
        values = prior[key]
        if not isinstance(values, list) or not values or len(values) > 100000:
            raise ValueError("Invalid prior exposure inventory")
        for value in values:
            _hash(value)
        if len(set(values)) != len(values):
            raise ValueError("Duplicate prior exposure digest")
    if policy["prior_inputs_sha256"] != digest(prior_raw):
        raise ValueError("Prior exposure inventory changed")
    if set(material["case_projection_sha256"].values()) & set(prior["model_input_sha256"]):
        raise ValueError("Holdout model input already dispatched")
    return data, ReviewedHoldout(digest(dataset_raw), material["dataset_canonical_sha256"], digest(policy_raw),
                                 digest(prior_raw), canonical(material), canonical(policy))


@contextmanager
def execution_lock(output):
    """Exclude live resumptions before reading or recovering their shared journal.

    Keep the inode after release: unlinking a locked file could admit a second
    independent lock. Kernel ownership ends on close or process death; durable
    corpus exposure remains separately recorded by claim_attempt.
    """
    import fcntl

    descriptor = os.open(Path(output) / ".execution.lock",
                         os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("Regular execution lock required")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def claim_attempt(approved, ledger, output, run_metadata, *, resume):
    """One-shot corpus/input reservation, retained even if the process crashes.

    Use a persistent native ledger shared by all attempts. A privileged operator
    can replace it; the trusted controller must bind its volume and retain it.
    """
    import fcntl

    ledger, output = Path(ledger), Path(output)
    if ledger.is_symlink() or not ledger.is_dir():
        raise ValueError("Persistent holdout ledger directory required")
    material = json.loads(approved.material_json)
    target = ledger / ("claim-" + material["case_set_sha256"] + ".json")
    value = {"dataset_canonical_sha256": approved.dataset_canonical_sha256,
             "policy_sha256": approved.policy_sha256, "run_metadata_sha256": digest(canonical(run_metadata)),
             "output": str(output.resolve()), "model_input_sha256": sorted(material["case_projection_sha256"].values())}
    fd = os.open(ledger / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Regular ledger lock required")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if target.exists() or target.is_symlink():
            _, previous = read_json(target)
            if not resume or previous != value:
                raise ValueError("Holdout already reserved/exposed; no fresh retry")
            return
        if resume:
            raise ValueError("Cannot resume without original holdout exposure claim")
        claims = list(ledger.glob("claim-*.json"))
        if len(claims) > 4096:
            raise ValueError("Exposure ledger review/rotation required")
        for path in claims:
            _, previous = read_json(path)
            if set(previous["model_input_sha256"]) & set(value["model_input_sha256"]):
                raise ValueError("Model input reused across holdout attempts")
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as handle:
            handle.write(canonical(value) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        descriptor = os.open(ledger, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        os.close(fd)
