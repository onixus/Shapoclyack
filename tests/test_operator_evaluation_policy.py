"""Policy mechanics with tiny abstract unit inputs, not an acceptance corpus."""
import copy
import json
import os
from pathlib import Path

import pytest

from api.services.local_operator import evaluation_policy as policy


def project(case):
    return policy.digest(policy.canonical(case['retrieval']))


def save(path, value):
    path.write_text(policy.canonical(value))
    return policy.digest(path.read_bytes())


def documents(tmp_path):
    # Abstract two-record protocol isolates policy validation, without model calls.
    base = {'required_counts': {'analysis': 2}, 'thresholds': {'minimum': .9},
            'rubric': {'rule': 'unit'}, 'cases': [
                {'case_id': 'old', 'kind': 'analysis', 'language': 'ru', 'retrieval': {'unit': 'old'}}]}
    data = {key: copy.deepcopy(base[key]) for key in ('required_counts', 'thresholds', 'rubric')}
    data.update(dataset_role=policy.ROLE, authoring={'review_status': 'reviewed',
        'independent_review': {'reviewer': 'independent-reviewer'}, 'human_domain_expert_reviewed': False}, cases=[
        {'case_id': 'unit-ru', 'scenario_family': 'unit-pair', 'kind': 'analysis', 'language': 'ru',
         'retrieval': {'unit': 'new-ru'}, 'gold': {'unit': True}},
        {'case_id': 'unit-en', 'scenario_family': 'unit-pair', 'kind': 'analysis', 'language': 'en',
         'retrieval': {'unit': 'new-en'}, 'gold': {'unit': True}}])
    prior = {'schema_version': 1, 'canonicalization': policy.CANONICALIZATION,
        'reviewer': 'independent-reviewer', 'reviewed_at': '2026-01-01T00:00:01Z',
        'model_input_sha256': [project(base['cases'][0])],
        'attempt_evidence_sha256': [policy.digest('prior-receipt')]}
    dataset_path, prior_path, approval_path = [tmp_path / name for name in ('data.json', 'prior.json', 'policy.json')]
    data_hash, prior_hash = save(dataset_path, data), save(prior_path, prior)
    approval = {'schema_version': 1, 'role': policy.ROLE, 'dataset_sha256': data_hash,
        **policy.review_material(data, base, project), 'development_exposed_case_ids': [],
        'prior_inputs_sha256': prior_hash,
        'author': {'name': 'blind-author', 'completed_at': '2026-01-01T00:00:00Z', 'blind_to_prior_outputs': True},
        'review': {'name': 'independent-reviewer', 'reviewed_at': '2026-01-01T00:00:02Z',
                   'before_model_outputs': True, 'gold_reviewed': True, 'scenario_novelty_reviewed': True},
        'claims': {'synthetic_only': True, 'human_domain_expert_reviewed': False,
                   'external_certification': False, 'pretraining_contamination_unknown': True}}
    save(approval_path, approval)
    return base, data, prior, approval, dataset_path, prior_path, approval_path


def approve(parts):
    base, _, _, _, data, prior, approval = parts
    return policy.approve(data, approval, policy.digest(approval.read_bytes()), prior, base, project)


def test_review_binds_all_bytes_and_claims(tmp_path):
    parts = documents(tmp_path)
    data, reviewed = approve(parts)
    exposure = reviewed.exposure(data)
    assert exposure['untouched_case_count'] == 2
    assert exposure['development_exposed_case_ids'] == []
    changed = copy.deepcopy(data)
    changed['cases'][0]['gold']['unit'] = False
    with pytest.raises(ValueError, match='changed'):
        reviewed.exposure(changed)


@pytest.mark.parametrize('where,key,value', [
    ('policy', 'schema_version', True), ('policy', 'role', 'waived'),
    ('policy', 'development_exposed_case_ids', ['unit-ru']),
    ('policy', 'unseen_case_ids', ['unit-ru']),
    ('author', 'name', 'independent-reviewer'), ('author', 'blind_to_prior_outputs', 1),
    ('review', 'gold_reviewed', False), ('review', 'before_model_outputs', 1),
    ('review', 'reviewed_at', '2099-01-01T00:00:00Z'),
    ('claims', 'external_certification', True), ('claims', 'synthetic_only', 1),
])
def test_rejects_waiver_mixed_reuse_and_false_review(tmp_path, where, key, value):
    parts = documents(tmp_path)
    approval = parts[3]
    (approval if where == 'policy' else approval[where])[key] = value
    save(parts[6], approval)
    with pytest.raises(ValueError):
        approve(parts)


@pytest.mark.parametrize('mutation', ['gold', 'input', 'counts', 'language', 'family', 'id', 'raw_reuse', 'wire_reuse', 'case_type'])
def test_tamper_or_incomplete_or_reused_corpus_rejected(tmp_path, mutation):
    parts = documents(tmp_path)
    base, data = parts[:2]
    if mutation == 'gold':
        data['cases'][0]['gold']['unit'] = False
    elif mutation == 'input':
        data['cases'][0]['retrieval']['unit'] = 'changed'
    elif mutation == 'counts':
        data['cases'].pop()
    elif mutation == 'language':
        data['cases'][0]['language'] = 'en'
    elif mutation == 'family':
        data['cases'][0]['scenario_family'] = 'unpaired'
    elif mutation == 'id':
        data['cases'][0]['case_id'] = 'old'
    elif mutation == 'case_type':
        data['cases'][0] = []
    else:
        data['cases'][0]['retrieval'] = copy.deepcopy(base['cases'][0]['retrieval'])
        if mutation == 'wire_reuse':
            data['cases'][0]['language'] = 'en'
    save(parts[4], data)
    with pytest.raises(ValueError):
        approve(parts)


@pytest.mark.parametrize('mutation', ['previously_dispatched', 'bad_type', 'duplicate', 'changed_bytes'])
def test_prior_exposure_inventory_is_bound_and_checked(tmp_path, mutation):
    parts = documents(tmp_path)
    prior, approval = parts[2:4]
    if mutation == 'previously_dispatched':
        prior['model_input_sha256'].append(project(parts[1]['cases'][0]))
    elif mutation == 'bad_type':
        prior['model_input_sha256'] = [{}]
    elif mutation == 'duplicate':
        prior['model_input_sha256'] *= 2
    else:
        prior['attempt_evidence_sha256'].append(policy.digest('changed'))
    changed_hash = save(parts[5], prior)
    if mutation != 'changed_bytes':
        approval['prior_inputs_sha256'] = changed_hash
        save(parts[6], approval)
    with pytest.raises(ValueError):
        approve(parts)


def test_policy_digest_must_be_independently_pinned(tmp_path):
    parts = documents(tmp_path)
    with pytest.raises(ValueError, match='Untrusted'):
        policy.approve(parts[4], parts[6], '0' * 64, parts[5], parts[0], project)


def test_one_shot_persistent_claim_permits_only_exact_resume(tmp_path):
    _, reviewed = approve(documents(tmp_path))
    ledger = tmp_path / 'ledger'
    ledger.mkdir()
    output = tmp_path / 'output'
    metadata = {'source': 'unit-frozen'}
    policy.claim_attempt(reviewed, ledger, output, metadata, resume=False)
    policy.claim_attempt(reviewed, ledger, output, metadata, resume=True)
    for changed_output, changed_meta, resume in [(output, metadata, False),
            (tmp_path / 'retry', metadata, True), (output, {'source': 'changed'}, True)]:
        with pytest.raises(ValueError):
            policy.claim_attempt(reviewed, ledger, changed_output, changed_meta, resume=resume)
    assert len(list(ledger.glob('claim-*.json'))) == 1


def test_resume_without_original_claim_is_not_fresh_attempt(tmp_path):
    _, reviewed = approve(documents(tmp_path))
    ledger = tmp_path / 'ledger'
    ledger.mkdir()
    with pytest.raises(ValueError, match='Cannot resume'):
        policy.claim_attempt(reviewed, ledger, tmp_path / 'out', {}, resume=True)


def test_cross_corpus_wire_reuse_and_incomplete_claim_fail_closed(tmp_path):
    _, reviewed = approve(documents(tmp_path))
    ledger = tmp_path / 'ledger'
    ledger.mkdir()
    projected = list(json.loads(reviewed.material_json)['case_projection_sha256'].values())
    save(ledger / ('claim-' + 'a' * 64 + '.json'), {'model_input_sha256': projected})
    with pytest.raises(ValueError, match='reused'):
        policy.claim_attempt(reviewed, ledger, tmp_path / 'out', {}, resume=False)
    (ledger / ('claim-' + 'a' * 64 + '.json')).write_text('{')
    with pytest.raises(ValueError):
        policy.claim_attempt(reviewed, ledger, tmp_path / 'out', {}, resume=False)


@pytest.mark.parametrize('content', ['{"key":1,"key":2}', '{"key":NaN}'])
def test_ambiguous_json_rejected(tmp_path, content):
    path = tmp_path / 'data'
    path.write_text(content)
    with pytest.raises(ValueError):
        policy.read_json(path)


def test_nonregular_and_symlink_inputs_fail_without_blocking(tmp_path):
    fifo = tmp_path / 'fifo'
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match='Regular'):
        policy.read_json(fifo)
    link = tmp_path / 'link'
    link.symlink_to(fifo)
    with pytest.raises(OSError):
        policy.read_json(link)


def test_default_corpus_unchanged_and_cannot_receive_override(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location('holdout_evaluator_unit', Path(__file__).parents[1] / 'scripts/operator-evaluate.py')
    evaluation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(evaluation)
    _, data, reviewed = evaluation.selected_dataset()
    assert reviewed is None
    assert evaluation.exposure_provenance(data)['untouched_case_count'] == 0
    assert len(data['cases']) == 190
    assert policy.digest(evaluation.DATASET.read_bytes()) == '3b059f9975627d5576a86518572e1a737c59739c4f4d3ed5beefdc1eb0858779'
    with pytest.raises(ValueError, match='Original exposed'):
        evaluation.selected_dataset(policy_path='anything')
    parts = documents(tmp_path)
    with pytest.raises(ValueError, match='requires exact'):
        evaluation.selected_dataset(parts[4])


def test_protocol_numeric_types_cannot_masquerade_as_thresholds(tmp_path):
    parts = documents(tmp_path)
    parts[0]['thresholds']['exact'] = 1.0
    parts[1]['thresholds']['exact'] = True
    with pytest.raises(ValueError, match='protocol'):
        policy.review_material(parts[1], parts[0], project)


def test_model_projection_ignores_gold_and_citation_retagging():
    import importlib.util
    spec = importlib.util.spec_from_file_location('holdout_projection_unit', Path(__file__).parents[1] / 'scripts/operator-evaluate.py')
    evaluation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(evaluation)
    original = next(case for case in evaluation.load_dataset()['cases']
                    if case.get('retrieval', {}).get('items'))
    changed = copy.deepcopy(original)
    changed['case_id'] = 'unit-retag-not-unseen'
    changed['gold'] = {'different': True}
    for i, item in enumerate(changed['retrieval']['items']):
        for obj in (item, item['citation']):
            obj['source_id'] = f'unit-retag-{i}'
            obj['source_hash'] = 'd' * 64
    assert evaluation.model_input_projection(original) == evaluation.model_input_projection(changed)


@pytest.fixture
def evaluation():
    import importlib.util
    spec = importlib.util.spec_from_file_location('holdout_runtime_unit', Path(__file__).parents[1] / 'scripts/operator-evaluate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('changed', [dict(development=True), dict(limit=1), dict(kind=['analysis']),
    dict(case_id=['unit-ru']), dict(exposure_ledger=None), dict(require_native_filesystem=False)])
def test_holdout_never_dispatches_pilot_subset_or_untracked_attempt(tmp_path, monkeypatch, evaluation, changed):
    import asyncio
    from types import SimpleNamespace
    parts = documents(tmp_path)
    data, reviewed = approve(parts)
    monkeypatch.setattr(evaluation, 'selected_dataset', lambda *a: (parts[4], data, reviewed))
    monkeypatch.setattr(evaluation, 'evaluate_one', lambda *a: pytest.fail('Forbidden holdout dispatch'))
    values = dict(provenance_json=None, development=False, limit=None, kind=None, case_id=None,
        exposure_ledger=str(tmp_path / 'ledger'), require_native_filesystem=True)
    values.update(changed)
    with pytest.raises(ValueError, match='complete final one-shot'):
        asyncio.run(evaluation.run(SimpleNamespace(**values)))


def test_reviewed_copy_preserves_exact_bytes_and_rejects_replacement(tmp_path, evaluation):
    source, destination = tmp_path / 'source', tmp_path / 'destination'
    source.write_bytes(b'{ "unit" : true }\n')
    expected = policy.digest(source.read_bytes())
    evaluation.copy_reviewed_input(source, destination, expected)
    assert destination.read_bytes() == source.read_bytes()
    source.write_bytes(b'{ "unit" : false }\n')
    with pytest.raises(ValueError, match='changed before persistence'):
        evaluation.copy_reviewed_input(source, destination, expected)
    assert policy.digest(destination.read_bytes()) == expected


def test_lock_contention_is_bounded_and_claim_is_not_written(tmp_path):
    import fcntl
    _, reviewed = approve(documents(tmp_path))
    ledger = tmp_path / 'ledger'
    ledger.mkdir()
    with (ledger / '.lock').open('w') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            policy.claim_attempt(reviewed, ledger, tmp_path / 'out', {}, resume=False)
    assert not list(ledger.glob('claim-*.json'))


@pytest.mark.parametrize('first_process_dies', [False, True])
def test_live_execution_excludes_second_process_before_dispatch_and_releases(tmp_path, first_process_dies):
    import select
    import subprocess
    import sys

    output = tmp_path / 'output'
    output.mkdir()
    marker = output / 'second-dispatch'
    source = str(Path(__file__).parents[1])
    first_code = ("import sys;sys.path.insert(0,sys.argv[1]);"
        "from api.services.local_operator import evaluation_policy as p;"
        "lock=p.execution_lock(sys.argv[2]);lock.__enter__();"
        "print('LOCKED',flush=True);sys.stdin.readline();lock.__exit__(None,None,None)")
    first = subprocess.Popen([sys.executable, '-c', first_code, source, str(output)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([first.stdout], [], [], 5)[0], 'Owner failed to acquire lock'
        assert first.stdout.readline().strip() == 'LOCKED'
        second_code = ("import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);"
            "from api.services.local_operator import evaluation_policy as p;"
            "lock=p.execution_lock(sys.argv[2]);lock.__enter__();"
            "Path(sys.argv[3]).write_text('fake dispatch');lock.__exit__(None,None,None)")
        second = subprocess.run([sys.executable, '-c', second_code, source, str(output), str(marker)],
                                capture_output=True, text=True, timeout=5)
        assert second.returncode != 0
        assert 'BlockingIOError' in second.stderr
        assert not marker.exists()  # competing executor never dispatches
        if first_process_dies:
            first.kill()
        else:
            first.stdin.write('\n')
            first.stdin.flush()
        first.wait(timeout=5)
        with policy.execution_lock(output):
            assert (output / '.execution.lock').is_file()  # inode survives normal/crash release
    finally:
        if first.poll() is None:
            first.kill()
        first.communicate(timeout=5)


def test_reviewed_resume_wrapper_locks_before_shared_journal_entry(tmp_path, monkeypatch, evaluation):
    import asyncio
    from types import SimpleNamespace

    parts = documents(tmp_path)
    data, reviewed = approve(parts)
    output = tmp_path / 'output'
    output.mkdir()
    journal = output / 'run.json'
    journal.write_text('sentinel: neither competing runner may repair this')
    manifest = {'dataset_sha256': policy.digest(parts[4].read_bytes()), 'source_sha256': {},
        'reviewed_dataset_binding': evaluation.reviewed_binding(reviewed),
        'thresholds': data['thresholds'], 'runtime': {}}
    manifest_path = tmp_path / 'manifest.json'
    save(manifest_path, manifest)
    monkeypatch.setattr(evaluation, 'selected_dataset', lambda *a: (parts[4], data, reviewed))
    monkeypatch.setattr(evaluation, 'source_provenance', lambda: {})
    monkeypatch.setattr(evaluation, 'runtime_provenance', lambda: {})
    args = SimpleNamespace(provenance_json=None, development=False, limit=None, kind=None, case_id=None,
        exposure_ledger=str(tmp_path / 'ledger'), require_native_filesystem=True, soak_seconds=3600,
        manifest=manifest_path, output=output, resume=True)
    entries = []

    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()

        async def locked_body(*arguments):
            entries.append(arguments[4])
            entered.set()
            await release.wait()
            raise RuntimeError('controlled interruption before real provider/journal access')

        monkeypatch.setattr(evaluation, '_run_locked', locked_body)
        owner = asyncio.create_task(evaluation.run(args))
        await asyncio.wait_for(entered.wait(), 2)
        try:
            with pytest.raises(BlockingIOError):
                await evaluation.run(args)
            assert entries == [output]
            assert journal.read_text().startswith('sentinel:')
        finally:
            release.set()
            with pytest.raises(RuntimeError, match='controlled interruption'):
                await owner
        with policy.execution_lock(output):
            pass  # finally releases the lock even on an async exception

    asyncio.run(scenario())


def test_reviewed_final_without_manifest_rejects_before_output_claim_or_dispatch(tmp_path, monkeypatch, evaluation):
    import asyncio
    from types import SimpleNamespace

    parts = documents(tmp_path)
    data, reviewed = approve(parts)
    monkeypatch.setattr(evaluation, 'selected_dataset', lambda *a: (parts[4], data, reviewed))
    monkeypatch.setattr(evaluation, '_run_locked', lambda *a: pytest.fail('Manifestless execution'))
    args = SimpleNamespace(provenance_json=None, development=False, limit=None, kind=None, case_id=None,
        exposure_ledger=str(tmp_path / 'ledger'), require_native_filesystem=True, soak_seconds=3600,
        manifest=None, output=tmp_path / 'output', resume=False)
    with pytest.raises(ValueError, match='Final runs require independently reviewed frozen provenance'):
        asyncio.run(evaluation.run(args))
    assert not args.output.exists()


@pytest.mark.parametrize('kind', ['symlink', 'fifo'])
def test_execution_lock_rejects_nonregular_or_symlink_without_blocking(tmp_path, kind):
    lock = tmp_path / '.execution.lock'
    if kind == 'symlink':
        target = tmp_path / 'target'
        target.write_text('unchanged')
        lock.symlink_to(target)
    else:
        os.mkfifo(lock)
    with pytest.raises((OSError, ValueError)):
        with policy.execution_lock(tmp_path):
            pytest.fail('Invalid execution lock admitted')
