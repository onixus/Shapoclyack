"""Offline wiki rendering and publication boundary checks."""
import importlib.util
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("wiki_renderer", ROOT / "scripts/render-wiki.py")
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)


@pytest.mark.parametrize("origin", [
    "https://github.com/example/project.git",
    "git@github.com:example/project.git",
    "ssh://git@github.com/example/project.git",
])
def test_repository_origin_formats(origin):
    assert renderer.repository_url(origin) == "https://github.com/example/project"


def test_links_keep_fragments_and_nested_paths():
    source = ROOT / "docs/wiki/README.md"
    pages = {source: "Home", ROOT / "docs/wiki/scenarios-ciso.md": "scenarios-ciso"}
    text = ('[home](README.md#intro) [role](scenarios-ciso.md#risk) '
            '[docs](../README.md#version-scope) '
            '[cluster](../../k8s/README.md "Deployment") '
            '[external](https://example.test/a.md) [local](#here)')
    result = renderer.render_page(text, source, pages, "https://github.com/other/fork", "release/test")
    assert '[home](Home#intro)' in result
    assert '[role](scenarios-ciso#risk)' in result
    assert '(https://github.com/other/fork/blob/release%2Ftest/docs/README.md#version-scope)' in result
    assert '(https://github.com/other/fork/blob/release%2Ftest/k8s/README.md "Deployment")' in result
    assert '[external](https://example.test/a.md) [local](#here)' in result


def test_fenced_examples_are_unchanged():
    text = '```markdown\n[example](missing.md)\n```\n~~~md\n[example](missing.md)\n~~~\n'
    assert renderer.render_page(text, ROOT / 'docs/wiki/README.md', {}, 'https://github.com/a/b', 'main') == text


def test_missing_target_fails_before_writing(tmp_path, monkeypatch):
    root = tmp_path / 'repo'
    wiki = root / 'docs/wiki'
    wiki.mkdir(parents=True)
    (wiki / 'README.md').write_text('[bad](missing.md)')
    monkeypatch.setattr(renderer, 'ROOT', root)
    output = tmp_path / 'out'
    with pytest.raises(ValueError, match='missing link target'):
        renderer.render(output, 'https://github.com/a/b', 'main')
    assert not output.exists()


def test_new_page_is_included_without_script_changes(tmp_path, monkeypatch):
    root = tmp_path / 'repo'
    wiki = root / 'docs/wiki'
    wiki.mkdir(parents=True)
    (wiki / 'README.md').write_text('[new](new-page.md)')
    (wiki / 'new-page.md').write_text('[home](README.md)')
    monkeypatch.setattr(renderer, 'ROOT', root)
    output = tmp_path / 'out'
    renderer.render(output, 'https://github.com/a/b', 'main')
    assert (output / 'Home.md').read_text() == '[new](new-page)'
    assert (output / 'new-page.md').read_text() == '[home](Home)'


def test_local_preview_renders_all_sources_without_network(tmp_path):
    # Only origin lookup is permitted. A clone/push/commit would fail this test.
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    git = bindir / 'git'
    git.write_text('#!/bin/sh\ncase "$*" in\n'
                   '  *"config --get remote.origin.url") echo https://github.com/example/fork.git ;;\n'
                   '  *) echo "unexpected git operation" >&2; exit 99 ;;\nesac\n')
    git.chmod(0o755)
    result = subprocess.run(
        ['bash', str(ROOT / 'scripts/publish-wiki.sh'), '--output', str(tmp_path / 'preview')],
        env={**os.environ, 'PATH': f'{bindir}:{os.environ["PATH"]}'}, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    names = {p.name for p in (tmp_path / 'preview').glob('*.md')}
    expected = {'Home.md' if p.name == 'README.md' else p.name for p in (ROOT / 'docs/wiki').glob('*.md')}
    assert names == expected
    assert '(Home)' in (tmp_path / 'preview/_Sidebar.md').read_text()
    assert 'https://github.com/example/fork/blob/main/docs/README.md' in (tmp_path / 'preview/Home.md').read_text()


def test_cli_refuses_overwriting_wiki_sources():
    result = subprocess.run(
        ['python3', str(ROOT / 'scripts/render-wiki.py'), '--output', str(ROOT / 'docs/wiki'),
         '--repo-url', 'https://github.com/a/b'], capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert 'must not overwrite' in result.stderr


def test_home_page_collision_is_reported(tmp_path, monkeypatch):
    root = tmp_path / 'repo'
    wiki = root / 'docs/wiki'
    wiki.mkdir(parents=True)
    (wiki / 'README.md').write_text('portal')
    (wiki / 'Home.md').write_text('another page')
    monkeypatch.setattr(renderer, 'ROOT', root)
    with pytest.raises(ValueError, match='Duplicate wiki page'):
        renderer.render(tmp_path / 'out', 'https://github.com/a/b', 'main')


@pytest.mark.parametrize('push_status', [0, 17])
def test_publication_pushes_cloned_branch_once(tmp_path, push_status):
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    calls = tmp_path / 'calls'
    git = bindir / 'git'
    git.write_text('''#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$TEST_CALLS"
if [[ "$3" == config ]]; then
    echo https://github.com/example/fork.git/
elif [[ "$1" == clone ]]; then
    mkdir -p "$3"
    echo 'keep this page' > "$3/custom-page.md"
elif [[ "$3" == diff ]]; then
    exit 1
elif [[ "$3" == push ]]; then
    test -f "$2/Home.md" && test -f "$2/_Sidebar.md" || exit 98
    test "$(cat "$2/custom-page.md")" == 'keep this page' || exit 99
    exit "$TEST_PUSH_STATUS"
fi
''')
    git.chmod(0o755)
    result = subprocess.run(['bash', str(ROOT / 'scripts/publish-wiki.sh')],
                            env={**os.environ, 'PATH': f'{bindir}:{os.environ["PATH"]}',
                                 'TEST_CALLS': str(calls), 'TEST_PUSH_STATUS': str(push_status)},
                            capture_output=True, text=True)
    assert result.returncode == push_status, result.stderr
    lines = calls.read_text().splitlines()
    assert any(line.startswith('clone https://github.com/example/fork.wiki.git ') for line in lines)
    pushes = [line for line in lines if ' push ' in line]
    assert len(pushes) == 1
    assert pushes[0].endswith(' push origin HEAD')
    assert ('Wiki published.' in result.stdout) == (push_status == 0)
