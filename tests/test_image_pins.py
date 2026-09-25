"""Every image the builds, pipelines and manifests pull is pinned by digest (#313).

A tag is a name the registry lets its owner move. `python:3.12-slim`,
`aquasec/trivy:latest` or a build stage's `golang:1.26-bookworm` can mean a
different image on the next build than on the one that was reviewed, and
nothing in the repository would show it. Pinned as `name:tag@sha256:…`, the
tag stays for humans and Renovate, and the digest decides what is pulled.

The check reads each kind of file the way it names images — Dockerfile
`FROM`, `image:` in manifests and workflows, the Jenkinsfiles' image
constants and `docker run`, script defaults `${X_IMAGE:-…}` — and fails on any
reference without a digest. The few that legitimately have none are listed in
LOCAL_IMAGES with the reason; everything else is a failure, so a new stage,
workflow or manifest is covered without anyone remembering to add it here.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
# name:tag@sha256:<digest>. The tag is required too: a bare name@sha256 pulls
# the right bytes but gives Renovate nothing to compare a newer release with,
# so the pin would never be proposed for a refresh and would quietly age.
PINNED = re.compile(r"^[a-z0-9][a-z0-9._/:-]*:[A-Za-z0-9_][A-Za-z0-9._-]{0,127}@sha256:[0-9a-f]{64}$")

# Built by the job or script that runs them, never pulled from a registry, so
# there is no digest to pin. Matched as a prefix of the reference.
LOCAL_IMAGES = {
    "network-scan-cli:": "the CI image built earlier in the same job",
    "ghcr.io/onixus/shapoclyack-aio:kind-dev": "built by scripts/dev-up.sh and loaded into kind",
}


def _is_local(ref: str) -> bool:
    return any(ref.startswith(prefix) for prefix in LOCAL_IMAGES)


def _assert_pinned(where: str, ref: str) -> None:
    if _is_local(ref):
        return
    assert PINNED.match(ref), f"{where}: {ref!r} is not pinned by digest (name:tag@sha256:…)"


def _text(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


# --- Dockerfiles: every stage ------------------------------------------------

DOCKERFILES = sorted(p.name for p in REPO_ROOT.glob("Dockerfile*"))


@pytest.mark.parametrize("dockerfile", DOCKERFILES)
def test_every_dockerfile_stage_is_pinned(dockerfile: str):
    stages: set[str] = set()
    froms = 0
    for line in _text(dockerfile).splitlines():
        match = re.match(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$", line, re.I)
        if not match:
            continue
        froms += 1
        ref, alias = match.group(1), match.group(2)
        if ref not in stages and ref != "scratch":
            _assert_pinned(f"{dockerfile} FROM", ref)
        if alias:
            stages.add(alias)
    assert froms, f"{dockerfile}: no FROM found"


# --- Kubernetes manifests ----------------------------------------------------


def _walk(node, path=()):
    if isinstance(node, dict):
        for key, value in node.items():
            yield path + (key,), key, value
            yield from _walk(value, path + (key,))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk(value, path + (index,))


def _dicts(node):
    """Every mapping in a parsed document, list elements included."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _dicts(value)
    elif isinstance(node, list):
        for value in node:
            yield from _dicts(value)


K8S_FILES = sorted(str(p.relative_to(REPO_ROOT)) for p in (REPO_ROOT / "k8s").rglob("*.y*ml"))


@pytest.mark.parametrize("path", K8S_FILES)
def test_every_kubernetes_image_is_pinned(path: str):
    for doc in yaml.safe_load_all(_text(path)):
        for _keys, key, value in _walk(doc):
            if key == "image" and isinstance(value, str):
                _assert_pinned(path, value)
        if isinstance(doc, dict) and doc.get("kind") == "Kustomization" or path.endswith(
            "kustomization.yaml"
        ):
            # A kustomize images: entry rewrites what the manifests pin. A
            # newTag alone drops the digest and a digest alone drops the tag,
            # so an entry that sets either sets both. One that only renames
            # (newName, the air-gap overlay's registry, #339) keeps the
            # manifests' tag@digest, which the files it renames are checked
            # for; test_every_rendered_image_is_pinned proves it on the render.
            for entry in (doc or {}).get("images", []) or []:
                if "newTag" not in entry and "digest" not in entry:
                    continue
                ref = f"{entry.get('newName', entry['name'])}:{entry.get('newTag', '')}"
                if not _is_local(ref):
                    assert "newTag" in entry and entry.get("digest", "").startswith("sha256:"), f"{path}: {entry}"


OVERLAYS = sorted(
    p.name for p in (REPO_ROOT / "k8s/shapoclyack/overlays").iterdir() if (p / "kustomization.yaml").is_file()
)


@pytest.mark.skipif(shutil.which("kubectl") is None, reason="needs kubectl (kustomize)")
@pytest.mark.parametrize("overlay", OVERLAYS)
def test_every_rendered_image_is_pinned(overlay: str):
    """What a cluster pulls is the render, not the files: base manifests,
    components, patches and images: entries together."""
    proc = subprocess.run(  # noqa: S603 - fixed argv
        [shutil.which("kubectl"), "kustomize", str(REPO_ROOT / "k8s/shapoclyack/overlays" / overlay)],
        capture_output=True,
        text=True,
        check=True,
    )
    images = [
        value
        for doc in yaml.safe_load_all(proc.stdout)
        for _keys, key, value in _walk(doc)
        if key == "image" and isinstance(value, str)
    ]
    assert images, f"overlays/{overlay} renders no image; the walk is broken"
    for ref in images:
        _assert_pinned(f"overlays/{overlay} (rendered)", ref)


# --- GitHub workflows and actions --------------------------------------------

GITHUB_FILES = sorted(str(p.relative_to(REPO_ROOT)) for p in (REPO_ROOT / ".github").rglob("*.y*ml"))
_BUILDX_OPTION = re.compile(r"\b(?:image|generator)=([^\s,\"']+)")


def _is_publish_destination(path: str, keys: tuple) -> bool:
    # docker-publish.yml's matrix names the repositories it pushes TO.
    return path.endswith("docker-publish.yml") and "matrix" in keys


@pytest.mark.parametrize("path", GITHUB_FILES)
def test_every_workflow_image_is_pinned(path: str):
    doc = yaml.safe_load(_text(path))
    for keys, key, value in _walk(doc):
        if not isinstance(value, str) or "${{" in value:
            continue
        if isinstance(key, str) and (key == "image" or key.endswith("_IMAGE")):
            if not _is_publish_destination(path, keys):
                _assert_pinned(f"{path} {'.'.join(map(str, keys))}", value)
        for ref in _BUILDX_OPTION.findall(value):
            _assert_pinned(f"{path} {'.'.join(map(str, keys))}", ref)
        if key == "run":
            for image in _docker_run_images(value):
                _assert_image_argument(f"{path} run", image)


@pytest.mark.parametrize("path", GITHUB_FILES)
def test_every_buildx_and_qemu_setup_pins_its_image(path: str):
    """The BuildKit daemon runs every build step and writes the provenance;
    the actions' defaults are moving tags."""
    steps = [node for node in _dicts(yaml.safe_load(_text(path))) if "uses" in node]
    if path.endswith(("ci.yml", "docker-publish.yml", "action.yml")):
        assert steps, f"{path}: no steps found; the walk is broken"
    for step in steps:
        uses, options = step["uses"], step.get("with") or {}
        if uses.startswith("docker/setup-buildx-action@"):
            refs = _BUILDX_OPTION.findall(options.get("driver-opts", ""))
            assert refs, f"{path}: setup-buildx-action without a pinned driver image"
        if uses.startswith("docker/setup-qemu-action@"):
            _assert_pinned(f"{path} setup-qemu", options.get("image", ""))


# --- docker run in pipeline scripts ------------------------------------------

# docker run flags that take a separate value, and those that take none. A flag
# in neither is an error: guessing would misread the image argument.
_RUN_VALUE_FLAGS = {
    "-v", "--volume", "-e", "--env", "-w", "--workdir", "-p", "--publish", "--name",
    "--network", "--network-alias", "--entrypoint", "--cap-add", "--cap-drop",
    "--tmpfs", "--env-file", "-u", "--user", "--mount", "--platform", "--restart",
}
_RUN_BOOL_FLAGS = {"--rm", "-d", "--detach", "-i", "-t", "-it", "--init", "--read-only"}


def _docker_run_images(script: str) -> list[str]:
    joined = re.sub(r"\\\n\s*", " ", script)
    images = []
    for match in re.finditer(r"\bdocker run\b([^\n;|&]*)", joined):
        prefix = joined[joined.rfind("\n", 0, match.start()) + 1 : match.start()]
        if "#" in prefix or "//" in prefix:
            continue  # prose in a comment
        # Token by token: what follows the image (`-c '…` spanning lines) is
        # not this check's business and need not even parse.
        lexer = shlex.shlex(match.group(1), posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        while (token := lexer.get_token()) is not None:
            if not token.startswith("-"):
                images.append(token)
                break
            if "=" in token or token in _RUN_BOOL_FLAGS:
                continue
            assert token in _RUN_VALUE_FLAGS, f"unknown docker run flag {token!r}; teach this test"
            lexer.get_token()
    return images


def _assert_image_argument(where: str, image: str) -> None:
    # A shell or Groovy variable is checked where it is defined.
    if image.startswith("$"):
        return
    _assert_pinned(where, image)


# --- Jenkinsfiles --------------------------------------------------------------

JENKINSFILES = sorted(p.name for p in REPO_ROOT.glob("Jenkinsfile*"))


def _groovy_constants(text: str) -> dict[str, list[str]]:
    constants = {name: [value] for name, value in re.findall(r"^def (\w+_IMAGE|\w+_GENERATOR) = '([^']*)'$", text, re.M)}
    for name, body in re.findall(r"^def (\w+_IMAGES) = \[(.*?)^\]", text, re.M | re.S):
        constants[name] = re.findall(r":\s*'([^']+)'", body)
    return constants


@pytest.mark.parametrize("jenkinsfile", JENKINSFILES)
def test_every_jenkins_image_is_pinned(jenkinsfile: str):
    text = _text(jenkinsfile)
    constants = _groovy_constants(text)
    for name, refs in constants.items():
        assert refs, f"{jenkinsfile}: {name} is empty"
        for ref in refs:
            _assert_pinned(f"{jenkinsfile} {name}", ref)
    # Images named at the point of use: docker.image(…), agent { docker { image … } }.
    for arg in re.findall(r"docker\.image\(([^)]*)\)", text) + re.findall(
        r"docker\s*\{\s*image\s+([^;}\n]+)", text
    ):
        arg = arg.strip()
        literal = re.fullmatch(r"""['"]([^'"]*)['"]""", arg)
        if literal:
            assert "$" not in literal.group(1), f"{jenkinsfile}: interpolated image {arg}"
            _assert_pinned(jenkinsfile, literal.group(1))
        else:
            name = re.match(r"(\w+)", arg).group(1)
            assert name in constants, f"{jenkinsfile}: image {arg} is not a pinned constant"
    for image in _docker_run_images(text):
        if image.startswith("${") and image.strip("${}") in constants:
            continue
        _assert_image_argument(jenkinsfile, image)


def test_the_jenkins_python_images_cover_the_test_matrix():
    text = _text("Jenkinsfile")
    matrix = re.search(r"for \(PY in \[([^\]]*)\]\)", text).group(1)
    body = re.search(r"^def PYTHON_IMAGES = \[(.*?)^\]", text, re.M | re.S).group(1)
    assert set(re.findall(r"'(3\.\d+)'", matrix)) == set(re.findall(r"'(3\.\d+)':", body))


def test_the_release_builder_runs_the_pinned_buildkit():
    text = _text("Jenkinsfile.publish")
    assert "--driver-opt image=${BUILDKIT_IMAGE}" in text
    assert "generator=${SBOM_GENERATOR}" in text


# --- script defaults and the server installer ---------------------------------

SCRIPT_DIRS = ["scripts", "k8s/scripts", "tests/e2e", "tests/load", "bench"]

# Not a build, pipeline or manifest: the sensor host installer's default is
# the operator's release choice, like the image the API's deployment snippets
# print. Pinning those to the release digest is a release-process change of
# its own, listed as a follow-up in docs/supply-chain.md.
_NOT_BUILD_INPUTS = {"scripts/install-agent.sh"}


def _script_files() -> list[str]:
    files = []
    for directory in SCRIPT_DIRS:
        for path in sorted((REPO_ROOT / directory).iterdir()):
            relative = str(path.relative_to(REPO_ROOT))
            if path.is_file() and path.suffix in {".sh", ".defaults", ""} and relative not in _NOT_BUILD_INPUTS:
                files.append(relative)
    return files


@pytest.mark.parametrize("path", _script_files())
def test_every_script_default_image_is_pinned(path: str):
    for ref in re.findall(r"IMAGE:-([^}\"]+)\}", _text(path)):
        _assert_pinned(path, ref)


def test_the_server_installer_writes_only_pinned_images():
    spec = importlib.util.spec_from_file_location(
        "server_installer_pins", REPO_ROOT / "scripts/install-server.py"
    )
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    compose = installer.manifest(installer.DEFAULT_IMAGE, "https://scan.example.com", 8080, "x" * 32)
    for name, service in compose["services"].items():
        _assert_pinned(f"install-server.py compose service {name}", service["image"])


# --- the checker itself ---------------------------------------------------------


@pytest.mark.parametrize(
    "ref",
    [
        "python:3.12-slim",
        "aquasec/trivy:latest",
        "nginx",
        "postgres:16-alpine@sha256:abc",
        # Pinned, but with no tag for Renovate to track.
        "lscr.io/linuxserver/openssh-server@sha256:" + "0" * 64,
        "registry.example:5000/app@sha256:" + "0" * 64,
    ],
)
def test_an_unpinned_reference_is_refused(ref: str):
    with pytest.raises(AssertionError):
        _assert_pinned("test", ref)


@pytest.mark.parametrize(
    "ref",
    [
        "python:3.12-slim@sha256:" + "0" * 64,
        "lscr.io/linuxserver/openssh-server:10.3_p1-r1-ls235@sha256:" + "0" * 64,
        "registry.example:5000/team/app:1.2@sha256:" + "0" * 64,
    ],
)
def test_a_tagged_digest_is_accepted(ref: str):
    _assert_pinned("test", ref)


def test_docker_run_parsing_finds_the_image_argument():
    script = (
        'docker run --rm -v "$W":/w -w /w --entrypoint sh aquasec/trivy:latest image x\n'
        "docker run -d --name n -p 1:1 \\\n  nats:2 --jetstream\n"
    )
    assert _docker_run_images(script) == ["aquasec/trivy:latest", "nats:2"]


# --- Renovate can see every pin outside the files its own managers parse ------

RENOVATE = (REPO_ROOT / ".github" / "renovate.json5").read_text(encoding="utf-8")
_ANY_PIN = re.compile(r"[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9_][A-Za-z0-9._-]*)?@sha256:[0-9a-f]{64}")


def _renovate_regex_managers() -> list[tuple[list[re.Pattern], list[re.Pattern]]]:
    """(file patterns, match strings) of each customManagers entry.

    Read from the JSON5 text rather than parsed: the two lists are plain JSON
    strings, which is all that is needed, and Renovate's (?<name>…) groups are
    turned into Python's (?P<name>…)."""
    managers = []
    for files, strings in re.findall(
        r"managerFilePatterns:\s*\[(.*?)\],\s*matchStrings:\s*\[(.*?)\],", RENOVATE, re.S
    ):
        decode = [json.loads(f'"{s}"') for s in re.findall(r'"((?:[^"\\]|\\.)*)"', files)]
        file_patterns = [re.compile(p.strip("/")) for p in decode]
        match_strings = [
            re.compile(json.loads(f'"{s}"').replace("(?<", "(?P<"))
            for s in re.findall(r'"((?:[^"\\]|\\.)*)"', strings)
        ]
        managers.append((file_patterns, match_strings))
    assert managers, "no customManagers found in .github/renovate.json5"
    return managers


# Files whose pins only a regex manager can reach: no Renovate manager parses
# Groovy, shell defaults or a Python constant.
_REGEX_MANAGED = [
    *JENKINSFILES,
    *_script_files(),
    "scripts/install-server.py",
]


@pytest.mark.parametrize("path", _REGEX_MANAGED)
def test_renovate_tracks_every_pin_in_files_only_a_regex_manager_reads(path: str):
    """A pin Renovate cannot see is never proposed for a refresh; the SSH test
    image sat as a bare name@sha256 that no match string could read."""
    text = _text(path)
    tracked = set()
    for file_patterns, match_strings in _renovate_regex_managers():
        if not any(p.search(path) for p in file_patterns):
            continue
        for pattern in match_strings:
            for m in pattern.finditer(text):
                tracked.add(f"{m['depName']}:{m['currentValue']}@{m['currentDigest']}")
    for ref in _ANY_PIN.findall(text):
        if not _is_local(ref):
            assert ref in tracked, f"{path}: Renovate does not track {ref}"
