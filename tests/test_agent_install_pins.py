"""What a sensor host is told to run is published, pinned and hash-checked.

The console's deployment snippets and ``scripts/install-agent.sh`` are how a
sensor host gets its code, and nothing downstream checks what they name. The
snippets used to name ``ghcr.io/onixus/shapoclyack:latest``, a repository the
release pipeline has never published (an anonymous pull is refused), and the
native installer pip-installed five unpinned packages the sensor does not
import while leaving out nats-py, which it does.

So the image has to be one ``Jenkinsfile.publish`` pushes, built from the
Dockerfile that carries the ``agent`` package, pinned as ``tag@sha256`` in
both places; and the native install has to go through a hash lock that covers
what ``agent/`` imports.
"""

from __future__ import annotations

import ast
import re
import shlex
import subprocess
import sys
from pathlib import Path

import yaml

from api.services.agents import SENSOR_IMAGE, get_deployment_snippets

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "scripts" / "install-agent.sh"
LOCK = REPO_ROOT / "requirements-agent.lock"
LOCK_INPUT = REPO_ROOT / "requirements-agent.txt"

# name:tag@sha256:<digest>, the tag being a release tag in the form
# Jenkinsfile.publish accepts for TAG. The tag is kept for humans; the digest
# is what gets pulled.
PINNED = re.compile(
    r"^(?P<repo>[a-z0-9][a-z0-9._/-]*)"
    r":(?P<tag>shapoclyack-\d+\.\d+-\d{4}(?:-(?:alpha|beta|rc)\d+)?)"
    r"@sha256:[0-9a-f]{64}$"
)

# The sensor worker's own command, and the capabilities naabu's file
# capabilities need to be allowed at all (Dockerfile: setcap
# cap_net_raw,cap_net_admin+eip).
SENSOR_COMMAND = ["python", "-m", "agent"]
SCAN_CAPABILITIES = {"NET_RAW", "NET_ADMIN"}


def _published_images() -> dict[str, set[str]]:
    """Repository -> the Dockerfiles Jenkinsfile.publish builds it from."""
    text = (REPO_ROOT / "Jenkinsfile.publish").read_text(encoding="utf-8")
    rows = re.findall(r"dockerfile:\s*'([^']+)',\s*image:\s*'([^']+)'", text)
    assert rows, "the image matrix in Jenkinsfile.publish moved; update this test"
    published: dict[str, set[str]] = {}
    for dockerfile, image in rows:
        published.setdefault(image, set()).add(dockerfile)
    return published


def _snippets() -> dict:
    return get_deployment_snippets(
        "default", "https://console.example.com", provisioning_key="octo-pk-test"
    )


# --- the image ---------------------------------------------------------------


def test_the_sensor_image_is_pinned_to_a_release_digest():
    assert PINNED.match(SENSOR_IMAGE), SENSOR_IMAGE


def test_the_sensor_image_is_one_the_release_publishes_with_the_sensor_in_it():
    repo = PINNED.match(SENSOR_IMAGE).group("repo")
    published = _published_images()
    assert repo in published, f"{repo} is not pushed by Jenkinsfile.publish: {sorted(published)}"
    for dockerfile in published[repo]:
        text = (REPO_ROOT / dockerfile).read_text(encoding="utf-8")
        assert re.search(r"^COPY agent /app/agent$", text, re.M), (
            f"{dockerfile} builds {repo} without the agent package"
        )


def test_the_installer_default_is_the_image_the_snippets_print():
    text = INSTALLER.read_text(encoding="utf-8")
    defaults = re.findall(r'^AGENT_IMAGE="\$\{AGENT_IMAGE:-([^}"]+)\}"$', text, re.M)
    assert defaults == [SENSOR_IMAGE]
    # No second literal hiding somewhere the release sed would have to find.
    assert set(re.findall(r"ghcr\.io/[^\s\"'}]+", text)) == {SENSOR_IMAGE}
    assert '"${AGENT_IMAGE}"' in text


# --- the snippets ------------------------------------------------------------


def test_no_snippet_names_any_other_image():
    for name, snippet in _snippets().items():
        if not isinstance(snippet, str):
            continue
        for ref in re.findall(r"ghcr\.io/[^\s\"']+", snippet):
            assert ref == SENSOR_IMAGE, f"{name}: {ref}"
        assert ":latest" not in snippet, name


def test_docker_run_starts_the_sensor_with_scan_capabilities():
    argv = shlex.split(_snippets()["docker_run"])
    assert argv[:2] == ["docker", "run"]
    # The image's ENTRYPOINT is scanner.main; `python -m agent` as a command
    # would only be arguments to it, and the scanner exits on them.
    at = argv.index("--entrypoint")
    assert argv[at + 1 : at + 3] == ["python", SENSOR_IMAGE]
    assert argv[at + 3 :] == ["-m", "agent"]
    caps = {argv[i + 1] for i, arg in enumerate(argv) if arg == "--cap-add"}
    assert SCAN_CAPABILITIES <= caps


def test_compose_starts_the_sensor_with_scan_capabilities():
    services = yaml.safe_load(_snippets()["docker_compose"])["services"]
    (service,) = services.values()
    assert service["image"] == SENSOR_IMAGE
    assert service["entrypoint"] == SENSOR_COMMAND
    assert "command" not in service
    assert SCAN_CAPABILITIES <= set(service["cap_add"])


def test_kubernetes_starts_the_sensor_with_scan_capabilities():
    doc = yaml.safe_load(_snippets()["kubernetes_yaml"])
    (container,) = doc["spec"]["template"]["spec"]["containers"]
    assert container["image"] == SENSOR_IMAGE
    assert container["command"] == SENSOR_COMMAND
    security = container["securityContext"]
    assert SCAN_CAPABILITIES <= set(security["capabilities"]["add"])
    # no_new_privs does not fail the exec; naabu just drops to a connect scan.
    assert security.get("allowPrivilegeEscalation") is not False


# --- the native install ------------------------------------------------------

_ENTRY = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[^\s;\\]+)")
_HASH = re.compile(r"^\s+--hash=sha256:[0-9a-f]{64}\s*\\?$")


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _lock_entries() -> dict[str, tuple[str, int]]:
    """name -> (version, number of hashes)."""
    entries: dict[str, list] = {}
    current = None
    for raw in LOCK.read_text(encoding="utf-8").splitlines():
        match = _ENTRY.match(raw)
        if match:
            current = entries.setdefault(_canonical(match["name"]), [match["version"], 0])
        elif _HASH.match(raw):
            assert current is not None, raw
            current[1] += 1
        else:
            assert not raw.strip() or raw.strip().startswith("#"), f"unexpected line {raw!r}"
    return {name: (version, hashes) for name, (version, hashes) in entries.items()}


def _pins(path: Path) -> dict[str, str]:
    pins = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            match = _ENTRY.match(line)
            assert match and line == match.group(0), f"{path.name}: {line!r} is not name==version"
            pins[_canonical(match["name"])] = match["version"]
    return pins


def test_the_installer_writes_exactly_the_lock(tmp_path):
    """Run the heredoc, not a regex over it: quoting or a stray tab would show."""
    text = INSTALLER.read_text(encoding="utf-8")
    function = re.search(r"^write_agent_lock\(\) \{\n.*?^\}\n", text, re.M | re.S)
    assert function, "write_agent_lock() moved in install-agent.sh"
    out = tmp_path / "written.lock"
    subprocess.run(
        ["bash", "-c", function.group(0) + 'write_agent_lock "$1"', "bash", str(out)],
        check=True,
    )
    assert out.read_bytes() == LOCK.read_bytes(), (
        "scripts/install-agent.sh carries a different lock than requirements-agent.lock; "
        "paste the regenerated lock between its LOCK lines"
    )


def test_the_lock_is_compiled_from_its_input_the_way_the_header_says():
    header = LOCK.read_text(encoding="utf-8").splitlines()[:2]
    assert header == [
        "# This file was autogenerated by uv via the following command:",
        "#    uv pip compile --universal --no-strip-extras --generate-hashes"
        " --python-version=3.11 --output-file=requirements-agent.lock requirements-agent.txt",
    ]
    entries = _lock_entries()
    for name, (version, hashes) in entries.items():
        assert hashes, f"{name}=={version} has no hash"
    for name, version in _pins(LOCK_INPUT).items():
        assert entries.get(name, (None,))[0] == version, (
            f"requirements-agent.txt pins {name}=={version}; regenerate requirements-agent.lock"
        )


def test_the_native_sensor_uses_the_nats_client_of_the_image():
    assert _pins(LOCK_INPUT)["nats-py"] == _pins(REPO_ROOT / "requirements.txt")["nats-py"]


# Imported by agent/ but deliberately not installed: nats-py needs aiohttp only
# for ws:// and wss:// URLs, and the worker refuses those with instructions
# when it is missing (agent/worker.py, check_nats_transport).
_OPTIONAL_IMPORTS = {"aiohttp"}
# Import name -> distribution, where they differ.
_DISTRIBUTIONS = {"nats": "nats-py"}


def test_the_lock_covers_what_the_agent_package_imports():
    imported: set[str] = set()
    for path in (REPO_ROOT / "agent").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                imported |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported.add(node.module.split(".")[0])
    third_party = imported - set(sys.stdlib_module_names) - {"agent", "__future__"}
    needed = {_canonical(_DISTRIBUTIONS.get(name, name)) for name in third_party - _OPTIONAL_IMPORTS}
    assert needed <= set(_lock_entries()), f"agent/ imports {sorted(needed - set(_lock_entries()))}"
    assert set(_pins(LOCK_INPUT)) <= needed, "requirements-agent.txt names what agent/ does not import"


def test_every_pip_install_in_the_installer_is_hash_checked():
    text = INSTALLER.read_text(encoding="utf-8").replace("\\\n", " ")
    installs = [line for line in text.splitlines() if re.search(r"\bpip\"? install\b", line)]
    assert installs, "no pip install found; update this test"
    for line in installs:
        assert "--require-hashes" in line, line
        assert "--only-binary :all:" in line, line
        assert '-r "${INSTALL_DIR}/requirements-agent.lock"' in line, line
        assert "--upgrade" not in line, line
