"""Release image signing: the script both publishers run, driven offline (#313).

``scripts/sign-release-image.sh`` is the whole definition of "a signed
Shapoclyack image", so what matters is its order and what it refuses: sign a
digest and never a tag, attest the build provenance, verify both the way a
customer will, and only then tag. These tests run the real script against a
recording ``cosign`` and ``docker`` and check exactly that — including that a
failure at any step leaves no tag behind, which is the property a skipped or
half-failed signing step would silently lose.

``scripts/install-cosign.sh`` is covered the same way: a binary that is not
the pinned one is refused and never installed.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SIGN = REPO_ROOT / "scripts" / "sign-release-image.sh"
INSTALL_COSIGN = REPO_ROOT / "scripts" / "install-cosign.sh"

REPO = "ghcr.io/onixus/shapoclyack-aio"
DIGEST = "sha256:" + "ab" * 32
REF = f"{REPO}@{DIGEST}"
PIN = re.search(r'^COSIGN_VERSION="(v[0-9.]+)"$', INSTALL_COSIGN.read_text(), re.M).group(1)

_V1 = {"buildDefinition": {"buildType": "https://example/buildkit"}, "runDetails": {}}
_V02 = {"buildType": "https://mobyproject.org/buildkit@v1", "invocation": {}}
PUBKEY = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfake\n-----END PUBLIC KEY-----\n"


@pytest.fixture
def signer(tmp_path: Path):
    """Run sign-release-image.sh against a cosign and docker that record calls.

    Returns run(*args, **fakes) -> (CompletedProcess, calls), where calls is the
    ordered list of argv lists both stubs received.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls.jsonl"
    # Each stub logs ["cosign"|"docker", *argv] as one JSON line.
    record = (
        "import json, sys\n"
        f"with open({str(log)!r}, 'a') as fh:\n"
        "    fh.write(json.dumps(sys.argv[1:]) + '\\n')\n"
    )
    (tmp_path / "record.py").write_text(record)
    (bindir / "cosign").write_text(
        "#!/usr/bin/env bash\n"
        f'python3 {tmp_path / "record.py"} cosign "$@"\n'
        'if [[ "$1" == "version" ]]; then echo "{\\"gitVersion\\": \\"${FAKE_COSIGN_VERSION}\\"}"; exit 0; fi\n'
        'if [[ "$1" == "public-key" ]]; then printf "%s" "${FAKE_DERIVED_PUBKEY}"; exit 0; fi\n'
        'if [[ "$1" == "${FAKE_COSIGN_FAIL:-}" ]]; then echo "cosign $1 failed" >&2; exit 1; fi\n'
        "exit 0\n"
    )
    (bindir / "docker").write_text(
        "#!/usr/bin/env bash\n"
        f'python3 {tmp_path / "record.py"} docker "$@"\n'
        'if [[ "$*" == *"{{json .Provenance}}"* ]]; then printf "%s" "${FAKE_PROVENANCE}"; exit 0; fi\n'
        'if [[ "$*" == *"{{json .Manifest}}"* ]]; then printf "{\\"digest\\": \\"%s\\"}" "${FAKE_TAG_DIGEST}"; exit 0; fi\n'
        "exit 0\n"
    )
    for stub in bindir.iterdir():
        stub.chmod(0o755)
    pubkey = tmp_path / "cosign.pub"
    pubkey.write_text(PUBKEY)

    def run(
        *args: str,
        provenance: object = None,
        fail: str = "",
        tag_digest: str = DIGEST,
        version: str = PIN,
        derived: str = PUBKEY,
    ):
        log.unlink(missing_ok=True)
        if provenance is None:
            provenance = {"linux/amd64": {"SLSA": _V1}, "linux/arm64": {"SLSA": _V1}}
        env = dict(
            os.environ,
            PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}",
            FAKE_PROVENANCE=json.dumps(provenance),
            FAKE_COSIGN_FAIL=fail,
            FAKE_TAG_DIGEST=tag_digest,
            FAKE_COSIGN_VERSION=version,
            FAKE_DERIVED_PUBKEY=derived,
        )
        proc = subprocess.run(
            ["bash", str(SIGN), *[a.replace("@PUBKEY@", str(pubkey)) for a in args]],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return proc, calls

    return run


def _key_args(*extra: str) -> list[str]:
    return ["--key", "cosign.key", "--pubkey", "@PUBKEY@", *extra]


def _keyless_args(*extra: str) -> list[str]:
    return [
        "--keyless",
        "--identity",
        "https://github.com/onixus/Shapoclyack/.github/workflows/docker-publish.yml@refs/tags/shapoclyack-0.47-1001",
        "--issuer",
        "https://token.actions.githubusercontent.com",
        *extra,
    ]


def _cosign(calls: list[list[str]], sub: str) -> list[list[str]]:
    return [c[1:] for c in calls if c[0] == "cosign" and c[1] == sub]


def _tagged(calls: list[list[str]]) -> list[str]:
    return [c[c.index("--tag") + 1] for c in calls if c[0] == "docker" and "create" in c]


# --- the happy path, in order ------------------------------------------------


def test_key_mode_signs_the_digest_attests_verifies_then_tags(signer):
    tags = [f"{REPO}:shapoclyack-0.47-1001", f"{REPO}:latest"]
    proc, calls = signer(
        *_key_args("--release", "shapoclyack-0.47-1001", "--tag", tags[0], "--tag", tags[1], REF)
    )
    assert proc.returncode == 0, proc.stderr

    (sign,) = _cosign(calls, "sign")
    assert sign[-1] == REF, "the signature must be over the digest, not a tag"
    assert sign[sign.index("--key") + 1] == "cosign.key"
    assert "--recursive" in sign, "each platform manifest is signed too"
    assert "--tlog-upload=true" in sign
    assert sign[sign.index("-a") + 1] == "release=shapoclyack-0.47-1001"

    attests = _cosign(calls, "attest")
    assert len(attests) == 2, "one SLSA v1 attestation per platform"
    for attest in attests:
        assert attest[-1] == REF
        assert attest[attest.index("--type") + 1] == "slsaprovenance1"

    # Verified against the committed public key, with the release annotation
    # required — the same command docs/supply-chain.md gives customers.
    (verify,) = _cosign(calls, "verify")
    assert verify[verify.index("--key") + 1].endswith("cosign.pub")
    assert verify[verify.index("-a") + 1] == "release=shapoclyack-0.47-1001"
    assert verify[-1] == REF
    (verify_att,) = _cosign(calls, "verify-attestation")
    assert verify_att[verify_att.index("--type") + 1] == "slsaprovenance1"

    assert _tagged(calls) == tags
    steps = []
    for call in calls:
        if call[0] == "cosign" and call[1] != "version":
            steps.append(call[1])
        elif call[0] == "docker" and "create" in call:
            steps.append("tag")
    assert steps == ["sign", "attest", "attest", "verify", "verify-attestation", "tag", "tag"]


def test_keyless_mode_verifies_the_exact_identity(signer):
    tag = f"{REPO}:shapoclyack-0.47-1001"
    proc, calls = signer(*_keyless_args("--tag", tag, REF))
    assert proc.returncode == 0, proc.stderr
    (sign,) = _cosign(calls, "sign")
    assert "--key" not in sign, "keyless signs with the ambient OIDC certificate"
    for verify in (*_cosign(calls, "verify"), *_cosign(calls, "verify-attestation")):
        assert verify[verify.index("--certificate-identity") + 1] == (
            "https://github.com/onixus/Shapoclyack/.github/workflows/docker-publish.yml"
            "@refs/tags/shapoclyack-0.47-1001"
        )
        assert verify[verify.index("--certificate-oidc-issuer") + 1] == (
            "https://token.actions.githubusercontent.com"
        )
        assert "--certificate-identity-regexp" not in verify
    assert _tagged(calls) == [tag]


def test_a_single_platform_image_is_attested_too(signer):
    proc, calls = signer(*_key_args(REF), provenance={"SLSA": _V1})
    assert proc.returncode == 0, proc.stderr
    assert len(_cosign(calls, "attest")) == 1


# --- fail closed: nothing gets a tag unless everything before it passed -----


@pytest.mark.parametrize("step", ["sign", "attest", "verify", "verify-attestation"])
def test_a_failed_step_leaves_no_tag(signer, step: str):
    proc, calls = signer(*_key_args("--tag", f"{REPO}:latest", REF), fail=step)
    assert proc.returncode != 0
    assert _tagged(calls) == []


def test_a_tag_that_does_not_resolve_to_the_signed_digest_fails(signer):
    proc, _ = signer(*_key_args("--tag", f"{REPO}:latest", REF), tag_digest="sha256:" + "cd" * 32)
    assert proc.returncode != 0
    assert "not the signed" in proc.stderr


@pytest.mark.parametrize(
    "ref",
    [
        f"{REPO}:shapoclyack-0.47-1001",
        f"{REPO}:shapoclyack-0.47-1001@{DIGEST}",
        f"{REPO}@sha256:abc",
        REPO,
    ],
)
def test_only_a_bare_digest_is_signed(signer, ref: str):
    proc, calls = signer(*_key_args(ref))
    assert proc.returncode != 0
    assert _cosign(calls, "sign") == []


@pytest.mark.parametrize(
    "provenance",
    [{}, {"linux/amd64": {"SLSA": None}}, {"linux/amd64": {"SLSA": _V02}}],
    ids=["none", "empty", "slsa-v0.2"],
)
def test_no_signature_without_slsa_v1_provenance(signer, provenance):
    proc, calls = signer(*_key_args(REF), provenance=provenance)
    assert proc.returncode != 0
    assert "provenance" in proc.stderr
    assert _cosign(calls, "sign") == []


def test_a_tag_for_another_repository_is_refused_before_signing(signer):
    proc, calls = signer(*_key_args("--tag", "ghcr.io/someone/else:latest", REF))
    assert proc.returncode != 0
    assert _cosign(calls, "sign") == []


def test_a_cosign_other_than_the_pinned_one_is_refused(signer):
    proc, calls = signer(*_key_args(REF), version="v3.1.3")
    assert proc.returncode != 0
    assert "not the pinned" in proc.stderr
    assert _cosign(calls, "sign") == []


def test_key_mode_without_the_public_key_file_is_refused(signer):
    proc, calls = signer("--key", "cosign.key", "--pubkey", "/nonexistent/cosign.pub", REF)
    assert proc.returncode != 0
    assert "missing or empty" in proc.stderr
    assert _cosign(calls, "sign") == []


def test_keyless_mode_without_an_identity_is_refused(signer):
    """cosign verify with no identity constraint accepts anyone's signature."""
    proc, calls = signer("--keyless", "--issuer", "https://token.actions.githubusercontent.com", REF)
    assert proc.returncode != 0
    assert _cosign(calls, "sign") == []


# --- the pre-flight key check --------------------------------------------------


def test_check_key_accepts_the_private_half_of_the_committed_key(signer):
    proc, calls = signer("--check-key", *_key_args(), derived=PUBKEY.replace("\n", "\r\n"))
    assert proc.returncode == 0, proc.stderr
    assert _cosign(calls, "sign") == []


def test_check_key_refuses_a_key_customers_do_not_trust(signer):
    other = PUBKEY.replace("fake", "other")
    proc, _ = signer("--check-key", *_key_args(), derived=other)
    assert proc.returncode != 0
    assert "not the private half" in proc.stderr


# --- the pinned cosign ---------------------------------------------------------


def _pins() -> dict[str, str]:
    text = INSTALL_COSIGN.read_text()
    return dict(re.findall(r'asset="(cosign-[a-z0-9-]+)"\s+want="([0-9a-f]{64})"', text))


def test_cosign_is_pinned_for_every_platform_the_pipelines_run_on():
    # Jenkins on the maintainer's Mac or in its Linux container, GitHub's
    # ubuntu runners; both architectures of each.
    assert set(_pins()) == {
        "cosign-linux-amd64",
        "cosign-linux-arm64",
        "cosign-darwin-amd64",
        "cosign-darwin-arm64",
    }


def test_install_cosign_refuses_a_binary_that_is_not_the_pinned_one(tmp_path: Path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    served = tmp_path / "served"
    served.write_bytes(b"#!/bin/sh\necho not cosign\n")
    # A curl that serves the wrong bytes for any URL, and a uname that says
    # linux/x86_64 whatever this machine is.
    (bindir / "curl").write_text(
        "#!/usr/bin/env bash\n"
        'while [[ $# -gt 0 ]]; do if [[ "$1" == "-o" ]]; then dest="$2"; shift; fi; shift; done\n'
        f'cp "{served}" "$dest"\n'
    )
    (bindir / "uname").write_text(
        '#!/usr/bin/env bash\nif [[ "$1" == "-s" ]]; then echo Linux; else echo x86_64; fi\n'
    )
    for stub in bindir.iterdir():
        stub.chmod(0o755)
    dest = tmp_path / "tools"
    proc = subprocess.run(
        ["bash", str(INSTALL_COSIGN), str(dest)],
        env=dict(os.environ, PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}"),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode != 0
    assert "sha256 mismatch" in proc.stderr
    assert not (dest / "cosign").exists()


def test_install_cosign_refuses_an_unpinned_platform(tmp_path: Path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "uname").write_text(
        '#!/usr/bin/env bash\nif [[ "$1" == "-s" ]]; then echo FreeBSD; else echo riscv64; fi\n'
    )
    (bindir / "uname").chmod(0o755)
    proc = subprocess.run(
        ["bash", str(INSTALL_COSIGN), str(tmp_path / "tools")],
        env=dict(os.environ, PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}"),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode != 0
    assert "no pinned" in proc.stderr
