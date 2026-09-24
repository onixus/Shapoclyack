"""Release image signing: the script both publishers run, driven offline (#313).

``scripts/sign-release-image.sh`` is the whole definition of "a signed
Shapoclyack image", so what matters is its order and what it refuses: sign a
digest and never a tag, attest the build provenance — on the index and on each
platform manifest, since a pod may name either — verify all of it the way a
customer will, and only then tag. These tests run the real script against a
recording ``cosign`` and ``docker`` and check exactly that — including that a
failure at any step leaves no tag behind, which is the property a skipped or
half-failed signing step would silently lose.

``scripts/install-cosign.sh`` is covered the same way: a binary that is not
the pinned one is refused and never installed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SIGN = REPO_ROOT / "scripts" / "sign-release-image.sh"
INSTALL_COSIGN = REPO_ROOT / "scripts" / "install-cosign.sh"
PIN = re.search(r'^COSIGN_VERSION="(v[0-9.]+)"$', INSTALL_COSIGN.read_text(), re.M).group(1)

REPO = "ghcr.io/onixus/shapoclyack-aio"
AMD64 = "sha256:" + "11" * 32
ARM64 = "sha256:" + "22" * 32
PLATFORM_DIGESTS = {"linux/amd64": AMD64, "linux/arm64": ARM64}


def _index(platforms: dict[str, str]) -> bytes:
    """An image index the way BuildKit pushes one: platform manifests plus one
    attestation manifest (platform unknown/unknown) per platform."""
    manifests = []
    for platform, digest in platforms.items():
        os_, arch = platform.split("/")
        manifests.append(
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": digest,
                "size": 1000,
                "platform": {"architecture": arch, "os": os_},
            }
        )
    for platform, digest in platforms.items():
        manifests.append(
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:" + hashlib.sha256(platform.encode()).hexdigest(),
                "size": 800,
                "annotations": {
                    "vnd.docker.reference.digest": digest,
                    "vnd.docker.reference.type": "attestation-manifest",
                },
                "platform": {"architecture": "unknown", "os": "unknown"},
            }
        )
    index = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": manifests,
    }
    return json.dumps(index, indent=2).encode()


INDEX = _index(PLATFORM_DIGESTS)
DIGEST = "sha256:" + hashlib.sha256(INDEX).hexdigest()
REF = f"{REPO}@{DIGEST}"


def _v1(platform: str) -> dict:
    """A BuildKit-shaped SLSA v1 predicate; the target platform shows in the
    resolved base image's purl, not in builderPlatform (the build machine)."""
    return {
        "buildDefinition": {
            "buildType": "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
            "internalParameters": {"builderPlatform": "linux/arm64"},
            "resolvedDependencies": [
                {"uri": f"pkg:docker/python@3.12-slim?platform={platform.replace('/', '%2F')}"}
            ],
        },
        "runDetails": {"builder": {"id": ""}},
    }


_V02 = {"buildType": "https://mobyproject.org/buildkit@v1", "invocation": {}}
PUBKEY = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfake\n-----END PUBLIC KEY-----\n"


@pytest.fixture
def signer(tmp_path: Path):
    """Run sign-release-image.sh against a cosign and docker that record calls.

    Returns run(*args, **fakes) -> (CompletedProcess, calls). Each call is
    {"argv": ["cosign"|"docker", ...], "predicate": <attested JSON or None>}.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls.jsonl"
    (tmp_path / "record.py").write_text(
        "import json, sys\n"
        "argv = sys.argv[1:]\n"
        "predicate = None\n"
        "if '--predicate' in argv:\n"
        "    predicate = json.load(open(argv[argv.index('--predicate') + 1]))\n"
        f"with open({str(log)!r}, 'a') as fh:\n"
        "    fh.write(json.dumps({'argv': argv, 'predicate': predicate}) + '\\n')\n"
    )
    (bindir / "cosign").write_text(
        "#!/usr/bin/env bash\n"
        f'python3 {tmp_path / "record.py"} cosign "$@"\n'
        'if [[ "$1" == "version" ]]; then echo "{\\"gitVersion\\": \\"${FAKE_COSIGN_VERSION}\\"}"; exit 0; fi\n'
        'if [[ "$1" == "public-key" ]]; then printf "%s" "${FAKE_DERIVED_PUBKEY}"; exit 0; fi\n'
        'if [[ "$1" == "${FAKE_COSIGN_FAIL:-}" ]]; then echo "cosign $1 failed" >&2; exit 1; fi\n'
        "exit 0\n"
    )
    # buildx imagetools: the index (by digest), the provenance, a tag's
    # digest, and `create --dry-run`, which prints what it would push.
    (bindir / "docker").write_text(
        "#!/usr/bin/env bash\n"
        f'python3 {tmp_path / "record.py"} docker "$@"\n'
        'if [[ "$*" == *"{{json .Provenance}}"* ]]; then printf "%s" "${FAKE_PROVENANCE}"; exit 0; fi\n'
        'if [[ "$*" == *"{{json .Manifest}}"* && "$*" == *@sha256:* ]]; then cat "${FAKE_MANIFEST}"; exit 0; fi\n'
        'if [[ "$*" == *"{{json .Manifest}}"* ]]; then printf "{\\"digest\\": \\"%s\\"}" "${FAKE_TAG_DIGEST}"; exit 0; fi\n'
        'if [[ "$*" == *"create --dry-run"* ]]; then cat "${FAKE_DRY_RUN}"; echo; exit 0; fi\n'
        "exit 0\n"
    )
    for stub in bindir.iterdir():
        stub.chmod(0o755)
    pubkey = tmp_path / "cosign.pub"
    pubkey.write_text(PUBKEY)

    def run(
        *args: str,
        provenance: object = None,
        index: bytes = INDEX,
        fail: str = "",
        tag_digest: str | None = None,
        dry_run: bytes | None = None,
        version: str = PIN,
        derived: str = PUBKEY,
    ):
        log.unlink(missing_ok=True)
        if provenance is None:
            provenance = {p: {"SLSA": _v1(p)} for p in PLATFORM_DIGESTS}
        digest = "sha256:" + hashlib.sha256(index).hexdigest()
        # What `imagetools inspect --format '{{json .Manifest}}'` prints for an
        # index: the index plus its own digest.
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps({**json.loads(index), "digest": digest}))
        would_push = tmp_path / "dry-run"
        would_push.write_bytes(index if dry_run is None else dry_run)
        env = dict(
            os.environ,
            PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}",
            FAKE_PROVENANCE=json.dumps(provenance),
            FAKE_MANIFEST=str(manifest),
            FAKE_DRY_RUN=str(would_push),
            FAKE_COSIGN_FAIL=fail,
            FAKE_TAG_DIGEST=tag_digest or digest,
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


IDENTITY = (
    "https://github.com/onixus/Shapoclyack/.github/workflows/docker-publish.yml"
    "@refs/tags/shapoclyack-0.47-1001"
)


def _keyless_args(*extra: str) -> list[str]:
    return [
        "--keyless",
        "--identity",
        IDENTITY,
        "--issuer",
        "https://token.actions.githubusercontent.com",
        *extra,
    ]


def _cosign(calls: list[dict], sub: str) -> list[list[str]]:
    return [c["argv"][1:] for c in calls if c["argv"][0] == "cosign" and c["argv"][1] == sub]


def _attests(calls: list[dict]) -> list[tuple[str, str]]:
    """(subject ref, target platform of the attested predicate) per attestation."""
    found = []
    for call in calls:
        argv = call["argv"]
        if argv[:2] == ["cosign", "attest"]:
            purl = call["predicate"]["buildDefinition"]["resolvedDependencies"][0]["uri"]
            found.append((argv[-1], purl.rsplit("platform=", 1)[1].replace("%2F", "/")))
    return found


def _created(calls: list[dict], *, dry_run: bool) -> list[str]:
    tags = []
    for call in calls:
        argv = call["argv"]
        if argv[0] == "docker" and "create" in argv and ("--dry-run" in argv) == dry_run:
            tags.append(argv[argv.index("--tag") + 1])
    return tags


def _steps(calls: list[dict]) -> list[str]:
    steps = []
    for call in calls:
        argv = call["argv"]
        if argv[0] == "cosign" and argv[1] != "version":
            steps.append(argv[1])
        elif argv[0] == "docker" and "create" in argv and "--dry-run" not in argv:
            steps.append("tag")
    return steps


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

    for attest in _cosign(calls, "attest"):
        assert attest[attest.index("--type") + 1] == "slsaprovenance1"

    # Verified against the committed public key, with the release annotation
    # required — the same command docs/supply-chain.md gives customers.
    verified = [v[-1] for v in _cosign(calls, "verify")]
    assert verified[0] == REF
    for verify in _cosign(calls, "verify"):
        assert verify[verify.index("--key") + 1].endswith("cosign.pub")
        assert verify[verify.index("-a") + 1] == "release=shapoclyack-0.47-1001"
    for verify_att in _cosign(calls, "verify-attestation"):
        assert verify_att[verify_att.index("--type") + 1] == "slsaprovenance1"

    assert _created(calls, dry_run=False) == tags
    steps = _steps(calls)
    assert steps[0] == "sign"
    last_attest = max(i for i, s in enumerate(steps) if s == "attest")
    first_verify = min(i for i, s in enumerate(steps) if s.startswith("verify"))
    first_tag = steps.index("tag")
    assert last_attest < first_verify, "everything is attested before anything is verified"
    assert all(s.startswith("verify") for s in steps[first_verify:first_tag])
    assert steps[first_tag:] == ["tag", "tag"]


def test_each_platform_manifest_carries_its_own_provenance(signer):
    """A pod may name a platform manifest's digest; --recursive signs it, so it
    must carry its attestation too, with that platform's predicate as subject
    — not the index's, and not the other platform's."""
    proc, calls = signer(*_key_args(REF))
    assert proc.returncode == 0, proc.stderr
    attests = _attests(calls)
    assert sorted(attests) == sorted(
        [(REF, "linux/amd64"), (REF, "linux/arm64")]
        + [(f"{REPO}@{d}", p) for p, d in PLATFORM_DIGESTS.items()]
    )


def test_every_platform_manifest_is_verified_before_tagging(signer):
    proc, calls = signer(*_key_args("--tag", f"{REPO}:latest", REF))
    assert proc.returncode == 0, proc.stderr
    platform_refs = {f"{REPO}@{d}" for d in PLATFORM_DIGESTS.values()}
    assert platform_refs <= {v[-1] for v in _cosign(calls, "verify")}
    assert platform_refs <= {v[-1] for v in _cosign(calls, "verify-attestation")}


def test_keyless_mode_verifies_the_exact_identity(signer):
    tag = f"{REPO}:shapoclyack-0.47-1001"
    proc, calls = signer(*_keyless_args("--tag", tag, REF))
    assert proc.returncode == 0, proc.stderr
    (sign,) = _cosign(calls, "sign")
    assert "--key" not in sign, "keyless signs with the ambient OIDC certificate"
    verifies = _cosign(calls, "verify") + _cosign(calls, "verify-attestation")
    assert verifies
    for verify in verifies:
        assert verify[verify.index("--certificate-identity") + 1] == IDENTITY
        assert verify[verify.index("--certificate-oidc-issuer") + 1] == (
            "https://token.actions.githubusercontent.com"
        )
        assert "--certificate-identity-regexp" not in verify
    assert _created(calls, dry_run=False) == [tag]


def test_a_single_platform_image_is_attested_on_index_and_manifest(signer):
    index = _index({"linux/arm64": ARM64})
    ref = f"{REPO}@sha256:{hashlib.sha256(index).hexdigest()}"
    proc, calls = signer(*_key_args(ref), provenance={"SLSA": _v1("linux/arm64")}, index=index)
    assert proc.returncode == 0, proc.stderr
    assert sorted(_attests(calls)) == sorted([(ref, "linux/arm64"), (f"{REPO}@{ARM64}", "linux/arm64")])


# --- fail closed: nothing gets a tag unless everything before it passed -----


@pytest.mark.parametrize("step", ["sign", "attest", "verify", "verify-attestation"])
def test_a_failed_step_leaves_no_tag(signer, step: str):
    proc, calls = signer(*_key_args("--tag", f"{REPO}:latest", REF), fail=step)
    assert proc.returncode != 0
    assert _created(calls, dry_run=False) == []


def test_a_tag_that_would_not_point_at_the_signed_digest_is_never_pushed(signer):
    """imagetools create re-uses a single source index byte for byte; if it
    ever re-wrapped it, the tag would name an unsigned index. The dry run shows
    what would be pushed, so the check happens before the tag exists."""
    proc, calls = signer(*_key_args("--tag", f"{REPO}:latest", REF), dry_run=INDEX + b" ")
    assert proc.returncode != 0
    assert "not the signed" in proc.stderr
    assert _created(calls, dry_run=True) == [f"{REPO}:latest"]
    assert _created(calls, dry_run=False) == []


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
    [
        {},
        {"linux/amd64": {"SLSA": None}, "linux/arm64": {"SLSA": None}},
        {p: {"SLSA": _V02} for p in PLATFORM_DIGESTS},
        # One platform with provenance does not vouch for the other.
        {"linux/amd64": {"SLSA": _v1("linux/amd64")}, "linux/arm64": {"SLSA": None}},
        {"linux/amd64": {"SLSA": _v1("linux/amd64")}},
        # Provenance for a platform the index does not hold.
        {**{p: {"SLSA": _v1(p)} for p in PLATFORM_DIGESTS}, "linux/s390x": {"SLSA": _v1("linux/s390x")}},
    ],
    ids=["none", "empty", "slsa-v0.2", "one-platform-empty", "one-platform-missing", "extra-platform"],
)
def test_no_signature_without_slsa_v1_provenance_for_every_platform(signer, provenance):
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


@pytest.mark.parametrize(
    "args",
    [
        [*_key_args(), *_keyless_args()],
        [*_keyless_args(), "--key", "cosign.key"],
    ],
    ids=["key-then-keyless", "keyless-then-key"],
)
def test_key_and_keyless_together_are_refused_in_either_order(signer, args):
    """A --key that silently lost to --keyless would sign with an identity the
    caller did not ask for."""
    proc, calls = signer(*args, REF)
    assert proc.returncode != 0
    assert "exclusive" in proc.stderr
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


# --- the release public key, once it is committed ----------------------------


def test_the_committed_release_key_is_a_pem_public_key():
    """cosign.pub is what every customer and both admission examples trust.
    It lands with the maintainer's key setup (docs/supply-chain.md); until then
    Jenkinsfile.publish refuses to publish, and there is nothing to parse."""
    path = REPO_ROOT / "cosign.pub"
    if not path.exists():
        pytest.skip("cosign.pub not committed yet: the release key setup in docs/supply-chain.md is pending")
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    text = path.read_text(encoding="ascii")
    assert "PRIVATE" not in text, "cosign.pub holds private key material"
    key = load_pem_public_key(text.encode())
    # The key types cosign verifies with: ECDSA from `cosign generate-key-pair`,
    # and the RSA or Ed25519 a pre-existing KMS key may be. Nothing weak.
    if isinstance(key, ec.EllipticCurvePublicKey):
        assert key.curve.name in {"secp256r1", "secp384r1", "secp521r1"}, key.curve.name
    elif isinstance(key, rsa.RSAPublicKey):
        assert key.key_size >= 2048, key.key_size
    else:
        assert isinstance(key, ed25519.Ed25519PublicKey), type(key)


def test_no_cosign_private_key_can_be_committed():
    assert "cosign.key" in (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").split()
    assert not (REPO_ROOT / "cosign.key").exists()
