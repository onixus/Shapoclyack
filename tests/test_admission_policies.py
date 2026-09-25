"""The example admission policies check what the pipelines actually sign (#313).

An admission policy is only as good as the identity in it. One that names a
workflow path that does not sign, a tag pattern the release job never
produces, or an image the matrix no longer publishes still parses, still
installs, and then either blocks every Shapoclyack pod or — worse, with a
loose pattern — admits signatures from identities nobody meant to trust.

So the examples are parsed and held to the publishers: the keyless subject
must be exactly docker-publish.yml at a release tag (the same tag grammar
Jenkinsfile.publish enforces), the key must be the one the release pipeline
verifies against, every published repository must be covered, and both
policies must demand the SLSA provenance that the signing script attests.
The publishers are held to their half too: push by digest, sign, then tag,
with nothing that lets a failed signature turn green.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = REPO_ROOT / "k8s" / "shapoclyack" / "examples"
KYVERNO = yaml.safe_load((EXAMPLES / "image-signature-kyverno.example.yaml").read_text())
CIP = yaml.safe_load((EXAMPLES / "image-signature-policy-controller.example.yaml").read_text())
JENKINS_PUBLISH = (REPO_ROOT / "Jenkinsfile.publish").read_text(encoding="utf-8")
WORKFLOW_PATH = ".github/workflows/docker-publish.yml"
WORKFLOW = yaml.safe_load((REPO_ROOT / WORKFLOW_PATH).read_text(encoding="utf-8"))
SIGN_SCRIPT = (REPO_ROOT / "scripts" / "sign-release-image.sh").read_text(encoding="utf-8")

ISSUER = "https://token.actions.githubusercontent.com"
IDENTITY_PREFIX = f"https://github.com/onixus/Shapoclyack/{WORKFLOW_PATH}@refs/tags/"
KEY_SECRET = "shapoclyack-release-key"
# Where Jenkinsfile.publish checks out its own revision's signing tooling.
TOOLING = ".release-tooling"

# Candidate refs: some are release tags, most are near misses. Which is which
# is decided by Jenkinsfile.publish's own TAG check, not by this list.
_CANDIDATE_TAGS = [
    "shapoclyack-0.46-0922",
    "shapoclyack-0.44-0907-beta1",
    "shapoclyack-1.0-0101-rc12",
    "shapoclyack-0.41-0817-alpha3",
    "shapoclyack-0.41",
    "shapoclyack-0.41-817",
    "shapoclyack-0.41-0817-hotfix",
    "shapoclyack-0.41-0817-rc",
    "v0.41",
    "0.41",
    "main",
    "shapoclyack-0.41-0817.evil",
]


def _jenkins_tag_regex() -> re.Pattern[str]:
    match = re.search(r"if \(!\(tag ==~ /(\^shapoclyack-[^/]+\$)/\)\)", JENKINS_PUBLISH)
    assert match, "the TAG check moved in Jenkinsfile.publish; update this test"
    return re.compile(match.group(1))


def _published_repositories() -> set[str]:
    from_jenkins = set(re.findall(r"image: '([^']+)'", JENKINS_PUBLISH))
    job = WORKFLOW["jobs"]["build-and-push"]
    from_workflow = {entry["image"] for entry in job["strategy"]["matrix"]["include"]}
    assert from_jenkins and from_jenkins == from_workflow, (from_jenkins, from_workflow)
    return from_jenkins


def _kyverno_verify() -> dict:
    (rule,) = KYVERNO["spec"]["rules"]
    (verify,) = rule["verifyImages"]
    return verify


def _kyverno_entries(attestors: list[dict]) -> list[dict]:
    (attestor_set,) = attestors
    assert attestor_set["count"] == 1, "ONE trusted identity suffices, not both"
    return attestor_set["entries"]


def _keyless_subjects() -> dict[str, tuple[str, str]]:
    """policy name -> (issuer, subjectRegExp) for every keyless identity."""
    found = {}
    verify = _kyverno_verify()
    lists = [("kyverno-signature", verify["attestors"])] + [
        (f"kyverno-attestation-{a['type']}", a["attestors"]) for a in verify["attestations"]
    ]
    for name, attestors in lists:
        (keyless,) = [e["keyless"] for e in _kyverno_entries(attestors) if "keyless" in e]
        found[name] = (keyless["issuer"], keyless["subjectRegExp"])
    for authority in CIP["spec"]["authorities"]:
        if "keyless" in authority:
            (identity,) = authority["keyless"]["identities"]
            found[f"cip-{authority['name']}"] = (identity["issuer"], identity["subjectRegExp"])
    return found


# --- the policies parse and enforce ----------------------------------------


def test_kyverno_policy_enforces_digest_pinned_signed_images():
    assert KYVERNO["apiVersion"] == "kyverno.io/v1"
    assert KYVERNO["kind"] == "ClusterPolicy"
    assert KYVERNO["spec"]["background"] is False
    verify = _kyverno_verify()
    assert verify["failureAction"] == "Enforce"
    assert verify["required"] is True
    assert verify["verifyDigest"] is True
    # mutateDigest would let a tag-only reference in, rewritten to whatever
    # digest the tag resolves to at admission time; with it off, what was
    # verified is exactly what the manifest names.
    assert verify["mutateDigest"] is False


def test_policy_controller_policy_enforces():
    assert CIP["apiVersion"] == "policy.sigstore.dev/v1beta1"
    assert CIP["kind"] == "ClusterImagePolicy"
    assert CIP["spec"]["mode"] == "enforce"
    assert {a["name"] for a in CIP["spec"]["authorities"]} == {"release-key", "github-actions-keyless"}


@pytest.mark.parametrize("repository", sorted(_published_repositories()))
def test_every_published_repository_is_covered(repository: str):
    ref = f"{repository}:shapoclyack-0.46-0922@sha256:{'0' * 64}"
    assert any(fnmatch.fnmatchcase(ref, p) for p in _kyverno_verify()["imageReferences"])
    assert any(fnmatch.fnmatchcase(repository, g["glob"]) for g in CIP["spec"]["images"])


# --- keyless: the workflow, at a release tag ---------------------------------


@pytest.mark.parametrize("name", sorted(_keyless_subjects()))
def test_keyless_identity_is_the_publish_workflow_at_a_release_tag(name: str):
    issuer, subject = _keyless_subjects()[name]
    assert issuer == ISSUER
    # Kyverno and policy-controller both use Go's regexp.MatchString, which
    # searches: the pattern's own anchors are all that stop a prefix or a
    # suffix. re.search is the same semantics (RE2 and Python agree on this
    # subset), so a dropped ^ or $ fails here. One difference is bridged: Go's
    # $ matches only at the very end, Python's also before a final newline.
    pattern = re.compile(re.sub(r"\$$", r"\\Z", subject))
    release = _jenkins_tag_regex()
    for tag in _CANDIDATE_TAGS:
        accepted = bool(pattern.search(IDENTITY_PREFIX + tag))
        assert accepted == bool(release.fullmatch(tag)), f"{name}: {tag!r}"
    good = IDENTITY_PREFIX + "shapoclyack-0.46-0922"
    assert pattern.search(good)
    for impostor in (
        good.replace("refs/tags/", "refs/heads/"),
        good.replace("docker-publish.yml", "ci.yml"),
        good.replace("onixus/Shapoclyack", "onixus/Shapoclyack-fork"),
        good.replace("https://github.com/", "https://github.com.evil.example/"),
        "https://evil.example/" + good,
        good + "-evil",
        good + "\n",
    ):
        assert not pattern.search(impostor), f"{name} accepts {impostor!r}"


def test_the_publish_workflow_signs_with_that_identity():
    job = WORKFLOW["jobs"]["build-and-push"]
    assert WORKFLOW["permissions"].get("id-token") == "write"
    (sign,) = [s for s in job["steps"] if "sign-release-image.sh" in s.get("run", "")]
    run = sign["run"]
    # GITHUB_WORKFLOW_REF is owner/repo/.github/workflows/<file>@<ref>: with
    # the server URL in front it is exactly the certificate's subject.
    assert '--identity "${GITHUB_SERVER_URL}/${GITHUB_WORKFLOW_REF}"' in run
    assert f"--issuer {ISSUER}" in run
    assert "--keyless" in run


# --- key: the one Jenkinsfile.publish verifies against ------------------------


def test_the_key_authority_is_the_release_key_secret():
    verify = _kyverno_verify()
    for attestors in [verify["attestors"]] + [a["attestors"] for a in verify["attestations"]]:
        (keys,) = [e["keys"] for e in _kyverno_entries(attestors) if "keys" in e]
        assert keys["secret"]["name"] == KEY_SECRET
        assert keys["rekor"]["url"] == "https://rekor.sigstore.dev"
    (authority,) = [a for a in CIP["spec"]["authorities"] if "key" in a]
    assert authority["key"]["secretRef"]["name"] == KEY_SECRET


def test_the_release_pipeline_signs_and_checks_with_the_committed_public_key():
    # The pre-flight and the signing step both name cosign.pub — the one in
    # the pipeline's own checkout; the policies' secret is documented as
    # created from that same file.
    assert JENKINS_PUBLISH.count(f"--pubkey {TOOLING}/cosign.pub") == 2
    for example in EXAMPLES.glob("image-signature-*.example.yaml"):
        assert f"secret generic {KEY_SECRET}" in example.read_text()
        assert "--from-file=cosign.pub=cosign.pub" in example.read_text()


# --- provenance is required and is what gets attested -------------------------


def test_both_policies_require_slsa_v1_provenance_from_the_same_identities():
    verify = _kyverno_verify()
    (attestation,) = verify["attestations"]
    assert attestation["type"] == "https://slsa.dev/provenance/v1"
    assert attestation["attestors"] == verify["attestors"], "same identities for both"
    for authority in CIP["spec"]["authorities"]:
        # The URI, not cosign's short name for it (`slsaprovenance1`).
        assert [a["predicateType"] for a in authority["attestations"]] == [
            "https://slsa.dev/provenance/v1"
        ]
    # …which is what the script attests and checks, from what both builds record.
    assert set(re.findall(r"--type (\S+)", SIGN_SCRIPT)) == {"slsaprovenance1"}
    assert "--provenance mode=max,version=v1" in JENKINS_PUBLISH
    build = _workflow_step("Build and push by digest")
    assert build["with"]["provenance"] == "mode=max,version=v1"


# --- the publishers: digest first, sign, then tag, nothing skippable ----------


def _workflow_step(name: str) -> dict:
    (step,) = [s for s in WORKFLOW["jobs"]["build-and-push"]["steps"] if s.get("name") == name]
    return step


def test_the_publish_workflow_pushes_by_digest_and_tags_only_after_signing():
    steps = WORKFLOW["jobs"]["build-and-push"]["steps"]
    build = _workflow_step("Build and push by digest")
    assert "push-by-digest=true" in build["with"]["outputs"]
    assert "tags" not in build["with"] and "push" not in build["with"]
    names = [s.get("name") for s in steps]
    assert names.index("Sign, attest provenance, verify, then tag") > names.index(
        "Build and push by digest"
    )
    for step in steps:
        assert "continue-on-error" not in step and "if" not in step, step.get("name")


def test_the_publish_workflow_pins_every_action_to_a_commit():
    """This job can sign as the project; a moved tag on a third-party action
    would hand that right to whoever moved it."""
    for step in WORKFLOW["jobs"]["build-and-push"]["steps"]:
        if "uses" in step:
            assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", step["uses"]), step["uses"]


def test_the_release_pipeline_pushes_by_digest_and_cannot_skip_signing():
    assert "push-by-digest=true" in JENKINS_PUBLISH
    assert "--push" not in JENKINS_PUBLISH
    build = re.search(r"docker buildx build(.*?)\$\{output\} \.", JENKINS_PUBLISH, re.S).group(1)
    assert not re.search(r"\s-t\s|--tag\b", build), "tags are set after signing, not at push"
    # The signing call: under `if (!params.DRY_RUN)`, not softened anywhere.
    sign = JENKINS_PUBLISH[JENKINS_PUBLISH.index("if (!params.DRY_RUN) {") :]
    assert f"{TOOLING}/scripts/sign-release-image.sh" in sign.split("if (params.DRY_RUN)")[0]
    assert "|| true" not in JENKINS_PUBLISH.split("stage('Signing key')")[1].split("post {")[0]
    # The only catchError is the DRY_RUN branch of the key pre-flight.
    assert JENKINS_PUBLISH.count("catchError(") == 1
    dry_branch = JENKINS_PUBLISH[JENKINS_PUBLISH.index("if (params.DRY_RUN) {\n            catchError(") :]
    assert "} else {\n            checkSigningKey()" in dry_branch


# --- the signing tooling comes from the pipeline, not from the tag -------------


def _groovy_function(name: str) -> str:
    start = JENKINS_PUBLISH.index(f"def {name}(")
    return JENKINS_PUBLISH[start : JENKINS_PUBLISH.index("\n}\n", start)]


def test_signing_runs_the_pipelines_own_tooling_not_the_tags():
    """The workspace holds the tag being built. A tag cut before #313 has no
    sign script, no install-cosign.sh and no cosign.pub, so re-publishing it
    would fail on a missing file; and a tag must not bring its own, older
    signing code. The tooling and the trusted key come from the revision
    Jenkinsfile.publish itself was loaded from, checked out beside the tag."""
    assert re.search(rf"dir\('{re.escape(TOOLING)}'\)\s*\{{[^}}]*checkout scm", JENKINS_PUBLISH)
    calls = re.findall(r"(\S*)scripts/(install-cosign|sign-release-image)\.sh", JENKINS_PUBLISH)
    assert calls, "no signing tooling is called"
    for prefix, script in calls:
        assert prefix.endswith(f"{TOOLING}/"), f"{script}.sh is run from the tag's checkout"
    for pubkey in re.findall(r"--pubkey (\S+)", JENKINS_PUBLISH):
        assert pubkey.startswith(f"{TOOLING}/"), pubkey
    # Checked out after the tag, so nothing the tag checkout does can replace
    # it, and before the key pre-flight uses it.
    checkout = JENKINS_PUBLISH.index("checkout scm")
    assert checkout > JENKINS_PUBLISH.index("refs/tags/${params.TAG}")
    assert checkout < JENKINS_PUBLISH.index("stage('Signing key')")


def test_a_missing_signing_credential_names_the_setup_doc():
    """The likely state right after merge is no COSIGN_PRIVATE_KEY in Jenkins:
    withCredentials then fails with Jenkins' generic "Could not find
    credentials entry", which says nothing about what to do. The pre-flight
    catches it, points at the setup, and still fails."""
    body = _groovy_function("checkSigningKey")
    assert body.index("try {") < body.index("withCredentials(")
    handler = body[body.index("} catch (") :]
    assert "docs/supply-chain.md" in handler
    assert re.search(r"\bthrow \w+", handler), "the failure must still propagate"
