# Maintaining documentation and installation guides

Commands run from the repository root. Review documentation changes alongside
code changes; [docs/README.md](README.md#documentation-ownership) defines the
owner guide for each behavior.

## Keep one procedure per task

- Root README files introduce the product and select an installation path.
- [docs/README.md](README.md) indexes technical contracts and records version scope.
- [Wiki](wiki/README.md) supplies role playbooks, security processes and rollout guidance.
- [ROADMAP.md](../ROADMAP.md) records delivery status and links to remaining work.
- [CHANGELOG.md](../CHANGELOG.md) records release-specific behavior.

Link to an owner guide rather than copying its procedure or delivery table.
When updating status, verify source evidence and distinguish merged code,
published artifacts and operational acceptance. Record a source revision rather
than claiming that a documentation review validated a deployment or CI build.

## Select the installer

| Tool | Purpose | Prerequisites and owner guide |
|---|---|---|
| `scripts/install-server.py` | Single-server prebuilt appliance; `prepare` creates configuration without Docker | Linux, Python 3.9+, Docker Engine, Compose v2 with `up --wait` and `run --pull`, HTTPS proxy; [server installation](server-install.ru.md) |
| `scripts/install-agent.sh` | Remote **sensor**, native or Docker; never Lariska | Root on a supported Linux distribution, provisioning key, staged sensor package or bundle URL for native installs; [sensor fleet](api-and-rbac.md#sensor-fleet-deployment-and-upgrade) |
| `scripts/install-pulse.sh` | Pulse probing backend for hosts and image builds | Bash, curl, tar, SHA-256 utility; private releases additionally need jq or Python 3; source builds need cargo/git; [Pulse backend](pulse-backend.md) |
| `scripts/install-cosign.sh DEST_DIR` | Reviewed cosign binary for release signing | Bash, curl, SHA-256 utility, install; [supply chain](supply-chain.md) |

The server script stays self-contained so operators can copy one file. Pulse
requires the adjacent `pulse-release-lib.sh` and, for reviewed release pins,
`pulse-pinned.sha256`; copying only `install-pulse.sh` is insufficient.
`PULSE_REF` must resolve to the requested source tag or branch; clone failures
abort the installation. They do not select a different ref.

Installer changes should preserve image and dependency pins, credential
handling, migration ordering and recovery behavior. Use focused offline tests:

```bash
scripts/ci-lint.sh
python -m pytest tests/test_server_installer.py tests/test_agent_install_pins.py \
  tests/test_installer_cli.py tests/test_pulse_supply_chain.py \
  tests/test_wiki_renderer.py -q
```

These checks do not establish successful deployment, live downloads or signing.

## Render and inspect GitHub Wiki pages

Edit the Markdown sources in `docs/wiki/`, including `_Sidebar.md`. Repository
links retain `.md` extensions; the renderer converts wiki-page links to page
names and `README.md` to `Home`. Links outside the wiki point back to the origin
repository at the selected revision, preserving fragments and nested paths.

```bash
scripts/publish-wiki.sh --output /tmp/shapoclyack-wiki --ref main
```

This only writes local files. Inspect `Home.md`, `_Sidebar.md` and the rendered
role guides. All top-level `docs/wiki/*.md` files are included automatically.
Missing local link targets fail rendering. Inline links are converted; use
inline Markdown links for navigation rather than reference-style definitions.
Unrelated pages in an existing Wiki repository are retained during publication.
Removing a published page requires a separate deliberate deletion.

To pin repository links to a release, pass its tag through `--ref`. For direct
rendering without an origin remote:

```bash
python3 scripts/render-wiki.py --output /tmp/shapoclyack-wiki \
  --repo-url https://github.com/onixus/Shapoclyack --ref main
```

## Publish after source changes are merged

Enable GitHub Wiki and create its initial page first. With git credentials that
can push to the origin Wiki, run:

```bash
scripts/publish-wiki.sh --ref main
```

Without `--output`, the script renders first, clones the origin's `.wiki.git`,
copies the generated pages, commits changed Markdown and pushes the cloned
branch. It needs git and Python 3.9+; Perl is no longer required. A failed push
returns an error. Review the repository PR before updating the published Wiki
so links to `main` resolve to the reviewed documentation.
