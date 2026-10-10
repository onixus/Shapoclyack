"""Rhai plugins handed to Pulse with ``--script-dir`` (#544, ADR 0002).

Nmap's ``default,safe`` NSE scripts identified things Pulse's banner and CVE
rules do not: weak SSH algorithms, anonymous FTP, services that cannot start
TLS. Pulse has a scripting layer of its own (Rhai, GenDec ``src/scanner/script.rs``
and ``sandbox.rs``); the plugins that fill the gap live in
``pulse_data/plugins/`` and are described in ``docs/pulse-plugins.md``.

Why the directory sits beside the code and not under ``scanner/data``: an
enrichment volume mounted there shadows it (same reason as ``services.tsv``,
``pulse_probe.SERVICES_DB``).

What this module owns, so that ``pulse_probe`` stays about the command line:

* **The set.** ``resolve_plugin_set`` hashes every ``*.rhai`` file. The set's
  digest goes into ``pulse/raw.json`` (``adapter.plugins``), into the chunk key
  and into the resume check: a resume must not reuse a run made with other
  plugins, and a verification must not credit a plugin that was edited since.
* **What pulse really loaded.** Pulse skips a script that does not compile
  without a word. ``verify_plugins`` runs ``pulse plugin check`` on each file
  once per run, so the receipt says which plugins were valid, not merely
  which were on disk.
* **What went wrong.** Runtime errors exist only as ``plugin error -- ...``
  lines on stderr; ``parse_plugin_errors`` turns them into records.
* **How long it may take.** ``plugin_budget_seconds``.

Wall-clock budget
-----------------
Pulse runs the scripts after the scan, in one blocking task, one open port at a
time and one script at a time: never concurrent. The connection cap (8 per
script run) is Pulse's own constant and is not a flag. What is bounded here is
the process, not the plugins: the sandbox's timeout applies to the connect and
to *each read*, and a call with a payload reads until EOF, so a server that
trickles bytes can stretch one call far beyond the plugin's timeout (measured:
14.5 s for a 1500 ms call; onixus/GenDec#38 asks for one deadline per call).
No per-call bound can be promised.

So a chunk gets ``endpoints * PLUGIN_SECONDS_PER_ENDPOINT`` extra seconds on the
process timeout, capped at ``PLUGIN_BUDGET_CAP_SECONDS`` (the open ports and
their services are not known when a chunk is cut, so every endpoint is
counted). The number is a typical-case allowance (two plugins can match one FTP
endpoint, a healthy call is a fraction of a second), not a worst case. When the
process still overruns, ``run_pulse_probe`` treats the chunk as unresolved
(no ``completion`` receipt, probed again on ``--resume``) instead of failing the
stage: see ``pulse_probe`` and ``verification_coverage``.

Scan policy: the plugins' connections are not paced by ``--rate`` and are not
counted by ``--host-parallel``. They are serial, so a host-concurrency ceiling
holds by construction, but a per-host packet-rate ceiling cannot be honoured:
``scan_policy.apply_policy`` turns the plugins off under it.
"""

from __future__ import annotations

import hashlib
import logging
import re
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Default location of the shipped plugins.
PLUGINS_DIR = Path(__file__).resolve().parent / "pulse_data" / "plugins"

#: Longest per-call timeout any shipped plugin may pass to ``probe_send`` /
#: ``probe_recv``. The sandbox clamps to 50..5000 ms on its own.
PLUGIN_CALL_TIMEOUT_MS = 1500

#: Extra wall-clock per scanned endpoint, and its ceiling per chunk. See the
#: module docstring: an allowance, not a bound.
PLUGIN_SECONDS_PER_ENDPOINT = 10
PLUGIN_BUDGET_CAP_SECONDS = 1800

#: ``pulse plugin check`` compiles and dry-runs one script; it opens no socket.
CHECK_TIMEOUT_SECONDS = 20

#: ``source`` Pulse gives a plugin's finding, and the ``finding_class``.
PLUGIN_SOURCE = "rhai_script"
PLUGIN_CLASS = "plugin_script"
#: ``match_reason`` Pulse writes: ``rhai script <name>``.
_MATCH_REASON = "rhai script "

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# GenDec ``main.rs``: ``eprintln!("  {}  plugin error — {err}", "warn")`` with
# ``err`` = ``<script name>: <rhai error>``.
_PLUGIN_ERROR = re.compile(r"plugin error\s+[—-]+\s+(?P<plugin>[A-Za-z0-9_.\-]+):\s*(?P<message>.*)$")

_SEVERITIES = {"critical", "high", "medium", "low"}


@dataclass(frozen=True)
class PluginFile:
    name: str
    sha256: str
    path: Path


@dataclass(frozen=True)
class PluginSet:
    """The plugins offered to one run; empty when disabled or unavailable."""

    directory: Path | None
    files: tuple[PluginFile, ...] = ()
    #: Why the set is empty although plugins were asked for (or ``None``).
    unavailable: str | None = None

    @property
    def digest(self) -> str:
        """Identity of the set; ``""`` for an empty one (so old keys stay valid)."""
        if not self.files:
            return ""
        material = "".join(f"{f.name} {f.sha256}\n" for f in self.files)
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    @property
    def shas(self) -> dict[str, str]:
        return {f.name: f.sha256 for f in self.files}

    @property
    def script_dir(self) -> str | None:
        return str(self.directory) if self.files and self.directory else None


def resolve_plugin_set(*, enabled: bool, directory: Path | None = None) -> PluginSet:
    """Hash the ``*.rhai`` files of the plugin directory.

    A missing or empty directory is a degraded run, not an error: the scan
    carries on without plugins and the receipt says why (the same stance as
    ``resolve_services_db``). Symlinks are ignored; the directory is ours.
    """
    if not enabled:
        return PluginSet(directory=None)
    root = Path(directory) if directory is not None else PLUGINS_DIR
    files: list[PluginFile] = []
    if root.is_dir():
        for path in sorted(root.glob("*.rhai")):
            if path.is_symlink() or not path.is_file():
                continue
            files.append(PluginFile(path.stem, hashlib.sha256(path.read_bytes()).hexdigest(), path))
    if not files:
        reason = f"no .rhai plugins in {root}"
        logging.warning("pulse_plugins: %s; Pulse runs without plugins", reason)
        return PluginSet(directory=root, unavailable=reason)
    return PluginSet(directory=root, files=tuple(files))


def plugin_budget_seconds(endpoints: int) -> int:
    """Seconds to add to the pulse process timeout for ``endpoints`` scanned endpoints."""
    return min(max(0, int(endpoints)) * PLUGIN_SECONDS_PER_ENDPOINT, PLUGIN_BUDGET_CAP_SECONDS)


def check_plugin(pulse_bin: str, path: Path, *, env: Mapping[str, str], cwd: str | Path) -> str | None:
    """``None`` when ``pulse plugin check`` accepts the script, else why not."""
    try:
        done = subprocess.run(  # noqa: S603 - argv list, our own binary
            [pulse_bin, "plugin", "check", str(path)],
            capture_output=True,
            text=True,
            timeout=CHECK_TIMEOUT_SECONDS,
            env=dict(env),
            cwd=str(cwd),
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"plugin check could not run: {exc.__class__.__name__}"
    if done.returncode == 0:
        return None
    text = _ANSI.sub("", (done.stdout or "") + (done.stderr or ""))
    for line in text.splitlines():
        if line.strip().startswith("Error:"):
            return line.strip()[len("Error:") :].strip()[:300]
    return f"plugin check exited {done.returncode}"


def active_digest(loaded: list[Mapping[str, str]]) -> str:
    """Identity of the plugins that will really run; ``""`` when none do."""
    if not loaded:
        return ""
    material = "".join(f"{p['name']} {p['sha256']}\n" for p in sorted(loaded, key=lambda p: p["name"]))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def verify_plugins(
    pulse_bin: str, plugin_set: PluginSet, staging: Path, *, env: Mapping[str, str], cwd: str | Path
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """``(loaded, rejected)`` receipts; the accepted files are copied into ``staging``.

    Pulse loads every script of the directory it is given that compiles, whatever
    we think of it. So Pulse is given ``staging``, which holds copies of the
    accepted files only, and the sha256 of a loaded plugin is the sha256 of the
    copy Pulse reads.
    """
    loaded: list[dict[str, str]] = []
    rejected: list[dict[str, str]] = []
    for plugin in plugin_set.files:
        copy = staging / f"{plugin.name}.rhai"
        copy.write_bytes(plugin.path.read_bytes())
        sha = hashlib.sha256(copy.read_bytes()).hexdigest()
        reason = check_plugin(pulse_bin, copy, env=env, cwd=cwd)
        if reason is None:
            loaded.append({"name": plugin.name, "sha256": sha})
        else:
            copy.unlink()
            logging.warning("pulse_plugins: %s rejected by pulse plugin check: %s", plugin.name, reason)
            rejected.append({"name": plugin.name, "sha256": sha, "reason": reason})
    return loaded, rejected


#: Which endpoints each shipped plugin acts on. A plugin whose gate does not
#: match returns without a word, so "plugin loaded, endpoint completed, no
#: finding" proves nothing about an endpoint it never looked at; the
#: ``pulse-plugin`` detector asks :func:`applies`. ``tests/test_pulse_plugins_files.py``
#: reads the gates out of the ``.rhai`` files and fails if this table differs.
#:
#: A plugin applies when the detected service is in ``services``, or the
#: banner (lower-cased) starts with a ``banner`` prefix and, where one is
#: given, contains the second string, or the port is in ``ports`` and the
#: service is unknown.
APPLICABILITY: dict[str, dict[str, Any]] = {
    "shapo_ssh_algorithms": {"services": {"ssh"}, "banner": (("ssh-", ""),), "ports": set()},
    "shapo_ssh_banner": {"services": {"ssh"}, "banner": (("ssh-", ""),), "ports": set()},
    "shapo_ftp_anonymous": {"services": {"ftp"}, "banner": (("220", "ftp"),), "ports": set()},
    "shapo_cleartext_services": {
        "services": {"telnet", "ftp", "pop3", "imap", "smtp"},
        "banner": (("220", "ftp"), ("+ok", ""), ("* ok", ""), ("220", "smtp")),
        "ports": {23},
    },
    "shapo_smb_exposure": {"services": {"smb", "microsoft-ds", "netbios-ssn"}, "banner": (), "ports": {445, 139}},
    "shapo_remote_admin_exposure": {
        "services": {"rdp", "ms-wbt-server", "vnc"}, "banner": (("rfb ", ""),), "ports": {3389},
    },
}


def applies(plugin: str, *, service: str, port: int, banner: str) -> bool:
    """Whether ``plugin`` would act on an endpoint with these scan results."""
    gate = APPLICABILITY.get(plugin)
    if gate is None:
        return False
    svc = (service or "").strip().lower()
    text = (banner or "").lower()
    if svc in gate["services"]:
        return True
    if any(text.startswith(prefix) and needle in text for prefix, needle in gate["banner"]):
        return True
    return svc in ("", "unknown") and port in gate["ports"]


def parse_plugin_errors(stderr: str) -> list[dict[str, str]]:
    """Plugin runtime errors from Pulse's stderr: ``[{"plugin", "message"}]``.

    Pulse prints each distinct ``<script>: <error>`` once per invocation (it
    de-duplicates), without the endpoint. A plugin that gives up on a probe
    ``throw``s, which is how a timed-out or refused probe becomes visible here
    instead of looking like a clean result.
    """
    out: list[dict[str, str]] = []
    for raw in (stderr or "").splitlines():
        match = _PLUGIN_ERROR.search(_ANSI.sub("", raw).strip())
        if match is None:
            continue
        record = {"plugin": match["plugin"], "message": match["message"].strip()[:300]}
        if record not in out:
            out.append(record)
    return out


def plugin_name_of(match_reason: str) -> str | None:
    """Plugin name from Pulse's ``rhai script <name>`` match reason."""
    text = (match_reason or "").strip()
    if text.startswith(_MATCH_REASON) and text[len(_MATCH_REASON) :].strip():
        return text[len(_MATCH_REASON) :].strip()
    return None


def normalize_severity(value: Any) -> str:
    """A plugin's free-text severity on the scanner's scale.

    ``critical|high|medium|low`` pass through (any case); ``info`` and
    anything else a plugin invents are ``info`` -- the report maps that to
    ``unknown`` like every other class-less observation, instead of ranking a
    typo as a finding.
    """
    text = str(value or "").strip().lower()
    return text if text in _SEVERITIES else "info"
