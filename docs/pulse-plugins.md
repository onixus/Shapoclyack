# Pulse plugins

Rhai plugins that Shapoclyack hands to Pulse with `--script-dir`
([ADR 0002](adr/0002-replacing-nmap-functions.md), work item
[#544](https://github.com/onixus/Shapoclyack/issues/544)). They are what is left
of Nmap's NSE `default,safe` identification that Pulse's scripting sandbox can
do: weak SSH algorithms, anonymous FTP, services that cannot start TLS, and the
reachability of SMB, RDP and VNC. They live in
`scanner/pipeline/pulse_data/plugins/`, beside the code and not under
`scanner/data/`, for the same reason `services.tsv` does: an enrichment volume
mounted over `scanner/data` would hide them.

On by default wherever Pulse is the report backend (`service_probe.backend:
pulse` or `hybrid`). Off with `service_probe.pulse.plugins: false` (also per
speed profile under `profiles.<mode>.pulse.plugins`).

## What ships

| Plugin | Finds | Severity | Replaces |
|---|---|---|---|
| `shapo_ssh_algorithms` | Weak key-exchange, host-key, cipher and MAC algorithms in the server's KEXINIT | MEDIUM broken (`diffie-hellman-group1-sha1`, `ssh-dss`, `3des-cbc`, `arcfour*`, `hmac-md5`, …), LOW deprecated (CBC ciphers, `diffie-hellman-group14-sha1`, `ssh-rsa` as the only RSA signature) | the weakness half of `ssh2-enum-algos` |
| `shapo_ssh_banner` | SSH protocol 1 (`SSH-1.5` HIGH, `SSH-1.99` MEDIUM), OpenSSH older than 7.0 (LOW: distributions backport fixes without changing the banner, so it is a hint to check the package) | see left | GenDec `ssh_audit` (derived, MIT) |
| `shapo_ftp_anonymous` | The server accepts `USER anonymous`: reply codes are parsed, and the answer to `PASS` (or to `USER`, for a server that logs in at once) must be `230`; a `230` in a multi-line greeting does not count | MEDIUM | `ftp-anon`, without the directory listing |
| `shapo_cleartext_services` | Telnet (HIGH); FTP, POP3, IMAP without a way to start TLS (MEDIUM), judged only when the capability command (`FEAT` 211, `CAPA` +OK, `CAPABILITY` OK, `EHLO` 250) was accepted, otherwise an error, not a finding; SMTP with `AUTH` but no STARTTLS (MEDIUM), without both (LOW) | see left | nothing in `default,safe` |
| `shapo_smb_exposure` | SMB / NetBIOS session service answers (by detected service; the port number counts only when the scan could not name the service) | LOW | GenDec `smb_netbios_exposure_audit` (derived, MIT) |
| `shapo_remote_admin_exposure` | RDP or VNC (confirmed from the `RFB` greeting) answers (same gate rule) | LOW | GenDec `rdp_vnc_exposure_audit` (derived, MIT) |

The two exposure plugins claim exposure only. SMB signing, SMBv1, RDP NLA and
NTLM host information are **not** checked, and the finding text says so.

Pulse's own rules already raise `exposure` findings for SMB and RDP (the
EternalBlue and BlueKeep hypotheses); the plugin findings are separate rows
under their own detector and are not merged with those.

## What the plugins cannot do

The sandbox of Pulse v1.3.0 (`src/scanner/sandbox.rs`) allows TCP to the one host
and port being audited, 8 connections per script run, timeouts of 50 to 5000 ms,
4 KiB out and 16 KiB in, and it passes the reply through `from_utf8_lossy` with
control characters turned into `.`. A plugin passes the payload as a Rhai string,
which is UTF-8. Consequences, checked against the real binary:

- **No byte above 0x7F can be sent.** `"\xfe"` goes out as `C3 BE`. SMB2 and SMB1
  negotiate (`FE 53 4D 42` / `FF 53 4D 42`), the RDP X.224 connection request
  (`0xE0`) and everything after it (NLA, CredSSP, NTLM host information) are
  unreachable: Nmap's `smb2-security-mode`, `smb-security-mode`, `smb-protocols`,
  `rdp-enum-encryption` and `rdp-ntlm-info` have no equivalent.
- **No UDP.** SNMP (`snmp-info`) and any other UDP probe cannot be written.
- **`ssh-hostkey` needs a key exchange**, which is a binary protocol. Not covered.
- **A second connection to another port is refused**, so `ftp-anon` cannot list the
  directory (PASV opens a data connection) and a STARTTLS upgrade cannot be
  followed.
- The reply is sanitised, so binary replies are read through what survives. The
  SSH plugin is built around that; see below.

The gap is filed for GenDec as
[onixus/GenDec#38](https://github.com/onixus/GenDec/issues/38): binary-safe payloads
(hex or a blob type), a UDP call and one deadline per call. Until then it is a documented gap, not a silent one: the
reference corpus lists each NSE script with the reason no plugin answers it
([Reference corpus](pulse-backend.md#reference-corpus-nmap-versus-pulse-541)).

### How `shapo_ssh_algorithms` reads a binary reply

It sends `SSH-2.0-shapoclyack_audit` and then bytes that are not a valid packet.
The server has already queued its `KEXINIT`, answers with it, and drops the
connection on the garbage, so the call ends at EOF rather than at the read
timeout. The name-lists arrive with their length prefixes turned into dots and one
printable (or replacement) character, so they cannot be split by position. They are
split by what survives: `,` between names and a run of two or more dots between
lists, and one leftover character in front of a list's first name is tolerated
when matching. `tests/test_pulse_plugins_files.py` runs the plugin against a stub
server whose list lengths and cookie change on every connection, with a weak name
first in every list, which is the case a naive parse loses.

## How Shapoclyack runs them

`scanner/pipeline/pulse_plugins.py` and `pulse_probe.run_pulse_probe`:

- `--script-dir <plugins dir>` on every invocation. Pulse loads that directory
  **plus** `./scripts` and `$HOME/.pulse/scripts`; the process therefore runs with an
  empty temporary directory as both its working directory and its `HOME`. Bare
  `--scripts` is never used.
- Once per run, each file goes through `pulse plugin check`. Pulse loads **every**
  script of the directory it is given that compiles, whatever the check said, so it is
  given a temporary directory holding copies of the accepted files only; the sha256 in
  the receipt is that of the copy. If none is accepted, `--script-dir` is not passed.
- Every path in the command is absolute: Pulse runs in its private directory, and a
  relative `output_dir` (the default, `scanner/output`) would point into it.
- A finding from a plugin that is not in the offered set is dropped with a warning.
- The set of plugins that **run** (`adapter.plugins.digest`, the digest of the
  accepted files, `""` for none) is part of `chunk_key` and of the resume decision:
  hosts probed with other plugins (or none, because every check failed that time) are
  probed again. On a host without a Pulse binary the check cannot be asked and the
  receipt's `offered_digest` (the files on disk) is compared instead.
- **Time.** Pulse runs the plugins after the scan, one open port and one plugin at a
  time, never concurrently. No per-call bound can be promised: the sandbox applies the
  timeout to the connect and to *each read*, and a call with a payload reads until EOF,
  so a server that trickles bytes stretches one call far past the plugin's timeout
  (14.5 s measured for a 1500 ms call; GenDec#38 asks for one deadline per call).
  A chunk therefore gets `endpoints * 10` seconds added to the process timeout,
  capped at 30 minutes (`PLUGIN_SECONDS_PER_ENDPOINT`, `PLUGIN_BUDGET_CAP_SECONDS`):
  an allowance for ordinary servers, not a worst case. The services behind the open
  ports are not known when a chunk is cut, so every endpoint is counted. When Pulse
  still overruns, the chunk is **unresolved**, not a crash: no success receipt, its
  hosts are reported through `on_unresolved` and probed again on `--resume`, the
  crash-loop counter (exits without JSON) is neither advanced nor reset by it, and
  `pulse/raw.json` marks the chunk `timed_out`. A verification then finds no receipt
  (`endpoint_not_probed`). What the tests check about the plugin files is stated as
  such: call *sites* (at most four per file), literal timeouts (at most 1500 ms),
  and `ports()` empty. They do not prove how many calls one run makes.

### Scan policy

The plugins' connections are not paced by `--rate` and are not counted by
`--host-parallel`. They are serial, so `max_host_concurrency` holds without help.
`per_host_rate` ("packets aimed at any single host") cannot be honoured for a burst
of up to eight connections a plugin run, so a policy with that ceiling turns the
plugins off in every speed profile (`scan_policy.apply_policy`). `skip_service_probe`
already skips the whole Pulse stage. A shadow run (`backend: nmap` with `shadow`)
runs Pulse only to compare services and discards its findings, so it makes no
plugin connections.

### The receipt

`pulse/raw.json` → `adapter.plugins`:

```json
{
  "requested": true, "active": true, "dir": ".../pulse_data/plugins",
  "digest": "<sha256 of the plugins that run; empty if none>",
  "offered_digest": "<sha256 of the files on disk>", "unavailable": null,
  "loaded":   [{"name": "shapo_ftp_anonymous", "sha256": "..."}],
  "rejected": [{"name": "...", "sha256": "...", "reason": "Compilation error: ..."}],
  "errors":   [{"plugin": "shapo_ssh_algorithms", "message": "Runtime error: ...",
                "chunk": "<chunk key>", "hosts": ["10.0.0.5"], "ports": [22]}]
}
```

Pulse prints a plugin's runtime error on stderr as `plugin error — <plugin>: <error>`
and does not say which endpoint it was for, so each error carries the hosts and
ports of the invocation that printed it. That is deliberately coarse: the error is
held against every host and port of the chunk (the safe direction, since an error means
"did not look"), so one failing endpoint costs the coverage of its neighbours in the
same invocation; a smaller `chunk_hosts` narrows the noise. **A plugin that cannot complete a probe
`throw`s** (connection refused, empty reply, the server hung up) instead of
returning nothing: nothing returned reads as "looked, clean", and that is what a
verification would otherwise credit.

## In the report and the tracker

A plugin finding is not a CVE. Pulse names it `SCRIPT-<NAME>`; in
`vulnerabilities.json` the row has `cve: ""`, `source: "pulse-plugin"`,
`script_id: "pulse-plugin:<plugin>"`, `finding_class: "plugin_script"` and
`ruleset_version: "sha256:<hex of the plugin file>"`. Severity is normalised:
`critical|high|medium|low` pass, `info` and anything a plugin invents become
`unknown` in the report. In `finding_evidence.json` it is an observation of kind
`plugin_report` whose rule is `plugin:<name>`.

### Verification (`pulse-plugin` detector)

A verification re-scan may close a finding that a plugin made only if its run
shows (`api/services/verification_coverage.py`):

1. `adapter.plugins.loaded` lists that plugin with the **same sha256** the finding
   was made with (an edited plugin is a different check: `plugin_changed`;
   a finding with no recorded sha: `plugin_version_not_recorded`; not loaded:
   `plugin_not_loaded`);
2. a success receipt (`completion`) for the host and port (`endpoint_not_probed`);
3. an `open[]` row for the endpoint that the plugin's own gate accepts
   (`plugin_not_applicable`): a plugin returns silently on a service it does not
   handle, which is not a look. The gates are mirrored in
   `pulse_plugins.APPLICABILITY`, and a test reads them out of the `.rhai` files and
   fails if the two differ;
4. no entry in `adapter.plugins.errors` for that plugin on a chunk that held the
   endpoint (`plugin_error`).

No database migration: `vulnerabilities.detectors` is JSON and the detector name is
a string.

## Writing or changing a plugin

- Name the file `shapo_<what>.rhai` and make `name()` return the same string: it is
  the `cve_id` suffix and the detector reference. A test fails otherwise.
- `ports()` returns `[]` (a test requires it: the applicability table does not model
  a port filter) and the plugin gates on `service` / `banner` in `run()`, so a service
  on a non-standard port is still checked and an unrelated port costs no connection.
  Add the gate to `pulse_plugins.APPLICABILITY` in the same change.
- A probe that fails `throw`s. Keep to one network call per path through `run()`;
  `probe_send` / `probe_recv` with a timeout of 1500 ms or less, no `http_get`. (The
  tests count call sites and read the literal timeouts; they cannot count calls.)
- ASCII source, and no escape that names a byte above `0x7F`.
- Licence header: Apache-2.0 (`// SPDX-License-Identifier: Apache-2.0`) for ours;
  a file derived from a GenDec script carries `SPDX-License-Identifier: MIT`, names
  the GenDec script and what changed, and is listed in `NOTICE` and
  [third-party.md](third-party.md).
- `pulse plugin check scanner/pipeline/pulse_data/plugins/<file>` must pass
  (`tests/test_pulse_plugins_files.py` runs it when a binary is available:
  `OCTO_PULSE_BIN=/path/to/pulse python -m pytest tests/test_pulse_plugins_files.py`).
- Changing a plugin means re-recording the Pulse side of the corpus
  (`RECORD_PARTS=pulse`, see [Pulse backend](pulse-backend.md#reference-corpus-nmap-versus-pulse-541));
  `tests/test_nmap_pulse_corpus.py` fails while the recorded sha256 and the shipped
  files differ.
