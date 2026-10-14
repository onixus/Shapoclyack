# Pulse plugins

Rhai plugins that Shapoclyack hands to Pulse with `--script-dir`
([ADR 0002](adr/0002-replacing-nmap-functions.md), [#544](https://github.com/onixus/Shapoclyack/issues/544)).
Content covers weak SSH advertisements, verified Ed25519 host-key
observations, anonymous FTP, cleartext capabilities, plain HTTP TRACE,
SMB dialect/signing and MS17-010 status hypotheses, RDP negotiation/type2
inventory, VNC security advertisements, and standalone UDP SNMP inventory.
The files live in `scanner/pipeline/pulse_data/plugins/`, where an enrichment
volume mounted over `scanner/data` cannot hide them.

On by default wherever Pulse runs (`service_probe.backend: pulse`, the only
backend). Off with `service_probe.pulse.plugins: false` (also per
speed profile under `profiles.<mode>.pulse.plugins`).

## Released content and engine dependency

These capabilities require signed [Pulse v1.4.0](https://github.com/onixus/GenDec/releases/tag/v1.4.0),
produced from merged GenDec#39. Dockerfiles, publish workflows and all four
checksum pins select v1.4.0 after verifying its Sigstore workflow/tag identity
and each downloaded archive. Source and released CLI fixtures do not establish
installed sensor or fleet acceptance.

## Plugins

| Plugin | Finds | Severity | Replaces |
|---|---|---|---|
| `shapo_ssh_algorithms` | Weak key-exchange, host-key, cipher and MAC algorithms in the server's KEXINIT | MEDIUM broken (`diffie-hellman-group1-sha1`, `ssh-dss`, `3des-cbc`, `arcfour*`, `hmac-md5`, …), LOW deprecated (CBC ciphers, `diffie-hellman-group14-sha1`, `ssh-rsa` as the only RSA signature) | the weakness half of `ssh2-enum-algos` |
| `shapo_ssh_banner` | SSH protocol 1 (`SSH-1.5` HIGH, `SSH-1.99` MEDIUM), OpenSSH older than 7.0 (LOW: distributions backport fixes without changing the banner, so it is a hint to check the package) | see left | GenDec `ssh_audit` (derived, MIT) |
| `shapo_ftp_anonymous` | The server accepts `USER anonymous`: reply codes are parsed, and the answer to `PASS` (or to `USER`, for a server that logs in at once) must be `230`; a `230` in a multi-line greeting does not count | MEDIUM | `ftp-anon`, without the directory listing |
| `shapo_http_trace` | The server answers `TRACE /` over plain HTTP with `200` and echoes a marker header in the body (a catch-all that answers 200 without echoing is not reported; HTTPS is out of the sandbox's reach; a hang-up on TRACE reads as refused (no finding, no error; it is not evidence that a fix worked, so a server that resets for another reason also reads clean), a non-HTTP reply is an error; an echo server answering every request with 200 is a false positive the plugin cannot tell apart) | LOW | `http-trace` (the TRACE half of `http-methods`) |
| `shapo_cleartext_services` | Telnet (HIGH); FTP, POP3, IMAP without a way to start TLS (MEDIUM), judged only when the capability command (`FEAT` 211, `CAPA` +OK, `CAPABILITY` OK, `EHLO` 250) was accepted, otherwise an error, not a finding; SMTP with `AUTH` but no STARTTLS (MEDIUM), without both (LOW) | see left | nothing in `default,safe` |
| `shapo_smb_exposure` | SMB / NetBIOS session service answers (by detected service; the port number counts only when the scan could not name the service) | LOW | GenDec `smb_netbios_exposure_audit` (derived, MIT) |
| `shapo_remote_admin_exposure` | RDP or VNC (confirmed from the `RFB` greeting) answers (same gate rule) | LOW | GenDec `rdp_vnc_exposure_audit` (derived, MIT) |
| `shapo_smb_signing` | Selected SMB2 NEGOTIATE response does not require signing; offers SMB 2.0.2 and 2.1 | MEDIUM | signing-policy portion of `smb2-security-mode` |
| `shapo_smb1` | SMB1-only NEGOTIATE explicitly selects NT LM 0.12 | MEDIUM | SMB1-support portion of `smb-protocols` |
| `shapo_rdp_negotiation` | X.224 negotiation accepts standard RDP security without mandatory NLA | MEDIUM | standard-security acceptance; not full `rdp-enum-encryption` |
| `shapo_ssh_hostkey` | Verified curve25519-sha256 / Ed25519 exchange signature and SHA256 host-key fingerprint | INFO observation; no known-host trust | native observation |
| `shapo_snmp_info` | One UDP SNMPv2c `public` GET of sysDescr/sysName | INFO; standalone/native UDP, not production adapter enrichment | native observation |
| `shapo_smb_protocols` | SMB1 and SMB2 2.0.2/2.1/3.0/3.0.2/3.1.1 selections/signing, including RFC1002 on 139 | MEDIUM when signing is not required; otherwise INFO inventory | native observation |
| `shapo_ms17_010` | Anonymous IPC$/FID0 Peek status indication | Positive hypothesis only; every non-indicator/error UNKNOWN, never patch proof | native observation |
| `shapo_rdp_ntlm_info` | X.224→TLS→CredSSP NTLM type2 host/domain/DNS/build/time fields | INFO unauthenticated inventory; no type3/credentials/session | native observation |
| `shapo_vnc_security` | RFB3.3/3.7/3.8 security-type advertisements | MEDIUM hypothesis when None is advertised; no security selection or desktop session | native observation |

The two exposure plugins still claim reachability only. Negotiation and
inventory observations do not establish relay/exploitability, trusted identity,
authenticated access or patch state. INFO records are retained as informational
plugin observations; the report maps their severity to unknown.

Pulse's own rules already raise `exposure` findings for SMB and RDP (the
EternalBlue and BlueKeep hypotheses); the plugin findings are separate rows
under their own detector and are not merged with those.

## Sandbox capabilities and remaining gaps

GenDec#39 adds `probe_send_hex` and `probe_udp_hex`: strict hex
requests and byte-preserving hex replies, restricted to the bound numeric IP
and port, with a shared eight-exchange budget. TCP connect/write/read share one
50–5000 ms deadline; UDP uses a connected peer and the same deadline, send
limit (4 KiB) and receive limit (16 KiB). Negotiation plugins request
1500 ms. The SNMP plugin uses UDP explicitly; UDP support does not make TCP completion
receipts interchangeable with UDP results.

Pulse v1.3.0 historically had text-only UTF-8 payloads, sanitised replies,
no UDP API and a timeout reset on each read. Those measured restrictions
explain the original GenDec#38 gap; GenDec#39 addresses the engine mechanisms,
not all protocol coverage. The existing SSH algorithm plugin continues to
parse sanitised ASCII name lists; it does not use the new binary API.

Stateful native helpers use scoped dialogues with an absolute deadline up to
5 seconds, total plaintext caps of 4 KiB sent/16KiB received and 64 KiB wire caps
per direction. Buffered TLS reads also check the deadline. They do not grant
an arbitrary host, second port, filesystem or process capability.

Remaining limits include SSH known-host trust/other algorithms, full RDP
security/authentication and VNC session acceptance. FTP PASV still needs a
second port and is not implemented. The cleartext plugin only observes
capabilities; native TLS enumeration separately performs bounded STARTTLS
upgrades ([TLS contract](pulse-endpoints.md#optional-tls-suite-enumeration)).
The [v1.3.0 reference corpus](pulse-backend.md#reference-corpus-nmap-versus-pulse-541)
is immutable historical evidence, not candidate or deployed acceptance.

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
  time, never concurrently. GenDec#39 applies one deadline per
  network call, including text calls. The old v1.3.0 per-read timeout allowed
  trickling responses to last 14.5 s for a nominal 1500 ms call; this is
  historical evidence, not the current deadline contract.
  A chunk therefore gets `endpoints * 10` seconds added to the process timeout,
  capped at 30 minutes (`PLUGIN_SECONDS_PER_ENDPOINT`, `PLUGIN_BUDGET_CAP_SECONDS`):
  an allowance for ordinary servers, not a worst case. The services behind the open
  ports are not known when a chunk is cut, so every endpoint is counted. When Pulse
  still overruns, the chunk is **unresolved**, not a crash: no success receipt, its
  hosts are reported through `on_unresolved` and probed again on `--resume`, the
  crash-loop counter (exits without JSON) is neither advanced nor reset by it, and
  `pulse/raw.json` marks the chunk `timed_out`. A verification then finds no receipt
  (`endpoint_not_probed`). Three timed-out chunks in a row stop the stage
  (`PulseTimeoutLoopError`, a subclass of `PulseCrashLoopError`) with a message naming
  what to change (`runtime.nse_timeout_seconds`, `chunk_hosts`, the plugins switch):
  each further chunk would cost two attempts of up to 40 minutes to give the same
  answer. Hosts finished earlier stay done; `--resume` asks again for the rest. What the tests check about the plugin files is stated as
  such: call *sites* (at most four per file), literal timeouts (at most 1500 ms),
  and `ports()` empty. They do not prove how many calls one run makes.

### Scan policy

The plugins' connections are not paced by `--rate` and are not counted by
`--host-parallel`. They are serial, so `max_host_concurrency` holds without help.
`per_host_rate` ("packets aimed at any single host") cannot be honoured for a burst
of up to eight connections a plugin run, so a policy with that ceiling turns the
plugins off in every speed profile (`scan_policy.apply_policy`). `skip_service_probe`
already skips the whole Pulse stage.

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
                "position": "line 135, position 9",
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
verification would otherwise credit. The one documented exception is `shapo_http_trace`: a
server that hangs up on `TRACE` has refused the method, so it returns clean without an error,
which means it cannot confirm that a fix worked (a reset for another reason reads the same).

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
   (`plugin_not_applicable`; the service is compared exactly, as the plugins do, and the
   banner in lower case, as the gates do): a plugin returns silently on a service it does not
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

### Binary negotiation probes (GenDec binary sandbox API)

The `shapo_smb_signing`, `shapo_smb1` and
`shapo_rdp_negotiation` require the engine's `probe_send_hex` API. Their
requests preserve bytes above 0x7f and contain only protocol negotiation,
without credentials, authentication attempts or exploit payloads. They use the
sandbox's existing target/port permission checks and 1500 ms per-call deadline.
Malformed, truncated, unexpected or failed replies raise script errors rather
than claiming that the endpoint was checked and clean.

`shapo_smb_signing` offers SMB 2.0.2 and 2.1 and checks the selected response's
SecurityMode. A response without the required-signing bit produces a MEDIUM
finding. This does not establish relay exploitability. `shapo_smb1` offers only
NT LM 0.12 and reports MEDIUM only when that SMB1 dialect is explicitly
selected. These plugins cover direct SMB on TCP; NetBIOS session negotiation
on port 139 remains exposure-only. Neither probe enumerates every dialect.

`shapo_smb_protocols` adds single-dialect SMB1/SMB2 offers and RFC1002
wildcard session setup on 139. `shapo_ms17_010` separately performs anonymous
SMB1 IPC$/FID0 PeekNamedPipe and records only the positive status hypothesis.
Denied/non-indicator responses remain UNKNOWN with assessment errors. Isolated
Samba 4.17.12 checks exercised 445/139 and signing optional/mandatory; its
INVALID_HANDLE response was unknown, not a patched verdict.

`shapo_rdp_negotiation` tests standard RDP negotiation. The native
`shapo_rdp_ntlm_info` helper proceeds through X.224/TLS/CredSSP only to an NTLM
type2 challenge; host/domain/build fields are advertised and unauthenticated.
It sends no type3, credentials or desktop-session messages. Full encryption
strength, login and password-policy assessment remain unimplemented.

`shapo_vnc_security` reads RFB3.3/3.7/3.8 security advertisements and stops before
selection/ClientInit. None is a conditional security finding, not proof of
an unauthenticated desktop session. RDP/VNC dialogue tests are synthetic
loopback fixtures; they are not native Windows or VNC fleet acceptance.

`shapo_snmp_info` performs one SNMPv2c GET with community `public`, requesting
only `sysDescr.0` and `sysName.0`. No community guessing or SET is performed.
It runs only when the endpoint transport is UDP. BER lengths, request ID,
community, response type, exact OIDs and container boundaries are checked;
exception values and malformed replies are errors, not empty clean results.
Its INFO observation retains raw values as bounded hex evidence. The adapter
keeps it as an informational plugin record (the report maps INFO to unknown),
not an assertion that a vulnerability was detected. Asset-name enrichment is not implemented by this
plugin. Standalone acceptance uses `pulse plugin run ... --protocol udp`;
the default is TCP, and an invalid or combined transport is rejected.

`shapo_ssh_hostkey` observes an Ed25519 host-key SHA256 fingerprint through
one scoped, bounded connection: SSH2 identification, curve25519-sha256 key
exchange, then verification of the server's Ed25519 exchange signature. No
password, authentication request or session channel is sent. The signature
proves possession on this connection; known-host trust and endpoint identity
are not established. Other key-exchange/host-key algorithms are UNKNOWN errors,
not negative evidence. The adapter retains the INFO observation as an informational plugin record
(the report maps INFO to unknown), not a vulnerability assertion. Its exchange encoding follows RFC 8731 section 3.1:
X25519's returned bytes are interpreted in network byte order for SSH mpint.

Transport provenance: native Pulse scan/standalone plugin results carry the
observed `tcp`/`udp` transport through parsing and report rows. Historical plugin
records lacking transport retain their TCP default; explicitly unknown
transport stays unknown. The production Shapoclyack adapter currently scans
TCP endpoints only. SNMP acceptance is therefore a standalone/native UDP scan
path, not newly enabled production UDP enrichment. Its UDP observations cannot
be closed by a TCP completion receipt on the same host, port and plugin hash:
verification remains inconclusive until an actual UDP completion contract is
implemented.
