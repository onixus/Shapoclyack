# Migrating off Nmap

Shapoclyack no longer runs Nmap. The NSE stage, the `hybrid` backend, the
Pulse-versus-Nmap shadow comparison and the Nmap lookups on `PATH` are gone
(#548, the last step of epic [#549](https://github.com/onixus/Shapoclyack/issues/549);
the reasoning is [ADR 0002](adr/0002-replacing-nmap-functions.md)). Pulse is the
only service-probe backend; what NSE `default,safe,vuln` identified now comes
from Pulse's probes and Rhai plugins, Nuclei network templates, and the TLS and
version-matching stages ([NSE `vuln` coverage](nse-vuln-coverage.md)).

**This is a breaking change.** A configuration that still names an Nmap setting
is refused when it is loaded, with the replacement in the message. Nothing is
ignored and nothing is quietly turned into a Pulse setting: a profile that said
`nmap_timing: T2` meant "scan gently", and loading it as Pulse's defaults would
scan harder than the operator asked for.

`shapoclyack-0.47-1009-rc1` was the last release with `-nmap` image tags; the
published images have carried no Nmap, NSE data, `nmap-vulners` or Vulscan since
([issue #97](https://github.com/onixus/Shapoclyack/issues/97), NPSL). See
[Third-party components](third-party.md).

## Settings that are now refused

The scanner exits with code 2 (`CONFIG_ERROR`) before any stage runs and prints
the lines below. The same check covers the config file, the environment, the
per-job config overlay a sensor receives from the API, and the console's saved
overrides.

| Setting | Refused where | Use instead |
|---|---|---|
| `service_probe.backend: nmap` or `hybrid` | config file, overlay (`service_probe.backend`), `PUT /api/config` | `pulse`, or delete the key |
| `profiles.<mode>.service_backend: nmap` or `hybrid` | config file | `pulse`, or delete the key |
| `OCTO_SERVICE_BACKEND` other than `pulse` (`nmap`, `hybrid`, anything unknown) | environment of the scanner | unset it, or `pulse` |
| `service_probe.shadow`, `OCTO_PULSE_SHADOW=1` | config file, overlay, environment, `PUT /api/config` | delete it: nothing runs Nmap to compare against |
| `profiles.<mode>.nmap_timing` | config file, overlay, `PUT /api/config` | `profiles.<mode>.pulse.rate` and `pulse.concurrency` ([below](#nmap_timing)) |
| `profiles.<mode>.nse_profile`, top-level `nse_profiles` | config file | delete them; there is no script set to select |
| `profiles.<mode>.nse_concurrency`, `profiles.<mode>.nse_max_rate` | config file | `pulse.concurrency` / `pulse.host_parallel`, and `pulse.rate` |
| `runtime.nse_concurrency`, `runtime.nse_max_rate`, `runtime.nse_hosts_per_scan` | config file | the same per-profile Pulse settings, and `service_probe.pulse.chunk_hosts` |

Where each is checked: the schema validators in
`scanner/pipeline/config_schema.py` (`RemovedNmapSettingError`) cover the file
and the merged overlay; `check_service_probe_env` covers the environment, called
from `scanner.main._config_for_run` before anything runs; the console's
`PUT /api/config` answers 422 naming the setting
(`api/services/config_override.py`).

Kept on purpose, because they were never Nmap's alone: `runtime.skip_nse` and
`--skip-nse` (the ports-only L1 switch: it skips the Pulse probe now) and
`runtime.nse_timeout_seconds` (the wall-clock cap of one Pulse invocation). The
names are historical; renaming them would break every config, schedule and job
record that carries them.

### `nmap_timing`

There is no exact equivalent: `-T3` paced probe retransmissions and timeouts of
one `nmap` process, Pulse paces packets per second and open connections. Take
the shipped profiles as the reference for what each used to mean, and adjust:

| Profile (it ran) | `pulse.rate` | `pulse.concurrency` | `pulse.host_parallel` |
|---|---|---|---|
| `safe` (`T3`) | 500 | 300 | 4 |
| `balanced` (`T4`) | 2000 | 800 | 16 |
| `fast` (`T4`) | 5000 | 1200 | 32 |

For a profile of your own, `T2` and below belong under `safe`'s figures and `T5`
above `fast`'s; Pulse's defaults (`rate: 2000`, `concurrency: 500`) are what the
profiles that never set a `pulse:` block get.

`scanner/config/default.yaml` and `k8s/shapoclyack/base/config/k8s.yaml` already
carried a `pulse:` block per profile, and keep those values. The bench, load and
e2e configs now state `rate: 2000` / `concurrency: 500` (what their `T4`
meant). A tenant scan policy's `per_host_rate` and `max_host_concurrency` hold
Pulse (`scanner/pipeline/scan_policy.py`) as they held the NSE stage.

The console no longer shows the per-profile timing select or the shadow toggle,
and the system page no longer lists NSE profiles or probes for `nmap`.

### Stored console overrides

Migration `0085_drop_nmap_config_overrides` deletes `profiles.*.nmap_timing` and
`service_probe.shadow` from the saved overrides document, and nothing else in
it. Without that the next scan would fail on a setting the console no longer
shows. A saved `service_probe.backend: nmap|hybrid` is **not** touched: scans
fail on it, naming it, and the console offers only `pulse` to replace it with.
The downgrade does nothing; the deleted values meant nothing without the stage.

## Old data is still read

Nothing writes `<run>/nmap/*.xml` any more, but past runs keep theirs, and these
readers still give the answers they gave:

| Reader | What it takes from an old run |
|---|---|
| `scanner/pipeline/legacy_nmap.py` (`parse_nmap_xml`) | services (with CPE and `extrainfo`), OS matches and script rows, for the report and the asset-services folding |
| `scanner/pipeline/report.py` | rebuilding the reports of an old run directory, with `source: nmap-nse` on its script findings |
| `scanner/pipeline/tls_posture.py` | `ssl-cert` / `ssl-enum-ciphers` output, `source: nmap-nse` |
| `scanner/pipeline/evidence_artifacts.py` | NSE reports as `nmap-nse` observations |
| `api/services/verification_coverage.py` | the `nmap-nse` rule: a finding an NSE script made is judged against the XML of the run that re-checked it |
| `api/services/asset_services.py`, `retro_match.py` | `prober: nmap` rows and nmap-shaped CPE and version strings |

The strings `nmap-nse` (a finding's detector and `source`) and `nmap` (a
service's prober) stay valid values in the database, the API and the console;
no row is migrated or deleted. A new run produces neither.
`summary.json` keeps its `nmap_open_services` key: it is a field of the report
contract that consumers read, and it now counts Pulse's open services.
`tests/test_legacy_nmap_run.py` pins all of this from one fixture run
directory (`tests/fixtures/legacy_nmap_run/`).

One consequence to know: a vulnerability that **only** an NSE script detected
cannot be closed by a verification re-scan any more, because nothing re-runs
that script. The re-scan still happens and ends *inconclusive* with the NSE
detector as the gap. If another detector (Pulse, Nuclei, a plugin) covers the
same host, the NSE detector is waived and the closure follows that one.

`tests/fixtures/nmap_pulse_corpus/` (the recorded Nmap and Pulse output of the
comparison stand, [#541](https://github.com/onixus/Shapoclyack/issues/541)) and
its tools `scripts/compare-nmap-pulse-corpus.py` and `scripts/pulse_corpus.py`
stay: Nmap was run on the stand to record it, and is not part of the product.

## Known gaps

What Nmap did that nothing replaces yet. These are not hidden by the migration;
each is tracked.

1. **TLS cipher-suite enumeration** ([#545](https://github.com/onixus/Shapoclyack/issues/545),
   waiting for [GenDec#34](https://github.com/onixus/GenDec/issues/34)). The
   grading code (`tls_grading.py`) and the contract for Pulse's enumeration are
   in place and tested against recordings, but Pulse does not enumerate suites
   yet. Until it does, **a real scan on the Pulse path produces no TLS grade
   A–F**, no `weak_cipher_grade`, and none of the findings that need the suite
   list. Certificate checks, the stdlib legacy-protocol handshakes and the
   hostname and chain checks run as before.
2. **Four NSE `vuln`/`safe` scripts have no replacement**: `smb-vuln-ms17-010`,
   `smb-vuln-ms10-061`, `smb-protocols` and `rdp-enum-encryption`. Each needs a
   binary protocol exchange that the Rhai sandbox cannot send and that has no
   Nuclei template ([GenDec#38](https://github.com/onixus/GenDec/issues/38);
   [NSE `vuln` coverage](nse-vuln-coverage.md)). On a host running SMBv1 or RDP
   without NLA, the run now says less than the Nmap run did.
3. **Pinned Pulse inputs are not complete** ([#543](https://github.com/onixus/Shapoclyack/issues/543),
   waiting for GenDec#31 and GenDec#32). The adapter passes `--services-db`,
   `--os-mode sinfp`, `--probe-db` and a private `HOME`, but Pulse still takes a
   service's name from its port table rather than from the probe that matched,
   and about 80 well-known ports keep names hard-coded in the engine
   ([Pulse backend](pulse-backend.md)).

## Running your own Nmap anyway

You can still install Nmap on a host; Shapoclyack will not call it. Anything you
built on the old `nmap/` output of new runs (a script reading
`nmap/tcp/*.xml`, a dashboard on `diff_pulse_nmap.json`) finds nothing, because
those files are no longer written. `scripts/install-agent.sh` and the images
install no Nmap, and CI asserts `! command -v nmap` in the scanner image
(`tests/test_no_bundled_nmap.py`, `Jenkinsfile`).
