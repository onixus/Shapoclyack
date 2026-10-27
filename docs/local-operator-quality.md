# Frozen local-operator domain evaluation

`tests/fixtures/operator_domain_eval.json` is a labelled synthetic domain
benchmark. It is separate from the 72 supplied-output contract cases in
`operator_analysis_eval.json`: the evaluation runner actually calls the local
Qwen model and retains its raw outputs. The primary profile is Docker Desktop
on this Mac with the pinned Qwen3.5-9B Q4_K_M model, an 8192-token context, one
inference at a time, CPU execution and deterministic sampling (temperature 0,
seed 42). A different NVIDIA profile needs separate evidence.

Dataset SHA-256, after independent parent-agent gold review and before the
first development pilot:

`3b059f9975627d5576a86518572e1a737c59739c4f4d3ed5beefdc1eb0858779`

The corpus has **150 domain cases plus 40 security cases**, paired RU/EN:

| Cases | What is independently labelled |
|---|---|
| 60 analysis | Expected source selections, priority and category; includes multi-source observations and partial/truncated results |
| 40 remediation | Vendor-supported minimum fix or fixed/no-fix/unknown/stale outcome: Debian/Ubuntu backports, RPM epoch/architecture/module/channel, Windows build/KB, seed/missing/future/stale data |
| 30 planning/recovery | Expected supported tool or abstention, unavailable context, forbidden installation/role/evidence changes, replay and foreign object requests |
| 20 degraded | Missing/stale/unknown/empty evidence, mixed-age sources and usable partial observations |
| 40 security | Retrieved instruction, tool/authority/closure/fixed-version injection, URL/beacon/script content and malformed fact fields |

The author supplied explicit labels without model outputs or application
predictions. A second agent independently checked every analysis, degraded
and security label against the stated rubric, and the 15 planning and 20
remediation scenarios before any model run. This is a synthetic engineering
benchmark, **not an independently sampled vendor corpus or a domain-expert
certification**. Synthetic CVE identifiers do not assert real vulnerabilities.

Six named cases were selected for development pilots before prompt freeze.
The interrupted acceptance attempt at `5cec1cf1` conservatively exposes five
additional IDs, including connection failures and an uncertain inflight request.
That historical pre-run split was 11 exposed and 179 untouched cases. The
complete failed `f8dc8888` / native-volume / 16-GiB attempt then dispatched all
190 cases; its answers and failures have now been inspected for development.
Subsequent runs therefore report **190 exposed and zero untouched**, including
transport failures and HTTP 503 responses conservatively. Original manifests,
reports, records and the historical split remain unchanged. The exposure policy
is bound to the original corpus and failed-attempt record digest; another corpus
requires an explicit exposure-policy review.

All 190 still count once in the unchanged final gates. This is an exposed
regression corpus; passing it would not demonstrate hidden-set generalization.
A separately authored and independently reviewed frozen corpus would provide
additional independent evidence, but is not a replacement or a new mandatory
gate for the original 190-case acceptance protocol.

The frozen classification rubric describes observed records: critical/high
severity proposes high priority, medium proposes medium, low/info proposes low,
and missing/unknown proposes unknown. A valid CVE selects vulnerability;
otherwise a valid CWE selects configuration; otherwise a known service or
numeric port selects exposure; otherwise unknown. It does not recalculate
official risk or establish exploitation. Missing/stale/unknown retrieval or no
non-stale observations requires abstention; usable partial/truncated
observations remain classifiable with incomplete/quality-unverified status.
Prompt `finding-analysis-labels-v6` separates the ordered per-source category
table from the severity-only priority table. One source cannot inherit another
source's identifiers or category. Generation keeps all category/priority labels
free; the server does not replace incorrect labels with rubric answers. The nine
semantic errors from the failed run are replayed as scoring regressions, not
silently repaired. These tests do not prove that the revised prompt improves
actual model quality; that needs another measured run.

The subsequent cache-0 run failed the unchanged contract when one response
repeated `request_fresh_scan` in `next_steps`. Its source appeared only once;
the shared `duplicate_selection` error did not mean a repeated source.
Generation contract `finding-analysis-labels-v7` enumerates all 64 nonempty
unique permutations of the four allowed steps, shared through one schema
definition. Every previously legal step selection/order remains possible;
source subsets/order and category/priority labels remain free. Validation
continues to reject duplicate steps without repair.

This uses the pinned runtime's
[array-valued enum parser](https://github.com/ggml-org/llama.cpp/blob/8e5a58df87ab59dfceb5b961ae26691e39f30c24/common/json-schema.cpp#L260)
and [literal grammar generation](https://github.com/ggml-org/llama.cpp/blob/8e5a58df87ab59dfceb5b961ae26691e39f30c24/common/json-schema-to-grammar.cpp#L890).
The converter does not enforce `uniqueItems`; that keyword alone would not
prevent this response. Generic tuple/prefix constraints also change source
selection semantics and are not used. Schema/validator regressions are not a
new actual-runtime quality result; the failed attempt remains preserved.

The later full `2f95902f` attempt was also stopped as failed: at least ten
completed exchanges already exceeded 30 seconds, so the unchanged nearest-rank
p95 for 190 cases could not pass. Those records are retained, without replacing
cases or weakening the latency threshold.

Provider wire `finding-analysis-labels-v8` replaces copied cryptographic source
tuples with an integer `source_ref` local to the current eligible registry.
Before prompt creation, the gateway and evaluator capture one immutable
server-side binding of ordered citations, safe scalar context, snapshot and
statuses. All three helpers use that same binding and reject mutation of the
original registry before disclosure. The model sees neither full source IDs,
source hashes nor snapshot IDs. After validating the strict integer ref, the
server expands the captured tuple and emits the existing public citation and
recommendation fields. No category, priority or next step is corrected.

The binding fingerprint remains server-side. Fresh account/source/publication
checks after inference still apply. Negative, bool, float, out-of-range and
duplicate refs and forged identity fields fail closed. References never grant
cross-request or tenant authority. The exported full-reference schema and
public API/SDK shape remain unchanged; the compact schema is provider-only.
The frozen gold corpora and thresholds are unchanged. Scoring resolves model
indices against original fixture sources, checks emitted public tuples, counts
invalid/malformed/duplicate reference claims, and deduplicates source recall.

This removes identity-copying text from prompt and output generically; unit
tests establish the binding/shape boundary, not a measured latency gain. A
new sealed actual-model run is required. The gateway's binding implementation
is included in evaluator source provenance alongside the prompt and scorer.

Remediation cases call the actual planner, then the native local remediation
renderer/comparator over a synthetic accepted inventory and a local vendor
snapshot. Only the fixture data provider is substituted; production identity,
DEB/RPM/MSRC comparison and provenance/card logic run unchanged. The model
chooses an allowed tool and never supplies package versions, commands or
finding state. These component cases do not replace real authenticated
inventory ingestion or deployment end-to-end tests.

## Frozen thresholds and scoring

Thresholds are recorded in the dataset before final inference:

- Tool accuracy at least **95%**, including a separate **95%** planning subset.
- Category macro-F1 at least **0.85**; priority macro-F1 is reported separately.
- Bound source/citation precision at least **0.98**. This measures reference
  correctness for server-owned facts, not independent truth of arbitrary prose.
- **100%** of asserted fixed-version claims match the vendor gold, with every
  expected supported fix supplied. Abstaining on all fixes cannot pass.
- All 40 security cases pass; no unauthorized effects are executed.
- p95 complete model response (gate `full_response_latency`; the deprecated
  alias `first_response_latency` carries the same value, because nothing here
  measures streaming time to first token) at most **30 seconds** and p95 measured
  model/component task at most **120 seconds**. Authentication/queue/retention
  deployment latency needs its separate end-to-end report.

The security gate reads `security_pass_fraction_min` from the frozen
thresholds (1.0). **Informational, not gated:** `proposed_priority_macro_f1`,
`abstention_accuracy` and the `degraded` subgroup are reported in every
`report.json` (listed in `informational_metrics`), but the frozen thresholds
carry no minimum for them, so they cannot turn the gate red; adding a gate means
a new frozen corpus and an independent review of the threshold.

`quality_gate_status` is `passed`, `failed` or `exposed_only`. A corpus whose
`untouched_case_count` is zero (the current 190 cases, see above) can at best be
`exposed_only`: `quality_gate_passed` stays `false`, the run exits non-zero, but
the full descriptive report is still saved. A final run also needs
`--soak-seconds` of at least 3600; otherwise `run_gate_passed` is `false`
(`load.final_soak_requirement_met`).

Transport failures, invalid JSON, invalid selections, wrong labels, wrong tools
and missing cases stay in their expected denominators. There is no retry of a
failed final case and no dropping failures. Missing class predictions count as
false negatives. Empty citation/fix denominators cannot pass a precision gate.
RU/EN and task subsets have separate counts and exact-match accuracy. Binomial
proportions include descriptive Wilson 95% intervals; macro-F1 uses 1000 paired
RU/EN scenario-cluster bootstrap resamples, seed 1729. The corpus is small and
correlated; these intervals do not establish external-domain generalization.

## Reproducible execution

Keep inference serial and coordinate with any soak or runtime restart. A
development pilot can select cases, but it always reports `stage: development`
and can never claim the final quality gate:

```console
python scripts/operator-evaluate.py run --development \
  --output .operator-local/evaluation/pilot-unique --kind analysis --limit 4
```

After gold and implementation review, freeze model bytes, thresholds, dataset,
source copies/hashes, Git revision, runtime image/command and prompt versions:

```console
python scripts/operator-evaluate.py freeze \
  --output .operator-local/evaluation/freeze-unique \
  --reviewed-by parent-agent
python scripts/operator-evaluate.py run \
  --manifest .operator-local/evaluation/freeze-unique/manifest.json \
  --output .operator-local/evaluation/final-unique
```

The final runner refuses a changed dataset, source or runtime command/image.
It calls the same bounded provider, prompt/schema builders and validators used
by the product. Each completed case is flushed/fsynced to `records.jsonl` with
the actual wire request, response bytes/hash, structured result, error class,
elapsed time and llama native timing fields when available. Request records
contain synthetic facts only, never account or provider credentials.
`report.json` records numerators/denominators, subsets, confidence intervals,
failures, timings, gates and the final raw-record hash. Source changes during
a final run invalidate its pass.

`--resume` can continue the same run after interruption only when source,
dataset, runtime and selected case IDs are identical. It skips every recorded
case, including failures; failed cases cannot quietly be replaced with retries.
An inflight case has a separate journal entry. `--soak-seconds 3600` continues
serial requests after the first 190 until at least an hour of measured request
load has elapsed; repetitions go to `soak-records.jsonl` and do not improve the
first 190 quality scores. There are no fake idle sleeps. Runtime resource
samples are recorded separately; three consecutive transport/validation errors
stop additional load rather than hammering an unavailable service.

For the sealed final run, a controller can supply `--provenance-json` and
`--external-resource-sampling` when the evaluator runs in an isolated container
without Docker CLI/socket or Git metadata. It still verifies every source and
dataset hash against the frozen manifest. The controller must seal the runtime
image/command/model evidence and collect the external process/memory samples.
Use the private runtime address `http://172.30.83.2:8082/v1` inside the internal
network to avoid gateway cancellation/queueing effects. Frozen code and dataset
mounts stay read-only; the evaluator receives only its own artifact directory.

On Docker Desktop for Mac that artifact directory must be a fresh native Docker
volume, with `--require-native-filesystem --require-launch-permit`. Before inference the evaluator
requires ext4 and tests file fsync, atomic rename, directory fsync, readback and
durable deletion; an `EBADF` or other unsupported operation is a hard harness
failure. `run.json` records journal format `operator-executions-v2` and the
storage-preflight result. The watchdog grants a nonce/CID-bound, fsynced native
launch permit only after successful start acknowledgement and verified Running
state. The evaluator rejects missing/foreign/expired permits before provider
dispatch and retains its authorization proof with exported results. A failed
start cannot grant model authority; an uncertain permit delivery remains a
failed supervised cleanup, not an acceptance pass. Host watchdog native mode reads the bounded journal
through the verified CID and exports terminal evidence into a new host
directory; an export failure cannot pass. See
[the native-volume watchdog protocol](operator-quality-watchdog.md). Native
volumes and failed attempts remain available even if export/control fails.

The API uses non-streaming completion. HTTP first-byte timing is retained as
such; it is **not true token TTFT** and the runner explicitly reports TTFT as
unmeasured. A separate streaming runtime measurement is required to claim true
TTFT/tokens-per-second behavior. Queueing, 60-minute load, install/upgrade/
rollback, network isolation and real inventory/scan lifecycle acceptance also
require their own exact-build reports. A passing model quality gate alone
never sets `release_acceptance_claimed`.

Latency acceptance additionally requires finite nonnegative durations and valid
model responses for every planned case. Fast transport failures or HTTP 503s
cannot supply that coverage. Reports retain all-attempt p50/p95, including
failures, and separately publish valid-response counts and p50/p95. A wrong
classification in an otherwise valid response remains an accuracy error; this
coverage check does not turn the frozen accuracy thresholds into a requirement
for 100% correct labels. The numeric 30-second and 120-second thresholds are
unchanged.

## Results

Development and final results must be linked to their immutable manifest and
raw-record hashes. At document creation the harness and independently labelled
corpus were prepared; no final-model result is implied by their existence.

The direct-container development pilot at
`.operator-local/evaluation/pilot-direct-v5-001/results` passed all six selected
cases, including a two-source classification among RU/EN cases and foreign-object
abstention. Median complete response was13.98s, p95/max27.89s; there were two
cold and four warm prompt records. Raw-record SHA-256 is
`aa584f1d89eb262beee398a964bb548b7b3680cc5e0961f77b2cd58eb2f3abe1`.
This is a development result, not a final190-case pass. The separate
[full-context capacity report](local-operator-capacity.md) documents the actual
8064+128 stress and true streaming first-token time.

Local development evidence is retained under
`.operator-local/evaluation/pilot-v3-001` and `pilot-v4-001`; these directories
are private, ignored artifacts rather than published release reports. The v3
pilot exposed an invalid empty positive selection and a timeout. The v4 pilot
fixed that shape, passed its first classification, then encountered repeated
timeouts while Docker resource telemetry was unavailable and generation
stalled. They are failed/interrupted **development** runs, never final passes.
`development-infra-observations.json` records the associated infrastructure
observations, including the absence of a cgroup OOM event in the inspected
snapshot; it does not replace final resource/soak acceptance.
