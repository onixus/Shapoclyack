# Mac acceptance evidence — status through 2026-11-06

The implementation and acceptance harnesses are delivered in PR #607. **The
Mac runtime and the complete epic are not accepted.** This record distinguishes
working components from failed or incomplete deployment measurements. Physical
NVIDIA acceptance remains separate in #609 under ADR 0005.

## Completed component evidence

- Frontend: 732 tests, type/lint checks and production export of 41 routes.
  Headless keyboard, planner, package/finding remediation, citation and runtime
  readiness checks used a synthetic loopback fixture and made no model/scan or
  external-origin requests.
- Real CPU embedding retrieval on application commit
  `5cec1cf1a0fdab64d5e6ee4304694f5816a9b1ef`: 180/180 queries, semantic recall@10
  120/120 and exact identifiers 60/60. Both model containers were running before
  and after, without observed OOM/restarts. Total execution was 50.88 seconds;
  p95 run/device/exact queries were 0.266/0.157/0.037 seconds. Corpus SHA-256:
  `d18074d87edc89d9e646c8cfe9d46ab4dc4dc6076ba3cc5bb153b1c0b3790092`.
- Native token capacity: one request processed all 8064 input tokens and emitted
  128 output tokens, with cache 8191 and no context shift. The pinned server
  reported its capacity-boundary `truncated` flag. The exact source-backed
  interpretation, original failed scorer output and raw stream are retained in
  [the capacity report](local-operator-capacity.md). This does not establish a
  resource/soak pass or typical-operation latency.
- A normal signed agent scan against an owned Apache fixture published a real
  Pulse TRACE observation. The finding remained `machine_verified=false`.
  Analysis, reviewed configuration change and real verification are still
  pending; the positive scan alone does not complete the end-to-end gate.

Note on the evaluator verdict: because all 190 benchmark cases are development
exposed, a fully green final run reports `quality_gate_status: exposed_only`
with `quality_gate_passed: false` and a non-zero exit, and a final run also
needs a soak of at least 3600 seconds. Figures above are descriptive local runs
and are not re-verified by the pull request.

## Failed and incomplete measurements

The frozen domain/security corpus has 190 cases and SHA-256
`3b059f9975627d5576a86518572e1a737c59739c4f4d3ed5beefdc1eb0858779`.
Its labels and quality/latency thresholds have not changed.

The first full attempt on `5cec1cf1` exceeded its exchange deadline: the first
transport failure took 158.85 seconds. Stopping that attempt produced four
additional transport errors and one uncertain inflight execution; 184 cases
were not run. All remain in the planned denominator. This is a failed attempt,
not a model accuracy result and not an accepted one-hour load run.

A temporary eager loading policy (`--load-mode none --lazy-mode off`) also
failed, with transport errors at 144.79 and 232.11 seconds. A temporary managed
Docker volume verified both GGUF copies by source-stream and destination hashes,
but its pilot could not start reliably. A subsequent microbatch-32 experiment
also encountered control-plane startup timeouts before actual model cases.
These experimental policies have not been adopted as a validated profile.

The shared machine was an Apple M5 Pro with 24 GiB RAM; Docker reported 15 CPUs
and 12,527,685,632 available bytes with a configured 12-GiB VM. Docker inspection,
container startup and even scoped stop requests intermittently exceeded their
deadlines under model load. An exact causal attribution requires a stable
environment and another measured run; successful short health requests do not
prove inference performance.

Development exposure is tracked conservatively, including failed/uncertain
requests. The historical protocol recorded 11 exposed and 179 untouched cases;
the subsequent full attempt sent all 190. Future tuning must therefore treat
the original corpus as 190 exposed and zero untouched cases. Failed cases are never replaced through
resume. Interrupted soak executions have their own durable journal and failed
soak records. The independent [host watchdog](operator-quality-watchdog.md)
enforces wall-clock failure receipts even when guest cleanup stalls.

Jenkins build 4 checked out `5cec1cf1` and failed: historical migration inventory,
configuration owner documentation, an audit test clock race and the distinction
between mandatory PostgreSQL tests and an opt-in real-runtime test required
correction. A terminal full-project success on the corrected final SHA remains
required. Earlier successful builds are not substituted.

### Recovery and harness correction — 2026-10-26

Jenkins build 5 on `05607225` finished with **FAILURE**. Both Python matrices
passed 10,327 tests each; mandatory PostgreSQL and NATS ledgers had zero skipped
or unexecuted tests. Web passed 732 tests and its 41-route build. Later image
smoke tests failed creating `/tmp/pytest-of-*` with `ENOSPC`; downstream security
and SBOM stages did not run. This is not a complete CI pass.

With no active builds or queued work, the owner-authorized Docker Desktop
restart preserved all 14 existing containers, images and volumes. Only unused
build cache was removed (677.3 MB plus 13.47 GB). Docker already had approximately
150 GiB free before this cleanup; do not attribute all recovered disk space to
this operation. Post-restart verification found roughly 165 GiB available,
Jenkins and the console responding, and the dev application pods Ready.

A fresh pilot on the original model/context/CPU settings obtained one valid
answer in 26.71 seconds, then failed directory `fsync` with `EBADF` on the Mac
shared filesystem while completing the journal. The five remaining pilot cases
were not executed. Its output and failed watchdog receipt are retained; it is
not a passing pilot or final accuracy run.

The evaluator now probes file, rename, directory-sync and unlink durability
before any inference. Production acceptance uses a new native ext4 Docker
volume for journals. The host watchdog reads only the ownership-checked runner's
bounded journal and exports terminal results without deleting native evidence.
Unsupported durability remains a hard failure. Model namespaces also disable
IPv6; startup/installation attestation verifies this policy instead of ignoring
unclassified neighbor or multicast traffic. These corrections require fresh
sealed-source measurement and do not convert previous failures into passes.

A native journal smoke test subsequently passed real ext4 synchronization,
live watchdog journal observation and terminal export in 6.51 seconds without
calling a model. The next pilot still failed: Docker completed its runner start
after the start RPC deadline and the controller lost supervision. The owner
stopped that runner and preserved its uncertain inflight journal. Server logs
show approximately 32 seconds of actual request processing before cancellation;
they do not establish a 120-second model timeout or an accuracy result.

The follow-up controller keeps failed pending starts under supervision until
the owned immutable container is confirmed terminal. A launch permit is issued
only after an acknowledged, ownership-checked start; a late start after a
failed acknowledgment receives no permit to invoke inference. GGUF storage is
also being tested in checksum-bound local Docker volumes rather than Mac host
binds. Both source and independently read-back destination hashes are required,
and actual read-only mounts are inspected. This is an I/O profile correction,
not evidence that host caching caused the previous failures or that the new
profile has passed performance acceptance.

### Native storage and 16-GiB VM measurement

With builds and queue empty, a second authorized maintenance operation changed
only Docker Desktop's configured VM memory from 12 to 16 GiB. Container state,
images, volumes and settings backup were preserved; Jenkins, the console and
the dev node recovered. The engine reported 16,747,139,072 available bytes.
Both pinned GGUF files were independently verified in a read-only native local
volume. These changes resolved the observed short control-plane stalls; they
did not establish sustained inference acceptance.

On source `f8dc88886a5acccb6e6abccc8ebb52b04bc67802`, the six-case pilot
passed with p95 complete-response time 20.4 seconds. Real retrieval with both
model containers resident passed 180/180 queries, including 120 semantic and
60 exact queries. The controlled-provider recovery drill passed 8/8 phases.
Frontend checks passed 751 tests and exported 42 routes. These are component
results, not a full-epic acceptance.

The subsequent full attempt failed. All 190 cases were submitted: the first
20 returned schema-valid responses, including nine genuine classification
errors (eight category and one priority). The remaining requests encountered
a transport failure and upstream rejection as the model restarted. Citations
were correct for the 25 returned references; that does not erase wrong labels
or missing useful responses. Three failed soak requests stopped additional
load; no one-hour pass was obtained. Fast HTTP errors must not count as a
successful useful-response latency gate.

The Docker VM kernel log at 13:26:53 UTC identifies `CONSTRAINT_MEMCG` for the
exact inference container: memory reached its 7-GiB cgroup limit, the kernel
killed `llama-server`, and exit 137 caused an automatic restart. Post-restart
`OOMKilled=false` and reset counters do not negate this historical evidence.
This proves a container-limit OOM, not a global 16-GiB VM OOM. The pinned
server's default RAM prompt-cache budget is 8192 MiB; the next diagnostic
profile explicitly disables that cache while retaining the same weights,
context, CPU allocation and 7-GiB limit. Cache causality and sustained fit
require a fresh measured run.

The failed attempt and observer are retained under
`.operator-local/evaluation/native-f8dc8888-16g-20261026-001/final/`.
The original corpus, gold and thresholds remain unchanged. Future reports must
describe its development exposure honestly; independent generalization needs
separately authored and reviewed evidence.

On `8fdafa6d`, the cache-disabled 24-case pilot returned 24 schema-valid answers,
22 matching gold; two CWE category errors remained. Complete-response p95 was
23.38 seconds. Both model containers retained their process epochs, with no
OOM/restart, sampling errors, DNS/external packets or kernel capture drops.
The follow-up full attempt was stopped after 46 completed records when a model
answer repeated `request_fresh_scan` in `next_steps`. The validator correctly
rejected it. This was a repeated next step, not a repeated evidence source;
the shared `duplicate_selection` error code covers both. Its interrupted last
exchange, missing cases and failed load gate are preserved. The roughly
12-minute run supports short-run resource stability only, not hour acceptance.
The next generation contract restricts next steps to the existing legal unique
arrays, while leaving source selection and category/priority labels free.

The image-smoke `ENOSPC` correction supplies a bounded 128-MiB writable tmpfs
for pytest temporary files under the unchanged production `scanner` user.
All seven real probe smoke tests passed on the cached production image with
that mount, with zero skips. This does not substitute for the final full CI.

The `55308d11` unique-step pilot returned 25 schema-valid responses and no
repeated steps, including the previously rejected case. Gold accuracy was
22/25, with three CWE category errors retained; p95 was 23.63 seconds and the
maximum 27.84 seconds. This verifies sampled native grammar compatibility,
not the final 190-case quality threshold. Offline deployment now pins the
PostgreSQL/API addresses and local host aliases, reserves a disjoint dynamic
address pool, and configures IPv4/resolver guards. Generated-graph tests do not
establish zero DNS/egress; fresh cold-start observation remains required.

On `2f95902f`, the native full-8K stress test passed: 8064 processed cold input
tokens, 128 independently counted output tokens and intact cache 8191. Raw SSE,
native counters, terminal fsync/export hashes and independent replay agree.
True first generated token was 234.94 seconds and total time 246.63 seconds;
these are full-context stress timings, not a typical-operation latency pass.
Both resident models retained their process epochs without OOM/restart; capture
had no DNS, external destinations, drops or receive errors.

Its subsequent typical-operation attempt was stopped with 106 completed
records, including an interrupted final exchange, and 84 cases not run.
All 60 analysis cases were schema-valid: category macro-F1 was 0.89476 and
priority macro-F1 1.0, with five CWE category errors retained. This is an
analysis-subset result, not the complete quality gate. Ten recorded responses
exceeded 30 seconds; even if every remaining planned response were fast, the
unchanged 190-case nearest-rank p95 would remain above 30 seconds. The observed
106-record p95 was 31.97 seconds. The attempt and failed load gate remain
preserved; no slow case is replaced by a retry.

The next candidate removes long source IDs, hashes and snapshot IDs from the
model wire. The model selects request-local integer references; the server
expands their original authorized citation tuples. A held immutable binding
is captured before dispatch, and changed source order/identity/status/context
must invalidate it before expansion. Category/priority decisions remain free,
with no repair to match gold. This reduces redundant copying, but latency and
full quality still require a fresh measured run.

## Independent holdout and compact-literal attempts — 2026-10-27/28

The retained native-volume records provide the later results that were absent
from this status document. On `4b97e6ef`, the independently authored and
reviewed 190-case holdout completed every first-shot case and a 3604.54-second
serial load phase, but failed quality: 130/190 overall gold cases, tool accuracy
25/70, remediation 0/40, category macro-F1 0.80890, citation precision 148/148,
and full-response p95 30.178 seconds. All 40 remediation cases were valid
`witness_unresolved` refusals: the parser treated package or descriptive text as
an explicit resource witness instead of the selected device. The hour-long load
gate passed; it does not offset the quality or latency failure. The authoritative
records remain in Docker volume `shapo-operator-quality-d357c0f748fd4117b93d3349a0527874`.
This holdout is now exposed and cannot be rerun as independent acceptance.

A later compact-literal engineering run on the exposed original corpus produced
181/190 gold cases, tool accuracy 67/70, category macro-F1 0.91944, citation
precision 117/117 and fixed-version support/recall 14/14. Two cases were
interrupted and full-response p95 was 36.312 seconds; no hour-long soak was run.
It therefore failed coverage and latency despite passing the measured accuracy
fractions. Its records remain in
`shapo-operator-quality-36b176096cea40b7a5a240a96fae800a`. These two attempts
use different corpora and configurations and are not interchangeable evidence.

## Compact v9 engineering run and cold-start diagnostics — 2026-11-04

The exposed original corpus was rerun with `finding-analysis-labels-v9` and
`operator-contextfree-intent-v5`; the relevant source bytes were subsequently
committed as `2ac852820a2100d8e94dc6d5ef1a409f9b7cc457`. All 190 responses were
valid and present. The run retained seven wrong analysis answers: six CWE
category errors and one English missing-severity priority error. Measured gates
nevertheless passed their frozen numeric thresholds: tool accuracy 70/70,
category macro-F1 0.86556 (minimum 0.85), citation precision 118/118, fixed
version support and recall 14/14, all 40 security cases, p50 3.049 seconds and
p95 7.622 seconds. Raw-record SHA-256 is
`c5457e584bbb4dbc388e0f1499308ecafec53cfb13d74d319449051e510471ae`; source and
reviewed inputs remained unchanged. Both models stayed healthy with no OOM or
restart. This was an 11.5-minute development run without the final hour soak;
`quality_gate_passed=false` remains correct because the corpus is exposed.

The verified exact-source offline bundle for `2ac85282` exported, independently
verified and completed a fresh authenticated import/start. Its manifest SHA-256
is `811e9ce577ea00c073a7fbd3f123d434cfb5e9ac9ed4d76edd2d75bd93ce3b9e`. No cold-start
packet capture was attached to that first import, so the network gate remains
open. One v5 cold planner request returned the contradictory combination
`selector=contextual` plus a package span and was correctly refused as
`witness_unresolved`. The v6 prompt explicitly forbids that combination and
resolved three subsequent diagnostic calls, but those calls used a temporary
`/tmp` source overlay and do not replace a fresh exact-v6 bundle/capture run.
An attempted `anyOf`/`oneOf` conditional schema was rejected for the product
because the pinned runtime generated an invalid shape; no such schema is used.

## Exact-v6 cold start and first independent holdout — 2026-11-04

A newly exported exact `aa3ddb9b5859ce51a4477ea08fd17af54deeb0a3` bundle passed
verification and fresh authenticated startup. Its manifest SHA-256 is
`19476740df6f13fdbfe53f99b131c4b681934467ca379e1dca8597619fb2aa28`. The real
package/device planner request returned `resolved` with contextual
`find_remediation`; no temporary source overlay was used. Host packet capture
began before startup and recorded zero DNS/drops and no external unicast IPv4
destination from the project subnet. A separate 60-second namespace observation
of inference, embeddings, API and worker found zero unexpected destinations,
DNS, receive errors or drops and no OOM/restarts. Shared-VM IPv6/IGMP process
attribution remains an explicit limitation of the host capture.

The independently authored/reviewed holdout completed all 190 first-shot cases
and a 3601.83-second serial load with 637 additional requests and no additional
errors. It failed quality: 138/190 gold cases, tool accuracy 39/70, fixed-version
recall 6/14 and 12 security classification errors. Category macro-F1 was 0.91268,
citation precision 156/156 and p95 9.695 seconds. The load gate passed, but it
does not offset quality. The 90-minute observer recorded no OOM/restart, DNS,
unexpected destination, drop or sampling error. Raw-record SHA-256 is
`1926fb09211bbe8e01273f97a704346166f33aa2c8545bf42892be92c291d2cb`; the watchdog
exported all native evidence and no OOM occurred. This holdout is now exposed
regression data and cannot supply another independent pass. Its remaining model
errors are being fixed without changing gold or thresholds.

Follow-up exposed diagnostics exercised representatives of every observed error
class. Literal witnesses removed offset errors; general intent and classification
examples corrected the selected remediation, planning, analysis, degraded and
security representatives on the final v12 planner/analysis rules. These selected
development calls are not a complete run or independent evidence. The 576
profile tests and Ruff passed. A separately authored/reviewed holdout remains
mandatory.

Jenkins build 3 checked out `aa3ddb9b` but was later ABORTED when the
`gaming-amd64` channel terminated and did not recover. It is not a CI pass.

## Durable API/worker run and early-abstain correction — 2026-11-05

The 30 authenticated API/session/worker scenarios on `25caf2ce` retained 27
successes and three failures. All three were empty-analysis early abstentions
whose server-generated JSON still contained legacy `language/summary` fields
rejected by the v9+ closed wire. The fix emits only `recommendations=[]` while
the server supplies the public language/summary. A real PostgreSQL run passed
132 analysis/gateway tests, and a fresh authenticated empty-analysis task then
succeeded with `inference_performed=false`. Idempotent replay returned the same
task ID and no network scan ran. The initial 27/30 record is retained; it is not
reported as a clean 30-scenario pass. A fresh run is required on the final commit.

## Second independent holdout and planner correction — 2026-11-05

The second independently reviewed 190-case holdout on `3dd34ca2` improved to
170/190 gold cases and passed all 40 security cases, category macro-F1 0.90278,
citation precision 166/166, p95 8.853 seconds and the 3603.54-second load phase
with 653 additional requests and no additional errors. It nevertheless failed:
tool accuracy was 62/70 and fixed-version recall 12/14. Twelve analysis label
errors, two mixed-intent selections and six remediation refusals remain recorded.
Raw-record SHA-256 is
`d2b46ff7634f2400f6271447d461bd52a674489d8176191d7a7feeaf23b76e96`; all
reviewed inputs and sources stayed unchanged. The observer found no OOM/restart,
DNS, unexpected destination, drop or sampling error. This corpus is exposed and
cannot be reused for a later independent claim.

Follow-up v13/v14 diagnostics corrected all six selected remediation refusals and
both mixed summary/compare selections without changing resolver or gold. These
are exposed development results only; a third independently authored/reviewed
holdout is required.

## Third independent holdout — 2026-11-06

The third independently authored/reviewed 190-case holdout on `4a5551e8` produced
165/190 gold cases and failed tool accuracy (60/70), planning and security. Fixed
version support/recall reached 14/14, category macro-F1 0.90455, citation precision
180/180 and p95 9.698 seconds. The 3603.36-second load phase completed 659
additional requests without additional errors. Raw-record SHA-256 is
`ac20efabbaea0e3f3d2c5b2afccd33f3e6a265784dab2ec22c8828e570c0f3cd`; reviewed
inputs and sources stayed unchanged. This corpus is exposed and not eligible for
another independent pass.

Selected v15/v13 diagnostics corrected nine of twelve gated failures sampled from
this run, but left one Russian informational-priority error and two future-inventory
abstentions. They are selected development evidence, not a quality pass. After
three independent failed quality runs, the pinned model must not be described as
accepted or reliable enough for the frozen release gate.

The local-only Mac CI profile ran the full Python matrices, Web, SSH, Kustomize,
image smoke and E2E. Its Trivy gate then failed on apt CVE-2026-109518: the pinned
base carries 3.0.3 while 3.0.4 is fixed. This is a separate base-image release
blocker, not a successful full-CI result or an operator quality finding.

## Evidence locations and remaining gates

The private local evidence root is `.operator-local/evaluation/`, including
`freeze-5cec1cf1`, `final-5cec1cf1/results`, `pilot-eager-v5-001`,
`pilot-managed-v5-001`, `pilot-managed-ub32-v5-001` and `capacity-8k-001`.
Raw records, uncertain inflight journals, controller receipts and original
scorer outputs are preserved. Temporary retrieval/UI/operational reports are
separate from those immutable model records.

The exact `05607225` controlled-provider operational drill passed all eight
phases, including restart, crash/cancellation, backup/restore, rollback/upgrade,
deletion and feature-off; it made no real model or network scan requests.
The offline artifact on that source passed export, independent verification and
fresh import/Docker load, but did not start a runtime. Its feed freshness and
incomplete vendor coverage remain explicit. Updated source requires a new bundle.

To accept the Mac profile, establish stable runtime operation and complete the
frozen 190-case evaluation and measured 60-minute bounded load. Also finish the
30 durable API/worker scenarios, actual fix-to-verification lifecycle, complete
offline cold start and exact-head CI. The completed controlled-provider recovery
drill does not substitute for those real-model gates.
Required feed snapshots carry their actual freshness and seed/unknown status;
offline availability never implies a fresh, complete vendor knowledge base.
