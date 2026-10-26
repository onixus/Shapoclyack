# Mac acceptance evidence — 2026-10-26

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
