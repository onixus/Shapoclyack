# Mac acceptance evidence — 2026-10-25

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
requests. The next protocol records 11 exposed and 179 untouched cases while
retaining the overall 190-case gate. Failed cases are never replaced through
resume. Interrupted soak executions have their own durable journal and failed
soak records. The independent [host watchdog](operator-quality-watchdog.md)
enforces wall-clock failure receipts even when guest cleanup stalls.

Jenkins build 4 checked out `5cec1cf1` and failed: historical migration inventory,
configuration owner documentation, an audit test clock race and the distinction
between mandatory PostgreSQL tests and an opt-in real-runtime test required
correction. A terminal full-project success on the corrected final SHA remains
required. Earlier successful builds are not substituted.

## Evidence locations and remaining gates

The private local evidence root is `.operator-local/evaluation/`, including
`freeze-5cec1cf1`, `final-5cec1cf1/results`, `pilot-eager-v5-001`,
`pilot-managed-v5-001`, `pilot-managed-ub32-v5-001` and `capacity-8k-001`.
Raw records, uncertain inflight journals, controller receipts and original
scorer outputs are preserved. Temporary retrieval/UI/operational reports are
separate from those immutable model records.

To accept the Mac profile, recover stable runtime operation and repeat the
frozen 190-case evaluation and measured 60-minute bounded load. Also finish the
30 durable API/worker scenarios, actual fix-to-verification lifecycle, complete
offline export/import/cold start, final recovery drill and exact-head CI.
Required feed snapshots carry their actual freshness and seed/unknown status;
offline availability never implies a fresh, complete vendor knowledge base.
