# ADR 0005: Mac as the primary local-operator acceptance profile

| | |
|---|---|
| Status | Accepted — onixus, 2026-10-25 |
| Supersedes | The hardware acceptance choice in [ADR 0004](0004-local-operator.md); its trust and authorization boundaries remain in force |
| Issues | [#583](https://github.com/onixus/Shapoclyack/issues/583), [#585](https://github.com/onixus/Shapoclyack/issues/585), [#593](https://github.com/onixus/Shapoclyack/issues/593); separate NVIDIA work [#609](https://github.com/onixus/Shapoclyack/issues/609) |

## Context

The owner requested that the AI module run in separate containers on the Mac,
then explicitly chose Mac as the primary acceptance platform and requested a
separate NVIDIA task. Earlier CPU transport smoke did not complete the epic.
The original model, context, quality and offline requirements still matter.

## Decision drivers

Acceptance must describe the actual deployment, keep immutable model/runtime
pins, measure quality separately from shape validation and avoid treating a
successful Mac run as evidence of CUDA behavior. Existing scanner services must
remain usable when the optional AI feature is disabled or unavailable.

## Decision

The primary workstation is Apple M5 Pro, 15 CPU, 24 GiB physical RAM, Docker
Desktop Linux ARM64 CPU containers with a 16-GiB VM budget. The owner-authorized
2026-10-26 maintenance increased the original 12-GiB budget after builds and
queue emptied; engine memory was measured at 16,747,139,072 bytes. This selection
does not establish sustained fit or quality acceptance. Use Qwen3.5-9B GGUF
Q4_K_M, 8192 total context, one active inference, four inference CPU threads and
a separate CPU Qwen3-Embedding-0.6B Q8_0 service. Pin runtime image/source and both
model revisions/digests. Sampling is temperature 0, seed 42. Keep inference
bounded at 7 GiB and embeddings at 1.5 GiB, with native read-only GGUF storage.
Explicitly disable the inference server's RAM prompt cache (`--cache-ram 0`);
the upstream 8-GiB default is unsuitable as an unbounded extra budget inside
this container. All resource limits still require measured acceptance.

Freeze labelled RU/EN cases and source/prompt/scorer hashes before the final
model run. Retain tool accuracy >=95%, category macro-F1 >=0.85, citation
precision >=0.98, 100% supported fixed-version claims, p95 first response <=30s
and typical completion <=120s. Report denominators, unsupported requests,
abstentions, failures and timings without substituting supplied-output fixture
scores for real-model results.

Require full 8K capacity, at least 30 serial scenarios and a measured 60-minute
bounded-load run without OOM; record process/cgroup and host/VM memory alongside
latency. Offline cold start and egress/DNS evidence, source-bound retrieval,
permission/replay/cancellation negatives, deployment recovery/rollback/disable
and exact-final-commit CI remain required.

## Consequences

NVIDIA-specific 8-GiB resident-language-layer/CUDA/VRAM guarantees are preserved
in #609 and do not block acceptance of this Mac profile. No GPU-fit claim follows
from CPU results. Mac performance must be accepted against measured results,
not inferred from the model size.

The VM budget includes other running containers. Recovery drills using isolated
fixture stacks and model/quality loads run sequentially to avoid global-memory
overcommit. Any earlier OOM/timeout remains recorded as a failed development
attempt; it does not become a passing acceptance sample after a restart.

## Not decided here

This decision does not approve arbitrary model tools, external AI egress,
automatic patch installation or vulnerability closure. It does not waive any
quality, security, retrieval or operational criterion, and is not itself evidence
that those criteria have passed.
