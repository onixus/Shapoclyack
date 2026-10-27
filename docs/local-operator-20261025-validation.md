# Operator delivery and Mac workstation evidence — 2026-10-25

This is a historical implementation-wave snapshot. For current measured gates,
including later retrieval/recovery results and failed runtime attempts, see
[acceptance status](local-operator-acceptance-status.md). ADR 0005 subsequently
made Mac the primary profile; NVIDIA acceptance is separate in #609.

This wave extends epic #583. It does not close the epic's frozen quality,
full semantic retrieval, NVIDIA hardware or full deployment acceptance gates.
The owner requested a separate Mac container during implementation, so the
Mac CPU profile is recorded independently from the original 8-GiB CUDA target.

## Delivered behavior

- Durable confirmed start/cancel/verification, with login/actor/tenant/expiry
  binding, current authority, actual admission/detector-plan fingerprints,
  unique claims and conservative unknown-outcome reconciliation.
- Deterministic vendor/inventory remediation cards, DEB/RPM/MSRC semantics,
  current bounded citations, explicit stale/seed/missing/unsupported behavior.
- Published-diff comparison, preserving incomplete coverage and never treating
  a removed observation as a verified fix.
- RU/EN console, history, queue/cancel, bound sources, readable plan review,
  explicit confirmation and tenant/actor cache cleanup.
- Trusted-manifest offline bundle verifier and pinned Mac CPU deployment.

## Automated verification

These runs overlap; their counts must not be added as unique coverage:

| Run | Result |
|---|---|
| PostgreSQL operator/actions/comparison/evidence/remediation/security/retention/privacy plus admission/idempotency | 271 passed |
| Independent final actions/comparison, job idempotency, admission, vulnerability verification/coverage | 226 passed |
| Earlier broad current operator/DSAR/route regression | 202 passed, 2 optional skips |
| Migration 0101 upgrade/downgrade, evidence-loss refusal and retention | 14 passed |
| Contract/provider/analysis/MCP and bundle/remediation units | 290 passed, 1 PostgreSQL-only skip before final bundle additions |
| Offline bundle CLI and local ingress boundary tests | 42 passed |
| Constrained provider/analysis follow-up | 139 unit and 49 PostgreSQL integration passed |
| Frontend | 98 files, 712 tests; typecheck/lint/build passed |
| Ruff and diff whitespace | Passed |
| SDK | OpenAPI parity passed; local wheel build skipped (setuptools/wheel unavailable) |
| Pinned SAST ERROR gate before constrained-provider follow-up | 113 rules, 1296 targets, zero reportable findings; 99.9% parsed lines, five nonfatal parser errors and documented skips |

SAST was run with the owning checkout's Git metadata mounted read-only because
the normal single-directory invocation cannot resolve an absolute `.git`
worktree link inside its container. The generic CLI's intentional `execve`
has a narrow documented rule exception: executable bytes are verified against
an independently trusted administrator digest, argv is fixed and environment
is a constant whitelist. It is not an API or model tool. Negative and positive
CLI tests exercise this trust boundary.

## Observed Mac runtime

Runtime/model pins are listed in [the Mac guide](local-operator-mac.md).
Docker Desktop runs Linux ARM64 CPU inference, four threads, one slot, 8192
context and a 7-GiB container ceiling. The model SHA-256 was verified before
launch. The server reported 8192 context, 8,953,803,264 parameters, Q4_K Medium
and text-only modalities. No projector or hosted provider was used.

The real provider adapter returned a Russian JSON count summary from synthetic
input in **6.031 seconds**. Server timings for that request were 55 prompt tokens,
24 output tokens, approximately 15.54 prompt tokens/s and 9.60 generated tokens/s.
An observed Docker working set was about 5.822 GiB after loading. This is one
observation, not peak-memory or percentile acceptance.

An authenticated end-to-end request exercised API → private PostgreSQL queue →
separate worker → real Qwen → stored result in **8.290 seconds**, with terminal
`succeeded` and quality unverified. Its publication was an explicitly synthetic
three-host/seven-port fixture, not a real scan. The temporary personal session,
source artifacts and job row were removed afterward; audit evidence remains.
No network scan was dispatched.

An additional real `analyze_run` smoke initially failed closed after 30.678
seconds because unconstrained model output did not pass the strict validator.
The follow-up adds schema-constrained generation with language and complete
source-reference tuples bound to server-owned constants, retaining all server
validation. The same one-finding synthetic path then succeeded in 32.988 seconds
with an explicit insufficient-evidence abstention and no recommendations or
citations. This proves the tested transport/queue/validation path, not useful
classification quality. Both outcomes belong in any later evaluation denominator.
The model's inherited image healthcheck was also corrected from port 8080 to
the actual configured port 8082; the running container subsequently became healthy.

The runtime network namespace had only the `172.30.83.0/24` connected route and
no default route. A TCP/443 connect probe to an external IP returned errno 101
(network unreachable). This establishes that tested route boundary, not a
packet-capture proof of every component, DNS attempt or 60-minute offline soak.
The credential-free fixed-target ingress alone has an ingress bridge. It rejects
unrelated browser origins, absolute proxy targets and CONNECT tunnels. Runtime,
API and PostgreSQL remain on internal networks; the worker joins the internal
console and inference networks.

The separate console has a private database and random local credentials, with
scan dispatch disabled and no fake evidence retained. Docker's VM disk was full
when initializing a new volume; only this new stand's database/state was moved
to private host bind directories. No pre-existing service, image or volume was
pruned. The stand uses exact already-present local image IDs and read-only
source/UI mounts; it is a development deployment, not a published release image.

## Historical gate list at the end of this wave

At that point, full project CI on the final commit, pinned CPU embeddings and semantic recall,
independently labelled domain/model evaluation, full operational/vendor plans,
8K-token context load tests, 30 scenarios/60-minute soak, complete offline bundle
and network evidence, deployment backup/restore/upgrade/rollback drills, and
the original physical NVIDIA acceptance remained separate gates. This wave's
API reported `not_checked` before the later readiness/fingerprint probe was
implemented. These historical limits do not override ADR 0005 or substitute
for the current acceptance evidence linked above.
