# LO-10 software acceptance record — 2026-11-21

This record is the software continuation of
[#593](https://github.com/onixus/Shapoclyack/issues/593). **The Mac profile is
not accepted. The epic is not accepted. `quality_gate_passed` is not true.**

No language model, GPU, offline bundle or packet capture was run for this
record. A green contract suite does not replace the physical gates in
[the 2026-10-26 evidence](local-operator-acceptance-status.md).

## What this continuation does claim

- The operator console names a policy refusal when `safe_only` is set and the
  requested mode is not `safe`. It does not treat a different policy profile
  as a rewritten mode: the server does not substitute one for the other, and
  the confirm control stays a server check. Offline operation stays unverified
  unless a deployment sets `offline_verified`.
- The security contract gate covers a foreign-tenant evidence read and audit
  redaction of credential field names, in addition to the cases already listed
  in [the security contract](local-operator-security.md).
- The evaluator still reports `quality_gate_status: exposed_only` and
  `quality_gate_passed: false` when every frozen case was seen in development.
  That refusal is the correct LO-10 behaviour for this corpus. It is not a pass.

## What this continuation does not claim

- Frozen 190-case quality on the pinned Qwen3.5-9B Q4_K_M model, including
  category macro-F1, citation precision and p95 latency.
- A measured 60-minute bounded load, 30 sequential durable scenarios, or a
  full 8192-token resource pass without OOM.
- An offline cold start from a prepared bundle with packet or deny-counter
  evidence of zero operator, runtime and index egress.
- An end-to-end published scan, confirmed vendor fix, verification job and
  `machine_verified` close on this SHA.
- Upgrade, rollback, backup, restore or feature-disable on a real runtime.
- Exact-head project CI with `Finished: SUCCESS` on this SHA.
- Physical NVIDIA acceptance. That remains [#609](https://github.com/onixus/Shapoclyack/issues/609).

Until those gates have their own raw records, #593 stays open. Do not treat
this file as acceptance evidence for them.
