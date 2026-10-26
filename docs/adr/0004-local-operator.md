# ADR 0004: Local Operator with explicit provider and tool boundaries

| | |
|---|---|
| Status | Accepted — onixus, 2026-10-21; implementation requested, runtime and hardware acceptance pending |
| Issue | [#584](https://github.com/onixus/Shapoclyack/issues/584), [EPIC #583](https://github.com/onixus/Shapoclyack/issues/583) |
| Date | 2026-10-21 |
| Specification | [Local Operator architecture and contracts](../local-operator.md) |

Hardware acceptance is superseded by [ADR 0005](0005-local-operator-mac-acceptance.md)
under the owner's explicit decision of 2026-10-25. The other boundaries below
remain in force; NVIDIA work is preserved separately in #609.

## Context

Operators need evidence-grounded assistance with inventory, findings, scanning
and remediation without giving generated text scanner privileges or access to
another tenant. Local deployments must retain offline operation. MCP clients
need a bounded, authenticated tool interface. OpenRouter and an explicitly
configured OmniRouter-compatible endpoint are additional requested provider
choices; the latter name does not establish a service URL or trust policy.

## Decision

Keep local operation as the default and disable the optional provider until
configured. Choose a language-only Qwen3.5-9B GGUF Q4_K_M model with an 8192-token
context as the candidate 8 GiB CUDA baseline; verify artifact provenance, actual
hardware fit and quality in #585/#593 before claiming acceptance. CPU embeddings
and single-inference concurrency are the initial design constraints.

Run inference orchestration in a separate durable, bounded worker (#586).
Reuse existing tenant-aware reads and scan/remediation service gates; do not
execute SQL, shell, arbitrary remote tools or routes selected by a model. Treat
MCP, model output and retrieved documents as untrusted inputs. Validate versioned
answer, citation, tool, proposal and execution records and resolve every cited
source to an authorized, hash-bound snapshot. The server owns actor/tenant
context; these fields in a validated record are provenance, not credentials.

Expose only a registered MCP read allowlist in this baseline. Future effectful
actions require a stored proposal, exact-argument confirmation, expiry,
idempotency, fresh authorization, scope/policy/quota checks and audit. A retry
or cancellation cannot silently cause another scan or hide an existing effect.

Allow hosted inference only through explicit administrator provider selection,
model/key configuration and egress opt-in. OmniRouter additionally requires an
explicit compatible endpoint URL. Never silently switch providers on failure.
Future retrieval must minimize and authorize disclosed tenant data separately.

## Consequences and acceptance

There is no inference dependency for existing scanner/API startup when disabled.
A shape-valid answer can still be false: source validation, authorization and
quality evaluation remain separate required controls. Providers and MCP adapters
can ship independently of a complete assistant without claiming the epic done.

Version 1 contracts and full/empty/partial/stale fixtures accompany this ADR;
worker, retrieval, analysis, proposals, UI and security/hardware acceptance stay
with #586–#593. Freeze the corpus and thresholds before final evaluation:
>=95% tool selection, F1>=0.85, citation precision>=0.98, 100% source-supported fixed-version claims, p95 first response <=30 seconds and typical completion <=120 seconds.
The specification defines the measurement record and remaining hardware report.

## Deployment profile and egress

The workstation package and the console stand run the API in production mode with
generated secrets (no `OCTO_ENV=dev`), keep state/output private to one uid, and
refuse to start with a hosted provider or an inference URL outside the isolated
network. Egress denial is a property of the compose `internal` network only;
Kubernetes is explicitly unsupported until a deployment ships with an egress
NetworkPolicy limited to the inference endpoints. Residual risk: the package is
single-tenant by design, and the unprivileged fallback runs the control
containers as the invoking user's uid.

## Alternatives

A hosted-only default makes offline operation depend on an external account and
egress. An autonomous model with scanner/database credentials bypasses existing
policy boundaries. An in-request inference loop ties expensive model work and
recovery to API worker lifetime. Defer all three; use explicit providers,
registered tools and durable orchestration instead.
