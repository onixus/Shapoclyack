# Local operator inference providers

This foundation implements bounded text inference through the OpenAI-compatible
`POST /chat/completions` protocol. It does not execute tools, expose a public
completion API, train a model, or establish GPU/runtime acceptance.

Inference is disabled by default. The local default is
`http://127.0.0.1:8080/v1`, with model identifier `Qwen3.5-9B-Q4_K_M`.
This is a deployment configuration, not evidence that a model with that identifier
is installed or running. A compatible local server must be installed separately;
its accepted model identifier must match the deployment setting.

## Deployment settings

| Environment setting | Default | Meaning |
| --- | --- | --- |
| `OCTO_OPERATOR_ENABLED` | `false` | Explicitly enable inference |
| `OCTO_OPERATOR_PROVIDER` | `local` | `local`, `openrouter`, `omnirouter`, or `openai_compatible` |
| `OCTO_OPERATOR_BASE_URL` | provider default | API base URL, excluding `/chat/completions` |
| `OCTO_OPERATOR_MODEL` | `Qwen3.5-9B-Q4_K_M` | Model identifier; set a provider-specific model for hosted use |
| `OCTO_OPERATOR_API_KEY` | empty | Optional local key; required for hosted inference |
| `OCTO_OPERATOR_ALLOW_EXTERNAL` | `false` | Explicit consent to send inference inputs to a hosted provider |
| `OCTO_OPERATOR_TIMEOUT_SECONDS` | `120` | Whole exchange deadline and transport timeout; maximum 120 seconds |
| `OCTO_OPERATOR_MAX_RESPONSE_BYTES` | `262144` | Maximum upstream response bytes; hard ceiling 1048576 |
| `OCTO_OPERATOR_MAX_INPUT_CHARS` | `24000` | Maximum combined message characters; hard ceiling 131072 |
| `OCTO_OPERATOR_MAX_OUTPUT_TOKENS` | `1024` | Requested output token limit; hard ceiling 8192 |

Enablement, worker activation and permission for external inference are
deployment-owned. Platform administrators can edit the endpoint through the
operator's dedicated settings API/UI. Tenant inference requests cannot supply
endpoints or credentials. API keys must not be committed to configuration
examples or stored through the general scanner configuration editor. Public
operator status omits the key and endpoint.

## Local isolation and hosted opt-in

The local provider accepts only literal IPv4 loopback/RFC1918 addresses or IPv6
loopback/ULA addresses. DNS names, public addresses, link-local metadata addresses,
URL credentials, query strings and fragments are rejected. IP literals avoid
DNS resolution changes between validation and connection. Use the explicit
private IP of a separately deployed inference server when necessary. Loopback
inside an API container refers to that container.

Local failures do not trigger a hosted fallback. Requests ignore environment
HTTP proxies, do not follow redirects, request uncompressed responses, and refuse
compressed responses. The overall deadline also bounds slow response bodies.
Hosted TLS certificate verification uses the HTTP client's normal verified TLS.

OpenRouter uses the fixed base `https://openrouter.ai/api/v1`, bearer-key
authentication, and a deployment-selected model. Its
[official chat completion documentation](https://openrouter.ai/docs/api/api-reference/chat/send-chat-completion-request)
defines this request and response protocol. Enabling it requires both
`OCTO_OPERATOR_ALLOW_EXTERNAL=true` and an API key. Input messages leave the local
deployment when it is enabled; the operator must decide which data can be sent.

OmniRouter support is a configurable OpenAI-compatible adapter. Several services
use that name, so no service URL is assumed. Set the trusted service's explicit
HTTPS API base URL, model and bearer key, and opt into external inference. The
adapter does not claim compatibility with non-chat-completion APIs or verify the
identity or retention policy of a service based on its name. Its URL is trusted
deployment configuration and must never be tenant-controlled.

`openai_compatible` is the same adapter for any other hosted OpenAI-compatible
service (a cloud vendor's endpoint, a self-hosted gateway behind a public name,
and so on). It has no default URL: set `OCTO_OPERATOR_BASE_URL` to the API base
that precedes `/chat/completions`, for example `https://llm.example.com/v1`, and
enable it with an API key and `OCTO_OPERATOR_ALLOW_EXTERNAL=true` like the other
hosted providers.

All hosted providers (`openrouter`, `omnirouter`, `openai_compatible`) require
HTTPS and a public host. Configuration refuses private, loopback, link-local,
CGNAT and metadata IP literals, IPv6 forms that embed an IPv4 address
(IPv4-mapped, NAT64, 6to4, Teredo), single-label names, `localhost` and
internal suffixes such as `.local`, `.internal`, `.lan`, `.svc` and
`.cluster.local` (`hosted_operator_requires_public_host`). A server on a private
address is configured as `local`, which never needs egress consent. Before every
exchange the provider also resolves the hosted name and refuses the request with
`operator_endpoint_not_public` when any resolved address is not public. The HTTP
client resolves the name again when it connects, so this check narrows DNS
rebinding rather than closing it; restrict API egress with a NetworkPolicy or
firewall to keep that boundary.

A local server on another machine, such as a Windows workstation with a GPU, is
reached through its private IP literal, for example
`OCTO_OPERATOR_BASE_URL=http://192.168.1.50:8080/v1`. The connection is plain
HTTP on the LAN; set a local `OCTO_OPERATOR_API_KEY` that matches the server's
key and restrict the port to the API host. See
[local-operator-windows.md](local-operator-windows.md).

| Goal | Provider | Base URL | Consent and key |
| --- | --- | --- | --- |
| Model on the API host | `local` | `http://127.0.0.1:8080/v1` (default) | Key optional |
| Model on a LAN machine | `local` | `http://<private IP>:<port>/v1` | Key recommended |
| OpenRouter | `openrouter` | fixed, leave empty | `ALLOW_EXTERNAL=true` + key |
| OmniRouter | `omnirouter` | the service's HTTPS base | `ALLOW_EXTERNAL=true` + key |
| Another cloud endpoint | `openai_compatible` | its HTTPS base | `ALLOW_EXTERNAL=true` + key |

## Service contract and verification boundary

`OperatorConfig.from_settings(settings)` validates deployment configuration.
`InferenceProvider(config).complete(messages)` accepts 1–64 messages containing
only `role` (`system`, `user`, `assistant`) and string `content`. It returns
`Completion(content, provider, model)`. It does not forward arbitrary provider
parameters or tool definitions. The requested token limit depends on enforcement
by the upstream; the independent response byte limit is enforced locally.
Non-200 responses, malformed bodies, timeouts and transport failures produce
stable error codes without returning upstream bodies, URLs or credentials.
Truncated, filtered, tool-call and explicit refusal responses are rejected as
incomplete. A missing `finish_reason` is accepted for local server compatibility;
this adapter does not independently prove semantic answer completeness.

Tests use mocked HTTP transports and resolvers to cover all four adapters, hosted host policy, resolved-address refusal, disabled behavior,
explicit hosted consent, URL policy, bounded inputs/output, redirects, invalid
responses, deadlines and sanitized transport failures. No hosted credential is
used. These checks do not measure runtime availability, model quality, GPU memory,
throughput, installed artifact provenance or physical deployment behavior.
`runtime_verified=false` in status communicates that boundary.

With a runtime manifest configured (`OCTO_OPERATOR_RUNTIME_MANIFEST_PATH` and its
pinned SHA-256) status reports `runtime_status=ready`,
`manifest_attested=true` and `model_integrity=manifest_attested`. This attests
that the manifest matches the pinned hash and configuration and that the live
runtime answers health with the configured model alias and context size. It does
not re-hash the weights: the manifest and the weights are written by the same
launcher, so a different server that reports the same alias and `n_ctx` would
also be reported ready. `runtime_verified` is a deprecated alias of
`manifest_attested`, removed after one release; the former value
`model_integrity=verified_at_startup` is replaced by `manifest_attested`.

When a manifest is configured, the worker probes the runtime before every task
and refuses it with `operator_runtime_not_ready` unless the probe is `ready`;
there is no silent skip. `GET /api/operator/status` serves the probe from a cache
(30 s for `ready`, 5 s otherwise, dropped when any `operator_*` setting changes)
so viewers cannot exhaust the thread pool; the worker never uses the cache.


## Admin connection settings

Platform administrators can expand **AI connection settings** on the Operator
page, including from the fleet view without selecting a tenant. The form edits
provider, API base URL (including `/v1` where required), model, optional local or
required cloud bearer key, external-data consent, timeout and output token limit.
Discover models and Test connection use the unsaved form. Discovery sends no
completion; the optional completion test sends a small fixed prompt and can incur
provider charges. Discovered identifiers are selectable in the model field.

The installation-wide API requires platform `config.write` permission:

| Method/path (under `/api`) | Behavior |
| --- | --- |
| `GET /operator/settings` | Deployment, saved override and effective settings; keys are represented only by presence/source |
| `PUT /operator/settings` | Validate and save editable fields, audit the change without credentials |
| `DELETE /operator/settings` | Restore deployment settings |
| `POST /operator/settings/test` | Validate unsaved candidate, discover models, optionally send one small completion (`completion: true`); never save |
| `GET /operator/settings/models` | Discover models from the saved effective endpoint |

PUT is replacement of the override: omitted or null non-secret fields inherit
deployment values. An omitted/null `api_key` preserves a saved key only for the
same provider and base URL; `""` clears it. Moving an endpoint does not inherit
the deployment key or its external-data consent. Cloud edits require both
`OCTO_OPERATOR_ALLOW_EXTERNAL=true` and explicit endpoint consent plus a key.
Revoking deployment consent disables a stored cloud endpoint. Limits remain
bounded and timeout must fit the worker lease. Operator/worker enablement,
manifest pins, input/response byte limits and queue settings cannot be edited.

Overrides use the existing `config_overrides` table (`operator` scope); no new
migration is required. Stored keys use the configured envelope-encryption
provider; configure secrets-at-rest encryption for encrypted database storage.
Storage/decryption failures fail closed. Changes apply to the next worker task;
an already running request retains its original configuration. Reset restores
the deployment endpoint and credentials. No endpoint or credential is accepted
on tenant task requests and there is no provider fallback.

Tests return sanitized codes, reachability, authentication, model presence,
model identifiers and completion status. Upstream bodies are never returned.
Discovery is limited to 500 entries and 1 MiB, with a 15-second deadline, no
redirects/proxies and the same hosted-address checks as inference. A server
without `/models` can pass an explicit completion test; automatic status remains
unavailable because it never spends inference tokens to check readiness.

`GET /operator/status` exposes cached `endpoint_status`/`endpoint_error` for
cloud and arbitrary local endpoints. A listed configured model establishes API
readiness, not successful generation, model quality or weight integrity.
`analysis_available` additionally requires an enabled worker. When a runtime
manifest is configured, its attested readiness remains mandatory and cannot be
bypassed through endpoint edits. Endpoint readiness does not confer manifest
attestation. The UI displays endpoint readiness and disables model requests when
analysis is unavailable.
