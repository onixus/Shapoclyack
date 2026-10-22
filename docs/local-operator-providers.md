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
| `OCTO_OPERATOR_PROVIDER` | `local` | `local`, `openrouter`, or `omnirouter` |
| `OCTO_OPERATOR_BASE_URL` | provider default | API base URL, excluding `/chat/completions` |
| `OCTO_OPERATOR_MODEL` | `Qwen3.5-9B-Q4_K_M` | Model identifier; set a provider-specific model for hosted use |
| `OCTO_OPERATOR_API_KEY` | empty | Optional local key; required for hosted inference |
| `OCTO_OPERATOR_ALLOW_EXTERNAL` | `false` | Explicit consent to send inference inputs to a hosted provider |
| `OCTO_OPERATOR_TIMEOUT_SECONDS` | `120` | Whole exchange deadline and transport timeout; maximum 120 seconds |
| `OCTO_OPERATOR_MAX_RESPONSE_BYTES` | `262144` | Maximum upstream response bytes; hard ceiling 1048576 |
| `OCTO_OPERATOR_MAX_INPUT_CHARS` | `24000` | Maximum combined message characters; hard ceiling 131072 |
| `OCTO_OPERATOR_MAX_OUTPUT_TOKENS` | `1024` | Requested output token limit; hard ceiling 8192 |

Settings are deployment-owned. Clients cannot supply an endpoint or credential
per inference request. API keys must come from a protected deployment secret and
must not be committed to configuration examples or stored through a general
configuration editor. The public configuration status omits the key and endpoint.

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

Tests use mocked HTTP transports to cover all three adapters, disabled behavior,
explicit hosted consent, URL policy, bounded inputs/output, redirects, invalid
responses, deadlines and sanitized transport failures. No hosted credential is
used. These checks do not measure runtime availability, model quality, GPU memory,
throughput, installed artifact provenance or physical deployment behavior.
`runtime_verified=false` in status communicates that boundary.
