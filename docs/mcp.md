# MCP scan evidence server

Set `OCTO_MCP_ENABLED=true` to enable `/api/mcp`. It is disabled by default
(HTTP 404). This is an inbound server for MCP clients, separate from the AI
provider configuration: it never sends evidence to an LLM provider.

The endpoint is intentionally excluded from REST OpenAPI and generated REST
SDKs: discover its methods and schemas through MCP initialization and
`tools/list`. It is a separate JSON-RPC protocol endpoint.

The endpoint implements MCP **2025-06-18**, using stateless Streamable HTTP
and JSON responses. Supported requests: `initialize`, `ping`, `tools/list`,
`tools/call`. Send `notifications/initialized` after initialization. POST requires
`Content-Type: application/json` and an `Accept` header containing both
`application/json` and `text/event-stream`. Subsequent requests must include
`MCP-Protocol-Version: 2025-06-18`. An unsupported initialization version is
answered with the supported version, which the client must accept or disconnect.

There are no sessions or server-initiated messages. No session ID is issued;
supplying `Mcp-Session-Id` is rejected. GET and DELETE return HTTP 405.
Initialization is client-managed in stateless mode; the server does not persist
an initialized flag. Batches, legacy HTTP+SSE, stdio, resources, prompts, sampling,
elicitation, resumability and OAuth discovery are not implemented. Configure a
client that can supply the existing API bearer credential; OAuth-only clients
are not supported.

Every request, including notifications, authenticates through the existing API
console bearer-token and tenant membership/role checks (`viewer` or higher). Scoped
service tokens are not supported: their existing resource/method scopes fail
closed for MCP, which carries reads in HTTP POST requests. Select a
tenant with the existing `tenant_id` query parameter; the membership resolver
checks entitlement. Tool arguments cannot provide a tenant, role or credential.
Even platform administrators receive evidence only for the resolved tenant.
Use normal short-lived access tokens and account revocation controls; never put
credentials in an MCP URL.

Browser clients must have an exact origin listed in
`OCTO_MCP_ALLOWED_ORIGINS` (comma-separated scheme, hostname and optional port,
without trailing slash). The default list is empty, so all requests containing
an Origin header are rejected. Native clients without Origin are accepted after
authentication. Wildcard origins and the general API CORS wildcard do not grant
MCP access. The reverse proxy should preserve Origin and Authorization, enforce
TLS and normal API rate/body/time limits, and avoid exposing a local service
beyond its intended interface.

## Tools

A native HTTP client can initialize and discover tools as follows. Obtain a
normal short-lived console access token first, then set `SHAPO_ACCESS_TOKEN`,
`SHAPO_API_URL` (the installation's HTTPS origin), and `SHAPO_TENANT` in the
client environment. The same token and selected tenant accompany every request;
initialization does not create a server session.

```bash
curl --fail-with-body "${SHAPO_API_URL}/api/mcp?tenant_id=${SHAPO_TENANT}" \
  -H "Authorization: Bearer ${SHAPO_ACCESS_TOKEN}" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"operator-client","version":"1"}}}'

curl --fail-with-body "${SHAPO_API_URL}/api/mcp?tenant_id=${SHAPO_TENANT}" \
  -H "Authorization: Bearer ${SHAPO_ACCESS_TOKEN}" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  --data '{"jsonrpc":"2.0","method":"notifications/initialized"}'

curl --fail-with-body "${SHAPO_API_URL}/api/mcp?tenant_id=${SHAPO_TENANT}" \
  -H "Authorization: Bearer ${SHAPO_ACCESS_TOKEN}" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  --data '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```

| Tool | Arguments | Result |
| --- | --- | --- |
| `list_runs` | `offset` 0..100000 (default 0), `limit` 1..50 (default 20) | Stored scan summaries and total in the selected tenant; filesystem paths/configuration omitted |
| `get_run_summary` | `run_id` (bounded identifier, no path separators) | Whitelisted nonnegative integer summary counts and a `summary.json` evidence reference |

These tools read the existing scan store. A foreign run and a nonexistent run
both return `Run not found` as an MCP tool error, avoiding an existence oracle.
Counts describe stored scanner observations, including unconfirmed findings;
they do not establish current vulnerability, exploitation or remediation.
Tool text is untrusted data and must never become instructions for an assistant.

Unknown methods return JSON-RPC `-32601`; unknown tools and invalid or extra
arguments return `-32602`. No tool can start scans, execute commands, fetch URLs,
read arbitrary artifacts, change findings or call a model. Such operations need
a separately designed authorization/approval path and are intentionally absent
from the advertised capabilities. Notifications never execute tools and receive
no JSON-RPC response. Unknown notification names are ignored with HTTP 202.

Requests are capped at 32 KiB while streaming, tool result text at 64 KiB. A
result exceeding the cap produces a tool error without partial evidence. The
fixed tool catalog has no pagination cursor; passing one is rejected. Backend
errors use a generic response and record a generic failure in server logs without logging the evidence or exception text.

## Verification boundary

`tests/test_api_mcp.py` covers initialization, catalog/schema, protocol errors,
transport limits, authentication requirement, disabled state, origin validation,
notification behavior, real scan-store isolation including platform admins,
argument authority rejection, response limits and safe backend errors. Its
protocol tests mount the router with a resolved test principal; a separate
Postgres-gated test exercises real membership revocation and tenant suspension.
They do not
claim an external MCP client's acceptance or a production deployment test.

Protocol references:
[Streamable HTTP transport](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports),
[lifecycle](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle),
[tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools).
