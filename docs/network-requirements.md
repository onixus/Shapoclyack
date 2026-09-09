# Network requirements

What Shapoclyack opens, in which direction, and what has to be allowed for an
installation on a corporate network to work
([#359](https://github.com/onixus/Shapoclyack/issues/359)). Hand this document
to whoever owns the firewall.

Two rules run through all of it:

- **Every component is outbound-only towards the control plane.** Nothing dials
  an agent, and nothing dials a scanner. A remote agent needs egress to the API
  and nothing needs ingress to the agent.
- **HTTP egress obeys a proxy; NATS does not.** That asymmetry decides how a
  proxy-only site is deployed, and it is spelled out under
  [NATS and proxies](#nats-and-proxies).

## Ports and directions

### Remote agent → control plane

| From | To | Port | Protocol | Required | What breaks without it |
|---|---|---|---|---|---|
| Agent | API (`OCTO_API_URL`) | 443 (or 80) | HTTPS | **Yes** | Everything: token exchange, registration, heartbeat, job claim, results upload |
| Agent | NATS broker | 4222 | TLS over TCP (`tls://`) | No | Job *push*. The agent falls back to HTTP claim polling |
| Agent | NATS broker | 443 | TLS over TCP through a stream ingress | No | Alternative to 4222 where the firewall only passes 443 |
| Agent | NATS broker | 443 | WebSocket over TLS (`wss://`) | No | Alternative again, where a raw TCP ingress is not available |
| Agent | DNS resolver | 53 | UDP/TCP | **Yes** | Name resolution for the API host and for every scan target |
| Agent | scan targets | as scoped | TCP/UDP/ICMP | **Yes** | The scan itself. The tenant's approved scan scope decides the range |

An agent needs **no inbound rule at all**. `k8s/shapoclyack/examples/networkpolicy-agent.example.yaml`
is the in-cluster expression of the same list.

### Inside the cluster

| From | To | Port | Protocol | Required |
|---|---|---|---|---|
| Ingress | API | 8080 | HTTP | **Yes** |
| API | Postgres | 5432 | TLS over TCP (`sslmode=verify-full`) | **Yes** |
| API | NATS | 4222 | TCP or TLS | No — without it jobs run in `local` mode |
| API | ClickHouse | 8123 / 8443 | HTTP / HTTPS | No — analytics only |
| Prometheus | API `/metrics` | 8080 | HTTP | No |
| NATS | NATS peers | 6222 | TCP | Only in an HA cluster |

### API → outside

Every one of these goes through the HTTP proxy when one is configured.

| To | Port | Protocol | What it is | Required |
|---|---|---|---|---|
| Webhook receivers | as configured | HTTPS/HTTP | Outbound webhook delivery | Only if subscriptions exist |
| Ticket trackers (Jira, etc.) | 443 | HTTPS | Ticket creation and status sync | Only if configured |
| OIDC provider | 443 | HTTPS | Discovery document and token exchange | Only with SSO |
| Advisory feeds | 443 | HTTPS | `OCTO_ADVISORY_FETCH_ENABLED` dataset refresh | No — the image ships overlays |
| SMTP relay | 25 / 465 / 587 | SMTP + STARTTLS | Report delivery | Only if a relay is configured |

SMTP is the exception: an HTTP proxy does not carry it, so the relay is dialed
directly and only the CA setting applies.

## Proxy and CA variables

| Variable | Applies to | Meaning |
|---|---|---|
| `OCTO_HTTPS_PROXY` | API, agent | Proxy for `https://` targets. `[scheme://][user:pass@]host[:port]`; `http://` and `https://` proxies only, no SOCKS |
| `OCTO_HTTP_PROXY` | API, agent | The same for `http://` targets |
| `OCTO_NO_PROXY` | API, agent | Comma-separated exemptions. `*` bypasses everything; a bare name matches it and its subdomains (`example.com` covers `api.example.com`, not `notexample.com`); `host:port` pins the port; a CIDR matches an address literal inside it |
| `OCTO_CA_BUNDLE` | API, agent | PEM file **added to** the system trust store, for HTTPS, SMTP and NATS alike. Verification is never turned off |

Each falls back to the conventional `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`
(and their lowercase spellings) when unset — with one exception: the
lowercase-only `http_proxy` is not read, because in a CGI-shaped environment it
is the caller's own `Proxy:` request header wearing an environment variable's
name (httpoxy).

The `OCTO_`-prefixed names exist so a pod can override a cluster-wide
`HTTPS_PROXY` injected for something else without unsetting the ambient one.

The agent logs its decision once at start, so "the agent cannot reach the API"
has one place to look:

```
INFO octo-agent: Egress to https://shapoclyack.example.com: proxy http://proxy.corp:3128, system trust store + /etc/corp-ca/ca.crt
```

A `OCTO_CA_BUNDLE` naming a file that does not exist, or one that is not a PEM
bundle, is an error rather than a silent fallback to the system store: falling
back would turn "verify against our internal root" into "every handshake behind
the inspecting proxy fails", diagnosed hours later.

## TLS inspection

Where an appliance terminates and re-signs TLS, the certificate the API or the
agent sees is the appliance's, issued by an internal root. Put that root in
`OCTO_CA_BUNDLE`. It is added to the system store rather than replacing it, so
the same process still verifies the receivers it reaches *without* the
inspector — a webhook to an on-cluster endpoint listed in `OCTO_NO_PROXY`, for
example.

Two things inspection does not change:

- **Verification stays on.** There is no variable that disables it, and naming
  the inspector's CA is the supported way to make an inspected connection
  verify. The one deliberate downgrade in the codebase is
  `OCTO_REPORT_SMTP_VERIFY_TLS=false` for the report relay, documented as a
  downgrade.
- **The SSRF boundary stays on.** A webhook target is still parsed, its port
  checked and its addresses resolved and refused under the `#151` policy before
  anything is sent. What proxying removes is the *pinning*: the proxy performs
  its own DNS lookup, so a name that resolves publicly here and privately there
  is decided by the proxy. On a proxied installation the proxy is therefore the
  boundary that decides where the network's traffic may land — configure its
  own allowlist accordingly.

A related consequence: behind a proxy the local resolver frequently has no view
of the outside at all. A webhook host that does not resolve is therefore *not*
treated as a delivery failure when a proxy applies to it, because the local
resolver's opinion is not the one that matters. Without a proxy it stays a
retryable failure, as before.

## NATS and proxies

**No HTTP proxy carries NATS.** `nats://`, `tls://` and nats-py's `wss://`
transport all open a connection directly; the client issues no `CONNECT`, and
there is no setting that makes it. This is a property of the client library,
not a gap in configuration.

So on a site where the proxy is the only way out:

1. Leave `OCTO_NATS_URL` **unset** on the agent.
2. The agent then polls `POST /api/agent/jobs/claim` over HTTP — through the
   proxy, like every other call — every `--poll-interval` seconds
   (`OCTO_AGENT_POLL_INTERVAL`, default 5).

HTTP claim is a supported mode, not a degraded one. The only difference is that
a job is picked up within the poll interval instead of being pushed, and that
the API does the fan-out. `k8s/shapoclyack/examples/agent-proxy-ca-patch.yaml`
is this configuration.

Where NATS *is* reachable but 4222 is not, use 443:

| Option | URL | What terminates TLS | Needs |
|---|---|---|---|
| TCP (stream) ingress | `tls://nats.example.com:443` | `nats-server` itself, end to end | An ingress controller forwarding raw TCP; `nats-tls-configmap-patch.yaml` |
| WebSocket | `wss://nats.example.com:443` | The HTTPS ingress in front | A `websocket {}` listener, an ordinary Ingress, and `aiohttp` installed on the agent |

`k8s/shapoclyack/examples/nats-443-ingress.example.yaml` has both, with the
Service and container ports each needs.

`wss://` is the more portable of the two and the weaker: the WebSocket upgrade
is an HTTP request, so anything terminating HTTPS in the path terminates it.
nats-py implements the transport through `aiohttp`, which the agent image does
not ship — the agent refuses at start with that message rather than failing
later inside its event loop.

## Bandwidth

The results upload is the largest thing an agent sends: one gzipped run
directory, whose size follows the number of hosts and whether screenshots are
on. On a branch office's uplink an unshaped upload is the reason the site's
voice traffic stutters for two minutes after every scan.

`OCTO_AGENT_UPLOAD_RATE_LIMIT_KBPS` shapes it — KiB/s, `0` (the default) for no
limit. The limit is applied as the archive is read off disk, so it bounds the
wire rate rather than the memory footprint of a buffer that was already filled.
The bucket holds one second's worth, so a burst up to the rate leaves
immediately and only a sustained stream is held back.

`OCTO_AGENT_RESULTS_MAX_BODY_BYTES` on the API side (default 128 MiB) is the
other half: it caps what a single upload may be, and a shaped agent whose
archive exceeds it still fails.

## See also

- [configuration.md](configuration.md#environment-variables) — every variable named here
- [operations.md](operations.md#transport-encryption) — which links are encrypted and how
- [architecture.md](architecture.md) — what talks to what, and why
