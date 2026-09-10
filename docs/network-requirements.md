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

### Scanner → outside

The scan itself goes to the tenant's own targets and is never proxied — routing
it through a corporate proxy would break the scan and hand the proxy a copy of
it. Several pipeline stages are different: they ask a *fixed, always-external*
service a question of their own, and on a proxy-only network those are the ones
that fail.

| Stage | To | Port | What it asks | Honours `OCTO_HTTPS_PROXY` / `OCTO_CA_BUNDLE` |
|---|---|---|---|---|
| `asn_discovery` | `stat.ripe.net` | 443 | ASN and announced prefixes for a seed domain | **Yes** |
| `cloud_discovery` | `*.s3.amazonaws.com`, `*.storage.googleapis.com`, `*.blob.core.windows.net` | 443 | Whether a guessed bucket name exists | **Yes** |
| `hostnames` | `crt.sh`, `api.certspotter.com`, `otx.alienvault.com` | 443 | Passive certificate and DNS sources | No — on `urllib`, so the ambient `HTTPS_PROXY` applies and the `OCTO_` names do not |
| `ownership` | `data.iana.org`, `rdap.org` and the registry it redirects to | 443 | RDAP registration data | No — `safe_http` pins the address it validated, and a proxy would resolve the name a second time |
| `alerts` | `cloudflare-dns.com`, Slack, Telegram | 443 | DoH lookup, run notifications | No — same pinning, and the webhook host is operator-supplied |
| `fingerprint`, `nuclei`, port scan | scan targets | as scoped | The scan | No, deliberately |

`OCTO_NO_PROXY` is not consulted by the two stages that do honour the proxy:
RIPEstat and the three object stores are never on the inside, so there is no
exemption to express, and honouring half the dialect would be worse than
honouring none of it. `scanner/pipeline/egress_env.py` is where this lives,
deliberately narrower than the API's and the agent's egress modules rather than
a third copy of them.

## Proxy and CA variables

| Variable | Applies to | Meaning |
|---|---|---|
| `OCTO_HTTPS_PROXY` | API, agent, scanner | Proxy for `https://` targets. `[http://][user:pass@]host[:port]` — the proxy URL itself must be `http://`, no `https://` and no SOCKS |
| `OCTO_HTTP_PROXY` | API, agent | The same for `http://` targets |
| `OCTO_NO_PROXY` | API, agent | Comma-separated exemptions. `*` bypasses everything; a bare name matches it and its subdomains (`example.com` covers `api.example.com`, not `notexample.com`); `host:port` pins the port; a CIDR matches an address literal inside it |
| `OCTO_CA_BUNDLE` | API, agent, scanner | PEM file **added to** the system trust store, for HTTPS, SMTP and NATS alike — on the API's NATS connection as well as the agent's. Verification is never turned off |

Each falls back to the conventional `HTTPS_PROXY` / `NO_PROXY` (and their
lowercase spellings) when unset — with one exception, and it runs the other way
round from the one most people expect. For the plain-HTTP direction only the
**lowercase** `http_proxy` is read; uppercase `HTTP_PROXY` is ignored. A
CGI-shaped environment derives `HTTP_PROXY` from an incoming `Proxy:` request
header, so the uppercase name is the one an untrusted caller can write
(httpoxy); curl reads only the lowercase spelling for the same reason. No
request header spells `HTTPS_PROXY`, so that direction reads both.

A proxy URL must be `http://`. Nothing here wraps the hop to the proxy in TLS —
HTTPS targets go through a plaintext `CONNECT`, and the proxy credentials ride
on it as `Proxy-Authorization: Basic` — so `https://` is refused with that
reason rather than silently downgraded. End-to-end TLS to the *receiver* is
unaffected: it is established inside the tunnel and verified against the
receiver's own name.

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
of the outside at all. **A webhook host that does not resolve here is still a
delivery failure**, proxy or no proxy. The addresses are what the `#151` policy
inspects, so a name with none of them has not been checked at all — and handing
it to a proxy that *can* resolve it would turn the proxy into an SSRF oracle:
any internal name a tenant admin cares to guess gets dialed, and the delivery
record hands back the answer. Give the API a resolver that can see the
receivers (a forwarder), or exempt on-network receivers with `OCTO_NO_PROXY`
and keep the pinned direct dial.

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
