# Network requirements

What Shapoclyack opens, in which direction, and what has to be allowed for an
installation on a corporate network to work
([#359](https://github.com/onixus/Shapoclyack/issues/359)). Hand this document
to whoever owns the firewall.

Two rules run through all of it:

- **Every component is outbound-only towards the control plane.** Nothing dials
  a sensor, and nothing dials a scanner. A sensor (the remote scanning node —
  API resource `agents`, `agent_kind = scanner`) needs egress to the API and
  nothing needs ingress to the sensor. The same holds for the Agent (Lariska),
  which only ever POSTs inventory to the API.
- **HTTP egress obeys a proxy; NATS does not.** That asymmetry decides how a
  proxy-only site is deployed, and it is spelled out under
  [NATS and proxies](#nats-and-proxies).

## Ports and directions

### Sensor → control plane

| From | To | Port | Protocol | Required | What breaks without it |
|---|---|---|---|---|---|
| Sensor | API (`--api-url`) | 443 (or 80) | HTTPS | **Yes** | Everything: token exchange, registration, heartbeat, job claim, results upload |
| Sensor | NATS broker | 4222 | TLS over TCP (`tls://`) | No | Job *push*. The sensor falls back to HTTP claim polling |
| Sensor | NATS broker | 443 | TLS over TCP through a stream ingress | No | Alternative to 4222 where the firewall only passes 443 |
| Sensor | NATS broker | 443 | WebSocket over TLS (`wss://`) | No | Alternative again, where a raw TCP ingress is not available |
| Sensor | DNS resolver | 53 | UDP/TCP | **Yes** | Name resolution for the API host and for every scan target. nuclei uses the host's own resolver or `dns.resolvers`. dnsx still asks public resolvers; see [DNS resolvers](#dns-resolvers) |
| Sensor | scan targets | as scoped | TCP/UDP/ICMP | **Yes** | The scan itself. The tenant's approved scan scope decides the range |

A sensor needs **no inbound rule at all**. An Agent (Lariska) needs only the
first row — HTTPS to the API — for `POST /api/endpoint/inventory`. `k8s/shapoclyack/examples/networkpolicy-agent.example.yaml`
is the in-cluster expression of the same list for the scanner-executor: DNS,
the API, and a target-range rule that ships with documentation prefixes and
has to be replaced with the approved scope before the sensor can scan
anything. Two things that list does not show. First, `dnsx` asks the pod's
own resolver — the cluster DNS, from `/etc/resolv.conf` — unless the scanner
config sets `dns.resolvers`, and then it needs UDP/TCP 53 to those instead.
Second, stages that query third
parties (CT logs, RDAP, …) need their providers' addresses. The example says
which.

The DNS row means the sensor's own resolver, not port 53 to the internet.
`dnsx`, which runs the scanner's DNS stages (target resolution, PTR names,
domain monitoring, zone and mail posture), is handed as `-r` the resolver libc
would ask — the first `nameserver` in `/etc/resolv.conf`, the first three under
`options rotate`, 127.0.0.1 when there is none — or the scanner config's
`dns.resolvers` when that is set, and then those addresses need the rule
instead. A backup `nameserver` is not passed on: dnsx would rotate over it
rather than fall back to it. Its built-in public resolvers (1.1.1.1, 8.8.8.8,
…) are never used, so internal names resolve and target names go only to the
resolver the network already trusts. Where that resolver cannot be reached
dnsx still exits 0; the `resolve` stage logs that no resolver answered, and a
run of names only ends with no targets.

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

The enrichment refresh (the `enrichment-refresh` CronJob and the API's
`fetch-enrichment` initContainer) reaches every feed host through the same
proxy and CA settings, and each feed can be pointed at an internal mirror
instead; [air-gap.md](air-gap.md#3-pointing-every-feed-at-a-mirror) lists the
hosts and the `*_URL` variables, and how to run with no egress at all.

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
| `nuclei`, only when `nuclei.interactsh_server` is set | your interactsh server | 443, or 80 for an `http://` server | OAST registration, a poll every 5 s, deregistration | No. See [Out-of-band testing](#out-of-band-testing-interactsh) |

`OCTO_NO_PROXY` is not consulted by the two stages that do honour the proxy:
RIPEstat and the three object stores are never on the inside, so there is no
exemption to express, and honouring half the dialect would be worse than
honouring none of it. `scanner/pipeline/egress_env.py` is where this lives,
deliberately narrower than the API's and the sensor's (`agent/egress.py`) egress modules rather than
a third copy of them.

### DNS resolvers

The scanner hands nuclei an explicit resolver list (`-resolvers`). The list is
`dns.resolvers` from the scanner config. When that is empty, which is the
default, it is the `nameserver` lines of `/etc/resolv.conf`, so nuclei asks the
same servers as the rest of the host. The run leaves the list it used in
`nuclei_resolvers.txt` next to `nuclei.json`.

Without the list, nuclei v3.11.1 adds its built-in public resolvers (1.1.1.1,
1.0.0.1, 8.8.8.8, 8.8.4.4) to the system one and picks among them round-robin.
Its DNS-protocol templates ask those four only. Measured on the kind stand with
the image's own binary and the scanner's own flags, against IP-only targets:

- 256 of 320 lookups went to a public resolver.
- Those lookups included the name an HTTP redirect pointed to, and query names
  built from the scanned address itself (`http://10.x.y.z`, from the
  JavaScript-protocol templates).
- A template that follows a redirect to an internal-only name matched nothing,
  because the name never resolved. With the list passed, the same template
  matched.

With the list passed, every name derived from a target went to the system
resolver only. The exception is nuclei's interactsh client, which ignores
`-resolvers`. It looks up the public interactsh servers (`oast.pro`,
`oast.live`, `oast.site`, `oast.online`, `oast.fun`, `oast.me`) through the
same public-plus-system rotation, and 160 of 312 lookups in the same run still
went to a public resolver, all of them for those six names. Those names are
fixed and say nothing about the targets. The scanner now runs nuclei with
`-no-interactsh` by default, so those lookups are gone. See
[Out-of-band testing](#out-of-band-testing-interactsh).

`dns.resolvers` accepts IP literals with an optional port (`10.0.0.53`,
`[2001:db8::53]:5353`). Names are refused, because a resolver given by name
would need a resolver first.

dnsx does not read the setting yet. It runs the `resolve`, `hostnames` and
org_profile DNS stages. Left to its defaults, dnsx v1.2.3 asks only its eight
built-in public resolvers and never the system one. Run the way `resolve`
runs it on the stand, dnsx sent an internal-only name to 8.8.8.8 and 1.0.0.1
and returned nothing. With `-r` pointed at the cluster resolver, it resolved
the name.

### Out-of-band testing (interactsh)

Some nuclei templates prove a blind vulnerability (SSRF, command injection,
Log4Shell-style lookups) by planting a unique hostname in the request and
waiting for the target to call it back. nuclei learns about the callback from
an interactsh server. Left to its defaults, nuclei registers with
ProjectDiscovery's public servers (`oast.pro`, `oast.live`, `oast.site`,
`oast.online`, `oast.fun`, `oast.me`), and the scanned hosts call back to those
public servers. The scanner does not allow that. It runs nuclei with
`-no-interactsh` unless `nuclei.interactsh_server` names a server you run.
Together with `-disable-update-check` on every naabu, dnsx and nuclei command
([air-gap.md](air-gap.md)), this means no scan contacts ProjectDiscovery.

Why not the public default:

- **It sends scan data to a third party.** Every callback from a scanned host
  is received by a server someone else operates. That includes the host's
  address and the request that reached it.
- **It makes internal hosts contact the internet.** The callback comes from the
  target, not from the sensor, so the traffic comes from inside the estate.
  `oast.*` lookups are also a common IDS signature.
- **It leaks lookups even where nothing else does.** As measured above, the
  interactsh client resolves the server names through public resolvers and
  ignores `-resolvers`. In a run on the kind stand with the image's nuclei and
  templates, 200 of 280 lookups were for those six names, spread over the four
  public resolvers and the cluster one.

With `-no-interactsh` the same run made no `oast.*` lookup, and it took 96 s
instead of 252 s. Part of that is the skipped templates. Part is that the
stand cannot reach public DNS, so the interactsh client spent its time waiting
on resolvers that never answered. The cost is the OAST templates themselves.
341 templates in nuclei-templates v9.9.4 ask for an interactsh URL, and 304 of
them pass the default severity and tag filters (counted with `nuclei -tl`).
nuclei still loads them but does not run them: two of them, tried against a
stub target, sent it nothing and failed with "interactsh client not
initialized". Each run records the choice in `nuclei.json` as
`"interactsh": "disabled"`, or as the server name.

To turn OAST on, run [interactsh-server](https://github.com/projectdiscovery/interactsh)
on a domain you control and set `nuclei.interactsh_server` to that domain:
`oast.corp.example` or `https://oast.corp.example` for HTTPS, or
`http://oast.corp.example` for plain HTTP. Ports, paths, IP literals and lists
are refused, because every payload is `<id>.<that host>` verbatim. If the
server was started with `-auth`, put its token in `OCTO_INTERACTSH_TOKEN` on the
sensor, not in the config file. The scanner passes the token to nuclei in a
temporary 0600 `-config` file, not on the command line, because the command
line is written to `scan.log`, which is uploaded with the run.

What that needs from the network:

| From | To | Port | Why |
|---|---|---|---|
| Sensor | interactsh server | 443 (bare name, `https://`) or 80 (`http://`) | Registration, polling, deregistration. A bare name means HTTPS only, because nuclei does not fall back to HTTP |
| Scanned hosts | interactsh server | 80, 443, and whichever of SMTP, LDAP, FTP and SMB the server is started with | The callbacks themselves |
| Scanned hosts' resolvers | interactsh server | 53 | DNS callbacks. The server must be authoritative for its domain, and your internal DNS must delegate the domain to it |

Measured against a stub interactsh server on the kind stand, with the two OAST
templates above:

- **The server name has to resolve without public DNS.** The interactsh
  client looked up an in-cluster-only server name through the same rotation of
  public resolvers plus the system resolver: 30 of 37 lookups went to a public
  resolver. None of those answered, and registration gave up after 30 s. Every
  OAST template was then skipped. With the name pinned in the sensor's
  `/etc/hosts`, registration made no DNS lookup at all and both templates
  matched. In Kubernetes, use `hostAliases`. With Docker, use `--add-host`. Pin
  the name even where public DNS is reachable, or the server name leaks to the
  public resolvers.
- **A failed registration is silent in nuclei.** Under `-silent` it printed
  nothing and exited 0. Only `-v` shows it, and `-v` logs every request. So
  with a server configured the scanner drops `-silent` and looks for the line
  nuclei prints once it has registered. `nuclei.json` records the result as
  `"interactsh_registered": true` or `false`, and `false` also logs a warning.
  `false` can also mean that no OAST template reached a live target.
- **The server's certificate is not verified.** A self-signed certificate was
  accepted. Setting `INTERACTSH_TLS_VERIFY=true`, which the interactsh client
  documents for this, changed nothing in this build. The token and the polled
  interactions therefore rely on the path between the sensor and the server
  being one you trust. Treat `http://` as cleartext.
- The client uses Go's `http.ProxyFromEnvironment`, so it follows an ambient
  `HTTPS_PROXY`/`NO_PROXY` and ignores the `OCTO_` names. This is from its
  source and was not measured.

## Proxy and CA variables

| Variable | Applies to | Meaning |
|---|---|---|
| `OCTO_HTTPS_PROXY` | API, sensor, scanner | Proxy for `https://` targets. `[http://][user:pass@]host[:port]` — the proxy URL itself must be `http://`, no `https://` and no SOCKS |
| `OCTO_HTTP_PROXY` | API, sensor | The same for `http://` targets |
| `OCTO_NO_PROXY` | API, sensor | Comma-separated exemptions. `*` bypasses everything; a bare name matches it and its subdomains (`example.com` covers `api.example.com`, not `notexample.com`); `host:port` pins the port; a CIDR matches an address literal inside it |
| `OCTO_CA_BUNDLE` | API, sensor, scanner | PEM file **added to** the system trust store, for HTTPS, SMTP and NATS alike — on the API's NATS connection as well as the sensor's. Verification is never turned off |

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

The sensor logs its decision once at start, so "the sensor cannot reach the API"
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
sensor sees is the appliance's, issued by an internal root. Put that root in
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

1. Leave `OCTO_NATS_URL` **unset** on the sensor.
2. The sensor then polls `POST /api/agent/jobs/claim` over HTTP — through the
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
| WebSocket | `wss://nats.example.com:443` | The HTTPS ingress in front | A `websocket {}` listener, an ordinary Ingress, and `aiohttp` installed on the sensor |

`k8s/shapoclyack/examples/nats-443-ingress.example.yaml` has both, with the
Service and container ports each needs.

`wss://` is the more portable of the two and the weaker: the WebSocket upgrade
is an HTTP request, so anything terminating HTTPS in the path terminates it.
nats-py implements the transport through `aiohttp`, which the sensor image does
not ship — the sensor refuses at start with that message rather than failing
later inside its event loop.

## Bandwidth

The results upload is the largest thing a sensor sends: one gzipped run
directory, whose size follows the number of hosts and whether screenshots are
on. On a branch office's uplink an unshaped upload is the reason the site's
voice traffic stutters for two minutes after every scan.

`OCTO_AGENT_UPLOAD_RATE_LIMIT_KBPS` shapes it — KiB/s, `0` (the default) for no
limit. The limit is applied as the archive is read off disk, so it bounds the
wire rate rather than the memory footprint of a buffer that was already filled.
The bucket holds one second's worth, so a burst up to the rate leaves
immediately and only a sustained stream is held back.

`OCTO_AGENT_RESULTS_MAX_BODY_BYTES` on the API side (default 128 MiB) is the
other half: it caps what a single upload may be, and a shaped sensor whose
archive exceeds it still fails.

## See also

- [configuration.md](configuration.md#environment-variables) — every variable named here
- [operations.md](operations.md#transport-encryption) — which links are encrypted and how
- [architecture.md](architecture.md) — what talks to what, and why
