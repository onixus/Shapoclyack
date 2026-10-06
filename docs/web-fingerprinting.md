# Web technology fingerprinting

The `fingerprint` stage (`scanner/pipeline/fingerprint.py`, opt-in with
`fingerprint.enabled`) GETs the root of every already-open web port and
classifies the answer against a catalogue of about 150 technologies. It never
scans a port and never merges what it finds into scan scope. This page is the
contract of what it reports; the stage's limits (`concurrency`, `max_targets`,
`body_max_bytes`, `timeout_seconds`, `verify_tls`, the port lists) are in
`FingerprintConfig` (`scanner/pipeline/config_schema.py`).

## What goes on the wire

* One `GET scheme://address:port/` per candidate endpoint.
* A redirect is followed — **at most three hops** — only to an
  `(address, port)` the port stage reported open in this run: the same
  address, on a port that was scanned. A port nobody scanned, or one the
  tenant excluded (#362), is never contacted from here. Anything else —
  another port, another address, a host name, `127.0.0.1.` with its trailing
  dot — is recorded as `redirect_location` with `redirected_off_host: true`
  and **not fetched**. A redirect to a name is the virtual-host case; the name
  is a target of its own. Credentials in a `Location` are never sent.
* `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` are ignored: scan traffic does not
  go through a proxy the sensor's environment happens to name.
* No second path is requested. A `/favicon.ico` hash or a probe of a known
  login path would identify more, and would be a request of its own.

Every URL written to `fingerprint.json` (`final_url`, `redirect_location`,
exposure `url`, URL evidence) is cut to `scheme://host:port/path`: no
userinfo, query, fragment or `;path-parameters` (`;jsessionid=` is a session).

## The catalogue

`scanner/pipeline/fingerprint_catalogue.json`, validated when the stage loads
it (`scanner/pipeline/fingerprint_catalogue.py`; a broken file stops the stage
rather than matching nothing). It sits next to the code, not under
`scanner/data`: the images mount the enrichment volume over `scanner/data`,
and a volume seeded before the file existed would hide it.

Each entry has an `id`, a `name`, a `category`, a default `confidence`, a list
of `match` rules (any one is enough), optionally `version` rules and optionally
an NVD `cpe` key (`part:vendor:product`).

| Matcher source | Selects | Tests |
|---|---|---|
| `header` | `name` or `prefix` of a response header | none (presence), `contains`, `equals`, `regex` |
| `cookie` | `name` or `prefix` of a `Set-Cookie` | presence only — a cookie value is a session secret, never read or reported |
| `status` | the HTTP status, as text | `equals`, `regex` |
| `url` | path and query that answered (same-address hops followed) | `equals`, `contains`, `regex` |
| `title` | the first `<title>`, entity-decoded | `equals`, `contains`, `regex` |
| `generator` | each `<meta name="generator">` | `equals`, `contains`, `regex` |
| `meta` | the `<meta>` whose `name`/`property` is `name` | none (presence) or a test on `content` |
| `asset` | what the page loads or submits to: script/img/iframe `src`, `<link href>`, `<form action>` — same-origin as a path, anything else as `//host/path`; `<a href>` is navigation and is not an asset | `equals`, `contains`, `regex` |
| `attr` | attribute `name` of element `tag` (or the element itself) | none (presence) or a test on the value |
| `script` | text of inline `<script>` elements | `contains`, `regex` |
| `json` | the body, only when the response is JSON (JSON content type, body opens with `{`/`[`) | `contains`, `regex` |
| `body` | the raw body — last resort, for product text with no structure, always in an `all` with the status or title the product sends | `contains` (5+ characters), `regex` |
| `all` | two or more of the above | all must hold |

Everything is case-insensitive. The point of the structural sources is that
somebody else's page quoting the product is not the product: a tutorial
showing `curl :9200` output in `<pre>` is HTML, not Elasticsearch; an article
on the Whitelabel Error Page is served with 200, not the error status; an
intranet page *linking* to `/dana-na/` is not the VPN; a hot-linked image from
somebody's WordPress is a foreign asset. `tests/fixtures/fingerprint/web_responses.json`
holds a positive fixture for every entry (every matcher must fire on one) and
a negative corpus — tutorials, write-ups, quotes, link pages — that must
identify nothing.

**Bounded cost.** The scanned host writes the body. The page is read once by a
linear scan with caps (2048 tags, 32 attributes each, 64 inline scripts of at
most 64 KiB; HTML comments are skipped, so markup inside `<!-- -->` is text).
A `<script>` cut off by `body_max_bytes` still counts as script up to the end
of what arrived — Grafana's boot data alone outgrows a 64 KiB read. Catalogue
regexes are checked twice when the catalogue loads:

* by shape — a repeat must be bounded (`{0,512}`, never `*`/`+`/`{n,}`, at
  most 1024, nested products at most 4096), no alternation inside a repeat,
  no two variable repeats in a row over overlapping characters (lookarounds
  looked through);
* by measurement — every pattern is run over hostile inputs built from its
  own literals, growing one character at a time and then doubling to
  64 KiB; one search over 50 ms refuses the whole catalogue.

Classification runs in a worker thread against a 2-second deadline, with an
outer timeout on the wait. The deadline is checked *between technologies*: a
single `re.search` holds the GIL and cannot be pre-empted, which is why the
patterns themselves are vetted at load rather than trusted to the timeout. An
endpoint past the deadline is reported with `error: classification_timeout`
and nothing derived from its body.

**Confidence** has two levels. `high`: the product says so itself — its own
header, cookie, exact page title or markup only it serves. `medium`: strong,
but a shared component, a reverse proxy or a customised page could produce
it. Only `high` raises exposure findings; `medium` is inventory.

**Versions** are read only where the product states one reliably (`X-Jenkins`,
`kbn-version`, `Server: nginx/1.24.0`, a WordPress generator tag). The capture
must be a short token starting with a digit or it is dropped. When the header
that states it also names a distribution (`Apache/2.4.52 (Ubuntu)`,
`PHP/8.1.2-1ubuntu2.14`, `+deb12`, `.el8`), the version is kept but left out of
the CPE, and the technology carries `distro_hint` and the raw `banner`: the
upstream number is not the code that runs (backports), and a later CPE→CVE
join must go through the distribution-aware logic, not around it.

**CPE**. Keys were checked against the NVD CPE dictionary
(`services.nvd.nist.gov/rest/json/cpes/2.0`) on the catalogue's `updated` date,
taking the key NVD files *current* releases under (`f5:nginx_open_source`, not
`f5:nginx` or the deprecated `nginx:nginx`;
`o:cisco:adaptive_security_appliance_software`, not the deprecated `a:` form).
A product with no single key — per-model firmware, an edition the page does
not reveal — has none, rather than a guess. The emitted value is a CPE 2.3
string (`cpe:2.3:a:jenkins:jenkins:2.414.3:*:…`) that
`api/services/retro_match.parse_cpe` reads back. Where the product shows a
build NVD does not file versions by (Exchange, SharePoint),
`version_in_cpe: false` keeps the version out of the CPE.

### Categories

| Category | Examples | Exposure finding |
|---|---|---|
| `cdn_waf` | Cloudflare, Akamai, Imperva, Qrator, DDoS-Guard, Variti, Azure Front Door | — |
| `load_balancer`, `proxy_cache` | BIG-IP LTM, NetScaler, FortiGate SLB, AWS ELB, Yandex ALB, Squid, Varnish | — |
| `web_server`, `app_server` | nginx, Apache, IIS, Angie, MiniServ, FortiOS httpsd, Tomcat, Jetty, WebLogic | — |
| `framework`, `cms`, `ecommerce` | Next.js, Laravel, Spring Boot, ASP.NET, WordPress, 1C-Bitrix, Tilda, Magento | — |
| `collaboration`, `business_app`, `storage` | SharePoint, Nextcloud, 1C:Enterprise web client, SAP NetWeaver, MinIO | — |
| `admin_panel`, `database_ui`, `database` | Webmin, cPanel/WHM, Plesk, Keycloak, vCenter, phpMyAdmin, Adminer, Elasticsearch | `exposed_admin_interface` |
| `devops`, `monitoring` | Jenkins, GitLab, Jira, Confluence, Argo CD, Portainer, Grafana, Kibana, Zabbix | `exposed_admin_interface` |
| `network_appliance` | FortiGate admin GUI, MikroTik RouterOS, BIG-IP TMUI, iLO, OPNsense, Synology DSM | `exposed_admin_interface` |
| `remote_access`, `mail_webmail` | FortiGate SSL-VPN, Ivanti Connect Secure, Citrix Gateway, GlobalProtect, Cisco ASA, F5 APM, Usermin, Exchange OWA, cPanel Webmail, Zimbra, Roundcube | `exposed_remote_access_gateway` |

## What lands in `fingerprint.json`

`findings` is still one record per endpoint, with the Phase 9.1 fields
unchanged and these added:

| Field | Meaning |
|---|---|
| `technologies[]` | `{id, name, category, version, cpe, confidence, evidence[]}` (+ `distro_hint`, `banner` when a distribution was named), in catalogue order |
| `final_url` | the URL that gave the answer (the endpoint, or a same-address hop), sanitized |
| `redirect_location` | where an unfollowed redirect pointed, sanitized |
| `redirected_off_host` | that redirect left the address |
| `title` | the page title, cut to 200 characters |

`cdn_waf` lists the CDN/WAF matches of **high** confidence on an endpoint that
did not redirect elsewhere, and `cms_framework` the CMS, framework and
e-commerce matches. The original ids (`cloudflare` … `fastly`, `wordpress`,
`drupal`, `joomla`, `nextjs`, `generic_php`) are kept; the lists now also
carry what the catalogue added. Joomla is no longer "the word *joomla*
anywhere in the body", WordPress no longer `wp-content` in text or a foreign
image, and an Imperva cookie is matched by name, not by a value that happens
to contain `incap_ses`.

At the top level, `catalogue` records the schema, `updated` date and size of
the catalogue the run used, and `exposures` holds the findings, one per final
origin (`scheme://host:port`), so `:80` redirecting to `:443` is one finding,
attributed to `:443`:

```json
{"kind": "exposed_admin_interface", "severity": "low",
 "host": "198.51.100.7", "port": 8080, "url": "http://198.51.100.7:8080/login",
 "technology": "jenkins", "evidence": ["header x-jenkins: 2.414.3"],
 "name": "Jenkins", "category": "devops", "version": "2.414.3",
 "cpe": "cpe:2.3:a:jenkins:jenkins:2.414.3:*:*:*:*:*:*:*", "confidence": "high",
 "http_status": 403, "auth_required": true,
 "detail": "Jenkins login page reachable (HTTP 403)"}
```

* `exposed_admin_interface` — a console, database UI or appliance management
  page answered, rated by what it answered. `auth_required` is a 401/403, a
  password field, or a login path (`/login`, `/users/sign_in`, …).
  * **high**: a `database` answered its API at 2xx with no login — an open
    database (Elasticsearch's tagline at 200).
  * **medium**: a console with no login page in front.
  * **low**: a login page — reachable, not open (`auth_required: true`); or a
    root that is served to anybody whether or not a login follows
    (`root_is_public`: the Argo CD, Portainer, Harbor and Kubernetes
    Dashboard app shells, the Keycloak and vCenter welcome pages, CouchDB's
    welcome document) — `auth_required: null`, "authentication not
    determinable from the landing page", never claimed open.
* `exposed_remote_access_gateway` (info) — a VPN, remote-access or webmail
  portal. These are meant to be reachable, so it is an inventory item, not a
  weakness. They are also the products with the most entries in CISA KEV; each
  carries its `cpe` and `version` so that a later step can join them with KEV.
  **No such join exists yet** — it is future work.
* `version_disclosure` (info) — a version stated in a **response header**
  (`header` names it), once per header and origin. A version in the body is
  inventory, not a disclosure.

No exposure, and no `cdn_waf`, comes from an endpoint whose answer was a
redirect off its address: its technologies are what that redirect itself
carried.

## Consumers

* **Risk model** (`api/services/risk_scoring.index_cdn_waf`, #173) reads
  `findings[].cdn_waf` and discounts likelihood by a named −6 for the six
  providers in `CDN_WAF_PROVIDERS` only. A CDN/WAF the catalogue learned later
  (Qrator, DDoS-Guard, Variti, Azure Front Door, Vercel) appears in `cdn_waf`
  and earns nothing; Barracuda and the BIG-IP ASM block page are medium and do
  not even appear there. Adding a provider to the discount is a risk-model
  decision — see [Risk scoring](risk-scoring.md#compensating-controls-are-observed-not-assumed).
* **Security controls** (`scanner/pipeline/controls.py`, *Технологии сайта*):
  console exposures count at their severity (an open database fails the
  control, a console or login page makes it `weak`), and `why` says which —
  "N database API(s) answer without authentication", "N admin/management
  console(s) answer with no login page in front", "N admin login page(s)
  reachable", "N admin console landing page(s) reachable, authentication not
  determinable". Gateways and other info items move neither the counts nor the
  status, but `why` always counts the gateways and three of the ten
  `top_findings` are kept for them. The control's own banner rule for
  `Server` / `X-Powered-By` (versioned medium, bare low) is unchanged, and a
  `version_disclosure` for those two headers is not counted again.
* `fingerprint_matches.txt` keeps its `host:port:scheme:cdn_waf,cms_framework`
  lines.

## Adding or changing an entry

1. Add the entry to `fingerprint_catalogue.json`. Prefer the product's own
   header, cookie, exact title or markup (`meta`, `asset`, `attr`); use `json`
   for an API's own document and `body` only inside an `all` with the status
   or title the product sends. Every regex needs bounded repeats.
2. Add a positive fixture to `tests/fixtures/fingerprint/web_responses.json`
   (synthetic, `example.test` names) that fires every matcher and checks the
   version, and a negative one for any text marker (the tutorial that quotes
   it). Run `python -m pytest tests/test_fingerprint_catalogue.py -q`.
3. Look the CPE key up in the NVD CPE dictionary
   (`?cpeMatchString=cpe:2.3:a:vendor:product`) and take the one whose newest
   entries are not deprecated. Leave it out when there is no single key.
4. Do not touch the six Phase 9.1 CDN/WAF entries' matchers without reading
   the risk-scoring section above.

## Limits, stated plainly

* Markers come from public knowledge and are tested against synthetic
  fixtures, not against captures of live hosts. A product that hides its
  markers, or that the catalogue does not know, is absent from the output.
* Not in the catalogue for want of a passive marker reliable enough to
  ship: Check Point Mobile Access, UserGate, StormWall, ISPmanager, pfSense,
  VMware Horizon, Apache Guacamole, Dell iDRAC, Juniper J-Web, and the
  Russian VPN gateways (Континент, ViPNet, С-Терра).
* Only what the root (and same-address redirects) answers is seen. A console
  that redirects to its configured host name is found when that name is
  scanned, not on the address; a product mounted under a path is not found.
* `auth_required` reads the first page. The SPA consoles the catalogue knows
  are `root_is_public` (low, not determinable); one it does not know draws its
  login form in JavaScript and reads as "no login page" (medium).
* Scanned by address, a site that writes its own asset URLs absolutely
  (`src="https://www.example.com/wp-content/..."`) reads them as foreign, so
  WordPress, Joomla and the like are missed on the address. The name-based
  (virtual-host) targets planned for this stage and nuclei will see them.
