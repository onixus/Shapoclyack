# Web technology fingerprinting

The `fingerprint` stage (`scanner/pipeline/fingerprint.py`, opt-in with
`fingerprint.enabled`) makes **one GET** to every already-open web port and
classifies the answer against a catalogue of about 140 technologies. It never
scans a port, never fetches a second path and never merges what it finds into
scan scope. This page is the contract of what it reports; the stage's limits
(`concurrency`, `max_targets`, `body_max_bytes`, `timeout_seconds`,
`verify_tls`, the port lists) are in `FingerprintConfig`
(`scanner/pipeline/config_schema.py`).

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
| `header` | `name` or `prefix` of a response header | none (presence), `contains`, `equals`, `regex` on the value |
| `cookie` | `name` or `prefix` of a `Set-Cookie` | presence only — a cookie value is a session secret and is never read or reported |
| `body` | the first `body_max_bytes` of the body | `contains` (5+ characters), `regex` |
| `title` | the `<title>` text, entity-decoded | `equals`, `contains`, `regex` |
| `generator` | each `<meta name="generator">` | `equals`, `contains`, `regex` |
| `url` | path and query the answer came from, after redirects | `equals`, `contains`, `regex` |
| `all` | two or more of the above | all must hold |

Everything is case-insensitive. Body markers are paths, element ids and script
variables, never a product name on its own: a blog post about Jenkins is not
Jenkins. Paths of the remote-access products are anchored to a quote
(`["']/dana-na/`), so an intranet page *linking* to the VPN is not taken for
the VPN. `tests/fixtures/fingerprint/web_responses.json` holds a positive
fixture for every entry (every matcher must fire on one) and a negative corpus
that must identify nothing at all.

**Confidence** has two levels. `high`: the product says so itself — its own
header, cookie or exact page title. `medium`: strong, but a shared component,
a reverse proxy or a customised page could produce it. Anything weaker is not
a signature and is not in the file.

**Versions** are read only where the product states one reliably (`X-Jenkins`,
`kbn-version`, `Server: nginx/1.24.0`, a WordPress generator tag). The capture
must be a short token starting with a digit or it is dropped.

**CPE**. Keys were checked against the NVD CPE dictionary
(`services.nvd.nist.gov/rest/json/cpes/2.0`) on the catalogue's `updated` date,
taking the key NVD files *current* releases under (`f5:nginx`, not the
deprecated `nginx:nginx`; `o:cisco:adaptive_security_appliance_software`, not
the deprecated `a:` form). A product with no single key — per-model firmware,
an edition the page does not reveal — has none, rather than a guess. The
emitted value is a CPE 2.3 string (`cpe:2.3:a:jenkins:jenkins:2.414.3:*:…`)
that `api/services/retro_match.parse_cpe` reads back. Where the product shows a
build NVD does not file versions by (Exchange, SharePoint, MiniServ's shared
numbering), `version_in_cpe: false` keeps the version out of the CPE and in
`version` only.

### Categories

| Category | Examples | Exposure finding |
|---|---|---|
| `cdn_waf` | Cloudflare, Akamai, Imperva, Qrator, DDoS-Guard, Variti, Azure Front Door | — |
| `load_balancer`, `proxy_cache` | BIG-IP LTM, NetScaler, AWS ELB, Yandex ALB, Squid, Varnish | — |
| `web_server`, `app_server` | nginx, Apache, IIS, Angie, Tomcat, Jetty, WebLogic, Werkzeug | — |
| `framework`, `cms`, `ecommerce` | Next.js, Laravel, Spring Boot, ASP.NET, WordPress, 1C-Bitrix, Tilda, Magento | — |
| `collaboration`, `business_app`, `storage` | SharePoint, Nextcloud, 1C:Enterprise web client, SAP NetWeaver, MinIO | — |
| `admin_panel`, `database_ui`, `database` | Webmin, cPanel, Plesk, Keycloak, vCenter, phpMyAdmin, Adminer, Elasticsearch | `exposed_admin_interface`, medium |
| `devops`, `monitoring` | Jenkins, GitLab, Jira, Confluence, Argo CD, Portainer, Grafana, Kibana, Zabbix | `exposed_admin_interface`, medium |
| `network_appliance` | MikroTik RouterOS, BIG-IP TMUI, iLO, OPNsense, Synology DSM | `exposed_admin_interface`, medium |
| `remote_access`, `mail_webmail` | FortiGate, Ivanti Connect Secure, Citrix Gateway, GlobalProtect, Cisco ASA, F5 APM, Exchange OWA, Zimbra, Roundcube | `exposed_remote_access_gateway`, info |

## What lands in `fingerprint.json`

`findings` is still one record per endpoint, with the Phase 9.1 fields
unchanged and these added:

| Field | Meaning |
|---|---|
| `technologies[]` | `{id, name, category, version, cpe, confidence, evidence[]}`, in catalogue order |
| `final_url` | where the answer came from after redirects, query dropped |
| `redirected_off_host` | the redirects ended on another host name |
| `title` | the page title, cut to 200 characters |

`cdn_waf` lists the CDN/WAF matches of **high** confidence, and `cms_framework`
the CMS, framework and e-commerce matches. The original ids (`cloudflare` …
`fastly`, `wordpress`, `drupal`, `joomla`, `nextjs`, `generic_php`) are kept;
the lists now also carry what the catalogue added. Joomla is no longer "the
word *joomla* anywhere in the body", and an Imperva cookie is matched by
name, not by a value that happens to contain `incap_ses`.

At the top level, `catalogue` records the schema, `updated` date and size of
the catalogue the run used, so an old run can be told apart from a new one.

`exposures` is new, one item per finding, in the posture modules' shape plus
what a later join needs:

```json
{"kind": "exposed_admin_interface", "severity": "medium",
 "host": "198.51.100.7", "port": 8080, "url": "http://198.51.100.7:8080/",
 "technology": "jenkins", "evidence": ["header x-jenkins: 2.414.3"],
 "name": "Jenkins", "category": "devops", "version": "2.414.3",
 "cpe": "cpe:2.3:a:jenkins:jenkins:2.414.3:*:*:*:*:*:*:*", "confidence": "high"}
```

* `exposed_admin_interface` (medium) — a console, database UI or appliance
  management page answered. A login page counts: reachable is the finding.
* `exposed_remote_access_gateway` (info) — a VPN, remote-desktop or webmail
  portal. These are meant to be reachable, so the finding is an inventory
  item, not a weakness. They are also the products with the most entries in
  CISA KEV; the `cpe` (and `version` where shown) is the join key —
  `cpe` → NVD ranges (`scanner/data/nvd-cpe`) → CVE → KEV overlay.
* `version_disclosure` (info) — a version stated in a **response header**
  (`header` names it). A version in the body is inventory, not a disclosure.

No exposure is raised for an endpoint whose redirects ended on another host:
a root that redirects to a hosted SSO or a SaaS tracker says nothing about
what that address exposes. Its technologies are still listed, with
`final_url` showing where they were seen.

## Consumers

* **Risk model** (`api/services/risk_scoring.index_cdn_waf`, #173) reads
  `findings[].cdn_waf` and discounts likelihood by a named −6 for the six
  providers in `CDN_WAF_PROVIDERS` only. A CDN/WAF the catalogue learned later
  (Qrator, DDoS-Guard, Variti, Azure Front Door, Vercel) appears in `cdn_waf`
  and earns nothing; Barracuda and the BIG-IP ASM block page are medium and do
  not even appear there. Adding a provider to the discount is a risk-model
  decision — see [Risk scoring](risk-scoring.md#compensating-controls-are-observed-not-assumed).
* **Security controls** (`scanner/pipeline/controls.py`, *Технологии сайта*):
  `exposed_admin_interface` counts as a medium finding and makes the control
  `weak`; info items are listed in `top_findings` and move neither the counts
  nor the status. The control's own banner rule for `Server` /
  `X-Powered-By` (versioned medium, bare low) is unchanged, and a
  `version_disclosure` for those two headers is not counted again.
* `fingerprint_matches.txt` keeps its `host:port:scheme:cdn_waf,cms_framework`
  lines.

## Adding or changing an entry

1. Add the entry to `fingerprint_catalogue.json`. Prefer the product's own
   header, cookie or exact title; anchor body paths to a quote; use `all` when
   two markers are only specific together.
2. Add a positive fixture to `tests/fixtures/fingerprint/web_responses.json`
   (synthetic, `example.test` names) that fires every matcher and checks the
   version, and run `python -m pytest tests/test_fingerprint_catalogue.py -q`.
   A fixture that also identifies another technology lists it in `also`.
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
* Only what the root answers is seen. Most consoles redirect `/` to their
  login page and are found; a product mounted under a path is not.
* A second request — a `/favicon.ico` hash, or a probe of a known login
  path — would identify more. It would also double the stage's requests per
  endpoint, so it is not made.
