# Risk scoring

How Shapoclyack decides what to work on first. Model **`nist-1`**, implemented in
[`api/services/risk_scoring.py`](../api/services/risk_scoring.py),
[`nist_risk.py`](../api/services/nist_risk.py) and
[`exploit_evidence.py`](../api/services/exploit_evidence.py).

## The question CVSS does not answer

CVSS scores *how bad it would be if exploited*. It deliberately says nothing
about whether anyone can exploit it here, or whether the machine matters. Two
findings that CVSS rates identically routinely differ by everything:

| | CVE-A | CVE-B |
|---|---|---|
| CVSS | 9.8 | 9.8 |
| Exploit code | none has ever been published | in Metasploit, exploited in the wild |
| Host | a lab VM | the payment gateway |

Any model that ranks these together will be ignored, and a model operators
ignore is worse than none — it launders inaction as triage.

## Structure: NIST SP 800-30 Rev. 1

Risk is assessed as two independent judgements combined through a fixed table,
rather than blended into one weighted sum:

```
risk = f(likelihood, impact)          NIST SP 800-30 Rev. 1, Table I-2
```

Keeping the axes apart is what makes the result arguable. "High, because
likelihood is High (exploited in the wild, reachable over the network) and
impact is High (full compromise of a criticality-4 asset)" is a sentence an
operator can push back on. "7.8" is not.

Both axes use the five qualitative levels and the 0–100 semi-quantitative bands
from Table D-2: **Very Low** (0–4), **Low** (5–20), **Moderate** (21–79),
**High** (80–95), **Very High** (96–100).

Table I-2 is transcribed verbatim, not computed. It is deliberately asymmetric —
a Very High likelihood against a Very Low impact is still **Very Low** risk,
while a Very Low likelihood against a Very High impact is **Low** — and any
formula smooth enough to be worth writing disagrees with the standard
somewhere. At that point it would be "NIST-inspired", which is a different
claim.

## Likelihood — will this be exploited?

| Input | Source | Role |
|---|---|---|
| Reachability | CVSS vector `AV`/`AC`/`AT`/`PR`/`UI` | How hard is it to reach and trigger *the vulnerability* |
| EPSS | per-finding, else the EPSS overlay | Population-level probability over the next 30 days |
| **Exploit maturity** | see below | Floor **and** ceiling |
| Scanner confidence | `finding_class` / `confidence` | Discount for hypotheses |
| **Network exposure** | this host: RFC1918 / operator-set / explicit | ±20 on likelihood after bounds. `unknown` is a no-op |
| **CVE age** | NVD `published`, else CVE-ID year | Raise-only, weak. Never a decay |
| **Compensating control** | fingerprint `cdn_waf` on the same host:port | −6, named. Not proof the vuln is blocked |
| **Same-asset path** | local finding + network foothold on one P4.2 asset | +8, named. Not a modelled exploit chain |

Reachability and EPSS are blended 65/35 — reachability describes *this* finding,
while EPSS is a statistic about the CVE that knows nothing about whether the
affected port is exposed here.

Maturity is applied last, as bounds rather than as another weighted term,
because it is the only input carrying evidence about whether exploitation
happens at all:

| Maturity | Meaning | Likelihood floor–ceiling |
|---|---|---|
| `attacked` | Observed exploited in the wild (CISA KEV) | 96–100 |
| `weaponized` | Packaged, reusable exploit (Metasploit) | 80–100 |
| `proof_of_concept` | Public exploit or working detection code exists | 40–95 |
| `unproven` | No public code found, but EPSS ≥ 0.10 | 5–79 |
| `theoretical` | Sources consulted; nobody has demonstrated it | 0–20 |
| `unknown` | **No exploit-intelligence source is configured** | 0–100 (no bound) |

The ceilings do the real work. Without them a theoretical finding with a perfect
vector scores as likely, which is exactly the false urgency that trains people
to stop reading severity columns.

**EPSS is not rescaled linearly.** Its distribution is extremely skewed — the
median CVE sits near 0.0005 and 0.5 is already the far tail — so the scale is
anchored at 0.5 and saturates above it. A linear map would contribute ~0 for
every real finding.

### `unknown` is not `theoretical`

This distinction is load-bearing. `theoretical` is a **finding**: sources were
consulted and none knows of exploit code. `unknown` is an **admission**: nothing
capable of answering was configured.

Collapsing them would let an installation with no overlay and no template corpus
rate its entire estate as low-likelihood — "we found nothing" rendered as "there
is nothing", which is the most dangerous sentence a security tool can say. So
`unknown` applies no bound at all and falls back to reachability and EPSS.

Note that **CISA KEV alone does not make absence meaningful**: KEV only ever says
"yes, exploited", never "no exploit is known".

### Network exposure is this host, not `AV:N`

CVSS `AV:N` means the *vulnerability* is network-exploitable. It does not
mean this machine is on the internet. Likelihood now takes a separate
`network_exposure` of `external` / `internal` / `unknown` (#171):

| Signal | Source | Shift |
|---|---|---|
| RFC1918 / loopback / link-local | `address-space` | `internal` −20 |
| Operator `exposure_level=internet` | `operator-set` | `external` +20 |
| Operator `exposure_level=internal` | `operator-set` | `internal` −20 |
| Public IP, partner, unset | `none` | `unknown` 0 |

A public address is **not** `external`. That would treat "this IP is routable"
as "we observed it from outside". `unknown` scores as the model did before
#171, so missing data cannot be read as "nothing is exposed". The
`risk_explanation` names the source.

### Compensating controls are observed, not assumed

A WAF in front of a vulnerable service is only a likelihood input when
fingerprint (Phase 9.1) actually saw a CDN/WAF header on **that** host:port
([#173](https://github.com/onixus/Shapoclyack/issues/173)). The providers
are the ones `fingerprint.py` already names: Cloudflare, Akamai, Sucuri,
Imperva/Incapsula, CloudFront, Fastly. A CMS match is not a control.

The discount is small (−6) and named in `risk_explanation`, with the caveat
that seeing Cloudflare is **not** evidence it blocks this CVE. Several
vendors on one endpoint still count once. A missing `fingerprint.json`, a
disabled fingerprint stage, or a hit on a different port is `none` — no
shift. This is not a qualitative "minus a level" rule.

A **same-asset path** is the other half of #173, and only after
[P4.2](asset-identity.md). A local finding (`AV:L`/`AV:P`) on the same
asset as a network foothold (`AV:N` or `exposure`) gets +8, named in the
explanation. Two Moderates that would combine into a domain takeover are
still two Moderates — there is no step-model of privilege escalation or
lateral movement.

## Impact — how bad if it is?

Technical impact comes from the CVSS vector's impact metrics (`VC`/`VI`/`VA` on
v4, `C`/`I`/`A` on v3). Operator-set **asset criticality** then shifts it:

| Criticality | Shift | Reading |
|---|---|---|
| 4 | +20 | Crown jewels |
| 3 | +10 | |
| 2 | 0 | **Neutral** — an installation that never sets criticality gets the pure technical assessment |
| 1 | −10 | |
| 0 | −20 | Lab, scratch, disposable |

±20 points crosses level boundaries in both directions, which is the point. In
the previous model (`mvp-2`) criticality carried weight 0.05 over a 0–4 scale —
the entire difference between a lab box and a payment gateway was 0.5 points out
of 10, less than an operator would notice. Business context has to be able to
change the answer, or it is decoration.

Criticality is read from the Phase 7 asset inventory (`Asset.asset_criticality`,
set via `PATCH /api/assets/{id}`); without it, a severity/port heuristic fills in
and the explanation says `(heuristic)` rather than `(operator-set)`.

## Outputs

Per finding, on `GET /api/runs/{id}/vulnerabilities` and in ClickHouse:

| Field | Meaning |
|---|---|
| `risk_level` | The NIST verdict from Table I-2 |
| `likelihood`, `impact` | The two axes, as qualitative levels |
| `exploit_maturity` | The ladder above |
| `exploit_evidence` | Named sources behind the call, e.g. `["cisa-kev", "nuclei-match"]` |
| `exploit_verified_on_host` | A working check fired **against this host** |
| `contextual_score` | Continuous 0–10 sort key (geometric mean of the axes) |
| `risk_explanation` | One line stating the verdict and each axis's reasons |
| `cisa_decision` | SSVC-lite Track / Attend / Act / Immediate (unchanged) |

`risk_level` is the verdict; `contextual_score` exists because a table needs to
be sortable *within* a level. The geometric mean means neither axis can carry a
finding alone — a certain-but-harmless issue and a catastrophic-but-impossible
one both land low.

## Data sources

| Overlay | Variable | Default | Refresh |
|---|---|---|---|
| EPSS | `OCTO_EPSS_DATABASE` | `scanner/data/epss/epss-overlay.json` | `scripts/fetch-epss-db.sh` |
| CISA KEV | `OCTO_KEV_DATABASE` | `scanner/data/kev/kev-overlay.json` | `scripts/fetch-kev-db.sh` |
| Exploit maturity | `OCTO_EXPLOIT_DATABASE` | `scanner/data/exploit/exploit-overlay.json` | `scripts/fetch-exploit-db.py` |
| nuclei templates | `OCTO_NUCLEI_TEMPLATES_DIR` | `/usr/share/nuclei-templates` | baked into the image |

All are optional and hot-reloaded (`OCTO_ENRICHMENT_RELOAD_SECONDS`, default 60),
so a refresh CronJob reaches every replica without a restart. The committed
defaults are seed stubs.

```bash
python3 scripts/fetch-exploit-db.py
```

Builds the maturity overlay from the Exploit-DB CSV index (`proof_of_concept`)
and Metasploit exploit-module metadata (`weaponized`). It merges rather than
replaces, and **refuses to publish an empty result** — an empty overlay is not
merely stale, it flips every finding from `theoretical` to `unknown` and widens
the assessed risk of the whole estate.

### The nuclei caveat, stated plainly

A nuclei template for a CVE is **not necessarily an exploit**: many are
version-banner matches that prove presence without demonstrating exploitation.
So the corpus is treated as `proof_of_concept` evidence *with its source named*
(`nuclei-corpus`), never folded silently into a higher rung — and a template that
actually **matched** during the scan is recorded separately (`nuclei-match`,
`exploit_verified_on_host: true`), because then a working check ran against this
host rather than a list being consulted.

Every level carries the sources that justified it, so a reader can disagree with
the inference instead of having to trust it.

## What this model does not do

Each of these is a real gap with its own issue, not a silent approximation.

- **Reachability of the vulnerability is still the CVSS vector.** Host
  reachability is now a separate likelihood input
  ([#171](https://github.com/onixus/Shapoclyack/issues/171)): `external` /
  `internal` / `unknown`. A public IP is **not** `external`. RFC1918 is
  `internal` (`address-space`). Operator `exposure_level=internet` is
  `external` (`operator-set`). `unknown` does not shift the score.
- **Finding-open age is still not a risk input.** How long *we* have had the
  finding is SLA ([#145](https://github.com/onixus/Shapoclyack/issues/145)).
  CVE *publication* age is now a weak raise-only likelihood bump
  ([#172](https://github.com/onixus/Shapoclyack/issues/172)): never negative.
  Stale EPSS/KEV/exploit overlays are named in the explanation and on
  `/api/system`; they do not silently age the score down.
- **No modelled exploit chain.**
  [#173](https://github.com/onixus/Shapoclyack/issues/173) still does not
  turn two Moderates into a domain takeover. After
  [P4.2](asset-identity.md), a **local** finding (`AV:L`/`AV:P`) on the
  same asset as a network foothold (`AV:N` or an `exposure`) gets a named
  +8 likelihood raise — "same-asset path", not a step-model of privilege
  escalation or lateral movement. Compensating controls remain the other
  half of #173: a small named discount when fingerprint saw a CDN/WAF on
  the same host:port, never "WAF = safe".
- **No data-classification input in the score.**
  [#146](https://github.com/onixus/Shapoclyack/issues/146) stores
  `owner` / `business_service` / environment / data class / exposure on the
  asset (see [asset-context.md](asset-context.md)). Scoring uses the 0–4
  `asset_criticality` dial and, since #171, `exposure_level=internet|internal`
  as a named likelihood source. Environment and data class still do not move
  the verdict.
