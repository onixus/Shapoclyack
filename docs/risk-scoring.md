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
| **Network exposure** | this host: RFC1918 / operator-set / operator-declared scan surface / explicit | ±20 on likelihood after bounds. `unknown` is a no-op |
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
| Operator-declared scan surface `external` | `scan-surface` | `external` +20 |
| Operator-declared scan surface `internal` | `scan-surface` | `internal` −20 |
| Public IP, partner, unset | `none` | `unknown` 0 |

A public address is **not** `external`. That would treat "this IP is routable"
as "we observed it from outside". `unknown` scores as the model did before
#171, so missing data cannot be read as "nothing is exposed". The
`risk_explanation` names the source.

The scan surface counts only when the **operator declared it** on the scan
request (`StartScanRequest.surface`, stored on the job as
`scan_options.surface` with `scan_options.surface_source = "operator"`). That
is the same class of evidence as `exposure_level` on the asset — a person
saying which network this scan faces — and it ranks just below it, because it
describes the whole scan rather than this one host. The surface the server
*derives* from the targets (`surface_source = "derived"`) is ignored here: it
is the address-space rule wearing a different hat, and feeding it back would
launder a routing fact into an observation. `mixed` names both answers at once,
so it is no evidence either. Only the tracked findings a run produces read the
job (`api/services/vulnerabilities.py`); the inventory-driven endpoint software
findings have no job behind them and are unaffected.

### Compensating controls are observed, not assumed

A WAF in front of a vulnerable service is only a likelihood input when
fingerprint (Phase 9.1) actually saw a CDN/WAF header on **that** host:port
([#173](https://github.com/onixus/Shapoclyack/issues/173)). The providers
are the six fingerprint shipped with: Cloudflare, Akamai, Sucuri,
Imperva/Incapsula, CloudFront, Fastly (`CDN_WAF_PROVIDERS`). The
[fingerprint catalogue](web-fingerprinting.md) knows more CDN/WAFs (Qrator,
DDoS-Guard, Variti, Azure Front Door, …) and reports them, but they earn no
discount until the risk model is changed to say so; a medium-confidence match
(a Barracuda cookie, an F5 ASM block page) does not even reach the `cdn_waf`
list. Imperva is matched by its cookie *names* — a cookie whose value merely
contains `incap_ses` used to count and no longer does. An endpoint whose answer was a redirect off its
address has an empty `cdn_waf`: a CDN in front of the name it points at is
not in front of the address. A CMS match is not a
control.

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
  `external` (`operator-set`), and an operator-declared scan surface is
  `scan-surface`; a derived one is nothing. `unknown` does not shift the score.
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

## Shared operation context and recorded assessments (#453)

`api.services.risk_context` supplies one tenant-scoped batch to the run API,
scan tracker and ClickHouse transform. Registered asset identities, IP/FQDN
identifiers, operator criticality/exposure and the operator-declared job surface
are read once per operation. Operator criticality **0–4**, including zero,
continues to override finding values. Several IPs/FQDNs already registered to
one asset share foothold correlation by `asset_id`; the builder does not perform
DNS lookup or merge identities. Both identifier and asset rows are tenant-filtered.
An explicit foreign-tenant asset ID is unresolved. Without a registered identity,
correlation is an explicitly named tenant-qualified host fallback; it cannot join
separate addresses. CDN/WAF remains evidence for the exact observed host:port,
never a protection inherited by every listener of an asset.

The formula and `nist-1` version are unchanged. Its clock can now be supplied
explicitly, so CVE age and intelligence freshness use the same evaluation time
for an operation. The loaded EPSS/KEV/exploit/Nuclei-CVE intelligence has a content
hash computed once when its scorer is loaded. Input observation, context and data
hashes are distinct. Missing criticality remains heuristic; missing exposure
remains unknown unless the existing scorer has explicit/operator/declared-surface
or private-address evidence. A missing context never asserts a complete snapshot.

The tracker captures immutable `run_risk_assessments` in the same transaction as
its fold. The key is `(tenant_id, run_id, execution_id, observation_digest)`;
`execution_id` names the accepted server publication, not the tenant-chosen run
ID. Concurrent writers/replays of that same publication reuse the first committed
receipt. A different accepted job/publication reusing the same run ID and exactly
the same observation bytes captures its own current operator context/time.
Older execution receipts remain immutable.
No existing rows are backfilled or recalculated. The
receipt contains all shared scores/explanations and the captured time,
model/data/context versions, origin/completeness and asset inputs. The latest
scan receipt is also retained on the tracked finding and in its observation event;
its finding key, assignment, state, deadline and exceptions keep their existing
lifecycle rules. Editing asset context or requesting current scores does not
rewrite these records.

`GET /api/runs/{id}/vulnerabilities?assessment_mode=historical` is the default and
returns the receipt of the actual server-published folder generation. Its job and
publication marker are matched to tenant/run/accepted receipt ownership, rather
than selecting the newest queued job. ClickHouse uses the exact publisher job
envelope (bound to the accepted receipt in PostgreSQL); ambiguous executions
are refused rather than selecting a newer assessment. `assessment_mode=current` explicitly computes a
read-only current assessment. `risk_assessment.mode`, `evaluated_at`, versions,
`inputs`, source and `complete` distinguish the two. Old runs with no receipt
return `legacy-current` (their old operator inputs cannot be reconstructed).
Without PostgreSQL the mode is `uncaptured-current`, context is unavailable and
`complete=false`; configured database errors remain errors, not silent fallback.
An unbound legacy direct registration computes `uncaptured-current`; it cannot
fabricate an accepted execution or immutable historical receipt. A new successful
server publication owns a `risk_assessment_contract` marker,
initially on its durable publication intent and retained on its tenant/job/run
binding when the outbox row closes. Any existing accepted execution receipt also preserves its
obligation after job retention. If such a run has no matching receipt,
the API labels its provisional current result `pending-current` and incomplete;
ClickHouse ingestion retries instead of storing it as historical. Legacy NULL
markers impose no new requirement. Client archive/payload flags cannot set this
obligation or provide trusted operator context.

The broker may deliver an archive before the tracker projection completes.
New publications therefore verify that their canonical receipt exists before
closing their durable intent; a failed capture remains retryable under the
existing publication lease/backoff. Successful empty scans capture an empty
receipt. Failed/cancelled archives add no successful-assessment obligation.
The order and ownership of the other post-publication projections is unchanged.
The tracker validates the server-written tenant/job/publication folder generation
before mutations and before commit. A replaced folder is an explicit retry and
rolls its fold back, preserving the accepted intent; it is not recorded under an
older execution. An already captured old execution can complete its outbox even
after a newer publication replaced the folder.

ClickHouse keeps its existing IPv4 row/key contract; FQDN-only observations are
still excluded from that projection while participating in batch asset
correlation. Its appended `risk_assessment` String holds the complete JSON score
and provenance used by the API/tracker, including explanations. It remains a
latest-value analytics projection with the existing ReplacingMergeTree key, not
the immutable assessment journal. Old ClickHouse rows have an empty receipt,
never fabricated provenance. On an existing deployment an administrator must
apply [`scripts/migrate-clickhouse-risk-context.sql`](../scripts/migrate-clickhouse-risk-context.sql)
before rolling out ingest workers. Runtime users need only SELECT+INSERT; no
ALTER grant or automatic history rewrite is required. Missing schema is a visible
migration error; ingestion never drops provenance to make an insert succeed.

The batch context costs at most three PostgreSQL SELECTs (identifiers, assets,
job surface), independent of observation count. A captured historical consumer
needs one receipt read. An uncaptured historical read additionally checks its
trusted obligation. The tracker still performs its existing per-finding identity,
SLA, event and verification work; these query bounds apply to context loading,
not a claim that the entire tracker operation takes constant time.

Evidence adapters accept tenant-validated `asset_id` and preserve each input's
source/CVSS/finding class/confirmation evidence. A local endpoint-software or
retro-match observation does not become network exposure merely by joining an
asset; same-asset path context needs a separate actual foothold observation.
This context contract does not implement all identity/evidence work of #449 or
change that observer's authoritative proofs.

Validation: `tests/test_risk_context.py` covers real PostgreSQL tenant/asset
correlation, multi-IP/FQDN, zero criticality, declared/unknown exposure, exact
endpoint CDN/WAF, consumer parity, historical/current separation, concurrent
capture, RLS append/read and UPDATE refusal, constant context query counts,
legacy/new publication obligations, two jobs reusing identical run ID/bytes,
wrong-generation rollback, and actual ClickHouse old-schema migration
plus SELECT+INSERT-only roundtrip. `tests/test_scan_risk_criticality.py` retains
its existing identity/owner/SLA/exception regression coverage. These are query
budget and correctness proofs, not a production latency benchmark.
