# Report factory and compliance mapping

Two features that answer the same question from opposite ends: *what do we tell
the customer?* The report factory renders and delivers the document; the
compliance mapping supplies the part of it an auditor reads.

Scope note up front, because it governs everything below: **this platform does
not certify compliance**. It reports which controls its own evidence can speak
to, and what that evidence says. A control it cannot observe is absent from the
catalogue or reported as *not assessed* — never as a pass.

---

## Compliance mapping

### How a control gets a status

Findings and estate facts are classified into a small closed vocabulary of
**signals** (`api/services/compliance/signals.py`), and each framework's
catalogue (`frameworks.py`) is written against that vocabulary rather than
against CVEs. Adding a framework is a catalogue entry; fixing how a weak-TLS
finding is recognised fixes it for every framework at once.

| Signal | Raised by |
|---|---|
| `unpatched_cve` | An open finding carrying a CVE id |
| `overdue_remediation` | An open finding past its SLA deadline |
| `known_exploited` | A finding on the CISA KEV catalogue |
| `internet_exposed_finding` | A finding whose service was observed as internet-facing (#171) |
| `weak_cryptography` | TLS/certificate/cipher findings |
| `insecure_protocol` | Telnet, FTP, legacy SMB, cleartext management |
| `default_or_weak_credentials` | Default, anonymous or absent authentication |
| `misconfiguration` | Directory listing, debug endpoints, exposed panels, missing headers |
| `exposed_admin_service` | An administrative or datastore port observed open |
| `information_disclosure` | Version, banner and diagnostic leakage |
| `unowned_asset` | An asset with no `owner_email` |
| `unclassified_asset` | An asset with no `environment` and no `data_classification` |
| `stale_asset` | An asset the registry still carries but scans no longer see |
| `unassessable_software` | Installed packages the advisory matcher returned `unknown` for |

A control names the signals that fail it — either **any-of** (`signals`) or a
**conjunction** (`combinations`, every signal in the group on the *same* piece of
evidence) — and a `severity_floor` below which a finding is evidence but not a
failure — PCI DSS 6.3.3 is written about critical
and high vulnerabilities, and a control that went red on an informational
banner would be red in every tenant forever and therefore read by nobody.

The conjunctions are not a refinement, they are what keeps the page usable.
PCI DSS 1.2.1, CIS 4.6 and ISO A.8.20 are written about an administrative
service *reachable from an untrusted network*; failing them on any open SSH port
would make them red in every estate that exists. PCI 11.3.2 is about external
scanning, and without the conjunction it is an exact duplicate of 11.3.1. Note
that a public IP address is **not** an exposure observation (see #171): the
pairing needs `network_exposure=external`, which comes from the finding or from
an operator's `exposure_level` decision.

Three statuses:

* **failed** — at least one piece of evidence at or above the floor;
* **passed** — the control's data source exists and nothing failed it;
* **not assessed** — the data source does not exist in this tenant (no assets,
  no endpoint inventory, no findings *at all*). Excluded from the score, so an
  empty estate scores nothing rather than 100%. A tenant whose findings have all
  been closed is assessed and passing, not unassessed: it was looked at.

Only **open** findings count. A closed finding is evidence that the control
worked. **Accepted risk** (a live `exception_until`) is reported per control as
`accepted_count` but does not fail it: the framework's own risk-acceptance
process is what covers it, and hiding the acceptance would be worse than either.

### Frameworks

| Framework | Catalogue covers | Deliberately excluded |
|---|---|---|
| PCI DSS 4.0 | 1.2.1, 2.2.4, 2.2.7, 4.2.1, 6.3.3, 6.4.1, 8.3.1, 11.3.1, 11.3.2, 12.5.1 | Cardholder-data scoping, segmentation testing, policy and personnel requirements |
| CIS Controls v8 | 1.1, 2.1, 3.10, 4.1, 4.6, 5.2, 7.1, 7.3, 7.7, 12.2, 13.1 | Data recovery, awareness, incident response, penetration testing |
| ISO/IEC 27001:2022 | A.5.9, A.5.10, A.8.5, A.8.8, A.8.9, A.8.19, A.8.20, A.8.21, A.8.23, A.8.24 | Organizational, people and physical controls (A.5 beyond inventory, A.6, A.7) |

`coverage_score` is the share of **assessed** controls that pass. It is not a
percentage of the standard, and the API returns the framework's `scope_note`
alongside it so a console or a report cannot present it as one.

### API

| Route | Role | Purpose |
|---|---|---|
| `GET /api/compliance/frameworks` | viewer | Catalogue list with scope notes |
| `GET /api/compliance/{framework_id}` | viewer | Posture: per-control status, counts, sample evidence |
| `GET /api/compliance/{framework_id}/controls/{control_id}` | viewer | Every piece of evidence behind one control |

A platform admin gets **no** cross-tenant view here, unlike the vulnerability
lists: a control status is a statement about one organisation's estate, and
merging three customers' findings would produce a number true of nobody.

---

## Report factory

### What a report is

`api/services/reports/content.py` builds a plain dict; the renderers
(`render.py`) turn it into PDF, HTML or JSON. The JSON export is therefore *the
same report* as the PDF rather than a second implementation of it — an MSSP
piping JSON into its own portal and a customer reading the attached PDF must not
be able to reach different conclusions about the same month.

Three kinds:

| Kind | Sections | For |
|---|---|---|
| `executive` | KPIs, risk trend, severity, SLA, compliance scores | The customer's management report |
| `technical` | KPIs, severity, top findings, asset coverage | The team doing the work |
| `compliance` | KPIs plus the full control table for one framework | The auditor |

An executive report carries every framework's score but no control tables; only
a compliance report carries the tables. A thirty-page control appendix on a
two-page summary is how a report stops being read.

Every number comes from the tracked-finding tables, the asset registry and the
compliance engine — never from a run directory. A report about a quarter has to
render after that quarter's runs were pruned by retention.

### Branding

One row per tenant (`PUT /api/reports/branding`, admin): organisation name,
primary and accent colour, a base64 PNG logo, footer text, contact email. The
logo is stored as bytes rather than a path or a URL — a path stops resolving on
whichever replica renders, and a URL would make the renderer fetch from the
network at render time, which is an SSRF sink reached by editing a settings
field. Colours and the PNG magic number are validated on write, so a mistake
fails the operator's request rather than the 03:00 render on the first of the
month.

### Templates, schedules and delivery

* **Templates** (`/api/reports/templates`, read `viewer`, write `operator`) —
  kind, framework, and per-section switches. A switch works in both directions:
  turning `top_findings` on in an executive template renders it. Deleting a
  template a schedule still points at is refused with `409` — the row cascades,
  so an operator would otherwise silently destroy an admin's recurring customer
  delivery; delete the schedule first.
* **Schedules** (`/api/reports/schedules`, **admin**) — a cron expression in
  UTC, an output format, and recipients. Admin because a schedule sends this
  tenant's findings to an address outside the installation on a recurring
  basis; the same bar webhook subscriptions use.
* **Delivery** — `email` through the configured SMTP relay with the report
  attached, or `webhook` through the same SSRF-validated, DNS-pinned,
  no-redirect wire the event webhooks use. The target is re-validated on every
  send: a hostname that resolved publicly when the schedule was written can
  resolve to link-local by the time it fires. When `OCTO_REPORT_SMTP_STARTTLS`
  is on and the relay refuses it, the message is **not sent** and the recipient's
  entry says why: continuing would put the relay password and the customer's
  whole vulnerability report on the wire in cleartext. An installation whose
  relay genuinely cannot do TLS sets the flag to `false` and owns that.

In a `PATCH`, a `null` field means "leave it alone". Clearing recipients is
`[]`, which is a thing an operator can mean; `null` is what a form sends for a
field it did not touch, and treating it as "deliver to nobody" would silently
mute a customer's report.

Each generated report records **one delivery entry per recipient** — transport,
target, status, error. "Sent" is not true when three of four bounced, and the
one that did not arrive is exactly the one somebody has to be told about.

### The dispatcher

`api/services/reports/dispatcher.py` is the scan-schedule dispatcher's twin: a
daemon thread in every replica, a Postgres advisory lock so only one acts, a
poll interval, a crash-restart loop.

One difference matters. The scan dispatcher relies on job idempotency keys to
make a brief double-run harmless; there is no equivalent for a report, because
the same PDF cannot be un-sent to a customer. So the schedule's `next_run_at` is
advanced **before** the render, in its own transaction. A replica that dies
mid-render skips that occurrence rather than repeating it — a customer noticing
a missing monthly report is a support ticket, while a customer receiving two
contradictory ones is a trust problem.

A failed render is recorded as a `failed` report row with the error on it, and
the schedule still advances. Leaving `next_run_at` in the past would retry every
tick: a report per poll interval, to every recipient, for as long as the failure
lasts.

### Storage and retention

Rendered bytes live under `output_dir/reports/<tenant>/<report_id>.<ext>`; the
row keeps a path relative to `output_dir`. The download endpoint **re-derives**
the path from the row's tenant, id and format rather than trusting the stored
string — a value read from the database and joined onto a directory is how a
path traversal reaches a file server.

`OCTO_REPORT_RETENTION_DAYS` (default 365) prunes old reports and their files
from the dispatcher's hourly sweep. A year, because "the quarterly report you
sent in March" is a thing customers ask for and the scan-retention window would
not cover it.

### API

| Route | Role | Purpose |
|---|---|---|
| `GET/PUT /api/reports/branding` | viewer / **admin** | Per-tenant report identity |
| `GET/POST /api/reports/templates`, `PATCH`/`DELETE /{id}` | viewer / operator | Report definitions |
| `GET/POST /api/reports/schedules`, `PATCH`/`DELETE /{id}` | viewer / **admin** | Cron delivery |
| `POST /api/reports/generate` | operator | Render one now, from a template or ad hoc |
| `GET /api/reports`, `GET /{id}` | viewer | Generated reports and their delivery trail |
| `GET /api/reports/{id}/download` | viewer | The bytes |
| `DELETE /api/reports/{id}` | operator | Remove a report and its file |

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_REPORTS_ENABLED` | `true` | Register `/api/reports`. Off means no report API at all |
| `OCTO_REPORT_DISPATCH_ENABLED` | `true` | Run the scheduled-report loop in *this* replica |
| `OCTO_REPORT_DISPATCH_INTERVAL_SECONDS` | `60` | Poll interval for due schedules (floored at 5) |
| `OCTO_REPORT_RETENTION_DAYS` | `365` | Age past which generated reports and their files are pruned; `0` keeps them |
| `OCTO_REPORT_SMTP_HOST` | *(empty)* | Relay for emailed reports. Empty means email recipients are recorded as `skipped`, with the reason |
| `OCTO_REPORT_SMTP_PORT` | `25` | Relay port |
| `OCTO_REPORT_SMTP_FROM` | *(empty)* | Envelope sender; required alongside the host |
| `OCTO_REPORT_SMTP_USERNAME` / `OCTO_REPORT_SMTP_PASSWORD` | *(empty)* | Relay credentials; login is attempted only when a username is set |
| `OCTO_REPORT_SMTP_STARTTLS` | `true` | Require an encrypted connection. A relay that refuses fails that recipient rather than downgrading to cleartext |
| `OCTO_REPORT_SMTP_TIMEOUT_SECONDS` | `20` | Per-message budget |

The report relay is deliberately separate from the scanner's alert SMTP
(`OCTO_SMTP_*`, [operations.md](operations.md)): an alert goes to an operations
channel and a report goes to a customer, and one installation routinely needs
different senders for the two.

---

## What is not here

* **No scheduled *compliance evidence collection*.** The posture is computed on
  read from current state; there is no signed, immutable point-in-time evidence
  package an auditor could archive. The compliance report is the closest thing,
  and it is a document, not an attestation.
* **No control ownership or remediation plan per control.** Findings have
  owners; controls do not.
* **No custom frameworks.** The catalogues are code — a per-tenant catalogue
  would let a tenant define the standard it passes.
