# Shapoclyack UI/UX Redesign Roadmap

## Goal

Transform the web interface from a scanner-oriented dashboard into an enterprise Vulnerability Management and Exposure Management platform aligned with NIST vulnerability management lifecycle.

The UI must represent risk management workflows, not only scan execution.

Current product direction:

```
Asset Discovery
      |
      v
Risk Assessment
      |
      v
Prioritization
      |
      v
Remediation
      |
      v
Verification
      |
      v
Reporting
```

---

# Product principles

## 1. Risk first

The first question of the platform should be:

> What creates the biggest security risk right now?

not:

> What scan finished last?

## 2. Asset as the primary object

The main relationship becomes:

```
Asset
 |
 + Risk
 + Vulnerabilities
 + Software
 + Owner
 + Business context
 + Exposure
 + History
```

## 3. Workflow visibility

Every vulnerability must have a visible lifecycle, owner and remediation state.

---

# Current UI gaps

The gaps this roadmap was written against, kept for the record. Each is
struck where the current console closes it ([ui.md](ui.md) is the
current-state guide):

- ~~UI focuses on scans and findings instead of business risk~~ — `/` is the
  Risk Overview, the sidebar leads with risk workflows.
- ~~Asset context is insufficient~~ — owner, service, environment, data class,
  criticality and exposure on `/assets/view` ([asset-context.md](asset-context.md)).
- ~~Vulnerability lifecycle is not visible~~ — `/vulnerabilities/view` stepper.
- ~~Remediation workflow is missing~~ — `/remediation` board.
- ~~Executive/CISO view is missing~~ — Risk Overview plus the executive report
  ([reports-and-compliance.md](reports-and-compliance.md)).
- ~~Risk calculation is not explained~~ — `risk_explanation` on every finding
  ([risk-scoring.md](risk-scoring.md)).
- Business impact is disconnected from technical findings — partly: asset
  criticality and exposure move the score; environment and data class still do
  not.

---

# Target information architecture

```
Dashboard
 |
 +-- Risk Overview
 +-- Assets
 +-- Vulnerabilities
 +-- Remediation
 +-- Threat Intelligence
 +-- Attack Surface
 +-- Reports
 |
 +-- Operations
 |     +-- Scans
 |     +-- Jobs
 |     +-- Agents (the sensor fleet; the console entry is still named Agents)
 |     +-- Schedules
 |
 +-- Administration
       +-- Tenants
       +-- Users
       +-- RBAC
       +-- Integrations
```

---

# Phase P0 - Core VM experience

## Risk Dashboard

Delivered on `/` (Risk Overview, [ui.md](ui.md#risk-overview)). One metric
below is deliberately **not** on it: internet-exposed assets, because exposure
is operator-declared, not measured
([#171](https://github.com/onixus/Shapoclyack/issues/171)).

Metrics:

- Overall risk score
- Critical vulnerabilities
- SLA violations
- Internet exposed assets
- Assets without owners
- Risk trend
- Top business risks

Users:

- CISO
- Security manager
- SOC lead

Acceptance criteria:

- User understands current risk without opening scan results.
- Risk changes are visible over time.

---

## Asset-centric UI

Asset page:

```
Asset
 |
 + Owner
 + Business service
 + Criticality
 + Software inventory
 + Vulnerabilities
 + Exposure
 + History
```

Required features (delivered on `/assets` and `/assets/view`,
[#136](https://github.com/onixus/Shapoclyack/issues/136) / [#146](https://github.com/onixus/Shapoclyack/issues/146)):

- ownership management;
- business context;
- vulnerability aggregation;
- software inventory view;
- historical changes.

---

## Vulnerability Center

Delivered on `/vulnerabilities` ([ui.md](ui.md#vulnerability-center)).

Required fields:

- CVE
- CWE
- CVSS
- EPSS
- KEV status
- affected assets
- owner
- SLA
- remediation status
- evidence
- detection source
- first/last seen

---

## Vulnerability lifecycle

Delivered ([vulnerability-lifecycle.md](vulnerability-lifecycle.md)):

```
OPEN
 |
ACKNOWLEDGED
 |
PLANNED
 |
FIXING
 |
VERIFYING
 |
CLOSED
```

---

# Phase P1 - Enterprise workflows

## Remediation Board

Delivered on `/remediation` ([ui.md](ui.md#remediation-board)), with one
departure from the sketch below: the columns are the lifecycle states
(`OPEN → ACKNOWLEDGED → PLANNED → FIXING → VERIFYING → CLOSED`) and accepted
risk is a badge on the card, not a "Waiting exception" column. The original
sketch:

```
New
 |
Assigned
 |
In progress
 |
Waiting exception
 |
Verification
 |
Closed
```

Features:

- owner assignment — done;
- SLA tracking — done;
- comments — done;
- evidence attachment — **not implemented** (evidence is the last observing run; file attachments are out of scope);
- exception handling — done (request/approve workflow, [#348](https://github.com/onixus/Shapoclyack/issues/348)).

---

## Ticket integration

Support:

- Micro Focus SMAX — link only (`ticket_system=smax`); no transport opens tickets there
- Jira — link, native create and status sync
- ServiceNow — link, native create and status sync
- DefectDojo — link, native create and status sync

Ticket view (**not implemented** as a page: the console shows the link and
sync state on the finding card, and ticket views beyond that are still
planned):

- linked vulnerability;
- affected assets;
- owner;
- due date;
- SLA status;
- remediation evidence.

---

## Risk explanation

Delivered as `risk_explanation` on every finding
([risk-scoring.md](risk-scoring.md)); the shape below is the sketch, the real
model is NIST SP 800-30 likelihood × impact rather than a sum.

Example:

```
Risk score

CVSS             9.8
EPSS             92%
KEV              YES
Internet         YES
Asset critical   HIGH

Final risk       CRITICAL
```

---

# Phase P2 - Advanced Exposure Management

## Attack Surface

Delivered in part on `/exposure` and `/attack-surface`
([#139](https://github.com/onixus/Shapoclyack/issues/139)):

- operator-declared exposure inventory (not a scan internet map — [#171](https://github.com/onixus/Shapoclyack/issues/171));
- existing hostname → IP → port → service graph of one scan.

Still open: attack paths ([#173](https://github.com/onixus/Shapoclyack/issues/173)).

---

## Threat Intelligence

Delivered on `/threats` ([#139](https://github.com/onixus/Shapoclyack/issues/139)):
open tracked findings on CISA KEV, with exploit maturity from the last
observation. Indicators beyond KEV/EPSS/maturity are still overlay data on
the finding card.

---

## MSSP view

Delivered on `/tenants` ([#139](https://github.com/onixus/Shapoclyack/issues/139)):
per-customer estate risk, open work, SLA, KEV, unowned assets. Scoped to the
caller's tenants so a customer operator cannot see the rest of the portfolio.

---

# Role based views

## Analyst

Focus:

- vulnerabilities;
- assets;
- evidence;
- remediation.

## Operator

Focus:

- scans;
- sensors (the Agents page, `/agents`);
- jobs;
- schedules.

## CISO

Focus:

- risk;
- trends;
- SLA;
- compliance.

---

# Frontend implementation backlog

## Navigation

- ~~redesign application shell~~ — done: grouped sidebar, `Ctrl/⌘-K`
  search-and-jump, live operations strip (see [ui.md](ui.md), "Application
  shell");
- ~~introduce role based menus~~ — done: entries below the signed-in role are
  hidden (presentation only, the API enforces);
- ~~separate operations and security workflows~~ — done: risk workflows first,
  then the external and internal scanning surfaces (`/scans/external`,
  `/scans/internal`), then shared operations and administration.

## Components

Create reusable components:

- RiskScoreCard;
- AssetRiskTable;
- VulnerabilityTimeline;
- SLAIndicator;
- RemediationBoard;
- EvidenceViewer.

---

# Backend dependencies

Required APIs:

- risk score API;
- vulnerability lifecycle API;
- SLA model;
- remediation state model;
- ticket integration API;
- business context API.

---

# Design system requirements

Create common patterns:

- severity colors;
- risk badges;
- status indicators;
- timeline components;
- tables with filtering;
- export patterns.

---

# Success criteria

The redesign is complete when a security manager can answer:

1. What is our current cyber risk?
2. Which assets create the biggest risk?
3. Who owns remediation?
4. Which vulnerabilities violate SLA?
5. Did remediation actually fix the problem?

without starting a scan or reading raw reports.
