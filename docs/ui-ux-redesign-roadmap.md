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

- UI focuses on scans and findings instead of business risk.
- Asset context is insufficient.
- Vulnerability lifecycle is not visible.
- Remediation workflow is missing.
- Executive/CISO view is missing.
- Risk calculation is not explained.
- Business impact is disconnected from technical findings.

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
 |     +-- Agents
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

Create executive dashboard.

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

Replace simple findings list with lifecycle management.

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

Implement visible workflow:

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

Kanban workflow:

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

- owner assignment;
- SLA tracking;
- comments;
- evidence attachment;
- exception handling.

---

## Ticket integration

Support:

- Micro Focus SMAX
- Jira
- ServiceNow
- DefectDojo

Ticket view:

- linked vulnerability;
- affected assets;
- owner;
- due date;
- SLA status;
- remediation evidence.

---

## Risk explanation

Every critical finding must explain why it has priority.

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
- agents;
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

- redesign application shell;
- introduce role based menus;
- separate operations and security workflows.

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
