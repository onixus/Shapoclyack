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

# GitHub work breakdown

Implementation is tracked under [Epic #134](https://github.com/onixus/Shapoclyack/issues/134).

## Frontend

| Priority | Issue | Scope |
|---|---|---|
| P0 | [#135](https://github.com/onixus/Shapoclyack/issues/135) | Risk Dashboard |
| P0 | [#136](https://github.com/onixus/Shapoclyack/issues/136) | Asset-centric security view |
| P0 | [#137](https://github.com/onixus/Shapoclyack/issues/137) | Vulnerability Center and lifecycle UI |
| P1 | [#138](https://github.com/onixus/Shapoclyack/issues/138) | Remediation workflow and integrations |
| P2 | [#139](https://github.com/onixus/Shapoclyack/issues/139) | Exposure Management and MSSP views |

## Backend dependencies

| Priority | Issue | Scope | Enables |
|---|---|---|---|
| P0 | [#144](https://github.com/onixus/Shapoclyack/issues/144) | Risk scoring engine and API | #135, #137 |
| P0 | [#145](https://github.com/onixus/Shapoclyack/issues/145) | Vulnerability lifecycle and SLA model | #137, #138 |
| P1 | [#146](https://github.com/onixus/Shapoclyack/issues/146) | Asset business context and risk enrichment | #135, #136 |

Dependency order:

```
#144 Risk Engine --------+----> #135 Risk Dashboard
                         +----> #137 Vulnerability Center

#145 Lifecycle + SLA ----+----> #137 Vulnerability Center
                         +----> #138 Remediation Workflow

#146 Asset Context ------+----> #136 Asset View
                         +----> #135 Risk Dashboard

#135 + #136 + #137 + #138 ----> #139 Exposure/MSSP
```

---

# Phase P0 - Core VM experience

## Risk Dashboard — #135

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

Backend dependencies: #144, #146.

---

## Asset-centric UI — #136

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

Required features:

- ownership management;
- business context;
- vulnerability aggregation;
- software inventory view;
- historical changes.

Backend dependency: #146.

---

## Vulnerability Center — #137

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

Backend dependencies: #144, #145.

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

The authoritative state machine and SLA behavior are implemented by #145.

---

# Phase P1 - Enterprise workflows

## Remediation Board — #138

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

Backend dependency: #145.

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

Risk calculation and explanation are implemented by #144.

---

# Phase P2 - Advanced Exposure Management

## Attack Surface — #139

Add:

- internet exposure map;
- attack paths;
- vulnerable services;
- external risk view.

---

## Threat Intelligence — #139

Integrate:

- KEV;
- exploit intelligence;
- active exploitation signals;
- threat indicators.

---

## MSSP view — #139

Multi-tenant dashboard:

```
Customer A
 Risk 82%

Customer B
 Risk 45%

Customer C
 Risk 91%
```

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

# Backend contract requirements

Required APIs:

- risk score API (#144);
- vulnerability lifecycle API (#145);
- SLA model (#145);
- remediation state model (#145);
- ticket integration API (#138 backend scope);
- business context API (#146).

API contracts must remain tenant-scoped and return enough explanation data for the UI to show why a score, SLA state or remediation status exists rather than merely displaying an opaque value.

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

# Delivery order

Recommended implementation sequence:

1. #144 Risk Engine API
2. #145 Vulnerability lifecycle + SLA
3. #146 Asset business context
4. #136 Asset-centric view
5. #137 Vulnerability Center
6. #135 Risk Dashboard
7. #138 Remediation workflow
8. #139 Exposure Management / MSSP

This order deliberately builds the domain model before polishing screens that depend on it. Otherwise the frontend becomes a museum of mocked cards waiting for data contracts.

---

# Success criteria

The redesign is complete when a security manager can answer:

1. What is our current cyber risk?
2. Which assets create the biggest risk?
3. Who owns remediation?
4. Which vulnerabilities violate SLA?
5. Did remediation actually fix the problem?

without starting a scan or reading raw reports.
