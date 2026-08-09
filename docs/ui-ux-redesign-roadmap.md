# Shapoclyack UI/UX Redesign Roadmap

## Goal

Transform the web interface from a scanner-oriented dashboard into an enterprise Vulnerability Management and Exposure Management platform aligned with NIST vulnerability management lifecycle.

Current product evolution:

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

The UI must represent risk management workflows, not only scan execution.

---

# Current gaps

## Main issues

- UI focuses on scans and findings instead of business risk.
- Asset context is insufficient.
- Vulnerability lifecycle is not visible.
- Remediation workflow is missing.
- Executive/CISO view is missing.
- Risk calculation is not explained to users.

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

## 1. Risk Dashboard

Create executive dashboard:

Metrics:

- Overall risk score
- Critical vulnerabilities
- SLA violations
- Internet exposed assets
- Assets without owners
- Risk trend

Users:

- CISO
- Security manager
- SOC lead

---

## 2. Asset-centric UI

Move from finding-first to asset-first model.

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

---

## 3. Vulnerability Center

Replace simple findings list with lifecycle management.

Required fields:

- CVE
- CVSS
- EPSS
- KEV status
- affected assets
- owner
- SLA
- remediation status
- evidence

---

## 4. Finding lifecycle

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

Add Kanban workflow:

Columns:

- New
- Assigned
- In progress
- Waiting exception
- Verification
- Closed

---

## Ticket integration

UI support for:

- Micro Focus SMAX
- Jira
- ServiceNow
- DefectDojo

Ticket view:

- linked vulnerability
- owner
- due date
- SLA status
- remediation evidence

---

## Risk explanation

Every critical finding should explain:

```
Risk score
=
CVSS
+
EPSS
+
Exposure
+
Asset criticality
+
Business impact
```

---

# Phase P2 - Advanced exposure management

## Attack Surface

Add:

- internet exposure map
- attack paths
- vulnerable services
- external risk view

---

## Threat Intelligence

Integrate:

- KEV
- exploit intelligence
- threat indicators
- active exploitation signals

---

## MSSP view

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

# Role-based views

## Analyst

Focus:

- vulnerabilities
- assets
- evidence
- remediation

## Operator

Focus:

- scans
- agents
- jobs
- schedules

## CISO

Focus:

- risk
- trends
- SLA
- compliance

---

# Implementation backlog

## Frontend

- redesign navigation
- create risk dashboard components
- redesign asset details
- redesign vulnerability details
- add lifecycle components
- add remediation workflow UI

## Backend dependencies

- risk score API
- vulnerability lifecycle API
- SLA model
- remediation state model
- ticket integration API

---

# Success criteria

The UI redesign is complete when a security manager can answer:

1. What is our current cyber risk?
2. Which assets create the biggest risk?
3. Who owns remediation?
4. Which vulnerabilities violate SLA?
5. Did remediation actually fix the problem?

without starting a scan or reading raw reports.
