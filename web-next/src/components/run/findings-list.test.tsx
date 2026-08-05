import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { FindingsList } from "@/components/run/findings-list";
import type { Vulnerability } from "@/lib/api";
import type { Severity } from "@/lib/run-data";

function vuln(overrides: Partial<Vulnerability>): Vulnerability {
  return {
    host: "10.0.0.1",
    port: "443",
    cve: "CVE-2021-44228",
    cvss: 10,
    cvss4: null,
    cvss4_vector: null,
    cvss4_severity: null,
    severity: "critical",
    script_id: null,
    country: null,
    city: null,
    country_iso: null,
    finding_class: "version_cve",
    confidence: 90,
    requires_confirmation: false,
    epss: 0.97,
    in_kev: true,
    contextual_score: 8.4,
    cisa_decision: "Immediate",
    risk_explanation: "CVSS 10 · EPSS 0.97 (scanner) · in CISA KEV (scanner)",
    ...overrides,
  };
}

function grouped(items: Vulnerability[]): Record<Severity, Vulnerability[]> {
  const empty = { critical: [], high: [], medium: [], low: [], unknown: [] } as Record<
    Severity,
    Vulnerability[]
  >;
  for (const item of items) {
    empty[(item.severity as Severity) ?? "unknown"].push(item);
  }
  return empty;
}

const NOT_TRUNCATED = { isTruncated: false, shown: 0, total: 0 };

describe("FindingsList prioritisation", () => {
  it("shows the risk score, decision, and explanation for a scored finding", () => {
    render(<FindingsList grouped={grouped([vuln({})])} truncation={NOT_TRUNCATED} />);
    expect(screen.getByText("risk 8.4 · Immediate")).toBeInTheDocument();
    expect(screen.getByText(/EPSS 0.97 \(scanner\)/)).toBeInTheDocument();
    expect(screen.getByText("KEV")).toBeInTheDocument();
    expect(screen.queryByText("unconfirmed")).not.toBeInTheDocument();
  });

  it("marks a finding the scanner could not confirm", () => {
    render(
      <FindingsList
        grouped={grouped([
          vuln({
            finding_class: "keyword_cve",
            confidence: 40,
            requires_confirmation: true,
            in_kev: false,
            cisa_decision: "Attend",
            contextual_score: 4.1,
            risk_explanation: "CVSS 10 · unconfirmed keyword_cve (scanner confidence 40%)",
          }),
        ])}
        truncation={NOT_TRUNCATED}
      />,
    );
    expect(screen.getByText("unconfirmed")).toBeInTheDocument();
    expect(screen.getByText("risk 4.1 · Attend")).toBeInTheDocument();
  });

  it("renders a CVE-less exposure finding by its script id", () => {
    render(
      <FindingsList
        grouped={grouped([
          vuln({
            cve: "",
            script_id: "pulse:exposure:445:eternalblue-smbv1-rce",
            severity: "medium",
            finding_class: "exposure",
            requires_confirmation: true,
            in_kev: false,
            risk_explanation: "CVSS 5 · unconfirmed exposure (scanner confidence 45%)",
          }),
        ])}
        truncation={NOT_TRUNCATED}
      />,
    );
    expect(screen.getByText(/pulse:exposure:445:eternalblue-smbv1-rce/)).toBeInTheDocument();
  });
});
