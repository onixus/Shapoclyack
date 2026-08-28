import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RunMetrics } from "@/components/run/run-metrics";

const NO_HOSTS: never[] = [];
const NO_PORTS: never[] = [];

describe("RunMetrics vulnerability count", () => {
  it("names the unconfirmed share of the headline total", () => {
    render(
      <RunMetrics
        summary={{ potential_vulnerabilities: 21, unconfirmed_findings: 18 }}
        hosts={NO_HOSTS}
        ports={NO_PORTS}
        vulnCount={21}
      />,
    );
    expect(screen.getByText("21")).toBeInTheDocument();
    expect(screen.getByText("18 unconfirmed")).toBeInTheDocument();
  });

  it("stays quiet when every finding was confirmed", () => {
    render(
      <RunMetrics
        summary={{ potential_vulnerabilities: 21, unconfirmed_findings: 0 }}
        hosts={NO_HOSTS}
        ports={NO_PORTS}
        vulnCount={21}
      />,
    );
    expect(screen.queryByText(/unconfirmed/)).not.toBeInTheDocument();
  });

  it("stays quiet for a run scanned before the field existed", () => {
    render(
      <RunMetrics
        summary={{ potential_vulnerabilities: 21 }}
        hosts={NO_HOSTS}
        ports={NO_PORTS}
        vulnCount={21}
      />,
    );
    expect(screen.queryByText(/unconfirmed/)).not.toBeInTheDocument();
  });
});
