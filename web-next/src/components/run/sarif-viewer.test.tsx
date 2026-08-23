import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { SarifViewerDialog, type SarifLog } from "@/components/run/sarif-viewer";

const SAMPLE_SARIF: SarifLog = {
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "Shapoclyack Scanner",
          version: "0.4.0",
          rules: [
            {
              id: "cve-2024-1234",
              name: "Critical Remote Code Execution",
              shortDescription: { text: "RCE in HTTP handler" },
              defaultConfiguration: { level: "error" },
              properties: { cve: "CVE-2024-1234", cwe: ["CWE-78"] },
              help: { text: "Upgrade service to version 2.0" },
            },
            {
              id: "http-missing-headers",
              name: "Missing Security Headers",
              shortDescription: { text: "HSTS header missing" },
              defaultConfiguration: { level: "warning" },
              properties: { cwe: ["CWE-693"] },
            },
          ],
        },
      },
      results: [
        {
          ruleId: "cve-2024-1234",
          level: "error",
          message: { text: "Vulnerable endpoint /api/exec detected" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "https://example.com/api/exec" },
              },
            },
          ],
          properties: { cve: "CVE-2024-1234", cvss_score: 9.8 },
        },
        {
          ruleId: "http-missing-headers",
          level: "warning",
          message: { text: "Strict-Transport-Security header not returned" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "http://example.com:80/" },
              },
            },
          ],
        },
      ],
    },
  ],
};

describe("SarifViewerDialog", () => {
  it("renders SARIF metrics, findings and target URIs correctly", () => {
    const onDownload = vi.fn();
    const onOpenChange = vi.fn();

    render(
      <SarifViewerDialog
        open={true}
        onOpenChange={onOpenChange}
        sarifText={JSON.stringify(SAMPLE_SARIF)}
        runId="run-test-sarif"
        onDownload={onDownload}
      />
    );

    expect(screen.getByText(/SARIF 2.1.0 Security Report/)).toBeInTheDocument();
    expect(screen.getByText("run-test-sarif")).toBeInTheDocument();
    expect(screen.getByText("cve-2024-1234")).toBeInTheDocument();
    expect(screen.getByText("CVE-2024-1234")).toBeInTheDocument();
    expect(screen.getByText("https://example.com/api/exec")).toBeInTheDocument();
    expect(screen.getByText("http://example.com:80/")).toBeInTheDocument();

    // Trigger download
    const dlBtn = screen.getByRole("button", { name: /Download sarif.json/i });
    fireEvent.click(dlBtn);
    expect(onDownload).toHaveBeenCalledTimes(1);
  });

  it("filters findings when typing search keyword", () => {
    render(
      <SarifViewerDialog
        open={true}
        onOpenChange={vi.fn()}
        sarifText={JSON.stringify(SAMPLE_SARIF)}
        runId="run-filter-sarif"
        onDownload={vi.fn()}
      />
    );

    const input = screen.getByPlaceholderText(/Filter rule, target, message/i);
    fireEvent.change(input, { target: { value: "Strict-Transport" } });

    expect(screen.getByText("http-missing-headers")).toBeInTheDocument();
    expect(screen.queryByText("cve-2024-1234")).not.toBeInTheDocument();
  });
});
