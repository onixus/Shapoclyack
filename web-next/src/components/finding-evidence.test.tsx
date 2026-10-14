import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { FindingEvidencePanel } from "@/components/finding-evidence";
import { downloadArtifact, type FindingEvidence } from "@/lib/api";

vi.mock("@/lib/api", () => ({ downloadArtifact: vi.fn() }));

function evidence(): FindingEvidence {
  return {
    observation_count: 2, finding_count: 2, projection_incomplete: true,
    findings: ["tcp", "udp"].map((protocol, index) => ({
      evidence_id: `subject-${index}`,
      observations: [{
        observation_id: `observation-${index}`, run_id: `historical-run-${index}`,
        source: index ? "nuclei" : "pulse", evidence_kind: "template_match",
        severity: "high", observed_at: null, preview: "Safe bounded preview",
        subject: { protocol, authority: null, sni: null, object_id: null },
        artifact_refs: [{ path: `report_sources-${index}.json`, sha256: "a".repeat(64), locator: "/0" }],
      }],
    })),
  };
}

describe("FindingEvidencePanel", () => {
  it("keeps subject observations separate and downloads each original run through the authenticated API", async () => {
    vi.mocked(downloadArtifact).mockResolvedValue(undefined);
    render(<FindingEvidencePanel evidence={evidence()} />);
    expect(screen.getByText("2 observations · 2 distinct subjects · incomplete")).toBeInTheDocument();
    expect(screen.getAllByText("Safe bounded preview")).toHaveLength(2);
    fireEvent.click(screen.getByText("report_sources-1.json"));
    await waitFor(() => expect(downloadArtifact).toHaveBeenCalledWith("historical-run-1", "report_sources-1.json"));
  });

  it("shows artifact permission failures without opening an arbitrary path or URL", async () => {
    vi.mocked(downloadArtifact).mockRejectedValue(new Error("Artifact not found"));
    render(<FindingEvidencePanel evidence={evidence()} />);
    fireEvent.click(screen.getByText("report_sources-0.json"));
    expect(await screen.findByRole("alert")).toHaveTextContent("Artifact not found");
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
});
