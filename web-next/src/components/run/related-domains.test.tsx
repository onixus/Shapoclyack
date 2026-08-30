import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RelatedDomainsPanel } from "@/components/run/related-domains";
import * as apiModule from "@/lib/api";
import type { OrgProfileDetail } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

const mockOrgProfile: OrgProfileDetail = {
  run_id: "run-test-org-123",
  seed_domains: ["example.com"],
  promoted_domains: [],
  ownership: {
    domains: {
      "example.com": {
        org_name: "Acme Corporation Inc.",
        registrar: "MarkMonitor Inc.",
        dnssec: true,
        nameservers: ["ns1.acmedns.com", "ns2.acmedns.com"],
      },
    },
  },
  related_domains: {
    status: "ok",
    seed_domains: ["example.com"],
    confirmed_count: 1,
    candidate_count: 1,
    total_candidates: 2,
    truncated: false,
    auto_merged: false,
    merged_domains: [],
    disclaimer: "Attribution is probabilistic.",
    candidates: [
      {
        domain: "acme-corp.net",
        status: "confirmed",
        confidence: 0.85,
        sources: ["cert_san", "ct_org"],
        evidence: [
          {
            source: "cert_san",
            indicator: "tls_san",
            detail: "Observed in TLS certificate SAN on 198.51.100.10:443",
          },
          {
            source: "ct_org",
            indicator: "crt_sh_org",
            detail: "Matched certificate issued to Organization 'Acme Corporation Inc.'",
          },
        ],
      },
      {
        domain: "acme-partner.org",
        status: "candidate",
        confidence: 0.45,
        sources: ["reverse_ns"],
        evidence: [
          {
            source: "reverse_ns",
            indicator: "shared_custom_ns",
            detail: "Shares authoritative nameserver 'ns1.acmedns.com' with verified domain(s)",
          },
        ],
      },
    ],
  },
};

function renderWithQuery(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });
  return render(<QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>);
}

describe("RelatedDomainsPanel Component", () => {
  it("renders organization ownership and related domains candidates", async () => {
    useAuthStore.setState({
      user: {
        username: "operator1",
        role: "operator",
        tenants: ["default"],
        default_tenant: "default",
        is_platform_admin: false,
      },
    });
    vi.spyOn(apiModule, "fetchOrgProfile").mockResolvedValue(mockOrgProfile);

    renderWithQuery(<RelatedDomainsPanel runId="run-test-org-123" />);

    expect(await screen.findByText("Acme Corporation Inc.")).toBeInTheDocument();
    expect(screen.getByText("Registrar: MarkMonitor Inc.")).toBeInTheDocument();
    expect(screen.getByText("DNSSEC: Signed")).toBeInTheDocument();
    expect(screen.getByText(/ns1.acmedns.com/)).toBeInTheDocument();

    expect(screen.getByText("acme-corp.net")).toBeInTheDocument();
    expect(screen.getByText("acme-partner.org")).toBeInTheDocument();
    expect(screen.getByText("CONFIRMED")).toBeInTheDocument();
    expect(screen.getByText("CANDIDATE")).toBeInTheDocument();
  });

  it("filters candidates by status", async () => {
    vi.spyOn(apiModule, "fetchOrgProfile").mockResolvedValue(mockOrgProfile);

    renderWithQuery(<RelatedDomainsPanel runId="run-test-org-123" />);

    await screen.findByText("acme-corp.net");

    // Click "Confirmed" filter
    fireEvent.click(screen.getByRole("button", { name: /Confirmed/i }));
    expect(screen.getByText("acme-corp.net")).toBeInTheDocument();
    expect(screen.queryByText("acme-partner.org")).not.toBeInTheDocument();

    // Click "Candidates" filter
    fireEvent.click(screen.getByRole("button", { name: /Candidates/i }));
    expect(screen.queryByText("acme-corp.net")).not.toBeInTheDocument();
    expect(screen.getByText("acme-partner.org")).toBeInTheDocument();
  });

  it("promotes domain to scope when Promote button is clicked", async () => {
    useAuthStore.setState({
      user: {
        username: "operator1",
        role: "operator",
        tenants: ["default"],
        default_tenant: "default",
        is_platform_admin: false,
      },
    });
    vi.spyOn(apiModule, "fetchOrgProfile").mockResolvedValue(mockOrgProfile);
    const promoteSpy = vi.spyOn(apiModule, "promoteRelatedDomain").mockResolvedValue({
      domain: "acme-corp.net",
      promoted: true,
      message: "Domain promoted",
    });

    renderWithQuery(<RelatedDomainsPanel runId="run-test-org-123" />);

    const promoteButtons = await screen.findAllByRole("button", { name: /Promote to Scope/i });
    expect(promoteButtons.length).toBeGreaterThan(0);

    fireEvent.click(promoteButtons[0]);
    await vi.waitFor(() => {
      expect(promoteSpy).toHaveBeenCalledWith("run-test-org-123", "acme-corp.net");
    });
  });
});
