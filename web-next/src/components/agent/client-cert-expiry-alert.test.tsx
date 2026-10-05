import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ClientCertExpiryAlert } from "@/components/agent/client-cert-expiry-alert";
import { type AgentFleetSummary } from "@/lib/api";

function summary(overrides: Partial<AgentFleetSummary> = {}): AgentFleetSummary {
  return {
    total_agents: 4,
    online_agents: 4,
    busy_agents: 0,
    stale_agents: 0,
    error_agents: 0,
    outdated_agents: 0,
    latest_version: "0.46",
    by_tenant: { default: 4 },
    client_cert_mode: "required",
    client_cert_agents: 4,
    client_certs_expiring: 0,
    client_certs_expired: 0,
    ...overrides,
  };
}

describe("ClientCertExpiryAlert", () => {
  it("stays silent when nothing is running out, and for an API that predates #309", () => {
    const { container, rerender } = render(<ClientCertExpiryAlert summary={summary()} />);
    expect(container).toBeEmptyDOMElement();
    const old = summary();
    delete old.client_certs_expiring;
    delete old.client_certs_expired;
    rerender(<ClientCertExpiryAlert summary={old} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("names how many are expiring and how many have expired", () => {
    render(
      <ClientCertExpiryAlert summary={summary({ client_certs_expiring: 2, client_certs_expired: 1 })} />,
    );
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toMatch(/2/);
    expect(alert.textContent).toMatch(/1/);
    expect(alert.textContent).toMatch(/required/);
  });

  it("raises a sensor shut out by another host's enrolment, and a locked one", () => {
    render(
      <ClientCertExpiryAlert summary={summary({ client_cert_conflicts: 1, client_cert_locked: 3 })} />,
    );
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toMatch(/another host/);
    expect(alert.textContent).toMatch(/3 locked/);
  });
});
