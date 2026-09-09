import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import IntegrationsPage from "@/app/(dashboard)/integrations/page";
import * as apiModule from "@/lib/api";
import type { Me, Page, Role, WebhookDelivery, WebhookInfo } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

/** Radix's checkbox measures itself through ResizeObserver, which jsdom does
 * not implement. */
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??= ResizeObserverStub as unknown as typeof ResizeObserver;

function me(role: Role): Me {
  return {
    username: role,
    role,
    tenants: ["default"],
    default_tenant: "default",
    is_platform_admin: role === "admin",
  };
}

function subscription(overrides: Partial<WebhookInfo> = {}): WebhookInfo {
  return {
    subscription_id: "wh_1",
    tenant_id: "default",
    name: "soc-alerts",
    url: "https://example.test/hook",
    enabled: true,
    event_kinds: ["new_cve"],
    min_severity: "high",
    has_secret: true,
    headers: {},
    transport: "webhook",
    transport_config: {},
    created_at: "2026-09-01T10:00:00Z",
    created_by: "admin",
    updated_at: "2026-09-01T10:00:00Z",
    last_delivery_at: "2026-09-05T08:00:00Z",
    last_status: "delivered",
    ...overrides,
  };
}

function delivery(overrides: Partial<WebhookDelivery> = {}): WebhookDelivery {
  return {
    delivery_id: "wd_1",
    tenant_id: "default",
    subscription_id: "wh_1",
    event_id: "ev_1",
    event_kind: "new_cve",
    status: "dead",
    attempts: 6,
    next_attempt_at: null,
    last_status_code: 500,
    last_error: "receiver answered 500",
    created_at: "2026-09-05T08:00:00Z",
    updated_at: "2026-09-05T08:10:00Z",
    delivered_at: null,
    ...overrides,
  };
}

function page<T>(items: T[]): Page<T> {
  return { items, total: items.length, offset: 0, limit: 15, has_more: false };
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <IntegrationsPage />
    </QueryClientProvider>,
  );
  return queryClient;
}

describe("IntegrationsPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useAuthStore.setState({ user: me("admin"), canOperate: true, activeTenant: "default" });
    vi.spyOn(apiModule, "fetchWebhookDeliveries").mockResolvedValue(page<WebhookDelivery>([]));
  });

  it("lists the subscriptions with their transport, routing and last delivery", async () => {
    vi.spyOn(apiModule, "fetchWebhooks").mockResolvedValue(
      page([
        subscription(),
        subscription({
          subscription_id: "wh_2",
          name: "jira-sec",
          transport: "jira",
          url: "https://acme.atlassian.test",
          event_kinds: [],
          min_severity: null,
          enabled: false,
          last_status: "dead",
          transport_config: { project_key: "SEC", issue_type: "Bug" },
        }),
      ]),
    );

    renderPage();

    expect(await screen.findByText("soc-alerts")).toBeInTheDocument();
    expect(screen.getByText("jira-sec")).toBeInTheDocument();
    expect(screen.getByText("https://acme.atlassian.test")).toBeInTheDocument();
    expect(screen.getByText("jira")).toBeInTheDocument();
    // An empty kind list is "everything", which is the opposite of "nothing".
    expect(screen.getByText("All events")).toBeInTheDocument();
    expect(screen.getByText("New CVE")).toBeInTheDocument();
    expect(screen.getByText("disabled")).toBeInTheDocument();
  });

  it("says integrations are switched off rather than reporting a failure", async () => {
    // The router is not registered, so the endpoint is not there at all.
    vi.spyOn(apiModule, "fetchWebhooks").mockResolvedValue(null);
    vi.spyOn(apiModule, "fetchWebhookDeliveries").mockResolvedValue(null);

    renderPage();

    expect(await screen.findByText(/Integrations are disabled/i)).toBeInTheDocument();
    expect(screen.getByText(/OCTO_WEBHOOKS_ENABLED/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /New integration/i })).not.toBeInTheDocument();
  });

  it("asks for what the chosen transport actually needs", async () => {
    vi.spyOn(apiModule, "fetchWebhooks").mockResolvedValue(page([subscription()]));
    const create = vi.spyOn(apiModule, "createWebhook").mockResolvedValue(subscription());

    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /New integration/i }));

    // A plain webhook: an endpoint we sign for, and an optional secret.
    expect(screen.getByLabelText("Endpoint URL")).toBeInTheDocument();
    expect(screen.getByLabelText("Signing secret (optional)")).toBeInTheDocument();
    expect(screen.queryByLabelText("Project key")).not.toBeInTheDocument();

    await userEvent.selectOptions(screen.getByLabelText("Transport"), "jira");

    // A tracker: the instance URL, a token, and the one knob the adapter
    // cannot guess (api/services/integrations/tickets.py).
    expect(screen.getByLabelText("Instance base URL")).toBeInTheDocument();
    expect(screen.getByLabelText("Project key")).toBeInTheDocument();
    expect(screen.getByLabelText("Issue type")).toHaveValue("Bug");
    expect(screen.getByLabelText("API token")).toBeInTheDocument();
    expect(screen.queryByLabelText("Endpoint URL")).not.toBeInTheDocument();
    expect(screen.getByText(/Opens a Jira issue/i)).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText("Name"), "jira-sec");
    await userEvent.type(screen.getByLabelText("Instance base URL"), "https://acme.atlassian.test");
    await userEvent.type(screen.getByLabelText("Project key"), "SEC");
    await userEvent.type(screen.getByLabelText("API token"), "tracker-token");
    await userEvent.click(screen.getByRole("checkbox", { name: "New CVE" }));
    await userEvent.click(screen.getByRole("button", { name: /Create integration/i }));

    await waitFor(() =>
      expect(create).toHaveBeenCalledWith({
        name: "jira-sec",
        url: "https://acme.atlassian.test",
        event_kinds: ["new_cve"],
        min_severity: null,
        enabled: true,
        transport: "jira",
        transport_config: { project_key: "SEC", issue_type: "Bug" },
        secret: "tracker-token",
      }),
    );
  });

  it("shows a rotated signing secret once and then drops it", async () => {
    vi.spyOn(apiModule, "fetchWebhooks").mockResolvedValue(page([subscription()]));
    const rotate = vi
      .spyOn(apiModule, "rotateWebhookSecret")
      .mockResolvedValue(subscription({ secret: "whsec_rotated" }));

    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /Rotate secret/i }));

    // React Query hands the mutation function a context object alongside the
    // variables, so only the first argument is ours to assert on.
    await waitFor(() => expect(rotate.mock.calls[0]?.[0]).toBe("wh_1"));
    expect(await screen.findByText("whsec_rotated")).toBeInTheDocument();
    expect(screen.getByText(/shown only once/i)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /I have copied it/i }));
    await waitFor(() => expect(screen.queryByText("whsec_rotated")).not.toBeInTheDocument());
  });

  it("refuses rotation on a ticket transport, where the secret is the tracker token", async () => {
    vi.spyOn(apiModule, "fetchWebhooks").mockResolvedValue(
      page([subscription({ transport: "jira", transport_config: { project_key: "SEC" } })]),
    );

    renderPage();

    expect(await screen.findByRole("button", { name: /Rotate secret/i })).toBeDisabled();
  });

  it("gives an operator the list and none of the write actions", async () => {
    useAuthStore.setState({ user: me("operator"), canOperate: true });
    vi.spyOn(apiModule, "fetchWebhooks").mockResolvedValue(page([subscription()]));

    renderPage();

    expect(await screen.findByText("soc-alerts")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /New integration/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Test$/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Rotate secret/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Delete/i })).not.toBeInTheDocument();
    expect(screen.getByText(/tenant administrator/i)).toBeInTheDocument();
  });

  it("offers a retry only for a delivery that has run out of attempts", async () => {
    vi.spyOn(apiModule, "fetchWebhooks").mockResolvedValue(page([subscription()]));
    vi.spyOn(apiModule, "fetchWebhookDeliveries").mockResolvedValue(
      page([
        delivery(),
        delivery({
          delivery_id: "wd_2",
          status: "pending",
          attempts: 1,
          last_status_code: null,
          last_error: null,
        }),
      ]),
    );
    const retry = vi.spyOn(apiModule, "retryWebhookDelivery").mockResolvedValue(delivery());

    renderPage();
    await userEvent.click(await screen.findByRole("tab", { name: "Deliveries" }));

    expect(await screen.findByText("receiver answered 500")).toBeInTheDocument();
    const retryButtons = screen.getAllByRole("button", { name: /Retry/i });
    expect(retryButtons).toHaveLength(1);

    await userEvent.click(retryButtons[0]);
    await waitFor(() => expect(retry.mock.calls[0]?.[0]).toBe("wd_1"));
  });
});
