import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { AxiosResponse, InternalAxiosRequestConfig } from "axios";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MfaPanel } from "@/components/mfa/mfa-panel";
import { api, type MfaStatus } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

const OFF: MfaStatus = {
  username: "admin",
  enabled: false,
  enabled_at: null,
  setup_pending: false,
  recovery_codes_remaining: 0,
  required: true,
  stepup_minutes: 15,
};

const ON: MfaStatus = {
  ...OFF,
  enabled: true,
  enabled_at: "2026-09-10T12:00:00Z",
  recovery_codes_remaining: 9,
};

const SETUP = {
  secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
  otpauth_uri: "otpauth://totp/console.example%3Aadmin?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
};

const RECOVERY = Array.from({ length: 10 }, (_, i) => `abcde-${String(i).repeat(5)}`);

type Reply = { status: number; data: unknown };

let client: QueryClient;
let originalAdapter: typeof api.defaults.adapter;

/** Only the transport is stubbed, so the request bodies `api.ts` builds — which
 * is where "is this a recovery code or an authenticator code" is decided — stay
 * under test. Every POST is recorded with its URL. */
function installTransport(get: Reply, posts: Record<string, Reply>) {
  const sent: { url: string; body: unknown }[] = [];
  api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
    const method = (config.method ?? "get").toLowerCase();
    const url = String(config.url);
    const reply =
      method === "get" ? get : (posts[url] ?? { status: 404, data: { detail: "no stub" } });
    if (method === "post") sent.push({ url, body: config.data ? JSON.parse(String(config.data)) : null });
    const response = { data: reply.data, status: reply.status, statusText: "", headers: {}, config } as AxiosResponse;
    if (reply.status >= 400) {
      throw Object.assign(new Error(`Request failed with status code ${reply.status}`), {
        isAxiosError: true,
        config,
        response,
      });
    }
    return response;
  };
  return sent;
}

function installLocalStorage() {
  const store = new Map<string, string>();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: {
      getItem: (key: string) => store.get(key) ?? null,
      setItem: (key: string, value: string) => void store.set(key, String(value)),
      removeItem: (key: string) => void store.delete(key),
      clear: () => store.clear(),
    },
  });
}

function renderPanel() {
  return render(
    <QueryClientProvider client={client}>
      <MfaPanel />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  installLocalStorage();
  originalAdapter = api.defaults.adapter;
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  useAuthStore.setState({
    user: {
      username: "admin",
      role: "admin",
      tenants: ["default"],
      default_tenant: "default",
      is_platform_admin: true,
    },
    hydrated: true,
    loading: false,
  });
});

afterEach(() => {
  api.defaults.adapter = originalAdapter;
  client.clear();
});

describe("MfaPanel", () => {
  it("shows the secret and the otpauth link, then the recovery codes once confirmed", async () => {
    installTransport(
      { status: 200, data: OFF },
      {
        "/auth/mfa/totp/setup": { status: 200, data: SETUP },
        "/auth/mfa/totp/confirm": { status: 200, data: { recovery_codes: RECOVERY } },
      },
    );
    renderPanel();

    await userEvent.click(await screen.findByRole("button", { name: /set up an authenticator/i }));

    // Both forms are on screen: the link an app imports, and the secret for an
    // app that will not take a link. Neither is hidden behind a copy button.
    expect(await screen.findByText(SETUP.otpauth_uri)).toBeInTheDocument();
    expect(screen.getByText(SETUP.secret)).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText(/code from the app/i), "123456");
    await userEvent.click(screen.getByRole("button", { name: /turn it on/i }));

    // The ten codes are shown once, and the enrolment form is gone with them.
    for (const code of RECOVERY) expect(await screen.findByText(code)).toBeInTheDocument();
    expect(screen.queryByLabelText(/code from the app/i)).not.toBeInTheDocument();
  });

  it("routes six digits as a code and anything else as a recovery code when turning it off", async () => {
    const sent = installTransport(
      { status: 200, data: ON },
      { "/auth/mfa/disable": { status: 200, data: { ...ON, enabled: false } } },
    );
    renderPanel();

    await userEvent.type(await screen.findByLabelText(/^password$/i), "hunter2");
    await userEvent.type(screen.getByLabelText(/code from the app, or a recovery code/i), "abcde-fghjk");
    await userEvent.click(screen.getByRole("button", { name: /^turn off$/i }));

    await waitFor(() => expect(sent).toHaveLength(1));
    // The distinction matters at the API: `code` goes to the TOTP verifier and
    // `recovery_code` to the ten hashes, and a recovery code sent as `code`
    // is simply refused.
    expect(sent[0]?.body).toEqual({ password: "hunter2", recovery_code: "abcde-fghjk" });
  });

  it("states the policy, the codes left and the step-up window while it is on", async () => {
    installTransport({ status: 200, data: ON }, {});
    renderPanel();

    expect(await screen.findByText(/requires a second factor for the admin role/i)).toBeInTheDocument();
    expect(screen.getByText(/9 of 10 recovery codes left/i)).toBeInTheDocument();
    expect(screen.getByText(/more than 15 minutes old/i)).toBeInTheDocument();
  });
});
