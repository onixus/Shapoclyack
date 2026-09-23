import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { AxiosResponse, InternalAxiosRequestConfig } from "axios";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SecurityKeysPanel } from "@/components/mfa/security-keys-panel";
import { api, setAccessToken, type MfaStatus, type WebAuthnKey } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

const STATUS: MfaStatus = {
  username: "admin",
  enabled: true,
  enabled_at: "2026-09-10T12:00:00Z",
  setup_pending: false,
  recovery_codes_remaining: 10,
  required: true,
  stepup_minutes: 15,
  password_required: true,
  webauthn_available: true,
  webauthn_credentials: 1,
  phishing_resistant_required: false,
  stepup_phishing_resistant: false,
};

const KEY: WebAuthnKey = {
  id: "k1",
  name: "YubiKey",
  credential_id: "BwgJ",
  aaguid: "",
  transports: ["usb"],
  backed_up: false,
  device_type: "single_device",
  created_at: "2026-09-20T10:00:00Z",
  last_used_at: null,
};

const ME = {
  username: "admin",
  role: "admin" as const,
  tenants: ["default"],
  default_tenant: "default",
  is_platform_admin: true,
};

type Reply = { status: number; data: unknown };

let client: QueryClient;
let originalAdapter: typeof api.defaults.adapter;

/** Only the transport is stubbed, as in the TOTP panel's test: the request
 * bodies `api.ts` builds — the credential JSON above all — stay under test. */
function installTransport(routes: Record<string, Reply>) {
  const sent: { method: string; url: string; body: unknown }[] = [];
  api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
    const method = (config.method ?? "get").toLowerCase();
    const url = String(config.url);
    const reply = routes[`${method} ${url}`] ?? { status: 404, data: { detail: "no stub" } };
    sent.push({ method, url, body: config.data ? JSON.parse(String(config.data)) : null });
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
      <SecurityKeysPanel />
    </QueryClientProvider>,
  );
}

function stubBrowserKey(create: ReturnType<typeof vi.fn>) {
  vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
  Object.defineProperty(navigator, "credentials", {
    configurable: true,
    value: { create, get: vi.fn() },
  });
}

beforeEach(() => {
  installLocalStorage();
  setAccessToken("session.jwt");
  originalAdapter = api.defaults.adapter;
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  useAuthStore.setState({ user: { ...ME }, hydrated: true, loading: false });
});

afterEach(() => {
  api.defaults.adapter = originalAdapter;
  client.clear();
  vi.unstubAllGlobals();
});

describe("SecurityKeysPanel", () => {
  it("lists the account's keys and removes one", async () => {
    stubBrowserKey(vi.fn());
    const sent = installTransport({
      "get /auth/mfa": { status: 200, data: STATUS },
      "get /auth/mfa/webauthn/credentials": { status: 200, data: [KEY] },
      "delete /auth/mfa/webauthn/credentials/k1": { status: 204, data: null },
    });
    renderPanel();

    expect(await screen.findByText("YubiKey")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /remove/i }));
    await waitFor(() =>
      expect(sent.some((item) => item.method === "delete" && item.url.endsWith("/k1"))).toBe(true),
    );
  });

  it("registers a key: options, the browser prompt, then the attestation with its name", async () => {
    const create = vi.fn().mockResolvedValue({
      id: "BwgJ",
      rawId: new Uint8Array([7, 8, 9]).buffer,
      type: "public-key",
      response: {
        clientDataJSON: new Uint8Array([1]).buffer,
        attestationObject: new Uint8Array([2]).buffer,
        getTransports: () => ["usb"],
      },
    });
    stubBrowserKey(create);
    const sent = installTransport({
      "get /auth/mfa": { status: 200, data: STATUS },
      "get /auth/mfa/webauthn/credentials": { status: 200, data: [] },
      "post /auth/mfa/webauthn/register/options": {
        status: 200,
        data: {
          challenge_id: "c-1",
          public_key: {
            rp: { id: "console.example", name: "Shapoclyack" },
            user: { id: "AQID", name: "admin", displayName: "admin" },
            challenge: "BAUG",
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          },
        },
      },
      "post /auth/mfa/webauthn/register/verify": { status: 201, data: KEY },
      "get /auth/me": { status: 200, data: ME },
    });
    renderPanel();

    await userEvent.type(await screen.findByLabelText(/name for the new key/i), "YubiKey");
    await userEvent.click(screen.getByRole("button", { name: /add a security key/i }));

    await waitFor(() =>
      expect(sent.some((item) => item.url === "/auth/mfa/webauthn/register/verify")).toBe(true),
    );
    const verify = sent.find((item) => item.url === "/auth/mfa/webauthn/register/verify");
    expect(verify?.body).toEqual({
      challenge_id: "c-1",
      name: "YubiKey",
      credential: {
        id: "BwgJ",
        rawId: "BwgJ",
        type: "public-key",
        response: { clientDataJSON: "AQ", attestationObject: "Ag", transports: ["usb"] },
      },
    });
    expect(create).toHaveBeenCalledTimes(1);
  });

  it("says a cancelled browser prompt in the console's words, not the browser's", async () => {
    const { toast } = await import("sonner");
    const cancelled = Object.assign(new Error("The operation either timed out or was not allowed."), {
      name: "NotAllowedError",
    });
    stubBrowserKey(vi.fn().mockRejectedValue(cancelled));
    installTransport({
      "get /auth/mfa": { status: 200, data: STATUS },
      "get /auth/mfa/webauthn/credentials": { status: 200, data: [] },
      "post /auth/mfa/webauthn/register/options": {
        status: 200,
        data: {
          challenge_id: "c-1",
          public_key: {
            rp: { id: "console.example", name: "Shapoclyack" },
            user: { id: "AQID", name: "admin", displayName: "admin" },
            challenge: "BAUG",
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          },
        },
      },
    });
    vi.mocked(toast.error).mockClear();
    renderPanel();

    await userEvent.click(await screen.findByRole("button", { name: /add a security key/i }));

    await waitFor(() => expect(toast.error).toHaveBeenCalledTimes(1));
    expect(toast.error).toHaveBeenCalledWith(expect.stringMatching(/cancelled or timed out/i));
  });

  it("says a key needs the authenticator app first, and offers no button", async () => {
    stubBrowserKey(vi.fn());
    installTransport({ "get /auth/mfa": { status: 200, data: { ...STATUS, enabled: false } } });
    renderPanel();

    expect(await screen.findByText(/authenticator app first/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /add a security key/i })).toBeNull();
  });

  it("renders nothing on an installation with no relying party", async () => {
    installTransport({
      "get /auth/mfa": { status: 200, data: { ...STATUS, webauthn_available: false } },
    });
    const { container } = renderPanel();
    await waitFor(() => expect(client.getQueryData(["auth", "mfa"])).toBeTruthy());
    expect(container).toBeEmptyDOMElement();
  });
});
