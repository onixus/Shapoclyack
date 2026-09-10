import type { AxiosResponse, InternalAxiosRequestConfig } from "axios";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { api, getAccessToken, setAccessToken, setActiveTenant } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

type Reply = { status: number; data: unknown };

let originalAdapter: typeof api.defaults.adapter;
/** Every request the transport saw, GETs included, with the params the
 * interceptor put on it — which is where the tenant scope lives. */
let seen: { url: string; params: Record<string, unknown> }[] = [];

/** Answers each URL from its own queue; the last answer stands for repeats. */
function installTransport(routes: Record<string, Reply[]>) {
  const sent: { url: string; body: unknown }[] = [];
  const queues: Record<string, Reply[]> = Object.fromEntries(
    Object.entries(routes).map(([url, replies]) => [url, [...replies]]),
  );
  seen = [];
  api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
    const url = String(config.url);
    seen.push({ url, params: (config.params ?? {}) as Record<string, unknown> });
    if ((config.method ?? "get").toLowerCase() === "post") {
      sent.push({ url, body: config.data ? JSON.parse(String(config.data)) : null });
    }
    const queue = queues[url] ?? [];
    const reply = queue.length > 1 ? (queue.shift() as Reply) : queue[0];
    if (!reply) throw new Error(`unexpected ${config.method} ${url}`);
    const response = {
      data: reply.data,
      status: reply.status,
      statusText: "",
      headers: {},
      config,
    } as AxiosResponse;
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

const ME = {
  username: "admin",
  role: "admin",
  tenants: ["default"],
  default_tenant: "default",
  is_platform_admin: true,
};

beforeEach(() => {
  installLocalStorage();
  originalAdapter = api.defaults.adapter;
  useAuthStore.setState({ user: null, hydrated: false, loading: true, activeTenant: null });
});

afterEach(() => {
  api.defaults.adapter = originalAdapter;
});

describe("login with a second factor (#315)", () => {
  it("stores no token and signs nobody in while the factor is outstanding", async () => {
    installTransport({
      "/auth/login": [
        {
          status: 200,
          data: {
            username: "admin",
            access_token: null,
            role: null,
            mfa_required: true,
            mfa_token: "challenge.jwt",
            expires_in: 300,
          },
        },
      ],
    });

    const step = await useAuthStore.getState().login("admin", "pw");

    expect(step).toEqual({ status: "mfa-required", mfaToken: "challenge.jwt", expiresIn: 300 });
    // The challenge opens one endpoint. Putting it where every request reads
    // its bearer token from would 401 the whole console.
    expect(getAccessToken()).toBeNull();
    expect(useAuthStore.getState().user).toBeNull();
  });

  it("completes the login when the code is presented", async () => {
    const sent = installTransport({
      "/auth/mfa/verify": [
        {
          status: 200,
          data: { username: "admin", access_token: "session.jwt", role: "admin" },
        },
      ],
      "/auth/me": [{ status: 200, data: ME }],
    });

    await useAuthStore.getState().verifyMfa({ mfaToken: "challenge.jwt", code: "123456" });

    expect(sent[0]?.body).toEqual({ mfa_token: "challenge.jwt", code: "123456" });
    expect(getAccessToken()).toBe("session.jwt");
    expect(useAuthStore.getState().user?.username).toBe("admin");
  });

  it("re-reads the principal for the tenant it switches to", async () => {
    // `tenant_role` and `permissions` are per tenant (#318) and every request
    // carries the selected tenant, so a switch that only moved the scope left
    // the console gating its pages on the authority of the tenant it left:
    // the /system config panel hidden in a tenant where the API serves it, and
    // rendered in one where the API answers 403.
    installTransport({
      "/auth/me": [
        { status: 200, data: { ...ME, role: "viewer", is_platform_admin: false,
                               tenants: ["acme", "globex"], default_tenant: "acme",
                               scoped_tenant: "acme", tenant_role: "auditor",
                               permissions: ["audit.read", "config.read"] } },
        { status: 200, data: { ...ME, role: "viewer", is_platform_admin: false,
                               tenants: ["acme", "globex"], default_tenant: "acme",
                               scoped_tenant: "globex", tenant_role: "viewer",
                               permissions: [] } },
      ],
    });
    setAccessToken("session.jwt");

    await useAuthStore.getState().hydrate();
    expect(useAuthStore.getState().user?.permissions).toContain("config.read");

    await useAuthStore.getState().selectTenant("globex");

    // The second /auth/me was asked about globex, not about the default.
    const meCalls = seen.filter((entry) => entry.url === "/auth/me");
    expect(meCalls).toHaveLength(2);
    expect(meCalls[1]?.params.tenant_id).toBe("globex");
    // ...and the gate every page reads now says what globex says.
    expect(useAuthStore.getState().user?.scoped_tenant).toBe("globex");
    expect(useAuthStore.getState().user?.permissions).toEqual([]);
    expect(useAuthStore.getState().activeTenant).toBe("globex");
  });

  it("keeps the tenant selected when the re-read fails", async () => {
    // The scope moved before the request went out, so the API is already being
    // asked in the right tenant; the cost of the failure is a stale gate, not
    // a wrong answer, and unselecting the tenant would be the wrong one.
    installTransport({
      "/auth/me": [
        { status: 200, data: ME },
        { status: 500, data: {} },
      ],
    });
    setAccessToken("session.jwt");
    await useAuthStore.getState().hydrate();

    await useAuthStore.getState().selectTenant("globex");

    expect(useAuthStore.getState().activeTenant).toBe("globex");
    expect(useAuthStore.getState().user?.username).toBe("admin");
  });

  it("does not carry a previous session's tenant into a login", async () => {
    // /auth/me is scoped by the request interceptor like everything else, so a
    // stale selection from whoever used this browser last would ask the API
    // about a tenant this account may hold nothing in — and be answered 403
    // where a principal should be.
    installTransport({
      "/auth/login": [
        { status: 200, data: { username: "admin", access_token: "session.jwt", role: "admin" } },
      ],
      "/auth/me": [{ status: 200, data: ME }],
    });
    setActiveTenant("someone-elses-tenant");

    await useAuthStore.getState().login("admin", "pw");

    const me = seen.find((entry) => entry.url === "/auth/me");
    expect(me?.params.tenant_id).toBeUndefined();
    expect(useAuthStore.getState().activeTenant).toBeNull();
  });

  it("signs a required-but-unenrolled account in, flagged as pending", async () => {
    installTransport({
      "/auth/login": [
        {
          status: 200,
          data: {
            username: "admin",
            access_token: "pending.jwt",
            role: "admin",
            mfa_required: true,
            mfa_token: null,
            expires_in: null,
          },
        },
      ],
      "/auth/me": [{ status: 200, data: { ...ME, mfa_required: true, mfa_pending: true } }],
    });

    const step = await useAuthStore.getState().login("admin", "pw");

    // A session, not a challenge — it just cannot do anything but enrol.
    expect(step).toEqual({ status: "signed-in", mfaPending: true });
    expect(getAccessToken()).toBe("pending.jwt");
  });
});
