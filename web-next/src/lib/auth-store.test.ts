import type { AxiosResponse, InternalAxiosRequestConfig } from "axios";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { api, getAccessToken } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

type Reply = { status: number; data: unknown };

let originalAdapter: typeof api.defaults.adapter;

/** Answers each URL from its own queue; the last answer stands for repeats. */
function installTransport(routes: Record<string, Reply[]>) {
  const sent: { url: string; body: unknown }[] = [];
  const queues: Record<string, Reply[]> = Object.fromEntries(
    Object.entries(routes).map(([url, replies]) => [url, [...replies]]),
  );
  api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
    const url = String(config.url);
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
