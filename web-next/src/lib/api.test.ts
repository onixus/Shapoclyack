import type { AxiosResponse, InternalAxiosRequestConfig } from "axios";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  api,
  fetchScanScope,
  getAccessToken,
  getActiveTenant,
  logout,
  revokeAllSessions,
  setAccessToken,
  setActiveTenant,
} from "@/lib/api";

/** The request interceptor registered in api.ts — invoked directly so the
 * tenant-scoping rule (ROADMAP P0) can be asserted without a live server. */
function applyInterceptor(config: Partial<InternalAxiosRequestConfig>) {
  const handlers = (
    api.interceptors.request as unknown as {
      handlers: { fulfilled: (c: InternalAxiosRequestConfig) => InternalAxiosRequestConfig }[];
    }
  ).handlers;
  return handlers[0].fulfilled({ headers: {}, ...config } as InternalAxiosRequestConfig);
}

/** jsdom in this setup exposes no Storage implementation, so stand one up. */
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

describe("active tenant", () => {
  beforeEach(() => {
    installLocalStorage();
  });

  it("round-trips through localStorage and clears on null", () => {
    setActiveTenant("ten_a");
    expect(getActiveTenant()).toBe("ten_a");
    setActiveTenant(null);
    expect(getActiveTenant()).toBeNull();
  });

  it("leaves requests unscoped when no tenant is selected", () => {
    // The server then resolves the tenant from the caller's memberships, which
    // for a platform admin is the fleet-wide view.
    expect(applyInterceptor({}).params).toBeUndefined();
    expect(applyInterceptor({ params: { limit: 25 } }).params).toEqual({ limit: 25 });
  });

  it("attaches the active tenant to plain-object and missing params", () => {
    setActiveTenant("ten_a");
    expect(applyInterceptor({}).params).toEqual({ tenant_id: "ten_a" });
    expect(applyInterceptor({ params: { limit: 25 } }).params).toEqual({
      limit: 25,
      tenant_id: "ten_a",
    });
  });

  it("never overrides a tenant the caller named explicitly", () => {
    // Deep links (…/assets/view?tenantId=ten_b) must keep pointing at their
    // own tenant regardless of what the header switcher currently shows.
    setActiveTenant("ten_a");
    expect(applyInterceptor({ params: { tenant_id: "ten_b" } }).params).toEqual({
      tenant_id: "ten_b",
    });
  });

  it("attaches the active tenant to URLSearchParams", () => {
    setActiveTenant("ten_a");
    const params = new URLSearchParams({ limit: "25" });
    const result = applyInterceptor({ params }).params as URLSearchParams;
    expect(result.get("tenant_id")).toBe("ten_a");

    const explicit = new URLSearchParams({ tenant_id: "ten_b" });
    expect((applyInterceptor({ params: explicit }).params as URLSearchParams).get("tenant_id")).toBe(
      "ten_b",
    );
  });
});

describe("error messages", () => {
  let originalAdapter: typeof api.defaults.adapter;

  beforeEach(() => {
    installLocalStorage();
    originalAdapter = api.defaults.adapter;
  });

  afterEach(() => {
    api.defaults.adapter = originalAdapter;
  });

  /** Answers every request with one failure, the way axios reports it. */
  function failWith(status: number, data: unknown, headers: Record<string, string> = {}) {
    api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
      throw Object.assign(new Error(`Request failed with status code ${status}`), {
        isAxiosError: true,
        config,
        response: { data, status, statusText: "", headers, config } as AxiosResponse,
      });
    };
  }

  it("names the field a pydantic error points at instead of showing its JSON", async () => {
    // What FastAPI answers when the request violates the schema rather than a
    // handler's own rule: a list, one item per offending field.
    failWith(422, {
      detail: [
        {
          type: "string_too_long",
          loc: ["body", "entries", 0, "value"],
          msg: "String should have at most 255 characters",
        },
        {
          type: "too_long",
          loc: ["body", "entries"],
          msg: "List should have at most 1000 items after validation, not 1001",
        },
      ],
    });

    await expect(fetchScanScope("default")).rejects.toThrow(
      "entries[0].value: String should have at most 255 characters; " +
        "entries: List should have at most 1000 items after validation, not 1001",
    );
  });

  it("passes a handler's own detail through as it stands", async () => {
    failWith(422, { detail: "not an IP or CIDR: '10.0.0'" });
    await expect(fetchScanScope("default")).rejects.toThrow("not an IP or CIDR: '10.0.0'");
  });

  it("falls back to the raw body for a detail that is neither", async () => {
    failWith(500, { detail: { code: 17 } });
    await expect(fetchScanScope("default")).rejects.toThrow('{"code":17}');
  });

  it("appends the request id a server-side failure came back with", async () => {
    // The one actionable thing a 500 carries: the token an operator greps the
    // API logs for (#330). Readable cross-origin because the API names the
    // header in its CORS `expose_headers`.
    failWith(500, { detail: "Internal Server Error" }, { "x-request-id": "corr-12345" });
    await expect(fetchScanScope("default")).rejects.toThrow(
      "Internal Server Error (request id: corr-12345)",
    );
  });

  it("leaves a client-side refusal's message alone", async () => {
    // A 422 already says what the request got wrong; the id would be noise.
    failWith(422, { detail: "not an IP or CIDR: '10.0.0'" }, { "x-request-id": "corr-12345" });
    await expect(fetchScanScope("default")).rejects.toThrow("not an IP or CIDR: '10.0.0'");
    await expect(fetchScanScope("default")).rejects.not.toThrow("corr-12345");
  });
});

describe("sign-out", () => {
  let originalAdapter: typeof api.defaults.adapter;
  let calls: string[];

  beforeEach(() => {
    installLocalStorage();
    // The response interceptor redirects on 401; pretending the console is
    // already on /login keeps it from asking jsdom to navigate.
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { pathname: "/login", href: "/login" },
    });
    originalAdapter = api.defaults.adapter;
    calls = [];
    setAccessToken("a.b.c");
  });

  afterEach(() => {
    api.defaults.adapter = originalAdapter;
  });

  /** Answers each path with a status; anything unlisted is a 200. */
  function serve(statuses: Record<string, number>) {
    api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
      const path = config.url ?? "";
      calls.push(path);
      const status = statuses[path] ?? 200;
      const response = { data: null, status, statusText: "", headers: {}, config };
      if (status >= 400) {
        throw Object.assign(new Error(`Request failed with status code ${status}`), {
          isAxiosError: true,
          config,
          response: response as AxiosResponse,
        });
      }
      return response as AxiosResponse;
    };
  }

  it("ends the session on the server and only then forgets the token", async () => {
    serve({});
    await expect(logout()).resolves.toBe("ended");
    expect(calls).toEqual(["/auth/logout"]);
    expect(getAccessToken()).toBeNull();
  });

  it("treats a refused token as already signed out", async () => {
    // 401: the session was gone before we asked. 403: the credential was never
    // a session — a service token may not touch `auth` at all.
    for (const status of [401, 403]) {
      setAccessToken("a.b.c");
      serve({ "/auth/logout": status });
      await expect(logout()).resolves.toBe("already-ended");
      expect(getAccessToken()).toBeNull();
    }
  });

  it("falls back to revoke-all when the server failed rather than refused", async () => {
    // The defect this guards: a 5xx (or the 400 a pre-#314 token with no `jti`
    // gets) left the token live on the server while the console reported a
    // completed sign-out. revoke-all needs no `jti` and ends it for real.
    serve({ "/auth/logout": 500 });
    await expect(logout()).resolves.toBe("ended");
    expect(calls).toEqual(["/auth/logout", "/auth/sessions/revoke-all"]);
    expect(getAccessToken()).toBeNull();
  });

  it("reports an unconfirmed sign-out when neither call got through", async () => {
    serve({ "/auth/logout": 502, "/auth/sessions/revoke-all": 502 });
    await expect(logout()).resolves.toBe("uncertain");
    // Local token dropped regardless: the user must be able to walk away from
    // a browser even when the API cannot be reached.
    expect(getAccessToken()).toBeNull();
  });

  it("keeps the token when an explicit revoke-all was refused", async () => {
    serve({ "/auth/sessions/revoke-all": 500 });
    await expect(revokeAllSessions()).rejects.toThrow();
    expect(getAccessToken()).toBe("a.b.c");
  });
});
