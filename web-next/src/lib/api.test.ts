import type { InternalAxiosRequestConfig } from "axios";
import { beforeEach, describe, expect, it } from "vitest";
import { api, getActiveTenant, setActiveTenant } from "@/lib/api";

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
