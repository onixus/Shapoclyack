"use client";

import { create } from "zustand";
import {
  fetchMe,
  getAccessToken,
  getActiveTenant,
  login as apiLogin,
  logout as apiLogout,
  revokeAllSessions as apiRevokeAllSessions,
  setAccessToken,
  setActiveTenant,
  type LogoutOutcome,
  type Me,
  type Role,
} from "@/lib/api";

type AuthState = {
  user: Me | null;
  loading: boolean;
  hydrated: boolean;
  canOperate: boolean;
  /** Tenant every request is scoped to, or `null` for the server's own choice
   * — the fleet-wide view for a platform admin (ROADMAP P0). */
  activeTenant: string | null;
  hydrate: () => Promise<void>;
  login: (username: string, password: string) => Promise<void>;
  /** Ends the session on the server as well as in this browser (#314), which
   * is why it is a promise now: forgetting the token locally left it working
   * for anyone who had copied it. The outcome is returned so the caller can
   * say so when the server could not confirm it. */
  logout: () => Promise<LogoutOutcome>;
  /** Ends every session of this account, not just this browser's (#314).
   * Throws when the server refused, in which case nothing was signed out. */
  revokeAllSessions: () => Promise<void>;
  selectTenant: (tenantId: string | null) => void;
};

function canOperate(role: Role | undefined) {
  return role === "operator" || role === "admin";
}

/** Keep a persisted tenant only while the signed-in user is still entitled to
 * it — a revoked membership (or a different user on the same browser) would
 * otherwise 403 every request until localStorage is cleared by hand. */
function reconcileTenant(user: Me): string | null {
  const stored = getActiveTenant();
  // An API older than P0 answers /auth/me without tenant context at all, hence
  // the `?? []` rather than a bare `.includes`.
  if (stored && (user.is_platform_admin || (user.tenants ?? []).includes(stored))) {
    return stored;
  }
  if (stored) setActiveTenant(null);
  return null;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  loading: true,
  hydrated: false,
  canOperate: false,
  activeTenant: null,
  async hydrate() {
    const token = getAccessToken();
    if (!token) {
      set({ user: null, loading: false, hydrated: true, canOperate: false, activeTenant: null });
      return;
    }
    try {
      const user = await fetchMe();
      set({
        user,
        loading: false,
        hydrated: true,
        canOperate: canOperate(user.role),
        activeTenant: reconcileTenant(user),
      });
    } catch {
      setAccessToken(null);
      set({ user: null, loading: false, hydrated: true, canOperate: false, activeTenant: null });
    }
  },
  async login(username, password) {
    const session = await apiLogin(username, password);
    // The login response carries no tenant context (ROADMAP P0), so read the
    // full principal — tenants, default tenant, platform-admin flag — from
    // /auth/me and fall back to the login payload if that call fails.
    let user: Me = {
      username: session.username,
      role: session.role,
      tenants: [],
      default_tenant: "default",
      is_platform_admin: session.role === "admin",
    };
    try {
      user = await fetchMe();
    } catch {
      // Keep the login-derived principal; hydrate() will retry on next load.
    }
    set({
      user,
      loading: false,
      hydrated: true,
      canOperate: canOperate(user.role),
      activeTenant: reconcileTenant(user),
    });
  },
  async logout() {
    // apiLogout clears the stored token whether or not the server answered, so
    // an unreachable API still signs the console out of this browser. What it
    // cannot do is promise the server agreed — that is what the outcome says.
    const outcome = await apiLogout();
    setActiveTenant(null);
    set({ user: null, loading: false, hydrated: true, canOperate: false, activeTenant: null });
    return outcome;
  },
  async revokeAllSessions() {
    // Deliberately not wrapped: a failure here ended nothing, and clearing the
    // console's own state would hide that.
    await apiRevokeAllSessions();
    setActiveTenant(null);
    set({ user: null, loading: false, hydrated: true, canOperate: false, activeTenant: null });
  },
  selectTenant(tenantId) {
    setActiveTenant(tenantId);
    set({ activeTenant: tenantId });
  },
}));
