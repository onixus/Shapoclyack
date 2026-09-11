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
  verifyMfa as apiVerifyMfa,
  type LogoutOutcome,
  type Me,
} from "@/lib/api";
import { canOperate as canOperateIn } from "@/lib/authz";

export { can, holdsPermission, isTenantAdmin, tenantRole } from "@/lib/authz";

/** What a password login produced: a session, or an outstanding challenge. */
export type LoginStep =
  | { status: "signed-in"; mfaPending: boolean }
  | { status: "mfa-required"; mfaToken: string; expiresIn: number | null };

type AuthState = {
  user: Me | null;
  loading: boolean;
  hydrated: boolean;
  /** Operator-or-better **in the active tenant** (`@/lib/authz`), not
   * globally: since #318 the authority lives in the membership, and reading
   * the JWT's global role here hid the scanning pages from every account whose
   * operator role was granted per tenant. Kept on the store rather than
   * recomputed per page so a page cannot ask the question a fourth way. */
  canOperate: boolean;
  /** Tenant every request is scoped to, or `null` for the server's own choice
   * — the fleet-wide view for a platform admin (ROADMAP P0). */
  activeTenant: string | null;
  hydrate: () => Promise<void>;
  /** Signs in, or reports that a second factor is still owed (#315). The
   * caller renders the code step from `mfaToken`; nothing is stored in the
   * browser until a real session exists. */
  login: (username: string, password: string) => Promise<LoginStep>;
  /** Second leg of a login, or a step-up on the current session. */
  verifyMfa: (input: { mfaToken?: string | null; code?: string; recoveryCode?: string }) =>
    Promise<void>;
  /** Ends the session on the server as well as in this browser (#314), which
   * is why it is a promise now: forgetting the token locally left it working
   * for anyone who had copied it. The outcome is returned so the caller can
   * say so when the server could not confirm it. */
  logout: () => Promise<LogoutOutcome>;
  /** Ends every session of this account, not just this browser's (#314).
   * Throws when the server refused, in which case nothing was signed out. */
  revokeAllSessions: () => Promise<void>;
  /** Switches the tenant every request is scoped to, and re-reads the
   * principal for it: the permissions a page gates on are per tenant (#318).
   * Awaitable so a caller can wait for the new authority before rendering. */
  selectTenant: (tenantId: string | null) => Promise<void>;
};

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
        canOperate: canOperateIn(user),
        activeTenant: reconcileTenant(user),
      });
    } catch {
      setAccessToken(null);
      set({ user: null, loading: false, hydrated: true, canOperate: false, activeTenant: null });
    }
  },
  async login(username, password) {
    const session = await apiLogin(username, password);
    if (session.mfa_required && !session.access_token) {
      // No state is set: this browser is not signed in, and pretending
      // otherwise would leave a half-authenticated console behind if the user
      // walked away at the code prompt.
      return {
        status: "mfa-required" as const,
        mfaToken: session.mfa_token ?? "",
        expiresIn: session.expires_in,
      };
    }
    // A login is a new session, and the tenant a previous user of this browser
    // had selected is not this user's to inherit: /auth/me is scoped by the
    // request interceptor, so leaving a stale selection in place would ask the
    // API about a tenant this account may hold nothing in and get a 403 where
    // a principal should be. The switcher starts at the server's own choice.
    setActiveTenant(null);
    // The login response carries no tenant context (ROADMAP P0), so read the
    // full principal — tenants, default tenant, platform-admin flag — from
    // /auth/me and fall back to the login payload if that call fails.
    let user: Me = {
      username: session.username,
      role: session.role ?? "viewer",
      tenants: [],
      default_tenant: "default",
      is_platform_admin: session.role === "admin",
      mfa_pending: session.mfa_required,
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
      canOperate: canOperateIn(user),
      activeTenant: reconcileTenant(user),
    });
    // A session that owes an enrolment is a session: the console shows the
    // banner and the setup page rather than the login form.
    return { status: "signed-in" as const, mfaPending: Boolean(user.mfa_pending) };
  },
  async verifyMfa({ mfaToken, code, recoveryCode }) {
    await apiVerifyMfa({ mfa_token: mfaToken, code, recovery_code: recoveryCode });
    // Deliberately re-read rather than derived from the verify response: this
    // is also the step-up path, where the store already holds a principal and
    // the only thing that changed is what the *token* now proves.
    await useAuthStore.getState().hydrate();
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
  async selectTenant(tenantId) {
    // Set first, so the request below — and anything the caller fires next —
    // is already in the new tenant.
    setActiveTenant(tenantId);
    set({ activeTenant: tenantId });
    // Then re-read the principal *for that tenant*. `tenant_role` and
    // `permissions` are per tenant (#318) and the request interceptor scopes
    // this call like every other, so without it the console would keep gating
    // its pages on the authority of the tenant it just left — hiding a panel
    // the API would serve, and showing one it refuses.
    try {
      const user = await fetchMe();
      set({ user, canOperate: canOperateIn(user) });
    } catch {
      // The tenant stays selected: the API is the boundary and it is now being
      // asked in the right scope, so the cost of a failure here is a stale
      // gate, not a wrong answer. hydrate() retries on the next page load.
    }
  },
}));
