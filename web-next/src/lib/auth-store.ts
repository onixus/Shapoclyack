"use client";

import { create } from "zustand";
import {
  fetchMe,
  getAccessToken,
  login as apiLogin,
  setAccessToken,
  type Me,
  type Role,
} from "@/lib/api";

type AuthState = {
  user: Me | null;
  loading: boolean;
  hydrated: boolean;
  canOperate: boolean;
  hydrate: () => Promise<void>;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
};

function canOperate(role: Role | undefined) {
  return role === "operator" || role === "admin";
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  loading: true,
  hydrated: false,
  canOperate: false,
  async hydrate() {
    const token = getAccessToken();
    if (!token) {
      set({ user: null, loading: false, hydrated: true, canOperate: false });
      return;
    }
    try {
      const user = await fetchMe();
      set({
        user,
        loading: false,
        hydrated: true,
        canOperate: canOperate(user.role),
      });
    } catch {
      setAccessToken(null);
      set({ user: null, loading: false, hydrated: true, canOperate: false });
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
    });
  },
  logout() {
    setAccessToken(null);
    set({ user: null, loading: false, hydrated: true, canOperate: false });
  },
}));
