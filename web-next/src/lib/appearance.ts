"use client";

import { create } from "zustand";

/** What the operator picked. `system` follows the OS colour scheme. */
export type ThemePreference = "dark" | "light" | "system";
/** The theme actually painted on `<html>`. */
export type Theme = "dark" | "light";
export type Locale = "en" | "ru";

export const THEME_STORAGE_KEY = "apex.theme";
export const LEGACY_THEME_STORAGE_KEY = "shapoclyack.theme";
export const LOCALE_STORAGE_KEY = "shapoclyack.locale";

function readStorage(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStorage(key: string, value: string) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    /* private mode / jsdom without Storage */
  }
}

export function isThemePreference(value: string | null): value is ThemePreference {
  return value === "dark" || value === "light" || value === "system";
}

export function prefersDark(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return true;
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

export function resolveTheme(preference: ThemePreference, systemDark = prefersDark()): Theme {
  if (preference === "system") return systemDark ? "dark" : "light";
  return preference;
}

/**
 * Read the saved preference. A value written before the APEX key
 * (`shapoclyack.theme` = dark|light) is copied across once.
 */
export function readThemePreference(): ThemePreference {
  const next = readStorage(THEME_STORAGE_KEY);
  if (isThemePreference(next)) return next;
  const legacy = readStorage(LEGACY_THEME_STORAGE_KEY);
  if (legacy === "dark" || legacy === "light") {
    writeStorage(THEME_STORAGE_KEY, legacy);
    return legacy;
  }
  return "dark";
}

export function applyTheme(theme: Theme) {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.classList.toggle("dark", theme === "dark");
  root.classList.toggle("light", theme === "light");
  root.dataset.theme = theme;
  root.style.colorScheme = theme;
}

export function applyLocale(locale: Locale) {
  if (typeof document === "undefined") return;
  document.documentElement.lang = locale;
}

type AppearanceState = {
  /** Resolved theme on `<html>`. */
  theme: Theme;
  preference: ThemePreference;
  locale: Locale;
  hydrated: boolean;
  hydrate: () => void;
  setTheme: (preference: ThemePreference) => void;
  setLocale: (locale: Locale) => void;
  toggleTheme: () => void;
};

function parseLocale(raw: string | null): Locale {
  return raw === "ru" ? "ru" : "en";
}

let systemQuery: MediaQueryList | null = null;

function onSystemThemeChange() {
  const state = useAppearanceStore.getState();
  if (state.preference !== "system" || !systemQuery) return;
  const theme = resolveTheme("system", systemQuery.matches);
  applyTheme(theme);
  useAppearanceStore.setState({ theme });
}

function bindSystemListener(preference: ThemePreference) {
  if (preference !== "system") {
    systemQuery?.removeEventListener("change", onSystemThemeChange);
    systemQuery = null;
    return;
  }
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
  if (!systemQuery) {
    systemQuery = window.matchMedia("(prefers-color-scheme: dark)");
    systemQuery.addEventListener("change", onSystemThemeChange);
  }
}

export const useAppearanceStore = create<AppearanceState>((set, get) => ({
  theme: "dark",
  preference: "dark",
  locale: "en",
  hydrated: false,
  hydrate() {
    const preference = readThemePreference();
    const theme = resolveTheme(preference);
    const locale = parseLocale(readStorage(LOCALE_STORAGE_KEY));
    applyTheme(theme);
    applyLocale(locale);
    bindSystemListener(preference);
    set({ theme, preference, locale, hydrated: true });
  },
  setTheme(preference) {
    writeStorage(THEME_STORAGE_KEY, preference);
    const theme = resolveTheme(preference);
    applyTheme(theme);
    bindSystemListener(preference);
    set({ preference, theme });
  },
  setLocale(locale) {
    writeStorage(LOCALE_STORAGE_KEY, locale);
    applyLocale(locale);
    set({ locale });
  },
  toggleTheme() {
    get().setTheme(get().theme === "dark" ? "light" : "dark");
  },
}));
