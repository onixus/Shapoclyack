"use client";

import { create } from "zustand";

export type Theme = "dark" | "light";
export type Locale = "en" | "ru";

export const THEME_STORAGE_KEY = "shapoclyack.theme";
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

export function applyTheme(theme: Theme) {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.classList.toggle("dark", theme === "dark");
  root.classList.toggle("light", theme === "light");
  root.style.colorScheme = theme;
}

export function applyLocale(locale: Locale) {
  if (typeof document === "undefined") return;
  document.documentElement.lang = locale;
}

type AppearanceState = {
  theme: Theme;
  locale: Locale;
  hydrated: boolean;
  hydrate: () => void;
  setTheme: (theme: Theme) => void;
  setLocale: (locale: Locale) => void;
  toggleTheme: () => void;
};

function parseTheme(raw: string | null): Theme {
  return raw === "light" ? "light" : "dark";
}

function parseLocale(raw: string | null): Locale {
  return raw === "ru" ? "ru" : "en";
}

export const useAppearanceStore = create<AppearanceState>((set, get) => ({
  theme: "dark",
  locale: "en",
  hydrated: false,
  hydrate() {
    const theme = parseTheme(readStorage(THEME_STORAGE_KEY));
    const locale = parseLocale(readStorage(LOCALE_STORAGE_KEY));
    applyTheme(theme);
    applyLocale(locale);
    set({ theme, locale, hydrated: true });
  },
  setTheme(theme) {
    writeStorage(THEME_STORAGE_KEY, theme);
    applyTheme(theme);
    set({ theme });
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
