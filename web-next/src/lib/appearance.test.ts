import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  applyLocale,
  applyTheme,
  LOCALE_STORAGE_KEY,
  THEME_STORAGE_KEY,
  useAppearanceStore,
} from "@/lib/appearance";

const memory = new Map<string, string>();
const storageStub: Storage = {
  get length() {
    return memory.size;
  },
  clear() {
    memory.clear();
  },
  getItem(key) {
    return memory.get(key) ?? null;
  },
  key(index) {
    return Array.from(memory.keys())[index] ?? null;
  },
  removeItem(key) {
    memory.delete(key);
  },
  setItem(key, value) {
    memory.set(key, value);
  },
};

function resetStore() {
  memory.clear();
  Object.defineProperty(window, "localStorage", { configurable: true, value: storageStub });
  useAppearanceStore.setState({ theme: "dark", locale: "en", hydrated: false });
  document.documentElement.className = "";
  document.documentElement.removeAttribute("style");
  document.documentElement.lang = "en";
}

describe("appearance", () => {
  beforeEach(resetStore);
  afterEach(resetStore);

  it("defaults to dark English until hydrate", () => {
    const state = useAppearanceStore.getState();
    expect(state.theme).toBe("dark");
    expect(state.locale).toBe("en");
    expect(state.hydrated).toBe(false);
  });

  it("hydrate reads light theme and Russian from storage", () => {
    window.localStorage.setItem(THEME_STORAGE_KEY, "light");
    window.localStorage.setItem(LOCALE_STORAGE_KEY, "ru");
    useAppearanceStore.getState().hydrate();
    const state = useAppearanceStore.getState();
    expect(state.theme).toBe("light");
    expect(state.locale).toBe("ru");
    expect(state.hydrated).toBe(true);
    expect(document.documentElement.classList.contains("light")).toBe(true);
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    expect(document.documentElement.lang).toBe("ru");
  });

  it("ignores unknown stored values", () => {
    window.localStorage.setItem(THEME_STORAGE_KEY, "solarized");
    window.localStorage.setItem(LOCALE_STORAGE_KEY, "de");
    useAppearanceStore.getState().hydrate();
    expect(useAppearanceStore.getState().theme).toBe("dark");
    expect(useAppearanceStore.getState().locale).toBe("en");
  });

  it("setTheme persists and remaps the html class", () => {
    useAppearanceStore.getState().setTheme("light");
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("light");
    expect(document.documentElement.classList.contains("light")).toBe(true);
    expect(document.documentElement.style.colorScheme).toBe("light");
    useAppearanceStore.getState().toggleTheme();
    expect(useAppearanceStore.getState().theme).toBe("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });

  it("applyTheme / applyLocale can run without a store", () => {
    applyTheme("light");
    applyLocale("ru");
    expect(document.documentElement.classList.contains("light")).toBe(true);
    expect(document.documentElement.lang).toBe("ru");
  });
});
