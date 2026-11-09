import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  applyLocale,
  applyTheme,
  LEGACY_THEME_STORAGE_KEY,
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
  useAppearanceStore.setState({
    theme: "dark",
    preference: "dark",
    locale: "en",
    hydrated: false,
  });
  document.documentElement.className = "";
  document.documentElement.removeAttribute("style");
  document.documentElement.removeAttribute("data-theme");
  document.documentElement.lang = "en";
}

describe("appearance", () => {
  beforeEach(resetStore);
  afterEach(resetStore);

  it("defaults to dark English until hydrate", () => {
    const state = useAppearanceStore.getState();
    expect(state.theme).toBe("dark");
    expect(state.preference).toBe("dark");
    expect(state.locale).toBe("en");
    expect(state.hydrated).toBe(false);
  });

  it("hydrate reads light theme and Russian from storage", () => {
    window.localStorage.setItem(THEME_STORAGE_KEY, "light");
    window.localStorage.setItem(LOCALE_STORAGE_KEY, "ru");
    useAppearanceStore.getState().hydrate();
    const state = useAppearanceStore.getState();
    expect(state.theme).toBe("light");
    expect(state.preference).toBe("light");
    expect(state.locale).toBe("ru");
    expect(state.hydrated).toBe(true);
    expect(document.documentElement.classList.contains("light")).toBe(true);
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(document.documentElement.style.colorScheme).toBe("light");
    expect(document.documentElement.lang).toBe("ru");
  });

  it("copies a legacy shapoclyack.theme value into apex.theme", () => {
    window.localStorage.setItem(LEGACY_THEME_STORAGE_KEY, "light");
    useAppearanceStore.getState().hydrate();
    expect(useAppearanceStore.getState().preference).toBe("light");
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("light");
  });

  it("ignores unknown stored values", () => {
    window.localStorage.setItem(THEME_STORAGE_KEY, "solarized");
    window.localStorage.setItem(LOCALE_STORAGE_KEY, "de");
    useAppearanceStore.getState().hydrate();
    expect(useAppearanceStore.getState().theme).toBe("dark");
    expect(useAppearanceStore.getState().preference).toBe("dark");
    expect(useAppearanceStore.getState().locale).toBe("en");
  });

  it("follows the system scheme when that preference is stored", () => {
    const query = {
      matches: false,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    };
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      value: vi.fn(() => query),
    });
    window.localStorage.setItem(THEME_STORAGE_KEY, "system");
    useAppearanceStore.getState().hydrate();
    expect(useAppearanceStore.getState().preference).toBe("system");
    expect(useAppearanceStore.getState().theme).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(query.addEventListener).toHaveBeenCalledWith("change", expect.any(Function));
    Reflect.deleteProperty(window, "matchMedia");
  });

  it("setTheme persists and remaps the html class", () => {
    useAppearanceStore.getState().setTheme("light");
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("light");
    expect(document.documentElement.classList.contains("light")).toBe(true);
    expect(document.documentElement.style.colorScheme).toBe("light");
    useAppearanceStore.getState().toggleTheme();
    expect(useAppearanceStore.getState().theme).toBe("dark");
    expect(useAppearanceStore.getState().preference).toBe("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });

  it("applyTheme / applyLocale can run without a store", () => {
    applyTheme("light");
    applyLocale("ru");
    expect(document.documentElement.classList.contains("light")).toBe(true);
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(document.documentElement.lang).toBe("ru");
  });
});
