import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";
import { useAppearanceStore } from "@/lib/appearance";

// Radix primitives (Select, Checkbox) measure themselves through
// ResizeObserver, which jsdom does not provide.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??= ResizeObserverStub as unknown as typeof ResizeObserver;

// RTL's automatic cleanup relies on a global afterEach, which we don't expose
// (vitest globals are off), so register it explicitly.
afterEach(() => {
  cleanup();
  useAppearanceStore.setState({ theme: "dark", locale: "en", hydrated: false });
});
