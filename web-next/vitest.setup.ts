import "@testing-library/jest-dom/vitest";
import { setTimeout as waitForTimerTurn } from "node:timers/promises";
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

// And Radix Select opens its dropdown through Pointer Events and scrolls the
// active item into view — neither of which jsdom implements, so a test that
// clicks a select trigger throws before the menu exists. The component depends
// on none of this behaviour; it only needs the methods to be callable.
const elementPrototype = globalThis.Element?.prototype as
  | (Element & Record<string, unknown>)
  | undefined;
if (elementPrototype) {
  elementPrototype.hasPointerCapture ??= () => false;
  elementPrototype.setPointerCapture ??= () => {};
  elementPrototype.releasePointerCapture ??= () => {};
  elementPrototype.scrollIntoView ??= () => {};
}

// RTL's automatic cleanup relies on a global afterEach, which we don't expose
// (vitest globals are off), so register it explicitly.
afterEach(async () => {
  cleanup();
  // Radix FocusScope dispatches its unmount autofocus event in a zero-delay
  // timer. Let that callback finish before Vitest replaces this file's jsdom
  // globals; otherwise it creates an Event from another realm and throws.
  await waitForTimerTurn(0);
  useAppearanceStore.setState({ theme: "dark", locale: "en", hydrated: false });
});
