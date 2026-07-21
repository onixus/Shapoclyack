import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// RTL's automatic cleanup relies on a global afterEach, which we don't expose
// (vitest globals are off), so register it explicitly.
afterEach(() => {
  cleanup();
});
